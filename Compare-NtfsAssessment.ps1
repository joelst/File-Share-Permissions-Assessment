#requires -Version 5.1
# DISCLAIMER:
# This script is provided "AS IS", without warranty of any kind, express or implied,
# including merchantability, fitness for a particular purpose, and noninfringement.
# To the maximum extent permitted by applicable law, the authors and contributors
# are not liable for any damages arising from its use or inability to use it.
# No technical support, maintenance, updates, or service-level commitment is provided.
# Use at your own risk. Review and test in a nonproduction environment, maintain
# verified backups, and obtain required approvals before use.
# This script is not an official Microsoft product or supported Microsoft service.

<#
.SYNOPSIS
  Reports permission differences between two collected assessment snapshots, offline.
.DESCRIPTION
  Defaults to the two newest runs under InputRoot, ordered by manifest CompletedUtc.
  BaselineRunFolder and ComparisonRunFolder instead select an explicit, directional pair.
  Compares directory owner/inheritance/SDDL, exact NTFS ACE multisets, collected SMB
  share metadata and share ACEs. A replacement ACE is reported as Removed plus Added.
  Run IDs, ACE hashes/ordinals, resolved display names, timestamps and row order are
  not permission identities. SID, numeric rights, type and inheritance flags are.

  Missing records are not proof of deleted files/shares or revoked effective access.
  Partial scans, different scan roots and unavailable data are reported explicitly.
  Individual file ACLs, group memberships and effective access are not compared.
  Does not connect to servers or change any permissions or inheritance.
.NOTES
  Release version: NtfsAssessment.Common.ps1, Comparison entry in NtfsVersions.
  Compares permission differences between two collected assessment snapshots, offline.
  
  Requires NtfsAssessment.Common.ps1 alongside this script.
  CSV parts are limited to 100,000,000 bytes. OutputFolder must be empty or new.
  Memory is bounded to one share pair, with a default guard of 1,000,000 folder/ACE
  records (including share ACEs) per share per run. Raise MaxRowsPerShare only
  with sufficient memory.
  Exit codes: 0 = completed (including differences); 1 = completed with limitations;
  2 = invalid input or failure. Check comparison-state.json before consuming outputs.
  Share principal SIDs and verified offline aliases are preferred to display names.
  Unverified identity changes or changed SVM boundaries are NotCompared.
  Mixed local/UNC or overlapping roots within a snapshot are rejected; mixed
  addressing across the explicit pair is also rejected. Disjoint subtrees are supported.
  Cleanup failures are persisted as warnings (exit 1), preserving analysis failures (2).
.EXAMPLE
  .\Compare-NtfsAssessment.ps1 -InputRoot C:\Assessments -OutputFolder C:\Reports\LatestDiff
.EXAMPLE
  .\Compare-NtfsAssessment.ps1 -BaselineRunFolder C:\Assessments\ASSESS_old `
      -ComparisonRunFolder C:\Assessments\ASSESS_new -OutputFolder C:\Reports\SelectedDiff
#>
[CmdletBinding(DefaultParameterSetName='Latest')]
param(
    [Parameter(ParameterSetName='Latest')][ValidateNotNullOrEmpty()][string]$InputRoot='.',
    [Parameter(Mandatory=$true,ParameterSetName='Explicit')][Alias('OldRunFolder')][ValidateNotNullOrEmpty()][string]$BaselineRunFolder,
    [Parameter(Mandatory=$true,ParameterSetName='Explicit')][Alias('NewRunFolder')][ValidateNotNullOrEmpty()][string]$ComparisonRunFolder,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputFolder,
    [ValidateRange(1,20000000)][int]$MaxRowsPerShare=1000000
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'NtfsAssessment.Common.ps1')

function Get-Value($Object,[string]$Name,[string]$Default='') {
    if($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name){return [string]$Object.$Name}
    return $Default
}
function Get-PathKey([string]$Path) {
    return Get-NtfsPathKey $Path
}
function Get-ShareKey([string]$Server,[string]$Share) {
    if([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Share)){throw 'Blank server/share in assessment data.'}
    return ConvertTo-NtfsCsvRecord @($Server.ToLowerInvariant(),$Share.ToLowerInvariant())
}
function Add-Limitation([string]$Message) {
    if($script:Limitations.Add($Message)){Write-Warning $Message}
}
function Save-ComparisonState([string]$Status,[string]$Stage,[string]$ErrorMessage='') {
    if(-not $script:OutputReady){return}
    [ordered]@{
        Version=$script:NtfsVersions.Comparison;Status=$Status;Stage=$Stage;Error=$ErrorMessage
        Limitations=@($script:Limitations|Sort-Object);UpdatedUtc=[datetime]::UtcNow.ToString('o')
    }|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $OutputFolder 'comparison-state.json') -Encoding UTF8
    Write-NtfsLog (Join-Path $OutputFolder 'comparison-stage.log') Comparison $Status $Stage $ErrorMessage
}
function Read-Manifest([string]$Directory) {
    $path=(Resolve-Path -LiteralPath $Directory -ErrorAction Stop).ProviderPath
    $manifestPath=Join-Path $path 'manifest.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop|ConvertFrom-Json
    [datetimeoffset]$completed=[datetimeoffset]::MinValue
    $validTime=$false
    if($manifest.PSObject.Properties.Name -contains 'CompletedUtc'){
        $time=$manifest.CompletedUtc
        if($time -is [datetime] -or $time -is [datetimeoffset]){$completed=[datetimeoffset]$time;$validTime=$true}
        else{$validTime=[datetimeoffset]::TryParse([string]$time,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$completed)}
    }
    if(-not(Get-Value $manifest 'RunId') -or -not $validTime){
        throw "Unrankable assessment manifest: $manifestPath. Repair the input or specify two other run folders explicitly."
    }
    return [pscustomobject]@{
        RunFolder=$path;RunId=[string]$manifest.RunId;CompletedUtc=$completed.ToUniversalTime();Manifest=$manifest
        Files=@{};Shares=@{};Coverage=@{};Errors=@{};Scopes=@{};Spools=@{};Legacy=$false
        ReadErrorCount=0L;SkippedCount=0L;ShareAclFailed=$false;ManifestSHA256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    }
}
function Read-Dataset($Run,[string]$Name,[string[]]$Required=@()) {
    $dataset=@(if(-not $Run.Legacy){$Run.Manifest.Datasets|Where-Object Name -eq $Name})
    $total=0L
    foreach($file in $Run.Files[$Name]){
        $partRows=0L
        if(-not $Run.Legacy){
            $reader=[IO.StreamReader]::new($file.FullName,[Text.Encoding]::UTF8,$true)
            try{
                $header=[NtfsAssessment.Csv]::ReadRecord($reader)
                $columns=@(if(-not [string]::IsNullOrWhiteSpace($header)){[NtfsAssessment.Csv]::Parse($header)})
                if((ConvertTo-NtfsCsvRecord $columns) -cne (ConvertTo-NtfsCsvRecord @($dataset[0].Columns))){throw "Manifest column mismatch: $($file.FullName)"}
            }finally{$reader.Dispose()}
        }
        Read-NtfsCsvFile $file.FullName $Required|ForEach-Object{
            $partRows++
            $id=Get-Value $_ 'RunId'
            if($id -and $id -ne $Run.RunId){throw "RunId mismatch in $($file.FullName): $id"}
            $_
        }
        $total+=$partRows
        if(-not $Run.Legacy){
            $part=@($dataset[0].Parts|Where-Object Name -eq $file.Name)[0]
            if($partRows -ne [long]$part.Rows){throw "Manifest part row-count mismatch: $($file.FullName)"}
        }
    }
    if(-not $Run.Legacy -and $dataset.Count -gt 0 -and $total -ne [long]$dataset[0].Rows){throw "Manifest dataset row-count mismatch: $Name"}
}
function Initialize-Run($Run) {
    $manifest=$Run.Manifest
    if(Get-Value $manifest 'FatalError'){throw "Run $($Run.RunId) has a fatal collection error. No fallback to older runs is allowed."}
    [version]$schema=$null;[version]$toolkit=$null
    $current=([version]::TryParse((Get-Value $manifest 'SchemaVersion'),[ref]$schema) -and $schema -ge [version]'1.3') -or
        ([version]::TryParse((Get-Value $manifest 'ToolkitVersion'),[ref]$toolkit) -and $toolkit -ge [version]'1.6.4')
    if($manifest.PSObject.Properties.Name -notcontains 'Datasets'){
        if($current){throw "Current-schema run $($Run.RunId) is missing its required integrity inventory."}
        $Run.Legacy=$true
        Add-Limitation "Run $($Run.RunId) is legacy data without a verified inventory; absent records cannot be confirmed."
    }
    $required=@('Shares.csv','Folders.csv','NtfsAcls.csv','ShareCoverage.csv','ScanErrors.csv','SkippedPaths.csv')
    if(-not $Run.Legacy){
        foreach($name in $required){
            if(@($manifest.Datasets|Where-Object Name -eq $name).Count -ne 1){throw "Required dataset missing or duplicated in run $($Run.RunId): $name"}
        }
        foreach($dataset in $manifest.Datasets){[void]@(Get-NtfsCsvFiles $Run.RunFolder $dataset.Name)}
    }
    foreach($name in ($required+@('SharePermissions.csv'))){
        $Run.Files[$name]=@(Get-NtfsCsvFiles $Run.RunFolder $name)
        if($Run.Files[$name].Count -eq 0 -and $name -in @('Shares.csv','Folders.csv','NtfsAcls.csv')){throw "Required dataset unavailable: $name in $($Run.RunFolder)"}
    }
    if([long]$manifest.Counts.Errors -gt 0 -or (Get-Value $manifest 'CoverageStatus') -ne 'CompleteDirectoriesOnly'){
        Add-Limitation "Run $($Run.RunId) has partial or unverified collection coverage."
    }
    if($manifest.PSObject.Properties.Name -contains 'Scopes'){$scopes=@($manifest.Scopes)}
    else{
        $scopes=@(Read-Dataset $Run 'Shares.csv' @('Server','Share'))
        Add-Limitation "Run $($Run.RunId) has no explicit scope inventory."
    }
    foreach($scope in $scopes){
        $key=Get-ShareKey $scope.Server $scope.Share
        if(-not $Run.Scopes.ContainsKey($key)){$Run.Scopes[$key]=[Collections.ArrayList]::new()}
        [void]$Run.Scopes[$key].Add($scope)
    }
    if($Run.Scopes.Count -eq 0){throw "Run $($Run.RunId) has no assessment scopes."}
    Assert-NtfsScopeRoots $scopes
    Read-Dataset $Run 'Shares.csv' @('Server','Share')|ForEach-Object{
        $key=Get-ShareKey $_.Server $_.Share
        if(-not $Run.Scopes.ContainsKey($key)){throw 'Shares.csv contains a share not declared in the manifest scopes.'}
        if(-not $Run.Shares.ContainsKey($key)){$Run.Shares[$key]=[Collections.ArrayList]::new()}
        $row=$_
        $fields=@('LocalPath','Description','EncryptData','ContinuouslyAvailable','ShareMetadataStatus')
        $signature=ConvertTo-NtfsCsvRecord @($fields|ForEach-Object{Get-Value $row $_})
        foreach($existing in $Run.Shares[$key]){
            if((ConvertTo-NtfsCsvRecord @($fields|ForEach-Object{Get-Value $existing $_})) -cne $signature){throw "Conflicting share metadata in run $($Run.RunId): $key"}
        }
        [void]$Run.Shares[$key].Add($row)
    }
    Read-Dataset $Run 'ShareCoverage.csv' @('Server','Share','Status')|ForEach-Object{
        $key=Get-ShareKey $_.Server $_.Share
        if(-not $Run.Coverage.ContainsKey($key)){$Run.Coverage[$key]=[Collections.ArrayList]::new()}
        [void]$Run.Coverage[$key].Add($_)
    }
    Read-Dataset $Run 'ScanErrors.csv' @('Stage','Path')|ForEach-Object{
        $Run.ReadErrorCount++
        if($_.Stage -in @('ShareACL','OntapSharePerms','OntapCsvImport')){$Run.ShareAclFailed=$true}
        # A folder can be emitted before its ACE loop fails. Such a partial ACE set
        # is never evidence that an allow or deny rule was removed.
        if($_.Stage -in @('ReadACL','ReadAccessRules','ValidateUNC')){
            $Run.Errors[(Get-PathKey $_.Path)]=$true
        }
    }
    Read-Dataset $Run 'SkippedPaths.csv' @('Path','Reason')|ForEach-Object{$Run.SkippedCount++}
    if($Run.ReadErrorCount -gt 0 -or $Run.SkippedCount -gt 0){Add-Limitation "Run $($Run.RunId) records collection errors or skipped paths; absence is not confirmed."}
}
function Get-Roots($Run,[string]$Key) {
    if(-not $Run.Scopes.ContainsKey($Key)){return}
    foreach($scope in $Run.Scopes[$Key]){
        $root=Get-Value $scope 'ScanRoot'
        if(-not $root){$root=Get-Value $scope 'UNC'}
        Get-PathKey $root
    }
}
function Test-CompleteScope($Run,[string]$Key) {
    if($Run.Legacy -or [long]$Run.Manifest.Counts.Errors -gt 0 -or $Run.ReadErrorCount -gt 0 -or $Run.SkippedCount -gt 0 -or -not $Run.Coverage.ContainsKey($Key)){return $false}
    $coverage=@($Run.Coverage[$Key])
    $roots=@(Get-Roots $Run $Key|Sort-Object -Unique)
    if($roots.Count -eq 0 -or $roots -contains ''){return $false}
    foreach($root in $roots){
        if(@($coverage|Where-Object{(Get-PathKey (Get-Value $_ 'UNC')) -eq $root}).Count -eq 0){return $false}
    }
    foreach($row in $coverage){
        if($row.Status -ne 'CompletedDirectoriesOnly' -or
            (Get-Value $row 'Errors') -notmatch '^0$' -or (Get-Value $row 'SkippedPaths') -notmatch '^0$'){return $false}
    }
    return $true
}
function Test-ReadableFolder($Run,$Folder) {
    if($null -eq $Folder -or $Run.Errors.ContainsKey((Get-PathKey $Folder.Path))){return $false}
    $status=Get-Value $Folder 'CollectionStatus'
    if($status){return $status -eq 'Read'}
    return -not [string]::IsNullOrWhiteSpace((Get-Value $Folder 'SDDL'))
}
function Stage-Run($Run,[string]$Side) {
    $writers=@{}
    try{
        foreach($dataset in @('Folders','NtfsAcls','SharePermissions')){
            $readCount=0L
            Read-Dataset $Run "$dataset.csv" $script:Required[$dataset]|ForEach-Object{
                $row=$_;$readCount++
                $key=Get-ShareKey $row.Server $row.Share
                if(-not $Run.Scopes.ContainsKey($key)){throw "$dataset row is outside declared scopes in run $($Run.RunId)."}
                if(-not $Run.Spools.ContainsKey($key)){$Run.Spools[$key]=@{Count=0L}}
                $spool=$Run.Spools[$key]
                if($dataset -ne 'SharePermissions'){
                    if(-not (Get-Value $row 'Path')){throw 'Blank path in collected folder/ACE data.'}
                }
                $spool.Count++
                if($spool.Count -gt $MaxRowsPerShare){throw "Run $($Run.RunId), $($row.Server)\$($row.Share) exceeds MaxRowsPerShare=$MaxRowsPerShare. Increase that guard only with sufficient memory or collect smaller scopes."}
                $writerKey="$dataset|$key"
                if(-not $writers.ContainsKey($writerKey)){
                    $path=Join-Path $TempDir ($Side+'_'+(Get-NtfsHash $key)+"_$dataset.tmp")
                    $writers[$writerKey]=[IO.StreamWriter]::new($path,$false,[Text.UTF8Encoding]::new($false))
                    $writers[$writerKey].WriteLine((ConvertTo-NtfsCsvRecord $script:Columns[$dataset]))
                    $spool[$dataset]=$path
                }
                $writers[$writerKey].WriteLine((ConvertTo-NtfsCsvRecord @($script:Columns[$dataset]|ForEach-Object{Get-Value $row $_})))
            }
            if($dataset -in @('Folders','NtfsAcls')){
                $countName=if($dataset -eq 'Folders'){'Folders'}else{'NtfsAces'}
                if($readCount -ne [long]$Run.Manifest.Counts.$countName){throw "Manifest row-count mismatch for $dataset in run $($Run.RunId)."}
            }
        }
    }finally{foreach($writer in $writers.Values){$writer.Dispose()}}
}
function Read-Staged($Run,[string]$Key,[string]$Dataset) {
    if($Run.Spools.ContainsKey($Key) -and $Run.Spools[$Key].ContainsKey($Dataset)){
        Read-NtfsCsvFile $Run.Spools[$Key][$Dataset]
    }
}
function Get-FolderIndex($Run,[string]$Key) {
    $index=@{}
    Read-Staged $Run $Key 'Folders'|ForEach-Object{
        $path=Get-PathKey $_.Path
        $signature=ConvertTo-NtfsCsvRecord @($_.Owner,$_.InheritanceProtected,$_.SDDL,$_.DaclState,$_.CollectionStatus)
        if($index.ContainsKey($path)){
            $existing=$index[$path]
            if($existing.Signature -cne $signature){throw "Conflicting folder observations for $($_.Path) in run $($Run.RunId)."}
        }else{$index[$path]=@{Row=$_;Signature=$signature}}
    }
    return $index
}
function Get-Mask([string]$Value) {
    [long]$number=0
    if(-not [long]::TryParse($Value,[ref]$number)){
        try{$number=[long][Enum]::Parse([Security.AccessControl.FileSystemRights],$Value,$true)}
        catch{throw "Unrecognized rights/mask '$Value'; cannot compare permissions safely."}
    }
    if($number -lt -2147483648 -or $number -gt 4294967295){throw "Access mask is outside 32 bits: $Value"}
    if($number -lt 0){$number+=4294967296}
    return $number.ToString([Globalization.CultureInfo]::InvariantCulture)
}
function Get-AceSignature($Row) {
    $principal=if($Row.SID){'sid:'+([string]$Row.SID).ToLowerInvariant()}else{'name:'+([string]$Row.Identity).ToLowerInvariant()}
    $rights=Get-Mask $Row.Rights
    if($Row.RightsValue -and (Get-Mask $Row.RightsValue) -ne $rights){throw "Rights and RightsValue disagree for $($Row.Path), $($Row.Identity)."}
    if($Row.AccessControlType -notin @('Allow','Deny') -or $Row.IsInherited -notin @('True','False')){throw "Unknown ACE type or inherited state: $($Row.Path)"}
    try{
        $inherit=[int][Enum]::Parse([Security.AccessControl.InheritanceFlags],$Row.InheritanceFlags,$true)
        $propagate=[int][Enum]::Parse([Security.AccessControl.PropagationFlags],$Row.PropagationFlags,$true)
    }catch{throw "Unknown inheritance/propagation flags: $($Row.Path)"}
    if($inherit -lt 0 -or $inherit -gt 3 -or $propagate -lt 0 -or $propagate -gt 3){throw "Unsupported inheritance flags: $($Row.Path)"}
    return ConvertTo-NtfsCsvRecord @((Get-PathKey $Row.Path),$principal,$rights,$Row.AccessControlType.ToLowerInvariant(),$Row.IsInherited.ToLowerInvariant(),$inherit,$propagate)
}
function Get-AceIndex($Run,[string]$Key,$Folders,$UnverifiedPaths) {
    $index=@{};$ordinals=@{}
    Read-Staged $Run $Key 'NtfsAcls'|ForEach-Object{
        $a=$_;$path=Get-PathKey $a.Path
        if(-not $Folders.ContainsKey($path)){throw "ACE has no collected folder observation: $($a.Path) in run $($Run.RunId)"}
        if($a.DescriptorHash -and $Folders[$path].Row.DescriptorHash -and $a.DescriptorHash -ne $Folders[$path].Row.DescriptorHash){throw "ACE/folder descriptor mismatch: $($a.Path)"}
        if([string]::IsNullOrWhiteSpace($a.SID)){
            $UnverifiedPaths[$path]=$true
            Add-Limitation "Stable SID identity is unavailable for an ACE on $path; that path's ACE set is not compared."
        }
        $signature=Get-AceSignature $a
        if($a.AceOrdinal -ne ''){
            [int]$ordinal=0
            if(-not [int]::TryParse($a.AceOrdinal,[ref]$ordinal) -or $ordinal -lt 0){throw 'Invalid ACE ordinal.'}
            $occurrence=ConvertTo-NtfsCsvRecord @($path,$ordinal)
            if($ordinals.ContainsKey($occurrence)){
                if($ordinals[$occurrence] -cne $signature){throw "Conflicting ACE occurrences for $($a.Path) in run $($Run.RunId)"}
                return
            }
            $ordinals[$occurrence]=$signature
        }
        if(-not $index.ContainsKey($signature)){$index[$signature]=@{Row=$a;Count=0L;PathKey=$path}}
        $index[$signature].Count++
    }
    return $index
}
function Write-Change([string]$Entity,[string]$Type,$Before,$After,[string[]]$Fields,[long]$BeforeCount,[long]$AfterCount,[string]$Reason) {
    $row=if($null -ne $After){$After}else{$Before}
    $beforeJson=if($null -eq $Before){''}else{$Before|ConvertTo-Json -Depth 5 -Compress}
    $afterJson=if($null -eq $After){''}else{$After|ConvertTo-Json -Depth 5 -Compress}
    $script:Changes.WriteLine((ConvertTo-NtfsCsvRecord @(
        $Baseline.RunId,$Comparison.RunId,$Entity,$Type,(Get-Value $row 'Server'),(Get-Value $row 'Share'),
        (Get-Value $row 'Path'),(Get-Value $row 'Identity' (Get-Value $row 'AccountName')),(Get-Value $row 'SID'),
        ($Fields -join ';'),$BeforeCount,$AfterCount,$beforeJson,$afterJson,$Reason
    )))
    $summaryKey="$Entity|$Type"
    if(-not $script:Counts.ContainsKey($summaryKey)){$script:Counts[$summaryKey]=0L}
    $script:Counts[$summaryKey]++
}
function Get-ChangedFields($Before,$After,[string[]]$Names) {
    foreach($name in $Names){
        $a=Get-Value $Before $name;$b=Get-Value $After $name
        $emptyAllowed=$name -eq 'Description' -and $Before.PSObject.Properties.Name -contains $name -and $After.PSObject.Properties.Name -contains $name
        if(((-not $emptyAllowed) -and ($a -eq '' -or $b -eq '')) -or
            $a -in @('NotExposed','NotCollected','NotAvailable','Unknown') -or $b -in @('NotExposed','NotCollected','NotAvailable','Unknown')){
            if($a -cne $b){Add-Limitation "Field $name is not available in both snapshots; unverified field changes were excluded."}
            continue
        }
        $different=if($name -eq 'SDDL'){$a -cne $b}else{$a -ine $b}
        if($different){$name}
    }
}
function Compare-FoldersAndAces([string]$Key,[bool]$Complete) {
    $oldFolders=Get-FolderIndex $Baseline $Key;$newFolders=Get-FolderIndex $Comparison $Key
    $unverifiedPaths=@{}
    $oldAces=Get-AceIndex $Baseline $Key $oldFolders $unverifiedPaths;$newAces=Get-AceIndex $Comparison $Key $newFolders $unverifiedPaths
    $paths=@(@($oldFolders.Keys)+@($newFolders.Keys)|Sort-Object -Unique)
    foreach($path in $paths){
        $before=if($oldFolders.ContainsKey($path)){$oldFolders[$path].Row}else{$null}
        $after=if($newFolders.ContainsKey($path)){$newFolders[$path].Row}else{$null}
        if($unverifiedPaths.ContainsKey($path)){
            Write-Change 'NTFSACL' 'NotCompared' $before $after @('SID') ([long]($null -ne $before)) ([long]($null -ne $after)) 'Stable SID identity unavailable in one or both ACE sets; identity-resolution differences are not permission changes.'
        }
        if($null -ne $before -and $null -ne $after){
            if(-not (Test-ReadableFolder $Baseline $before) -or -not (Test-ReadableFolder $Comparison $after)){
                Add-Limitation "A folder ACL was not read successfully in both snapshots: $path"
                Write-Change 'Folder' 'NotCompared' $before $after @() 1 1 'ACL read failure or unknown read state; partial ACE sets are not compared.'
                continue
            }
            $fields=@(Get-ChangedFields $before $after @('Owner','InheritanceProtected','DaclState','SDDL'))
            if($fields.Count -gt 0){Write-Change 'Folder' 'Modified' $before $after $fields 1 1 'Observed descriptor fields differ. SDDL includes order/descriptor details; effective access is not calculated.'}
        }else{
            $type=if($null -eq $before){'Added'}else{'Removed'}
            $observed=if($null -ne $before){Test-ReadableFolder $Baseline $before}else{Test-ReadableFolder $Comparison $after}
            if(-not $Complete -or -not $observed){
                $type=if($null -eq $before){'ObservedOnlyAfter'}else{'ObservedOnlyBefore'}
            }
            Write-Change 'Folder' $type $before $after @() ([long]($null -ne $before)) ([long]($null -ne $after)) 'Snapshot inventory difference only; not proof of physical creation/deletion. Missingness is confirmed only for equal, complete scan scopes.'
        }
    }
    foreach($signature in @(@($oldAces.Keys)+@($newAces.Keys)|Sort-Object -Unique)){
        $old=if($oldAces.ContainsKey($signature)){$oldAces[$signature]}else{$null}
        $new=if($newAces.ContainsKey($signature)){$newAces[$signature]}else{$null}
        $oldCount=if($null -eq $old){0L}else{$old.Count};$newCount=if($null -eq $new){0L}else{$new.Count}
        if($oldCount -eq $newCount){continue}
        $entry=if($null -ne $new){$new}else{$old}
        $path=$entry.PathKey
        if($unverifiedPaths.ContainsKey($path)){continue}
        $both=$oldFolders.ContainsKey($path) -and $newFolders.ContainsKey($path)
        if($both){
            if(-not (Test-ReadableFolder $Baseline $oldFolders[$path].Row) -or -not (Test-ReadableFolder $Comparison $newFolders[$path].Row)){continue}
        }else{
            if($oldFolders.ContainsKey($path) -and -not (Test-ReadableFolder $Baseline $oldFolders[$path].Row)){continue}
            if($newFolders.ContainsKey($path) -and -not (Test-ReadableFolder $Comparison $newFolders[$path].Row)){continue}
        }
        $type=if($newCount -gt $oldCount){'Added'}else{'Removed'}
        if($Baseline.Legacy -or $Comparison.Legacy -or (-not $both -and -not $Complete)){$type=if($newCount -gt $oldCount){'ObservedOnlyAfter'}else{'ObservedOnlyBefore'}}
        Write-Change 'NTFSACE' $type $(if($null -ne $old){$old.Row}else{$null}) $(if($null -ne $new){$new.Row}else{$null}) @('OccurrenceCount') $oldCount $newCount 'Exact ACE multiset difference; replacements appear as Removed plus Added. No arbitrary ACE pairing or effective-access inference.'
    }
}
function Test-ShareAclCollected($Run,[string]$Key) {
    if($Run.Legacy -or $Run.ShareAclFailed -or $Run.Files['SharePermissions.csv'].Count -eq 0 -or -not $Run.Shares.ContainsKey($Key)){return $false}
    if(@($Run.Shares[$Key]|Where-Object{(Get-Value $_ 'ShareMetadataStatus') -ne 'Collected'}).Count -gt 0){return $false}
    return $true
}
function Get-ShareAceIndex($Run,[string]$Key) {
    $index=@{}
    Read-Staged $Run $Key 'SharePermissions'|ForEach-Object{
        $a=$_
        if($a.AccessControlType -notin @('Allow','Deny') -or -not $a.AccountName){throw 'Invalid share permission identity/type.'}
        $right=$a.AccessRight.Replace('_',' ').ToLowerInvariant()
        if($right -in @('full','full control')){$right='full'}
        if($right -notin @('full','change','read','no access')){throw "Unknown share permission right: $($a.AccessRight)"}
        $principal=Get-NtfsPrincipalKey $a.AccountName (Get-Value $a 'SID')
        $signature=ConvertTo-NtfsCsvRecord @($(if($principal){$principal}else{'name:'+$a.AccountName.ToLowerInvariant()}),$a.AccessControlType.ToLowerInvariant(),$right,$a.Vserver.ToLowerInvariant())
        # SMB share ACLs identify one account/type/right entry; repeated collection
        # of that entry is not another permission occurrence.
        if(-not $index.ContainsKey($signature)){$index[$signature]=@{Row=$a;Count=1L;VerifiedIdentity=[bool]$principal}}
    }
    return $index
}
function Compare-SharePermissions([string]$Key) {
    $old=Get-ShareAceIndex $Baseline $Key;$new=Get-ShareAceIndex $Comparison $Key
    $oldSvms=@($old.Values|ForEach-Object{$_.Row.Vserver.ToLowerInvariant()}|Sort-Object -Unique)
    $newSvms=@($new.Values|ForEach-Object{$_.Row.Vserver.ToLowerInvariant()}|Sort-Object -Unique)
    $uncertainSvm=@($oldSvms+$newSvms|Where-Object{$_}).Count -gt 0 -and
        (ConvertTo-NtfsCsvRecord $oldSvms) -cne (ConvertTo-NtfsCsvRecord $newSvms)
    $uncertainIdentity=@(@($old.Values)+@($new.Values)|Where-Object{-not $_.VerifiedIdentity}).Count -gt 0
    $complete=(Test-ShareAclCollected $Baseline $Key) -and (Test-ShareAclCollected $Comparison $Key)
    if(-not $complete){
        Add-Limitation "Share ACL collection completeness is not established on both sides for $Key; differences are observed-only."
    }
    foreach($signature in @(@($old.Keys)+@($new.Keys)|Sort-Object -Unique)){
        $before=if($old.ContainsKey($signature)){$old[$signature]}else{$null};$after=if($new.ContainsKey($signature)){$new[$signature]}else{$null}
        $oldCount=if($null -ne $before){$before.Count}else{0L};$newCount=if($null -ne $after){$after.Count}else{0L}
        if($oldCount -eq $newCount){continue}
        $type=if($newCount -gt $oldCount){'Added'}else{'Removed'}
        if(-not $complete){$type=if($newCount -gt $oldCount){'ObservedOnlyAfter'}else{'ObservedOnlyBefore'}}
        $reason='SMB share ACE snapshot difference; share denies and group tokens are not evaluated for effective access.'
        if($uncertainSvm -or $uncertainIdentity){
            $type='NotCompared'
            $reason='Share principal identity or SVM boundary is not verified across snapshots; no permission replacement is confirmed.'
            Add-Limitation "$reason Share=$Key"
        }
        Write-Change 'SharePermission' $type $(if($null -ne $before){$before.Row}else{$null}) $(if($null -ne $after){$after.Row}else{$null}) @('OccurrenceCount') $oldCount $newCount $reason
    }
}

$script:Limitations=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$script:OutputReady=$false;$script:Changes=$null;$scopeWriter=$null;$TempDir=$null;$script:Counts=@{};$exitCode=2
$script:Columns=@{
    Folders=@('RunId','Server','Share','ScanRoot','Path','PathHash','Owner','InheritanceProtected','SDDL','DaclState','DescriptorHash','CollectionStatus')
    NtfsAcls=@('RunId','Server','Share','ScanRoot','Path','PathHash','AceHash','AceOrdinal','DescriptorHash','Identity','SID','Rights','RightsValue','AccessControlType','IsInherited','InheritanceFlags','PropagationFlags')
    SharePermissions=@('RunId','Server','Share','AccountName','SID','AccessControlType','AccessRight','Source','Vserver')
}
$script:Required=@{
    Folders=@('Server','Share','Path','Owner','InheritanceProtected')
    NtfsAcls=@('Server','Share','Path','Identity','SID','Rights','AccessControlType','IsInherited','InheritanceFlags','PropagationFlags')
    SharePermissions=@('Server','Share','AccountName','AccessControlType','AccessRight')
}
try{
    $OutputFolder=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFolder)
    if(Test-Path -LiteralPath $OutputFolder){
        if(-not(Test-Path -LiteralPath $OutputFolder -PathType Container) -or @(Get-ChildItem -LiteralPath $OutputFolder -Force).Count -gt 0){throw 'OutputFolder must be a new or empty directory; existing data is not overwritten.'}
    }
    if($PSCmdlet.ParameterSetName -eq 'Explicit'){
        $Baseline=Read-Manifest $BaselineRunFolder;$Comparison=Read-Manifest $ComparisonRunFolder
    }else{
        $InputRoot=(Resolve-Path -LiteralPath $InputRoot -ErrorAction Stop).ProviderPath
        $outputPrefix=$OutputFolder.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
        $unfinished=@(Get-ChildItem -LiteralPath $InputRoot -Recurse -Directory -Filter 'ASSESS_*' -ErrorAction Stop|Where-Object{
            $_.FullName -ne $OutputFolder -and -not $_.FullName.StartsWith($outputPrefix,[StringComparison]::OrdinalIgnoreCase) -and
            -not(Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json'))
        })
        if($unfinished.Count -gt 0){throw 'Unfinished assessment folders found. Wait for collection to finish or specify two run folders explicitly.'}
        $runs=@(Get-ChildItem -LiteralPath $InputRoot -Recurse -File -Filter 'manifest.json' -ErrorAction Stop|
            Where-Object{-not $_.FullName.StartsWith($outputPrefix,[StringComparison]::OrdinalIgnoreCase)}|
            ForEach-Object{Read-Manifest $_.Directory.FullName}|Sort-Object @{Expression='CompletedUtc';Descending=$true},RunId)
        if($runs.Count -lt 2){throw 'At least two assessment runs are required.'}
        if(@($runs.RunId|Sort-Object -Unique).Count -ne $runs.Count){throw 'Duplicate RunIds found; specify two distinct run folders explicitly.'}
        if($runs[0].CompletedUtc -eq $runs[1].CompletedUtc -or ($runs.Count -gt 2 -and $runs[1].CompletedUtc -eq $runs[2].CompletedUtc)){
            throw 'Completion timestamps do not uniquely identify the last two runs. Specify baseline and comparison folders explicitly.'
        }
        $Baseline=$runs[1];$Comparison=$runs[0]
    }
    if($Baseline.RunId -eq $Comparison.RunId -or $Baseline.RunFolder -eq $Comparison.RunFolder){throw 'Baseline and comparison must be two distinct assessment runs.'}
    foreach($run in @($Baseline,$Comparison)){
        if($OutputFolder.StartsWith($run.RunFolder.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or $OutputFolder -eq $run.RunFolder){throw 'OutputFolder must be outside both source run folders.'}
    }
    if(-not(Test-Path -LiteralPath $OutputFolder)){[void](New-Item -ItemType Directory -Path $OutputFolder -ErrorAction Stop)}
    $script:OutputReady=$true
    Save-ComparisonState Running Selection
    foreach($run in @($Baseline,$Comparison)){
        Initialize-Run $run
    }
    Write-Host "Baseline:   $($Baseline.RunId) ($($Baseline.CompletedUtc.ToString('o'))) $($Baseline.RunFolder)"
    Write-Host "Comparison: $($Comparison.RunId) ($($Comparison.CompletedUtc.ToString('o'))) $($Comparison.RunFolder)"
    $TempDir=Join-Path $OutputFolder ('_temp_'+[guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $TempDir -ErrorAction Stop)
    Save-ComparisonState Running Reading
    foreach($key in $Baseline.Scopes.Keys){
        if(-not $Comparison.Scopes.ContainsKey($key)){continue}
        $beforeRoots=@(Get-Roots $Baseline $key);$afterRoots=@(Get-Roots $Comparison $key)
        if(@($beforeRoots+$afterRoots|Where-Object{$_.StartsWith('\\')}).Count -gt 0 -and
           @($beforeRoots+$afterRoots|Where-Object{$_ -and -not $_.StartsWith('\\')}).Count -gt 0){
            throw "Ambiguous mixed local/UNC addressing across snapshots for $key."
        }
    }
    Stage-Run $Baseline 'before';Stage-Run $Comparison 'after'
    $script:Changes=New-NtfsCsvWriter (Join-Path $OutputFolder 'NTFS_Changes.csv')
    $script:Changes.WriteLine((ConvertTo-NtfsCsvRecord @('BaselineRunId','ComparisonRunId','EntityType','ChangeType','Server','Share','Path','Identity','SID','ChangedFields','BeforeCount','AfterCount','BeforeJson','AfterJson','Reason')))
    $scopeWriter=New-NtfsCsvWriter (Join-Path $OutputFolder 'NTFS_ComparisonCoverage.csv')
    $scopeWriter.WriteLine((ConvertTo-NtfsCsvRecord @('Server','Share','BaselineRunId','ComparisonRunId','BaselineRoots','ComparisonRoots','BaselineComplete','ComparisonComplete','Status','Reason')))
    Save-ComparisonState Running Comparing
    foreach($key in @(@($Baseline.Scopes.Keys)+@($Comparison.Scopes.Keys)|Sort-Object -Unique)){
        $hasBefore=$Baseline.Scopes.ContainsKey($key);$hasAfter=$Comparison.Scopes.ContainsKey($key)
        $scope=if($hasAfter){$Comparison.Scopes[$key][0]}else{$Baseline.Scopes[$key][0]}
        $beforeRoots=@(Get-Roots $Baseline $key|Sort-Object -Unique);$afterRoots=@(Get-Roots $Comparison $key|Sort-Object -Unique)
        $completeBefore=Test-CompleteScope $Baseline $key;$completeAfter=Test-CompleteScope $Comparison $key
        $sameRoots=$hasBefore -and $hasAfter -and $beforeRoots.Count -gt 0 -and $beforeRoots -notcontains '' -and
            (ConvertTo-NtfsCsvRecord $beforeRoots) -ceq (ConvertTo-NtfsCsvRecord $afterRoots)
        if(-not $hasBefore -or -not $hasAfter){
            $status='NotCompared';$reason='Server/share is absent from one assessment scope; this does not prove a share was created or deleted.'
            Add-Limitation "$($scope.Server)\$($scope.Share): $reason"
            Write-Change 'Scope' 'NotCompared' $(if($hasBefore){$Baseline.Scopes[$key][0]}else{$null}) $(if($hasAfter){$Comparison.Scopes[$key][0]}else{$null}) @('AssessmentScope') ([long]$hasBefore) ([long]$hasAfter) $reason
        }elseif(-not $sameRoots){
            $status='NotCompared';$reason='Scan roots differ or are unknown. Local paths and UNC aliases are not assumed to be the same object.'
            Add-Limitation "$($scope.Server)\$($scope.Share): $reason"
            Write-Change 'Scope' 'NotCompared' $Baseline.Scopes[$key][0] $Comparison.Scopes[$key][0] @('ScanRoot') 1 1 $reason
        }else{
            $status=if($completeBefore -and $completeAfter){'ComparedCompleteDirectories'}else{'ComparedObservedPathsOnly'}
            $reason='Matched directory scopes; no file ACL, group-membership or effective-access comparison.'
            if(-not $completeBefore -or -not $completeAfter){Add-Limitation "$($scope.Server)\$($scope.Share): incomplete coverage; unobserved directories/ACEs are not treated as confirmed removals."}
            Compare-FoldersAndAces $key ($completeBefore -and $completeAfter)
        }
        $scopeWriter.WriteLine((ConvertTo-NtfsCsvRecord @($scope.Server,$scope.Share,$Baseline.RunId,$Comparison.RunId,($beforeRoots -join ';'),($afterRoots -join ';'),$completeBefore,$completeAfter,$status,$reason)))
        if($hasBefore -and $hasAfter){
            Compare-SharePermissions $key
            $oldShares=@(if($Baseline.Shares.ContainsKey($key)){$Baseline.Shares[$key]})
            $newShares=@(if($Comparison.Shares.ContainsKey($key)){$Comparison.Shares[$key]})
            if($oldShares.Count -gt 0 -and $newShares.Count -gt 0){
                $fields=@(Get-ChangedFields $oldShares[0] $newShares[0] @('LocalPath','Description','EncryptData','ContinuouslyAvailable'))
                if($fields.Count -gt 0){Write-Change 'Share' 'Modified' $oldShares[0] $newShares[0] $fields 1 1 'Collected share metadata fields differ.'}
            }
        }
    }
    $script:Changes.Dispose();$scopeWriter.Dispose()
    $summaryRows=@(foreach($key in @($script:Counts.Keys|Sort-Object)){
        $parts=$key.Split('|')
        [pscustomobject]@{EntityType=$parts[0];ChangeType=$parts[1];Count=$script:Counts[$key]}
    })
    Export-NtfsCsvData $summaryRows (Join-Path $OutputFolder 'NTFS_ChangesSummary.csv')
    if((@($script:Counts.Values)|Measure-Object -Sum).Sum -ne $script:Changes.Rows){throw 'Comparison row-count reconciliation failed.'}
    $sources=@(foreach($item in @(@('Baseline',$Baseline),@('Comparison',$Comparison))){
        $run=$item[1]
        if((Get-FileHash -LiteralPath (Join-Path $run.RunFolder 'manifest.json') -Algorithm SHA256).Hash -ne $run.ManifestSHA256){throw 'An input manifest changed while comparison was running.'}
        [pscustomobject]@{Role=$item[0];RunId=$run.RunId;RunFolder=$run.RunFolder;CompletedUtc=$run.CompletedUtc.ToString('o');ManifestSHA256=$run.ManifestSHA256}
    })
    Export-NtfsCsvData $sources (Join-Path $OutputFolder 'NTFS_ComparisonRuns.csv')
    $summary=[ordered]@{
        Version=$script:NtfsVersions.Comparison;GeneratedUtc=[datetime]::UtcNow.ToString('o');Baseline=$sources[0];Comparison=$sources[1]
        DifferenceRows=$script:Changes.Rows;Counts=$summaryRows;Limitations=@($script:Limitations|Sort-Object)
        Scope='Directory permissions, collected share permissions and share metadata only.'
        Interpretation='Added/Removed refer to snapshot records, not proven creation/deletion, effective-access changes, or remediation approvals.'
        MaxCsvFileBytes=100000000;Datasets=@(Get-NtfsDatasetInventory $OutputFolder)
    }
    $summary|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $OutputFolder 'NTFS_ComparisonSummary.json') -Encoding UTF8
    $exitCode=if($script:Limitations.Count -gt 0){1}else{0}
    Save-ComparisonState $(if($exitCode -eq 0){'Completed'}else{'CompletedWithWarnings'}) Complete
    Write-Host "Comparison completed: $($script:Changes.Rows) difference rows; $($script:Limitations.Count) limitations. Reports: $OutputFolder"
    if($summaryRows.Count -gt 0){$summaryRows|Format-Table -AutoSize|Out-Host}
}catch{
    $message="$($_.Exception.Message) $($_.ScriptStackTrace)"
    Save-ComparisonState Failed Comparison $message
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $exitCode=2
}finally{
    $cleanupErrors=@(Invoke-NtfsCleanup @(
        {if($null -ne $script:Changes){$script:Changes.Dispose()}},
        {if($null -ne $scopeWriter){$scopeWriter.Dispose()}},
        {if($null -ne $TempDir -and (Test-Path -LiteralPath $TempDir)){Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction Stop}}
    ))
    foreach($errorMessage in $cleanupErrors){Add-Limitation $errorMessage}
    if($cleanupErrors.Count -gt 0){
        if($exitCode -lt 2){
            $exitCode=1
            $summary.Limitations=@($script:Limitations|Sort-Object)
            $summary|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $OutputFolder 'NTFS_ComparisonSummary.json') -Encoding UTF8
            Save-ComparisonState CompletedWithWarnings Cleanup
        }else{Save-ComparisonState Failed Cleanup $message}
    }
}
exit $exitCode
