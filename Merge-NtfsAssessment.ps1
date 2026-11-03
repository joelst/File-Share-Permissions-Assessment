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
  Consolidates directory ACL inventories into offline review reports.
.NOTES
  Version 2.8.4. Consolidates directory ACL inventories into offline review reports.
  
  Read-only against assessed systems. Requires NtfsAssessment.Common.ps1.
  Findings are indicators, not effective-access calculations or approved remediation.
  Mixed local/UNC or overlapping scan roots for one share are rejected; use disjoint
  subtrees or one parent scope. Share permissions outside manifest scopes are rejected.
  Collected share principal SID and Vserver evidence is preserved in reports.
  Cleanup failures are persisted as warnings (exit 1), preserving analysis failures (2).
  Memory includes the active shares plus identity/membership lookups; use ThrottleLimit=1
  for large inventories. Parallel workers multiply per-share memory use.
  MaxRowsPerShare bounds folder, NTFS ACE and share ACE input rows per selected share.
  Incomplete folder ACLs have no risk score and are excluded from risk averages.
  LatestSuccessful selects the newest snapshot per server/share, including partial snapshots.
  It never fills gaps with older permissions. AllSuccessful/Explicit reject overlapping snapshots.
  CSV parts are limited to 100,000,000 bytes including BOM, headers and record terminators.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$InputRoot,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputFolder,
    [ValidateSet('LatestSuccessful','AllSuccessful','Explicit')][string]$RunSelection='LatestSuccessful',
    [string[]]$RunFolder=@(),
    [ValidateRange(120,32767)][int]$LongPathThreshold=240,
    [ValidateRange(1,64)][int]$ThrottleLimit=1,
    [string[]]$ShareFilter=@(),
    [ValidateRange(1,20000000)][int]$MaxRowsPerShare=1000000
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'NtfsAssessment.Common.ps1')

function SafeProp($Object,[string]$Name,[string]$Default='') {
    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) { return [string]$Object.$Name }
    return $Default
}
function Get-ShareKey([string]$Server,[string]$Share) {
    if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Share)) { throw 'Blank server/share in source data.' }
    return (ConvertTo-NtfsCsvRecord @($Server.Trim().ToLowerInvariant(),$Share.Trim().ToLowerInvariant()))
}
function IsBroad([string]$Identity,[string]$SID) {
    return $SID -in @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546') -or
        $SID -match '^S-1-5-21-(\d+-){2}\d+-(513|514)$' -or
        $Identity -match '(?i)(^|\\)(everyone|authenticated users|domain users|domain guests|users|guests)$'
}
function Normalize-Rights([string]$Rights) {
    [long]$value=0
    if (-not [long]::TryParse($Rights.Trim(),[ref]$value)) { return $Rights.Trim() }
    if ($value -lt -2147483648 -or $value -gt 4294967295) { throw "Invalid 32-bit access mask: $Rights" }
    if ($value -lt 0) { $value+=4294967296 }
    $names=[Collections.ArrayList]::new()
    foreach ($flag in @(
        @(268435456,'GenericAll'),@(536870912,'GenericExecute'),@(1073741824,'GenericWrite'),@(2147483648,'GenericRead'),
        @(1,'ReadData'),@(2,'WriteData'),@(4,'AppendData'),@(8,'ReadExtendedAttributes'),@(16,'WriteExtendedAttributes'),
        @(32,'ExecuteFile'),@(64,'DeleteSubdirectoriesAndFiles'),@(128,'ReadAttributes'),@(256,'WriteAttributes'),
        @(65536,'Delete'),@(131072,'ReadPermissions'),@(262144,'ChangePermissions'),@(524288,'TakeOwnership'),
        @(1048576,'Synchronize'),@(16777216,'AccessSystemSecurity'),@(33554432,'MaximumAllowed')
    )) {
        if (($value -band [long]$flag[0]) -ne 0) { [void]$names.Add($flag[1]); $value=$value -bxor [long]$flag[0] }
    }
    if ($value -ne 0) { [void]$names.Add(('UnknownMask0x{0:X8}' -f $value)) }
    if ($names.Count -eq 0) { return 'None' }
    return $names -join ', '
}
function IsWrite([string]$Rights) { return (Normalize-Rights $Rights) -match '(?i)FullControl|GenericAll|GenericWrite|Modify|Write|Append|Delete|ChangePermissions|TakeOwnership|MaximumAllowed' }
function IsPrivileged([string]$Rights) { return (Normalize-Rights $Rights) -match '(?i)FullControl|GenericAll|ChangePermissions|TakeOwnership|AccessSystemSecurity|MaximumAllowed' }
function IsFullControl([string]$Rights) {
    [long]$bits=0
    if ([long]::TryParse($Rights,[ref]$bits)) { return ($bits -band 2032127) -eq 2032127 -or ($bits -band 268435456) -ne 0 }
    return $Rights -match '(?i)(^|,\s*)(FullControl|GenericAll)(,|$)'
}
function RiskLevel([int]$Score) { if($Score -ge 70){'Critical'}elseif($Score -ge 45){'High'}elseif($Score -ge 20){'Medium'}elseif($Score -gt 0){'Low'}else{'Informational'} }
function Get-AppliesTo([string]$Inheritance,[string]$Propagation) {
    if ($Inheritance -notmatch '^(None|ContainerInherit|ObjectInherit|ContainerInherit, ObjectInherit|ObjectInherit, ContainerInherit)$' -or
        $Propagation -notmatch '^(None|InheritOnly|NoPropagateInherit|InheritOnly, NoPropagateInherit|NoPropagateInherit, InheritOnly)$') { return 'Unknown' }
    $container=$Inheritance -match 'ContainerInherit';$object=$Inheritance -match 'ObjectInherit';$only=$Propagation -match 'InheritOnly'
    $targets=@()
    if (-not $only) { $targets+='This folder' }
    if ($container) { $targets+='subfolders' }
    if ($object) { $targets+='files' }
    $result=if($targets.Count -eq 0){'No applicable objects'}else{$targets -join ', '}
    if ($Propagation -match 'NoPropagateInherit') { $result+=' (immediate children only)' }
    return $result
}
function Write-CsvRow($Writer,[object[]]$Values) { $Writer.WriteLine((ConvertTo-NtfsCsvRecord $Values)) }
function Write-Finding($Writer,$Ace,[string]$Type,[string]$Severity,[string]$Reason,[string]$Recommendation,[string]$ShareStatus='NotEvaluated') {
    Write-CsvRow $Writer @(
        [guid]::NewGuid().Guid,$Ace.Server,$Ace.Share,$Ace.Path,(SafeProp $Ace 'PathHash'),$Type,$Severity,
        (SafeProp $Ace 'Identity'),(SafeProp $Ace 'SID'),(SafeProp $Ace 'Rights'),(SafeProp $Ace 'IsInherited'),
        $Reason,$Recommendation,(SafeProp $Ace 'AceHash'),$ShareStatus,(SafeProp $Ace 'SourceRunId'),
        (SafeProp $Ace 'RightsValue'),(SafeProp $Ace 'InheritanceFlags'),(SafeProp $Ace 'PropagationFlags'),
        (SafeProp $Ace 'DescriptorHash'),(SafeProp $Ace 'AceOrdinal')
    )
}
function Get-GroupStatus([string]$RunId,[string]$Identity,$Expansion) {
    $key=ConvertTo-NtfsCsvRecord @($RunId,$Identity)
    if (-not $Expansion.ContainsKey($key)) { return 'UnknownOrNotCollected' }
    $row=$Expansion[$key]
    if ($row.Status -ne 'Complete') { return [string]$row.Status }
    if ([long]$row.MemberCount -eq 0) { return 'ConfirmedEmpty' }
    return "Complete; Members=$($row.MemberCount)"
}
function Register-GroupIdentity([string]$RunId,[string]$Identity,$Index) {
    $key=ConvertTo-NtfsCsvRecord @($RunId,$Identity)
    if($Index.ContainsKey($key)){
        if((SafeProp $Index[$key] 'ObjectClass') -eq 'user'){throw "Conflicting user/group classification for $Identity in run $RunId"}
        $Index[$key]|Add-Member -NotePropertyName ObjectClass -NotePropertyValue 'group' -Force
    }else{$Index[$key]=[pscustomobject]@{Identity=$Identity;ObjectClass='group'}}
}

$script:OwnedWriters=[Collections.ArrayList]::new()
$script:SpoolWriters=@{}
$script:Warnings=[Collections.ArrayList]::new()
function Add-MergeWarning([string]$Message) {
    [void]$script:Warnings.Add($Message);Write-Warning $Message
}
function Open-Report([string]$Name,[string[]]$Columns) {
    $writer=New-NtfsCsvWriter (Join-Path $OutputFolder $Name)
    [void]$script:OwnedWriters.Add($writer)
    Write-CsvRow $writer $Columns
    return $writer
}
function Read-RunDataset($Run,[string]$Name,[string[]]$Required=@()) {
    foreach ($file in @(Get-NtfsCsvFiles $Run.RunFolder $Name)) {
        Read-NtfsCsvFile $file.FullName $Required | ForEach-Object {
            $row=$_
            $sourceId=SafeProp $row 'RunId'
            if ($sourceId -and $sourceId -ne $Run.RunId) { throw "RunId mismatch in $($file.FullName): $sourceId" }
            $row | Add-Member -NotePropertyName SourceRunId -NotePropertyValue $Run.RunId -Force
            $row
        }
    }
}
function Test-SelectedRow($Row,$Run) {
    $key=Get-ShareKey $Row.Server $Row.Share
    return $Owners.ContainsKey($key) -and $Owners[$key].RunId -eq $Run.RunId
}
function Add-SpoolRow($Spool) {
    $Spool.InputRows++
    if($Spool.InputRows -gt $MaxRowsPerShare){
        throw "Run $($Spool.RunId), $($Spool.Server)\$($Spool.Share) exceeds MaxRowsPerShare=$MaxRowsPerShare. Increase that guard only with sufficient memory or collect smaller scopes; parallel workers multiply memory use."
    }
}
function Save-State([string]$Status,[string]$Stage,[string]$Message='') {
    if (-not $script:OutputReady) { return }
    [ordered]@{ToolkitVersion='2.8.4';Status=$Status;CurrentStage=$Stage;Error=$Message;Warnings=@($script:Warnings);UpdatedUtc=[datetime]::UtcNow.ToString('o')} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputFolder 'merge-state.json') -Encoding UTF8
    Add-Content -LiteralPath (Join-Path $OutputFolder 'merge-stage.log') -Value ("{0:o}`t{1}`t{2}`t{3}" -f [datetime]::UtcNow,$Status,$Stage,$Message) -Encoding UTF8
}

$script:OutputReady=$false;$TempDir=$null;$pool=$null;$jobs=[Collections.ArrayList]::new()
$exitCode=2
try {
    $InputRoot=(Resolve-Path -LiteralPath $InputRoot -ErrorAction Stop).ProviderPath
    $OutputFolder=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFolder)
    if (Test-Path -LiteralPath $OutputFolder) {
        if (-not (Test-Path -LiteralPath $OutputFolder -PathType Container)) { throw 'OutputFolder is not a directory.' }
        if (@(Get-ChildItem -LiteralPath $OutputFolder -Force).Count -gt 0) { throw 'OutputFolder must be empty; existing reports will not be overwritten.' }
    }
    if ($InputRoot.TrimEnd('\','/') -eq $OutputFolder.TrimEnd('\','/')) { throw 'InputRoot and OutputFolder must differ.' }
    $manifestFiles=if($RunSelection -eq 'Explicit'){
        if($RunFolder.Count -eq 0){throw 'Explicit requires -RunFolder.'}
        @($RunFolder|ForEach-Object{Get-Item -LiteralPath (Join-Path $_ 'manifest.json') -ErrorAction Stop})
    }else{
        $outputPrefix=$OutputFolder.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
        $unfinished=@(Get-ChildItem -LiteralPath $InputRoot -Recurse -Directory -Filter 'ASSESS_*' -ErrorAction Stop|Where-Object{
            $_.FullName -ne $OutputFolder -and -not $_.FullName.StartsWith($outputPrefix,[StringComparison]::OrdinalIgnoreCase) -and
            -not(Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json'))
        })
        if($unfinished.Count -gt 0){throw 'Unfinished assessment folders found. Wait for collection to finish or use -RunSelection Explicit -RunFolder to select known completed runs.'}
        @(Get-ChildItem -LiteralPath $InputRoot -Recurse -File -Filter 'manifest.json' -ErrorAction Stop |
            Where-Object { -not $_.FullName.StartsWith($OutputFolder.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) })
    }
    foreach($file in $manifestFiles){
        $source=$file.Directory.FullName
        if($OutputFolder -eq $source -or $OutputFolder.StartsWith($source.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){
            throw 'OutputFolder must be outside every source run folder.'
        }
    }
    if(-not(Test-Path -LiteralPath $OutputFolder)){[void](New-Item -ItemType Directory -Path $OutputFolder -ErrorAction Stop)}
    $script:OutputReady=$true
    $TempDir=Join-Path $OutputFolder ('_temp_'+[guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $TempDir -ErrorAction Stop)
    Save-State Running RunSelection
    $runs=[Collections.ArrayList]::new();$runIds=@{}
    foreach($file in $manifestFiles){
        $m=Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop|ConvertFrom-Json
        $runId=[string]$m.RunId
        if(-not $runId -or $runIds.ContainsKey($runId)){throw "Missing or duplicate RunId: $($file.FullName)"}
        [version]$schemaVersion=$null;[version]$toolkitVersion=$null
        $currentSchema=([version]::TryParse((SafeProp $m 'SchemaVersion'),[ref]$schemaVersion) -and $schemaVersion -ge [version]'1.3') -or
            ([version]::TryParse((SafeProp $m 'ToolkitVersion'),[ref]$toolkitVersion) -and $toolkitVersion -ge [version]'1.6.4')
        if($m.PSObject.Properties.Name -notcontains 'Datasets'){
            if($currentSchema){throw "Current-schema run $runId is missing its required dataset integrity inventory."}
            Add-MergeWarning "Legacy run $runId has no integrity inventory; input integrity cannot be fully verified."
        }
        $runIds[$runId]=$true
        $run=[pscustomobject]@{
            RunFolder=$file.Directory.FullName;RunId=$runId;Manifest=$m;CompletedUtc=[datetime]$m.CompletedUtc
            SelectionStatus='Rejected';SelectionReason='Superseded or outside filter';Scopes=@()
        }
        if($m.PSObject.Properties.Name -contains 'Scopes'){$run.Scopes=@($m.Scopes)}
        else{
            $run.Scopes=@(Read-RunDataset $run 'Shares.csv' @('Server','Share'))
            Add-MergeWarning "Legacy run $runId has no scope inventory; deriving server/share scopes from Shares.csv."
        }
        if($run.Scopes.Count -eq 0){throw "Run $runId has no assessable scope; choose known runs with -RunSelection Explicit. No automatic fallback is allowed."}
        [void]$runs.Add($run)
    }
    if($runs.Count -eq 0){throw 'No assessment manifests found.'}
    $filters=@($ShareFilter|ForEach-Object{$_ -split ','}|ForEach-Object{$_.Trim()}|Where-Object{$_})
    $Owners=@{}
    foreach($run in @($runs|Sort-Object @{Expression='CompletedUtc';Descending=$true},RunId)){
        foreach($scope in $run.Scopes){
            $key=Get-ShareKey $scope.Server $scope.Share
            $display="$($scope.Server)|$($scope.Share)"
            if($filters.Count -gt 0 -and @($filters|Where-Object{$display -like "*$_*"}).Count -eq 0){continue}
            if($Owners.ContainsKey($key)){
                if($Owners[$key].RunId -eq $run.RunId){continue}
                if($RunSelection -ne 'LatestSuccessful'){throw "Overlapping snapshots for $display. Choose one run per server/share; historical permission unions are not supported."}
                if($Owners[$key].CompletedUtc -eq $run.CompletedUtc){throw "Ambiguous equal-time snapshots for $display; use Explicit selection."}
            }else{
                $Owners[$key]=$run;$run.SelectionStatus='Selected';$run.SelectionReason='Snapshot per server/share; no historical backfill'
            }
        }
    }
    if($Owners.Count -eq 0){throw 'No shares match the requested selection/filter.'}
    $selectedRuns=@($runs|Where-Object SelectionStatus -eq 'Selected')
    foreach($run in $selectedRuns){
        Assert-NtfsScopeRoots $run.Scopes
        if(SafeProp $run.Manifest 'FatalError'){throw "Selected run $($run.RunId) has a fatal collection error. No fallback to older permissions."}
        if([int]$run.Manifest.Counts.Errors -gt 0 -or (SafeProp $run.Manifest 'CoverageStatus') -ne 'CompleteDirectoriesOnly'){
            Add-MergeWarning "Run $($run.RunId) has partial or unverified coverage; reporting only, no remediation authorization."
        }
        if($run.Manifest.PSObject.Properties.Name -contains 'Datasets'){
            foreach($required in @('Shares.csv','Folders.csv','NtfsAcls.csv','Identities.csv','GroupMemberships.csv','ScanErrors.csv','SkippedPaths.csv','ShareCoverage.csv')){
                if(@($run.Manifest.Datasets|Where-Object Name -eq $required).Count -ne 1){throw "Missing or duplicate required dataset $required in run $($run.RunId)."}
            }
            foreach($dataset in $run.Manifest.Datasets){[void]@(Get-NtfsCsvFiles $run.RunFolder $dataset.Name)}
        }
        $sums=Join-Path $run.RunFolder 'SHA256SUMS.csv'
        if(Test-Path -LiteralPath $sums){
            foreach($part in @(Get-NtfsCsvFiles $run.RunFolder 'SHA256SUMS.csv')){
                Read-NtfsCsvFile $part.FullName @('Path','Hash','Algorithm')|ForEach-Object{
                    $relative=([string]$_.Path).Replace('\','/')
                    # Legacy checksum lists use absolute paths; only files within this run are eligible.
                    $marker='/'+[IO.Path]::GetFileName($run.RunFolder)+'/'
                    $offset=$relative.LastIndexOf($marker,[StringComparison]::OrdinalIgnoreCase)
                    if($offset -ge 0){$relative=$relative.Substring($offset+$marker.Length)}
                    elseif($relative.Contains('/')){throw "Checksum path is outside the selected run: $relative"}
                    $path=[IO.Path]::GetFullPath((Join-Path $run.RunFolder $relative))
                    if(-not $path.StartsWith($run.RunFolder.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or $_.Algorithm -ne 'SHA256'){throw 'Invalid checksum entry.'}
                    if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $_.Hash){throw "Checksum mismatch: $path"}
                }
            }
        }
    }
    Export-NtfsCsvData @($runs|Select-Object RunFolder,RunId,CompletedUtc,SelectionStatus,SelectionReason) (Join-Path $OutputFolder 'MergeSourceRuns.csv')
    Save-State Running StreamMerge
    $aceColumns=@('RunId','CollectorHost','Server','Share','ScanRoot','CollectionMode','Path','PathHash','AceHash','AceOrdinal','DescriptorHash','Identity','SID','Resolved','AccessControlType','Rights','RightsValue','IsInherited','InheritanceFlags','PropagationFlags','SourceRunId')
    $folderColumns=@('RunId','CollectorHost','Server','Share','ScanRoot','CollectionMode','Path','PathHash','Depth','PathLength','Owner','InheritanceProtected','LastWriteUtc','Attributes','SDDL','CollectionStatus','DaclState','DescriptorHash','SourceRunId')
    $aceReport=Open-Report 'NTFS_AllAces.csv' $aceColumns
    $folderReport=Open-Report 'NTFS_Folders.csv' $folderColumns
    $shareReport=Open-Report 'NTFS_Shares.csv' @('RunId','Server','Share','UNC','ScanRoot','LocalPath','ShareMetadataStatus','SourceRunId')
    $sharePermissionReport=Open-Report 'NTFS_SharePermissions.csv' @('RunId','Server','Share','AccountName','SID','AccessControlType','AccessRight','Source','Vserver','SourceRunId')
    $coverageReport=Open-Report 'NTFS_ShareCoverage.csv' @('RunId','Server','Share','UNC','Status','FoldersCollected','AcesCollected','SkippedPaths','Errors','Detail','SourceRunId')
    $errorReport=Open-Report 'NTFS_ScanErrors.csv' @('RunId','Target','Stage','Path','Error','HResult','Utc','SourceRunId')
    $skippedReport=Open-Report 'NTFS_SkippedPaths.csv' @('RunId','Target','Stage','Path','Reason','Detail','Utc','SourceRunId')
    $reportColumns=@{
        Shares=@('RunId','Server','Share','UNC','ScanRoot','LocalPath','ShareMetadataStatus','SourceRunId')
        ShareCoverage=@('RunId','Server','Share','UNC','Status','FoldersCollected','AcesCollected','SkippedPaths','Errors','Detail','SourceRunId')
        ScanErrors=@('RunId','Target','Stage','Path','Error','HResult','Utc','SourceRunId')
        SkippedPaths=@('RunId','Target','Stage','Path','Reason','Detail','Utc','SourceRunId')
    }
    $smallReports=@{Shares=$shareReport;ShareCoverage=$coverageReport;ScanErrors=$errorReport;SkippedPaths=$skippedReport}
    $shareAcls=@{};$identities=@{};$members=@{};$expansion=@{};$spools=@{};$skippedCount=0;$errorCount=0
    foreach($key in $Owners.Keys){
        $spools[$key]=@{
            Id=(Get-NtfsHash $key);RunId=$Owners[$key].RunId;Server='';Share='';AceCount=0;FolderCount=0;InputRows=0L
            Coverage=[Collections.ArrayList]::new();Roots=[Collections.ArrayList]::new();FailedPaths=@{}
            VerifiedInventory=($Owners[$key].Manifest.PSObject.Properties.Name -contains 'Datasets')
        }
    }
    foreach($run in $selectedRuns){
        foreach($scope in $run.Scopes){
            $key=Get-ShareKey $scope.Server $scope.Share
            if($Owners.ContainsKey($key) -and $Owners[$key].RunId -eq $run.RunId){
                $spools[$key].Server=[string]$scope.Server;$spools[$key].Share=[string]$scope.Share
                [void]$spools[$key].Roots.Add((SafeProp $scope 'ScanRoot'))
            }
        }
        foreach($name in $smallReports.Keys){
            Read-RunDataset $run "$name.csv"|ForEach-Object{
                $row=$_
                if($name -in @('Shares','ShareCoverage') -and -not(Test-SelectedRow $row $run)){return}
                Write-CsvRow $smallReports[$name] @($reportColumns[$name]|ForEach-Object{SafeProp $row $_})
                if($name -eq 'ShareCoverage'){[void]$spools[(Get-ShareKey $row.Server $row.Share)].Coverage.Add($row)}
                if($name -eq 'SkippedPaths'){$skippedCount++}
                if($name -eq 'ScanErrors'){
                    $errorCount++
                    if((SafeProp $row 'Stage') -in @('ReadACL','ReadAccessRules','ValidateUNC')){
                        $path=Get-NtfsPathKey (SafeProp $row 'Path')
                        foreach($spool in $spools.Values){
                            if($spool.RunId -ne $run.RunId){continue}
                            foreach($root in $spool.Roots){
                                $rootKey=Get-NtfsPathKey $root
                                if($rootKey -and ($path -eq $rootKey -or $path.StartsWith($rootKey+'\',[StringComparison]::OrdinalIgnoreCase))){$spool.FailedPaths[$path]=$true;break}
                            }
                        }
                    }
                }
            }
        }
        Read-RunDataset $run 'SharePermissions.csv' @('Server','Share','AccountName','AccessControlType','AccessRight')|ForEach-Object{
            $rowKey=Get-ShareKey $_.Server $_.Share
            if(@($run.Scopes|Where-Object{(Get-ShareKey $_.Server $_.Share) -eq $rowKey}).Count -eq 0){
                throw "SharePermissions row is outside declared scopes in run $($run.RunId)."
            }
            if(Test-SelectedRow $_ $run){
                $row=$_
                $key=Get-ShareKey $row.Server $row.Share
                Add-SpoolRow $spools[$key]
                Write-CsvRow $sharePermissionReport @(@('RunId','Server','Share','AccountName','SID','AccessControlType','AccessRight','Source','Vserver','SourceRunId')|ForEach-Object{SafeProp $row $_})
                if(-not $shareAcls.ContainsKey($key)){$shareAcls[$key]=[Collections.ArrayList]::new()}
                [void]$shareAcls[$key].Add($_)
            }
        }
        Read-RunDataset $run 'Identities.csv' @('Identity')|ForEach-Object{
            $identities[(ConvertTo-NtfsCsvRecord @($run.RunId,$_.Identity))]=$_ 
        }
        Read-RunDataset $run 'GroupExpansion.csv' @('GroupIdentity','Status','MemberCount')|ForEach-Object{
            $expansion[(ConvertTo-NtfsCsvRecord @($run.RunId,$_.GroupIdentity))]=$_
            Register-GroupIdentity $run.RunId $_.GroupIdentity $identities
        }
        Read-RunDataset $run 'GroupMemberships.csv' @('GroupIdentity')|ForEach-Object{
            $key=ConvertTo-NtfsCsvRecord @($run.RunId,$_.GroupIdentity)
            if(-not $members.ContainsKey($key)){$members[$key]=[Collections.ArrayList]::new()}
            [void]$members[$key].Add($_)
            Register-GroupIdentity $run.RunId $_.GroupIdentity $identities
        }
        foreach($dataset in @('NtfsAcls','Folders')){
            $readCount=0L
            $columns=if($dataset -eq 'NtfsAcls'){$aceColumns}else{$folderColumns}
            $required=if($dataset -eq 'NtfsAcls'){@('Server','Share','Path','AceHash','Identity','SID','Rights','AccessControlType','IsInherited','InheritanceFlags','PropagationFlags','Resolved')}else{@('Server','Share','Path','InheritanceProtected')}
            Read-RunDataset $run "$dataset.csv" $required|ForEach-Object{
                $row=$_
                $readCount++
                if(-not(Test-SelectedRow $row $run)){return}
                if(-not (SafeProp $row 'Path')){throw 'Blank object path in source data.'}
                if($dataset -eq 'NtfsAcls' -and ($row.AccessControlType -notin @('Allow','Deny') -or $row.IsInherited -notin @('True','False') -or $row.Resolved -notin @('True','False'))){
                    throw "Unknown ACE type or state in run $($run.RunId): $($row.Path)"
                }
                $key=Get-ShareKey $row.Server $row.Share
                Add-SpoolRow $spools[$key]
                $record=ConvertTo-NtfsCsvRecord @($columns|ForEach-Object{SafeProp $row $_})
                $id="$dataset|$key"
                if(-not $script:SpoolWriters.ContainsKey($id)){
                    $path=Join-Path $TempDir ($spools[$key].Id+"_$dataset.tmp")
                    $writer=[IO.StreamWriter]::new($path,$false,[Text.UTF8Encoding]::new($false))
                    $script:SpoolWriters[$id]=$writer
                    $writer.WriteLine((ConvertTo-NtfsCsvRecord $columns))
                    $spools[$key][$dataset]=$path
                }
                $script:SpoolWriters[$id].WriteLine($record)
                if($dataset -eq 'NtfsAcls'){$aceReport.WriteLine($record);$spools[$key].AceCount++}
                else{$folderReport.WriteLine($record);$spools[$key].FolderCount++}
            }
            $countName=if($dataset -eq 'NtfsAcls'){'NtfsAces'}else{'Folders'}
            if($readCount -ne [long]$run.Manifest.Counts.$countName){throw "Manifest row-count mismatch for $dataset in run $($run.RunId)."}
        }
    }
    foreach($writer in $script:SpoolWriters.Values){$writer.Dispose()}
    $script:SpoolWriters.Clear()
    foreach($spool in $spools.Values){
        if($spool.Coverage.Count -eq 0){Add-MergeWarning "No coverage evidence for $($spool.Server)\$($spool.Share)."}
        foreach($coverage in $spool.Coverage){
            if($coverage.Status -ne 'CompletedDirectoriesOnly'){Add-MergeWarning "Coverage $($coverage.Status): $($spool.Server)\$($spool.Share)."}
        }
        if($spool.Roots.Count -eq 0 -or @($spool.Roots|Where-Object{[string]::IsNullOrWhiteSpace($_) -or $_ -match '^\\\\[^\\]+\\[^\\]+\\[^\\]'}).Count -gt 0){
            Add-MergeWarning "Selected scope may be a subtree: $($spool.Server)\$($spool.Share); do not infer whole-share coverage."
        }
    }
    Save-State Running PerShareProcessing
    $findingColumns=@('FindingId','Server','Share','Path','PathHash','FindingType','Severity','Identity','SID','Rights','Inherited','Reason','Recommendation','EvidenceAceHash','SharePermissionStatus','RunId','RightsValue','InheritanceFlags','PropagationFlags','DescriptorHash','AceOrdinal')
    $riskColumns=@('Server','Share','Path','RiskScore','RiskLevel','RiskFactors','AceCount','ExplicitAceCount','BroadAceCount','UnresolvedAceCount','InheritanceProtected','RunId','DaclState','AssessmentStatus')
    $broadColumns=@('Identity','SID','Rights','AccessControlType','IsInherited','Resolved','Server','Share','Path','SharePermissionStatus','ShareRight','EffectiveAccess','AccessLevel','AppliesTo','Remediable','AccessScope','GroupStatus','RunId','PathHash','EvidenceAceHash','RightsValue','InheritanceFlags','PropagationFlags','DescriptorHash','AceOrdinal')
    $groupColumns=@('GroupIdentity','GroupPath','NestedGroupPath','MemberSamAccountName','MemberName','MemberObjectClass','MemberEnabled','Server','Share','RunId','ExpansionStatus','GroupSID','MemberSID','MemberDistinguishedName','Path','Rights','AccessControlType','IsInherited')
    $gbsColumns=$groupColumns[0..13]
    $specs=@{
        'findings'=@('NTFS_Findings.csv',$findingColumns);'risk'=@('NTFS_RiskByFolder.csv',$riskColumns)
        'broad'=@('NTFS_BroadAccess.csv',$broadColumns);'direct'=@('NTFS_DirectAssignments.csv',$aceColumns)
        'unresolved'=@('NTFS_UnresolvedIdentities.csv',$aceColumns);'privileged'=@('NTFS_PrivilegedRights.csv',$aceColumns)
        'deny'=@('NTFS_DenyAces.csv',$aceColumns);'broken'=@('NTFS_BrokenInheritance.csv',$folderColumns)
        'groups'=@('NTFS_GroupReport.csv',$groupColumns);'groupsByShare'=@('NTFS_GroupReportByShare.csv',$gbsColumns)
    }
    $reports=@{}
    foreach($name in $specs.Keys){$reports[$name]=Open-Report $specs[$name][0] $specs[$name][1]}
    $worker={
        param($Spool,$OutRoot,$CommonPath,$Helpers,$Identities,$Members,$Expansion,$ShareAcls,$LPT,$Specs)
        Set-StrictMode -Version Latest
        $ErrorActionPreference='Stop'
        . $CommonPath
        . ([scriptblock]::Create($Helpers))
        $outDir=Join-Path $OutRoot $Spool.Id
        [void](New-Item -ItemType Directory -Path $outDir -ErrorAction Stop)
        $writers=@{};$counts=@{Findings=0;Folders=0;AssessedFolders=0;NotAssessedFolders=0;UnreportedAclFailures=0;UniqueAces=0;Broad=0;Direct=0;Unresolved=0;Privileged=0;Deny=0;Broken=0;Critical=0;High=0;Max=0;Sum=0}
        $index=@{};$seen=@{};$seenFolders=@{};$seenGroups=@{};$seenGBS=@{};$descriptors=@{}
        try{
            foreach($name in $Specs.Keys){$writers[$name]=[IO.StreamWriter]::new((Join-Path $outDir "$name.tmp"),$false,[Text.UTF8Encoding]::new($false))}
            if($Spool.ContainsKey('NtfsAcls')){
                Read-NtfsCsvFile $Spool.NtfsAcls|ForEach-Object{
                    $a=$_
                    if($a.DescriptorHash){
                        if($descriptors.ContainsKey($a.Path) -and $descriptors[$a.Path] -ne $a.DescriptorHash){throw "Conflicting descriptors for $($a.Path) in one snapshot."}
                        $descriptors[$a.Path]=$a.DescriptorHash
                    }
                    # Preserve occurrence/order; deduplicate only repeat collection of the same evidence.
                    $evidence=ConvertTo-NtfsCsvRecord @($a.SourceRunId,$a.Path,$a.AceHash,$a.AceOrdinal,$a.Rights,$a.RightsValue,$a.Identity,$a.AccessControlType,$a.IsInherited,$a.InheritanceFlags,$a.PropagationFlags)
                    if($seen.ContainsKey($evidence)){return}
                    $seen[$evidence]=$true;$counts.UniqueAces++
                    if(-not $index.ContainsKey($a.Path)){$index[$a.Path]=[Collections.ArrayList]::new()}
                    [void]$index[$a.Path].Add($a)
                    $record=ConvertTo-NtfsCsvRecord @($Specs.direct[1]|ForEach-Object{SafeProp $a $_})
                    $lookup=ConvertTo-NtfsCsvRecord @($a.SourceRunId,$a.Identity)
                    $class=if($Identities.ContainsKey($lookup)){SafeProp $Identities[$lookup] 'ObjectClass'}else{'Unknown'}
                    if($a.IsInherited -eq 'False' -and $class -eq 'user'){$writers.direct.WriteLine($record);$counts.Direct++}
                    if($a.Resolved -eq 'False'){$writers.unresolved.WriteLine($record);$counts.Unresolved++}
                    $rights=Normalize-Rights $a.Rights
                    $allow=$a.AccessControlType -eq 'Allow'
                    if(IsPrivileged $rights){$writers.privileged.WriteLine($record);$counts.Privileged++}
                    if($a.AccessControlType -eq 'Deny'){
                        $writers.deny.WriteLine($record);$counts.Deny++
                        if($a.IsInherited -eq 'False'){Write-Finding $writers.findings $a 'ExplicitDeny' 'High' 'Explicit deny requires access review; it is not a grant.' 'Validate business intent before any change.';$counts.Findings++}
                    }
                    if($allow -and $a.Resolved -eq 'False' -and (IsWrite $rights)){
                        Write-Finding $writers.findings $a 'UnresolvedSIDWrite' 'Critical' 'Unresolved identity has write-capable allow rights.' 'Resolve the SID; do not assume the account was deleted.'
                        $counts.Findings++
                    }
                    if(IsBroad $a.Identity $a.SID){
                        $status=if($ShareAcls.Count -gt 0){'CollectedNotEvaluated'}else{'NoShareData'}
                        $level=if(-not $allow){'NotAnAllowGrant'}elseif(IsWrite $rights){'WriteCapableAllow'}else{'OtherAllowRights'}
                        Write-CsvRow $writers.broad @(
                            $a.Identity,$a.SID,$a.Rights,$a.AccessControlType,$a.IsInherited,$a.Resolved,$a.Server,$a.Share,$a.Path,
                            $status,'','NotCalculated',$level,(Get-AppliesTo $a.InheritanceFlags $a.PropagationFlags),
                            'RequiresApproval','ExactAceScope',(Get-GroupStatus $a.SourceRunId $a.Identity $Expansion),
                            $a.SourceRunId,$a.PathHash,$a.AceHash,$a.RightsValue,$a.InheritanceFlags,$a.PropagationFlags,$a.DescriptorHash,$a.AceOrdinal
                        )
                        $counts.Broad++
                        if($allow -and ((IsFullControl $a.Rights) -or (IsWrite $rights))){
                            $type=if(IsFullControl $a.Rights){'BroadPrincipalFullControl'}else{'BroadPrincipalWrite'}
                            $severity=if($type -eq 'BroadPrincipalFullControl'){'Critical'}else{'High'}
                            Write-Finding $writers.findings $a $type $severity 'Broad principal has a write-capable allow ACE; effective access is not calculated.' 'Validate exact ACE, inheritance scope and business ownership before proposing changes.' $status
                            $counts.Findings++
                        }
                    }
                    if($class -eq 'group'){
                        $groupKey=ConvertTo-NtfsCsvRecord @($lookup,$a.Path,$a.Rights,$a.AccessControlType,$a.IsInherited)
                        if(-not $seenGroups.ContainsKey($groupKey)){
                            $seenGroups[$groupKey]=$true
                            $groupStatus=Get-GroupStatus $a.SourceRunId $a.Identity $Expansion
                            $groupMembers=@(if($Members.ContainsKey($lookup)){$Members[$lookup]}else{$null})
                            foreach($member in $groupMembers){
                                $values=@($a.Identity,(SafeProp $member 'GroupPath'),(SafeProp $member 'NestedGroupPath'),
                                    (SafeProp $member 'MemberSamAccountName'),(SafeProp $member 'MemberName'),(SafeProp $member 'MemberObjectClass'),
                                    (SafeProp $member 'MemberEnabled'),$a.Server,$a.Share,$a.SourceRunId,$groupStatus,$a.SID,
                                    (SafeProp $member 'MemberSID'),(SafeProp $member 'MemberDistinguishedName'))
                                Write-CsvRow $writers.groups ($values+@($a.Path,$a.Rights,$a.AccessControlType,$a.IsInherited))
                                $gbsKey=ConvertTo-NtfsCsvRecord $values
                                if(-not $seenGBS.ContainsKey($gbsKey)){$seenGBS[$gbsKey]=$true;Write-CsvRow $writers.groupsByShare $values}
                            }
                        }
                    }
                }
            }
            if($Spool.ContainsKey('Folders')){
                Read-NtfsCsvFile $Spool.Folders|ForEach-Object{
                    $f=$_
                    $fingerprint=ConvertTo-NtfsCsvRecord @($f.Owner,$f.InheritanceProtected,$f.SDDL,$f.DaclState,$f.DescriptorHash)
                    if($seenFolders.ContainsKey($f.Path)){
                        if($seenFolders[$f.Path] -cne $fingerprint){throw "Conflicting folder descriptors for $($f.Path) in one snapshot."}
                        return
                    }
                    if($f.DescriptorHash -and $descriptors.ContainsKey($f.Path) -and $descriptors[$f.Path] -ne $f.DescriptorHash){throw "ACE/folder descriptor mismatch: $($f.Path)"}
                    $seenFolders[$f.Path]=$fingerprint;$counts.Folders++
                    $pathKey=Get-NtfsPathKey $f.Path
                    $assessed=$Spool.VerifiedInventory -and $f.CollectionStatus -eq 'Read' -and -not $Spool.FailedPaths.ContainsKey($pathKey)
                    if($assessed){$counts.AssessedFolders++}else{$counts.NotAssessedFolders++}
                    $aces=@(if($index.ContainsKey($f.Path)){$index[$f.Path]})
                    $score=0;$factors=[Collections.ArrayList]::new()
                    if($f.InheritanceProtected -eq 'True'){
                        $counts.Broken++;$score+=10;[void]$factors.Add('InheritanceProtected')
                        Write-CsvRow $writers.broken @($Specs.broken[1]|ForEach-Object{SafeProp $f $_})
                        Write-Finding $writers.findings $f 'InheritanceProtected' 'Medium' 'Permission inheritance is protected.' 'Leave inheritance unchanged unless a separate change is explicitly approved.'
                        $counts.Findings++
                    }
                    [int]$length=0
                    if([int]::TryParse($f.PathLength,[ref]$length) -and $length -ge $LPT){
                        Write-Finding $writers.findings $f 'LongPath' 'Medium' "Path length is $length." 'Validate application and backup compatibility.';$counts.Findings++
                    }
                    if($f.DaclState -eq 'NullDacl'){
                        $score=100;[void]$factors.Add('NullDacl')
                        Write-Finding $writers.findings $f 'NullDacl' 'Critical' 'Null DACL permits unrestricted access at the filesystem DACL layer.' 'Validate the live descriptor and share controls before proposing a change.';$counts.Findings++
                    }
                    $broad=0;$unresolved=0;$explicit=0;$hasBroadAllow=$false;$hasConfirmedGroup=$false
                    foreach($a in $aces){
                        $allow=$a.AccessControlType -eq 'Allow';$rights=Normalize-Rights $a.Rights
                        if($a.IsInherited -eq 'False'){$explicit++}
                        if($a.Resolved -eq 'False'){$unresolved++;if($allow -and (IsWrite $rights)){$score+=25;[void]$factors.Add('UnresolvedWrite')}}
                        if(IsBroad $a.Identity $a.SID){
                            $broad++
                            if($allow){
                                $hasBroadAllow=$true
                                if(IsFullControl $a.Rights){$score+=40;[void]$factors.Add('BroadFullControl')}
                                elseif(IsWrite $rights){$score+=30;[void]$factors.Add('BroadWrite')}
                            }
                        }else{
                            $lookup=ConvertTo-NtfsCsvRecord @($a.SourceRunId,$a.Identity)
                            if($allow -and $Identities.ContainsKey($lookup) -and (SafeProp $Identities[$lookup] 'ObjectClass') -eq 'group'){$hasConfirmedGroup=$true}
                        }
                        if($allow -and (IsPrivileged $rights)){$score+=35;[void]$factors.Add('PrivilegedRights')}
                        if($a.AccessControlType -eq 'Deny' -and $a.IsInherited -eq 'False'){$score+=15;[void]$factors.Add('ExplicitDeny')}
                    }
                    if($assessed -and $hasBroadAllow -and -not $hasConfirmedGroup){
                        Write-Finding $writers.findings $f 'BroadAccessMissingGroups' 'High' 'Broad allow ACE exists without a confirmed purpose-built group in collected identity data.' 'Validate group classification; unknown identities are not confirmed users or empty groups.';$counts.Findings++
                    }
                    if($assessed){
                        $score=[math]::Min(100,$score);$counts.Sum+=$score;$counts.Max=[math]::Max($counts.Max,$score)
                        if($score -ge 70){$counts.Critical++}elseif($score -ge 45){$counts.High++}
                        $level=RiskLevel $score;$assessmentStatus='Assessed'
                    }else{
                        $score='';$level='NotAssessed';$assessmentStatus='IncompleteOrUnverified'
                        [void]$factors.Add('IncompleteOrUnverifiedAcl')
                    }
                    Write-CsvRow $writers.risk @($f.Server,$f.Share,$f.Path,$score,$level,(@($factors|Sort-Object -Unique)-join ';'),$aces.Count,$explicit,$broad,$unresolved,$f.InheritanceProtected,$f.SourceRunId,$f.DaclState,$assessmentStatus)
                }
            }
            foreach($path in $index.Keys){if(-not $seenFolders.ContainsKey($path)){throw "ACE has no collected folder descriptor: $path"}}
            $knownPaths=@{}
            foreach($path in $seenFolders.Keys){$knownPaths[(Get-NtfsPathKey $path)]=$true}
            foreach($path in $Spool.FailedPaths.Keys){if(-not $knownPaths.ContainsKey($path)){$counts.UnreportedAclFailures++}}
        }finally{foreach($writer in $writers.Values){$writer.Dispose()}}
        return [pscustomobject]@{OutDir=$outDir;Counts=$counts;Server=$Spool.Server;Share=$Spool.Share;RunId=$Spool.RunId}
    }
    $helperNames=@('SafeProp','IsBroad','Normalize-Rights','IsWrite','IsPrivileged','IsFullControl','RiskLevel','Get-AppliesTo','Write-CsvRow','Write-Finding','Get-GroupStatus')
    $helpers=($helperNames|ForEach-Object{"function $_ { $((Get-Item "function:$_").Definition) }"}) -join "`n"
    $commonPath=Join-Path $PSScriptRoot 'NtfsAssessment.Common.ps1'
    $results=[Collections.ArrayList]::new()
    if($ThrottleLimit -gt 1){$pool=[RunspaceFactory]::CreateRunspacePool(1,$ThrottleLimit);$pool.Open()}
    foreach($key in @($spools.Keys|Sort-Object)){
        $spool=$spools[$key];$sa=@(if($shareAcls.ContainsKey($key)){$shareAcls[$key]})
        $args=@{Spool=$spool;OutRoot=$TempDir;CommonPath=$commonPath;Helpers=$helpers;Identities=$identities;Members=$members;Expansion=$expansion;ShareAcls=$sa;LPT=$LongPathThreshold;Specs=$specs}
        if($null -eq $pool){[void]$results.Add((& $worker @args))}
        else{
            $ps=[PowerShell]::Create();$ps.RunspacePool=$pool
            [void]$ps.AddScript($worker.ToString()).AddParameters($args)
            [void]$jobs.Add(@{PS=$ps;Handle=$ps.BeginInvoke()})
        }
    }
    foreach($job in $jobs){
        $value=$job.PS.EndInvoke($job.Handle)
        if($job.PS.HadErrors -or $job.PS.Streams.Error.Count -gt 0 -or $value.Count -ne 1){
            throw "Per-share processing failed: $($job.PS.Streams.Error -join '; ')"
        }
        [void]$results.Add($value[0])
    }
    if($results.Count -ne $Owners.Count){throw 'Missing per-share processing result.'}
    $totals=@{Findings=0;Folders=0;AssessedFolders=0;NotAssessedFolders=0;UnreportedAclFailures=0;UniqueAces=0;Broad=0;Direct=0;Unresolved=0;Privileged=0;Deny=0;Broken=0;Critical=0;High=0}
    $riskShares=[Collections.ArrayList]::new()
    foreach($result in $results){
        foreach($name in $specs.Keys){
            $reader=[IO.StreamReader]::new((Join-Path $result.OutDir "$name.tmp"),[Text.Encoding]::UTF8)
            try{while($null -ne ($record=[NtfsAssessment.Csv]::ReadRecord($reader))){$reports[$name].WriteLine($record)}}
            finally{$reader.Dispose()}
        }
        foreach($name in @($totals.Keys)){$totals[$name]+=$result.Counts[$name]}
        if($result.Counts.NotAssessedFolders -gt 0 -or $result.Counts.UnreportedAclFailures -gt 0){Add-MergeWarning "Incomplete or unverified ACL evidence for $($result.Server)\$($result.Share); unassessed paths are excluded from risk scores."}
        $key=Get-ShareKey $result.Server $result.Share
        [void]$riskShares.Add([pscustomobject]@{
            Server=$result.Server;Share=$result.Share;RunId=$result.RunId;Folders=$result.Counts.Folders
            AssessedFolders=$result.Counts.AssessedFolders;NotAssessedFolders=$result.Counts.NotAssessedFolders;UnreportedAclFailures=$result.Counts.UnreportedAclFailures
            CriticalFolders=$result.Counts.Critical;HighFolders=$result.Counts.High
            MaxRiskScore=$(if($result.Counts.AssessedFolders -gt 0){$result.Counts.Max}else{''})
            AverageRiskScore=$(if($result.Counts.AssessedFolders -gt 0){[math]::Round($result.Counts.Sum/$result.Counts.AssessedFolders,2)}else{''})
            UnknownDirectoryCoverage=($spools[$key].Coverage.Count -eq 0 -or @($spools[$key].Coverage|Where-Object Status -ne 'CompletedDirectoriesOnly').Count -gt 0)
            CoverageStatus=(@($spools[$key].Coverage|ForEach-Object{$_.Status}|Sort-Object -Unique)-join ';')
            SkippedPaths=(@($spools[$key].Coverage|ForEach-Object{[long]$_.SkippedPaths}|Measure-Object -Sum).Sum)
        })
    }
    foreach($writer in $script:OwnedWriters){$writer.Dispose()}
    if($reports.findings.Rows -ne $totals.Findings -or $reports.risk.Rows -ne $totals.Folders -or
        $reports.broad.Rows -ne $totals.Broad -or $reports.deny.Rows -ne $totals.Deny -or
        $reports.broken.Rows -ne $totals.Broken){throw 'Report row-count reconciliation failed.'}
    Save-State Running Analytics
    Export-NtfsCsvData $riskShares (Join-Path $OutputFolder 'NTFS_RiskByShare.csv')
    $comparison=@(foreach($key in @($spools.Keys|Sort-Object)){
        $spool=$spools[$key]
        [pscustomobject]@{Server=$spool.Server;Share=$spool.Share;RunId=$spool.RunId;ShareAceCount=$(if($shareAcls.ContainsKey($key)){$shareAcls[$key].Count}else{0});Status='NotCalculated';Limitation='No effective-access calculation. Deny precedence, tokens, nested groups, SID history and conditional ACEs require independent validation.'}
    })
    Export-NtfsCsvData $comparison (Join-Path $OutputFolder 'NTFS_ShareVsNtfs.csv')
    $summary=@{}
    foreach($file in @(Get-NtfsCsvFiles $OutputFolder 'NTFS_Findings.csv')){
        Read-NtfsCsvFile $file.FullName|ForEach-Object{
            $key=ConvertTo-NtfsCsvRecord @($_.Severity,$_.FindingType)
            if(-not $summary.ContainsKey($key)){$summary[$key]=[pscustomobject]@{Severity=$_.Severity;FindingType=$_.FindingType;Count=0}}
            $summary[$key].Count++
        }
    }
    Export-NtfsCsvData @($summary.Values|Sort-Object Severity,FindingType) (Join-Path $OutputFolder 'NTFS_FindingsSummary.csv')
    $limitations=@('Directory ACL inventory only; individual file ACLs are not assessed.','Risk scores are heuristic prioritization indicators, not authorization decisions.','Risk averages and maxima include assessed folders only; failed or unverified ACLs have no score, and unreachable subtrees have unknown folder counts.','Effective access is not calculated.','Inheritance is never changed.','Reports are not an approved remediation or rollback plan.')
    $executive=[ordered]@{
        Version='2.8.4';GeneratedUtc=[datetime]::UtcNow.ToString('o');Targets=$selectedRuns.Count;Shares=$Owners.Count
        Folders=$totals.Folders;UniqueACEs=$totals.UniqueAces;CriticalFolders=$totals.Critical;HighFolders=$totals.High
        AssessedFolders=$totals.AssessedFolders;NotAssessedFolders=$totals.NotAssessedFolders;UnreportedAclFailures=$totals.UnreportedAclFailures
        DirectAssignments=$totals.Direct;UnresolvedIdentities=$totals.Unresolved;BroadAccessAces=$totals.Broad
        PrivilegedRightsAces=$totals.Privileged;DenyAces=$totals.Deny;BrokenInheritance=$totals.Broken
        SkippedPaths=$skippedCount;Findings=$totals.Findings;Limitations=$limitations;Warnings=@($script:Warnings)
    }
    $executive|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $OutputFolder 'NTFS_ExecutiveSummary.json') -Encoding UTF8
    $inventory=@(Get-NtfsDatasetInventory $OutputFolder)
    [ordered]@{
        ToolkitVersion='2.8.4';GeneratedUtc=[datetime]::UtcNow.ToString('o');InputRoot=$InputRoot;OutputFolder=$OutputFolder
        RunSelection=$RunSelection;SelectedRunFolders=@($selectedRuns.RunFolder);MaxCsvFileBytes=100000000
        MaxRowsPerShare=$MaxRowsPerShare
        Counts=$totals;Errors=$errorCount;Warnings=@($script:Warnings);Datasets=$inventory;Limitations=$limitations
    }|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $OutputFolder 'NTFS_QA.json') -Encoding UTF8
    $exitCode=if($errorCount -gt 0 -or $script:Warnings.Count -gt 0){1}else{0}
    Save-State $(if($exitCode -eq 0){'Completed'}else{'CompletedWithWarnings'}) Complete
    Write-Host ("Merge completed. Shares={0}; Folders={1}; UniqueACEs={2}; Findings={3}; Warnings={4}" -f $Owners.Count,$totals.Folders,$totals.UniqueAces,$totals.Findings,$script:Warnings.Count)
}catch{
    $message="$($_.Exception.Message) $($_.ScriptStackTrace)"
    Save-State Failed Merge $message
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $exitCode=2
}finally{
    $cleanupErrors=@(
        foreach($job in $jobs){
            Invoke-NtfsCleanup @({if(-not $job.Handle.IsCompleted){$job.PS.Stop()}},{$job.PS.Dispose()})
        }
        if($null -ne $pool){Invoke-NtfsCleanup @({$pool.Close()},{$pool.Dispose()})}
        foreach($writer in $script:SpoolWriters.Values){Invoke-NtfsCleanup {$writer.Dispose()}}
        foreach($writer in $script:OwnedWriters){Invoke-NtfsCleanup {$writer.Dispose()}}
        Invoke-NtfsCleanup {if($null -ne $TempDir -and (Test-Path -LiteralPath $TempDir)){Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction Stop}}
    )
    foreach($errorMessage in $cleanupErrors){Add-MergeWarning $errorMessage}
    if($cleanupErrors.Count -gt 0){
        if($exitCode -lt 2){
            $exitCode=1
            $executive.Warnings=@($script:Warnings)
            $executive|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $OutputFolder 'NTFS_ExecutiveSummary.json') -Encoding UTF8
            $qaPath=Join-Path $OutputFolder 'NTFS_QA.json'
            $qa=Get-Content -LiteralPath $qaPath -Raw|ConvertFrom-Json
            $qa.Warnings=@($script:Warnings)
            $qa|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $qaPath -Encoding UTF8
            Save-State CompletedWithWarnings Cleanup
        }else{Save-State Failed Cleanup $message}
    }
}
exit $exitCode
