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

[CmdletBinding()]
param([switch]$KeepArtifacts,[string]$ResultsPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'NtfsAssessment.Common.ps1')
$engine=(Get-Process -Id $PID).Path
# Keep nested evidence paths below Windows PowerShell 5.1's MAX_PATH in this checkout.
$testRoot=Join-Path $PSScriptRoot ('Nat_'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $testRoot)
$script:checks=0
$script:TestArea='CSV and parsing'
$script:CheckResults=[Collections.ArrayList]::new()
$script:SuiteCompleted=$false
$script:FailureMessage=''
function Assert($Condition,[string]$Message) {
    $script:checks++
    [void]$script:CheckResults.Add([pscustomobject]@{Id=$script:checks;Area=$script:TestArea;Message=$Message;Passed=[bool]$Condition})
    if(-not $Condition){throw "FAILED: $Message"}
}
function Assert-Throws([scriptblock]$Action,[string]$Message,[string]$ExpectedPattern='',[int]$ExpectedNativeCode=0) {
    $threw=$false
    try{& $Action}catch{
        $threw=(-not $ExpectedPattern -or $_.Exception.Message -match $ExpectedPattern) -and
            ($ExpectedNativeCode -eq 0 -or ($_.Exception.GetBaseException().HResult -band 0xffff) -eq $ExpectedNativeCode)
    }
    Assert $threw $Message
}
function Import-Functions([string]$Path,[string[]]$Names) {
    $tokens=$null;$errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count -gt 0){throw ($errors -join '; ')}
    foreach($name in $Names){
        $definition=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
        if($null -eq $definition){throw "Function not found: $name"}
        $text=$definition.Extent.Text -replace ('^function\s+'+[regex]::Escape($name)), "function script:$name"
        . ([scriptblock]::Create($text))
    }
}
function New-Ace([string]$Share,[string]$Suffix,[string]$Hash,[string]$Identity,[string]$Rights,[string]$Type='Allow',[string]$Inherited='False',[string]$Propagation='None') {
    [pscustomobject][ordered]@{
        RunId='fixture';Server='server';Share=$Share;ScanRoot="\\server\$Share";Path="\\server\$Share$Suffix";PathHash="path-$Hash"
        AceHash=$Hash;AceOrdinal=0;DescriptorHash='descriptor';Identity=$Identity
        SID=$(if($Identity -eq 'Everyone'){'S-1-1-0'}else{'S-1-5-21-1-2-3-1001'})
        Resolved=$(if($Identity -like 'S-1-*'){'False'}else{'True'})
        AccessControlType=$Type;Rights=$Rights;RightsValue='';IsInherited=$Inherited
        InheritanceFlags='ContainerInherit, ObjectInherit';PropagationFlags=$Propagation
    }
}
function New-Folder([string]$Share,[string]$Suffix='',[string]$DaclState='Present') {
    [pscustomobject][ordered]@{
        RunId='fixture';Server='server';Share=$Share;ScanRoot="\\server\$Share";Path="\\server\$Share$Suffix";PathHash='path'
        PathLength=("\\server\$Share$Suffix").Length;Owner='TEST\Owner';InheritanceProtected='True';SDDL='D:';DaclState=$DaclState;DescriptorHash='descriptor';CollectionStatus='Read'
    }
}
function New-Run([string]$Name,[string]$RunId,[string]$Completed,$Aces,$Folders,[string]$Status='CompleteDirectoriesOnly') {
    $directory=Join-Path $testRoot $Name
    [void](New-Item -ItemType Directory -Path $directory -Force)
    foreach($row in @($Aces)+@($Folders)){$row.RunId=$RunId}
    $shares=@($Folders|Select-Object Server,Share,ScanRoot -Unique|ForEach-Object{
        $_|Add-Member -NotePropertyName ShareMetadataStatus -NotePropertyValue 'Collected' -PassThru
    })
    Export-NtfsCsvData $Aces (Join-Path $directory 'NtfsAcls.csv')
    Export-NtfsCsvData $Folders (Join-Path $directory 'Folders.csv')
    Export-NtfsCsvData $shares (Join-Path $directory 'Shares.csv')
    $sharePermissions=@(foreach($share in $shares){
        [pscustomobject]@{RunId=$RunId;Server=$share.Server;Share=$share.Share;AccountName='Everyone';AccessControlType='Deny';AccessRight='Full'}
    })
    Export-NtfsCsvData $sharePermissions (Join-Path $directory 'SharePermissions.csv')
    $coverage=@(foreach($share in $shares){
        [pscustomobject]@{RunId=$RunId;Server=$share.Server;Share=$share.Share;UNC=$share.ScanRoot;Status=$(if($Status -eq 'CompleteDirectoriesOnly'){'CompletedDirectoriesOnly'}else{$Status});FoldersCollected=@($Folders|Where-Object Share -eq $share.Share).Count;AcesCollected=@($Aces|Where-Object Share -eq $share.Share).Count;SkippedPaths=0;Errors=0;Detail='Synthetic'}
    })
    Export-NtfsCsvData $coverage (Join-Path $directory 'ShareCoverage.csv')
    $ids=@(
        [pscustomobject]@{Identity='TEST\User';ObjectClass='user'}
        [pscustomobject]@{Identity='TEST\Empty';ObjectClass='group'}
        [pscustomobject]@{Identity='TEST\NotExpanded';ObjectClass='group'}
        [pscustomobject]@{Identity='TEST\Unknown';ObjectClass='Unknown'}
    )
    Export-NtfsCsvData $ids (Join-Path $directory 'Identities.csv')
    Export-NtfsCsvData @([pscustomobject]@{RunId=$RunId;GroupIdentity='TEST\Empty';Status='Complete';MemberCount=0}) (Join-Path $directory 'GroupExpansion.csv')
    foreach($name in @('GroupMemberships','GroupAcesFound','ScanErrors','SkippedPaths')){Export-NtfsCsvData @() (Join-Path $directory "$name.csv")}
    Write-RunManifest $directory $RunId $Completed $shares $Status @($Aces).Count @($Folders).Count
    return $directory
}
function Write-RunManifest($Directory,$RunId,$Completed,$Scopes,$Status,$AceCount,$FolderCount) {
    [ordered]@{
        SchemaVersion='1.3';RunId=$RunId;ToolkitVersion='1.6.4';CompletedUtc=$Completed;FatalError=$null;CollectorHost='collector'
        CoverageStatus=$Status;Scopes=@($Scopes);Datasets=@(Get-NtfsDatasetInventory $Directory)
        Counts=@{Shares=@($Scopes).Count;Folders=$FolderCount;NtfsAces=$AceCount;Errors=0}
    }|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $Directory 'manifest.json') -Encoding UTF8
}
function Invoke-Merge($InputPath,$OutputName,[int]$Throttle=1,[string]$Selection='LatestSuccessful',[int]$ExpectedExit=0,[string[]]$Extra=@()) {
    $output=Join-Path $testRoot $OutputName
    # Capture expected native stderr without PowerShell 5.1 stopping before exit-code checks.
    $log=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'Merge-NtfsAssessment.ps1') -InputRoot $InputPath -OutputFolder $output -ThrottleLimit $Throttle -RunSelection $Selection @Extra 2>&1 })
    $code=$LASTEXITCODE
    $log|Set-Content -LiteralPath (Join-Path $testRoot ('merge-'+(Get-NtfsHash $OutputName)+'.log'))
    Assert ($code -eq $ExpectedExit) "Merge $OutputName exit=$code expected=$ExpectedExit : $($log -join "`n")"
    $console=$log -join "`n"
    if($code -eq 2){
        Assert ($console.Contains('Merge: Failed.') -and $console.Contains('Do not consume partial reports')) 'Failed merge gives diagnostic guidance rather than a success hint'
    }else{
        Assert ($console -notmatch '\b0 (folders without assessed ACL evidence|unverified ACL failures|source error records|warnings)\b') 'Merge action guidance omits zero-count categories'
        Assert ($console.Contains("Output: $($output)") -and $console.Contains((Join-Path $output 'NTFS_QA.json')) -and $console.Contains('Next:')) 'Merge completion points to actual reports and a next step'
        if($code -eq 1){Assert ($console.Contains('Merge: CompletedWithWarnings.') -and $console.Contains('Review QA warnings and coverage')) 'Partial merge highlights limitations before using findings'}
    }
    if($code -lt 2){
        Get-ChildItem -LiteralPath $output -File -Filter '*.csv'|ForEach-Object{
            Assert ($_.Length -le 100000000) "Output size: $($_.Name)"
            [void]@(Read-NtfsCsvFile $_.FullName)
        }
    }else{
        $state=Join-Path $output 'merge-state.json'
        if(Test-Path -LiteralPath $state){Assert ((Get-Content -LiteralPath $state -Raw|ConvertFrom-Json).Status -eq 'Failed') 'Failure does not claim successful completion'}
    }
    if(Test-Path -LiteralPath (Join-Path $output 'merge-state.json')){
        Assert ((Get-Content -LiteralPath (Join-Path $output 'merge-state.json') -Raw|ConvertFrom-Json).ToolkitVersion -eq $script:NtfsVersions.Merge) 'Merge state uses registered version'
        Assert-VersionLog (Join-Path $output 'merge-stage.log') Merge
    }
    return $output
}
function Rows([string]$Directory,[string]$Name) {
    foreach($part in @(Get-NtfsCsvFiles $Directory $Name)){Read-NtfsCsvFile $part.FullName}
}
function Read-ZipEntryText($Archive,[string]$Name) {
    $entry=$Archive.GetEntry($Name)
    if($null -eq $entry){throw "ZIP entry unavailable: $Name"}
    $reader=[IO.StreamReader]::new($entry.Open(),[Text.Encoding]::UTF8,$true)
    try{return $reader.ReadToEnd()}finally{$reader.Dispose()}
}
function ConvertFrom-NtfsExcelXstring([string]$Text) {
    return [regex]::Replace($Text,'_x([0-9A-Fa-f]{4})_',{
        param($match)
        [char][Convert]::ToInt32($match.Groups[1].Value,16)
    })
}
function New-NtfsTestFileLink([string]$Path,[string]$Target) {
    try{
        [void](New-Item -ItemType SymbolicLink -Path $Path -Target $Target -ErrorAction Stop)
        return $true
    }catch{
        try{
            [void](New-Item -ItemType HardLink -Path $Path -Target $Target -ErrorAction Stop)
            return $true
        }catch{return $false}
    }
}
function Invoke-Comparison([string]$OutputName,[int]$ExpectedExit,[string[]]$Arguments) {
    $output=Join-Path $testRoot $OutputName
    $state=Join-Path $output 'comparison-state.json'
    $existingState=Test-Path -LiteralPath $state
    $log=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'Compare-NtfsAssessment.ps1') -OutputFolder $output @Arguments 2>&1 })
    $code=$LASTEXITCODE
    $log|Set-Content -LiteralPath (Join-Path $testRoot ('comparison-'+(Get-NtfsHash $OutputName)+'.log'))
    Assert ($code -eq $ExpectedExit) "Comparison $OutputName exit=$code expected=$ExpectedExit : $($log -join "`n")"
    $console=$log -join "`n"
    if($code -eq 2){
        Assert ($console.Contains('Comparison: Failed.') -and $console.Contains('Do not treat partial output as a completed comparison')) 'Failed comparison gives diagnostic guidance rather than a success hint'
    }else{
        Assert ($console.Contains("Output: $($output)") -and $console.Contains((Join-Path $output 'NTFS_ComparisonCoverage.csv')) -and $console.Contains('Next:')) 'Comparison completion points to real coverage and change reports'
        if($code -eq 1){Assert ($console.Contains('Comparison: CompletedWithWarnings.') -and $console.Contains('Missing records are not proof')) 'Partial comparison warns about interpretation before suggesting further work'}
    }
    if($code -lt 2){
        Assert ((Get-Content -LiteralPath $state -Raw|ConvertFrom-Json).Status -in @('Completed','CompletedWithWarnings')) 'Comparison completed state persisted'
        $summary=Get-Content -LiteralPath (Join-Path $output 'NTFS_ComparisonSummary.json') -Raw|ConvertFrom-Json
        Assert ($summary.Version -eq $script:NtfsVersions.Comparison) 'Comparison summary uses registered version'
        Assert ($summary.DifferenceRows -eq @(Rows $output 'NTFS_Changes.csv').Count) 'Comparison counts reconcile'
        $coverage=@(Rows $output 'NTFS_ComparisonCoverage.csv')
        foreach($scopeStatus in @('NotCompared','ComparedObservedPathsOnly','ComparedCompleteDirectories')){
            Assert ($summary.ScopeCounts.$scopeStatus -eq @($coverage|Where-Object Status -eq $scopeStatus).Count) "Comparison $($scopeStatus) scope count matches coverage records"
        }
        foreach($category in @(
            @{Count=$summary.ScopeCounts.NotCompared;Label='uncomparable scopes'},
            @{Count=$summary.ScopeCounts.ComparedObservedPathsOnly;Label='partial-coverage scopes'}
        )){
            $present=$console.Contains("$($category.Count) $($category.Label)")
            Assert ($present -eq ($category.Count -gt 0)) "Comparison guidance includes only positive $($category.Label) counts"
        }
        if($ExpectedExit -eq 0){Assert (-not $console.Contains('Resolve/review:')) 'Complete comparison has no resolve/review section when no action is needed'}
        Get-ChildItem -LiteralPath $output -File -Filter '*.csv'|ForEach-Object{
            Assert ($_.Length -le 100000000) "Comparison CSV capped: $($_.Name)"
            [void]@(Read-NtfsCsvFile $_.FullName)
        }
    }elseif(-not $existingState -and (Test-Path -LiteralPath $state)){Assert ((Get-Content -LiteralPath $state -Raw|ConvertFrom-Json).Status -eq 'Failed') 'Comparison failure never claims completion'}
    if(Test-Path -LiteralPath $state){
        Assert ((Get-Content -LiteralPath $state -Raw|ConvertFrom-Json).Version -eq $script:NtfsVersions.Comparison) 'Comparison state uses registered version'
        Assert-VersionLog (Join-Path $output 'comparison-stage.log') Comparison
    }
    return $output
}
function Assert-VersionLog([string]$Path,[string]$Component) {
    $lines=@(Get-Content -LiteralPath $Path)
    $version="Version=$($script:NtfsVersions[$Component])"
    Assert ($lines.Count -gt 0 -and @($lines|Where-Object { -not $_.Contains($version) }).Count -eq 0) "$Component log records the registered version on every line"
    Assert ([IO.Path]::GetFileName($Path) -notmatch '\d+\.\d+') "$Component log filename is version-free"
}
function Update-RunInventory([string]$Directory) {
    $manifestPath=Join-Path $Directory 'manifest.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    $manifest.Datasets=@(Get-NtfsDatasetInventory $Directory)
    $manifest|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $manifestPath -Encoding UTF8
}
function Write-FixtureDataset([string]$Directory,[string]$Name,$Data) {
    foreach($part in @(Get-NtfsCsvFiles $Directory $Name)){Remove-Item -LiteralPath $part.FullName}
    Export-NtfsCsvData $Data (Join-Path $Directory $Name)
    Update-RunInventory $Directory
}
function Set-FixtureOrdinals($Data) {
    $paths=@{}
    foreach($row in $Data){
        if(-not $paths.ContainsKey($row.Path)){$paths[$row.Path]=0}
        $row.AceOrdinal=$paths[$row.Path];$paths[$row.Path]++
    }
}

try {
    $script:TestArea='Version registry and logging'
    foreach($component in $script:NtfsVersions.Keys){
        $versionLog=Join-Path $testRoot "$component.log"
        Write-NtfsLog $versionLog $component INFO Start "Version logging fixture`r`nSecond line`nThird line"
        Assert-VersionLog $versionLog $component
        Assert (@(Get-Content -LiteralPath $versionLog).Count -eq 3) "$component multiline log retains version on each line"
    }
    Assert-Throws { Write-NtfsLog (Join-Path $testRoot 'unknown.log') Unknown INFO Start } 'Unknown version components fail explicitly' 'Unknown version component'
    Assert-Throws { Write-NtfsLog (Join-Path $testRoot 'missing/run.log') Assessment INFO Start } 'Version log write failures propagate'
    $script:TestArea='CSV and parsing'
    foreach($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.ps1')){
        $tokens=$null;$errors=$null
        [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
        Assert ($errors.Count -eq 0) "Syntax: $($file.Name)"
    }
    # Rotation counts actual UTF-8 bytes, including BOM/header and complete multiline records.
    $partsPath=Join-Path $testRoot 'parts.csv'
    $writer=New-NtfsCsvWriter $partsPath 80
    $unicode=[string][char]0x00E9
    $values=@("comma,value","quote`"value","line`r`nbreak",$unicode*6)
    try{
        $writer.WriteLine('"Value"')
        foreach($value in $values){$writer.WriteLine((ConvertTo-NtfsCsvRecord @($value)))}
    }finally{$writer.Dispose()}
    $read=@(Rows $testRoot 'parts.csv')
    Assert ($writer.Parts.Count -gt 1) 'Small cap rotates CSV parts'
    Assert ($read.Count -eq $values.Count) 'All rotated records remain available'
    for($i=0;$i -lt $values.Count;$i++){Assert ($read[$i].Value -ceq $values[$i]) 'CSV round-trip preserves quotes, comma, CRLF and Unicode'}
    foreach($path in $writer.Parts){Assert ((Get-Item -LiteralPath $path).Length -le 80) 'Small cap includes BOM/header/newlines'}
    $oversize=New-NtfsCsvWriter (Join-Path $testRoot 'oversize.csv') 20
    try{$oversize.WriteLine('"x"');Assert-Throws {$oversize.WriteLine((ConvertTo-NtfsCsvRecord @('x'*30)))} 'Oversize records fail explicitly'}
    finally{$oversize.Dispose()}
    Assert-Throws {[NtfsAssessment.Csv]::Parse('"a"x,"b"')} 'Malformed CSV rejected'
    $broken=Join-Path $testRoot 'broken.csv';[IO.File]::WriteAllText($broken,"`"a`"`r`n`"unterminated")
    Assert-Throws {@(Read-NtfsCsvFile $broken)} 'Unterminated multiline CSV rejected'
    $duplicate=Join-Path $testRoot 'duplicate.csv';[IO.File]::WriteAllText($duplicate,"`"a`",`"a`"`r`n`"x`",`"y`"")
    Assert-Throws {@(Read-NtfsCsvFile $duplicate)} 'Duplicate CSV headers rejected'
    # Exercise the actual production cap, not only a scaled proxy.
    $large=New-NtfsCsvWriter (Join-Path $testRoot 'production-cap.csv')
    $record=ConvertTo-NtfsCsvRecord @('x'*999996)
    try{$large.WriteLine('"Value"');for($i=0;$i -lt 101;$i++){$large.WriteLine($record)}}finally{$large.Dispose()}
    Assert ($large.Parts.Count -eq 2) 'Production 100,000,000-byte cap rotates'
    Assert ($large.Rows -eq 101) 'Production cap preserves every record'
    foreach($path in $large.Parts){Assert ((Get-Item -LiteralPath $path).Length -le 100000000) 'Production part never exceeds 100 MB'}

    $script:TestArea='Merger'
    $aces=@(
        (New-Ace 'data' '' 'allow' 'Everyone' 'Modify')
        (New-Ace 'data' '' 'deny' 'Everyone' 'FullControl' 'Deny')
        (New-Ace 'data' '\child' 'inheritonly' 'Everyone' 'Write' 'Allow' 'False' 'InheritOnly')
        (New-Ace 'data' '\child' 'inherited' 'Everyone' 'Write' 'Allow' 'True' 'NoPropagateInherit')
        (New-Ace 'data' '' 'numeric' 'S-1-5-21-1-2-3-1001' '262144')
        (New-Ace 'data' '' 'generic' 'S-1-5-21-1-2-3-1002' '1073741824')
        (New-Ace 'data' '' 'direct' 'TEST\User' 'Read')
        (New-Ace 'data' '' 'empty' 'TEST\Empty' 'Read')
        (New-Ace 'data' '' 'notexpanded' 'TEST\NotExpanded' 'Read')
        (New-Ace 'data' '' 'unknown' 'TEST\Unknown' 'Read')
        (New-Ace 'data' '' 'quoted' "TEST\Quoted,`"name`r`nsecond" 'Write')
        (New-Ace 'data.one' '' 'one' 'Everyone' 'Read')
        (New-Ace 'data$one' '' 'two' 'Everyone' 'Modify')
    )
    $folders=@((New-Folder 'data'),(New-Folder 'data' '\child'),(New-Folder 'data.one'),(New-Folder 'data$one'),(New-Folder 'data' '\noaces' 'NullDacl'))
    $inputRoot=Join-Path $testRoot 'baseline'
    $run=New-Run 'baseline/run' 'baseline' '2026-10-29T12:00:00Z' $aces $folders
    foreach($throttle in @(1,2)){
        $out=Invoke-Merge $inputRoot "baseline-out-$throttle" $throttle
        $summary=Get-Content -LiteralPath (Join-Path $out 'NTFS_ExecutiveSummary.json') -Raw|ConvertFrom-Json
        Assert ($summary.Version -eq $script:NtfsVersions.Merge) 'Merge summary uses registered version'
        $broad=@(Rows $out 'NTFS_BroadAccess.csv')
        $findings=@(Rows $out 'NTFS_Findings.csv')
        $all=@(Rows $out 'NTFS_AllAces.csv')
        Assert ($all.Count -eq $aces.Count) 'Raw ACE count preserved'
        Assert (@($all|Where-Object Identity -eq "TEST\Quoted,`"name`r`nsecond").Count -eq 1) 'Multiline identity survives E2E merge'
        Assert ($summary.BroadAccessAces -eq $broad.Count) 'Broad summary reconciles'
        Assert ($summary.DenyAces -eq @(Rows $out 'NTFS_DenyAces.csv').Count -and $summary.DenyAces -eq 1) 'Deny summary reconciles'
        Assert ($summary.BrokenInheritance -eq $folders.Count) 'Broken inheritance summary reconciles'
        Assert ($summary.DirectAssignments -eq 1) 'Only confirmed users counted as direct user assignments'
        Assert (@($findings|Where-Object FindingType -eq 'UnresolvedSIDWrite').Count -eq 2) 'Specific/generic numeric write-capable rights detected'
        Assert (@($findings|Where-Object{ $_.FindingType -match '^BroadPrincipal' -and (-not $_.EvidenceAceHash -or -not $_.PathHash -or -not $_.RunId) }).Count -eq 0) 'Broad findings retain ACE provenance'
        Assert (@($findings|Where-Object{ $_.FindingType -eq 'BroadPrincipalFullControl' -and $_.EvidenceAceHash -eq 'deny' }).Count -eq 0) 'Deny is not a broad allow grant'
        Assert (@($broad|Where-Object EffectiveAccess -ne 'NotCalculated').Count -eq 0) 'No false effective-access assertion'
        Assert (@($broad|Where-Object{ $_.EvidenceAceHash -eq 'inheritonly' -and $_.AppliesTo -match 'This folder' }).Count -eq 0) 'InheritOnly excludes current folder'
        Assert (@($broad|Where-Object{ $_.EvidenceAceHash -eq 'inherited' -and $_.AppliesTo -match 'immediate children only' }).Count -eq 1) 'NoPropagate retained'
        Assert (@($broad|Where-Object Remediable -eq 'Yes').Count -eq 0) 'Inheritance does not imply remediation approval'
        Assert (@($broad|Where-Object{ $_.Share -eq 'data$one' -and $_.Path -eq '\\server\data$one' -and $_.Rights -eq 'Modify' }).Count -eq 1) 'Punctuation share collision eliminated'
        $groups=@(Rows $out 'NTFS_GroupReport.csv')
        Assert (@($groups|Where-Object{ $_.GroupIdentity -eq 'TEST\Empty' -and $_.ExpansionStatus -eq 'ConfirmedEmpty' -and $_.Share -eq 'data' }).Count -eq 1) 'Confirmed empty group has correctly aligned columns'
        Assert (@($groups|Where-Object{ $_.GroupIdentity -eq 'TEST\NotExpanded' -and $_.ExpansionStatus -eq 'UnknownOrNotCollected' }).Count -eq 1) 'Missing expansion is not empty'
        Assert (@($findings|Where-Object FindingType -eq 'NullDacl').Count -eq 1) 'Null DACL directory without ACEs remains visible'
        Assert ($summary.UniqueACEs -eq $aces.Count) 'Unique counters returned from workers'
        Assert ((Get-Content -LiteralPath (Join-Path $out 'merge-state.json') -Raw|ConvertFrom-Json).Status -eq 'Completed') 'Successful merge persisted'
    }
    Import-Functions (Join-Path $root 'Merge-NtfsAssessment.ps1') @('Normalize-Rights','IsFullControl')
    Assert ((Normalize-Rights '262144') -eq 'ChangePermissions') 'ChangePermissions is not expanded to FullControl'
    Assert ((Normalize-Rights '1073741824') -eq 'GenericWrite') 'GenericWrite is not expanded to Modify'
    Assert ((Normalize-Rights '-2147483648') -eq 'GenericRead') 'Signed generic read decoded without broadening'
    Assert ((Normalize-Rights '2147483648') -eq 'GenericRead') 'Unsigned generic read decoded'
    Assert (-not(IsFullControl '262144')) 'IsFullControl respects exact masks'

    $historyRoot=Join-Path $testRoot 'history'
    [void](New-Run 'history/old' 'old' '2026-10-28T12:00:00Z' @((New-Ace 'data' '' 'old' 'Everyone' 'Modify')) @((New-Folder 'data')))
    [void](New-Run 'history/new' 'new' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'new' 'Everyone' 'Read')) @((New-Folder 'data')))
    $latest=Invoke-Merge $historyRoot 'latest-out'
    Assert (@(Rows $latest 'NTFS_AllAces.csv').Count -eq 1 -and @(Rows $latest 'NTFS_AllAces.csv')[0].Rights -eq 'Read') 'Newest scope replaces old grants'
    [void](Invoke-Merge $historyRoot 'history-union-out' 1 'AllSuccessful' 2)
    $emptyRun=New-Run 'history/newempty' 'newempty' '2026-10-30T12:00:00Z' @() @((New-Folder 'data' '' 'EmptyDacl')) 'PartialDirectoriesOnly'
    $emptyOut=Invoke-Merge $historyRoot 'newempty-out' 1 'LatestSuccessful' 1
    Assert (@(Rows $emptyOut 'NTFS_AllAces.csv').Count -eq 0) 'Newest empty partial scan never backfills old grants'
    Assert (@(Rows $emptyOut 'NTFS_RiskByFolder.csv').Count -eq 1) 'Zero-ACE scope still processed'

    $script:TestArea='Excel review export'
    $nativeExcel=[Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    $excelSource=Join-Path $testRoot 'excel-report'
    [void](New-Item -ItemType Directory -Path $excelSource)
    Copy-Item -LiteralPath @(Get-ChildItem -LiteralPath $out -Force|ForEach-Object FullName) -Destination $excelSource -Recurse
    $excelRows=@(
        [pscustomobject][ordered]@{Value='=HYPERLINK("x","y") literal _x000D_ adjacent _x000D__x000A_ overlap _x000D_x000A_x0041_ and _x005F_';Code='00123';Count='1';Resolved='True';MaxRiskScore='25';AverageRiskScore='12.34';RiskScore='';UnknownDirectoryCoverage='True';'_x0041_Header_x000D_x000A_'='header _x000D_'},
        [pscustomobject][ordered]@{Value="Quoted,`"value`"`r`nline";Code='00007';Count='0';Resolved='False';MaxRiskScore='';AverageRiskScore='';RiskScore='';UnknownDirectoryCoverage='False';'_x0041_Header_x000D_x000A_'='second'},
        [pscustomobject][ordered]@{Value='Third';Code='12345678901234567890';Count='3';Resolved='True';MaxRiskScore='45';AverageRiskScore='31.25';RiskScore='';UnknownDirectoryCoverage='True';'_x0041_Header_x000D_x000A_'='third'},
        [pscustomobject][ordered]@{Value='Fourth';Code='0042';Count='4';Resolved='False';MaxRiskScore='50';AverageRiskScore='40';RiskScore='';UnknownDirectoryCoverage='False';'_x0041_Header_x000D_x000A_'='fourth'},
        [pscustomobject][ordered]@{Value='Fifth';Code='0';Count='1234567890123456';Resolved='True';MaxRiskScore='70';AverageRiskScore='12345678901234.56';RiskScore='';UnknownDirectoryCoverage='True';'_x0041_Header_x000D_x000A_'='fifth'}
    )
    Export-NtfsCsvData $excelRows (Join-Path $excelSource 'ExcelParts.csv') 500
    $longRows=@([pscustomobject]@{Value=('x'*32768);Code='long';Count='1';Resolved='True'})
    Export-NtfsCsvData $longRows (Join-Path $excelSource 'TooLong.csv')
    Export-NtfsCsvData @([pscustomobject]@{Value='apostrophe name'}) (Join-Path $excelSource "'Odd.csv")
    Export-NtfsCsvData @([pscustomobject]@{Value='linked source'}) (Join-Path $excelSource 'Linked.csv')
    $xmlHeader='Header'+[char]0xFFFE+'_x000D_x000A__x0041'+[char]1
    $xmlValues=@(
        [string][char]0xFFFE
        [string][char]0xFFFF
        "control$([char]0)$([char]1)$([char]0xB)$([char]0xC)$([char]0x1F)end"
        "literal _xFFFE_ and _x005F_ actual$([char]0xFFFE)"
        "allowed`twhitespace`r`nand $([char]::ConvertFromUtf32(0x1F600))"
        "_x0041$([char]1)"
        "_x0041$([char]0xFFFE)"
        '_x0041'
        "_x0041_x0042$([char]1)"
        ("line`n"*253)
    )
    $xmlRows=@(for($index=0;$index -lt $xmlValues.Count;$index++){
        [pscustomobject][ordered]@{
            Inherited=[string]($index%2 -eq 0);IsInherited=[string]($index%2 -ne 0)
            $xmlHeader=$xmlValues[$index]
        }
    })
    Export-NtfsCsvData $xmlRows (Join-Path $excelSource 'XmlStrings.csv')
    $outsideSource=Join-Path $testRoot 'excel-outside-source'
    [void](New-Item -ItemType Directory -Path $outsideSource)
    Copy-Item -LiteralPath (Join-Path $excelSource 'Linked.csv') -Destination (Join-Path $outsideSource 'Linked.csv')
    Remove-Item -LiteralPath (Join-Path $excelSource 'NTFS_FindingsSummary.csv') -Force -ErrorAction Stop
    Export-NtfsCsvData @() (Join-Path $excelSource 'NTFS_FindingsSummary.csv')
    $excelQaPath=Join-Path $excelSource 'NTFS_QA.json'
    $excelQa=Get-Content -LiteralPath $excelQaPath -Raw|ConvertFrom-Json
    $excelQa.Datasets=@(Get-NtfsDatasetInventory $excelSource)
    $excelQa|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $excelQaPath -Encoding UTF8
    $executivePath=Join-Path $excelSource 'NTFS_ExecutiveSummary.json'
    $expectedGeneratedUtc='2026-11-25T10:15:30.1234567Z'
    $excelExecutive=Get-Content -LiteralPath $executivePath -Raw|ConvertFrom-Json
    $excelExecutive.GeneratedUtc=$expectedGeneratedUtc
    $excelExecutive|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $executivePath -Encoding UTF8
    $excelPartFiles=@(Get-NtfsCsvFiles $excelSource 'ExcelParts.csv')
    Assert ($excelPartFiles.Count -gt 1) 'Excel test fixture contains multiple QA-bound CSV parts'
    $excelSourceHashes=@($excelPartFiles|ForEach-Object{
        [pscustomobject]@{Name=$_.Name;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })

    $excelOutput=Join-Path $testRoot 'excel-output.xlsx'
    $excelLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
        -InputReportFolder ($excelSource+[IO.Path]::DirectorySeparatorChar) -OutputPath $excelOutput -Dataset excelparts.csv -MaxRowsPerSheet 2 2>&1 })
    $excelExit=$LASTEXITCODE
    Assert ($excelExit -eq 0 -and (Test-Path -LiteralPath $excelOutput -PathType Leaf)) "Excel review succeeds: $($excelLog -join "`n")"
    Assert ((Get-Item -LiteralPath $excelOutput).Length -gt 0) 'Excel review creates a nonempty workbook'
    foreach($hash in $excelSourceHashes){
        Assert ((Get-FileHash -LiteralPath (Join-Path $excelSource $hash.Name) -Algorithm SHA256).Hash -ceq $hash.SHA256) "Excel review leaves $($hash.Name) unchanged"
    }
    Import-Functions (Join-Path $root 'New-NtfsExcelReview.ps1') @('Read-NtfsExcelCompletionState')
    $readinessPath=Join-Path $excelSource 'merge-state.json'
    $readinessSharing=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $readinessWriter=[IO.FileStream]::new($readinessPath,[IO.FileMode]::Open,[IO.FileAccess]::Write,$readinessSharing)
    try{
        $readinessState=Read-NtfsExcelCompletionState $readinessPath
        Assert ($readinessState.Finalized -eq $true) 'Shared readiness probe reads finalized state while a concurrent merger write handle remains open'
    }finally{$readinessWriter.Dispose()}
    $excelStream=[IO.File]::Open($excelOutput,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $excelArchive=$null
    try{
        $excelArchive=[IO.Compression.ZipArchive]::new($excelStream,[IO.Compression.ZipArchiveMode]::Read,$false)
        foreach($part in @('[Content_Types].xml','_rels/.rels','xl/workbook.xml','xl/_rels/workbook.xml.rels','xl/styles.xml')){
            Assert ($null -ne $excelArchive.GetEntry($part)) "Excel package contains $part"
        }
        $workbookText=Read-ZipEntryText $excelArchive 'xl/workbook.xml'
        $workbookXml=[xml]$workbookText
        $sheetNames=@($workbookXml.workbook.sheets.sheet|ForEach-Object{$_.name})
        Assert ($sheetNames -contains 'Overview' -and $sheetNames -contains 'Excel Parts' -and $sheetNames -contains 'Excel Parts (2)' -and $sheetNames -contains 'Excel Parts (3)') 'Excel workbook splits rows with usable continuation names'
        $sheetEntries=@($excelArchive.Entries|Where-Object{$_.FullName -match '^xl/worksheets/sheet\d+\.xml$'})
        Assert ($sheetEntries.Count -eq 4) 'Excel workbook contains Overview and every split data sheet'
        $sheetXml=($sheetEntries|ForEach-Object{Read-ZipEntryText $excelArchive $_.FullName}) -join "`n"
        Assert ($sheetXml.Contains($expectedGeneratedUtc)) 'Overview preserves GeneratedUtc as invariant round-trip UTC text'
        Assert ($sheetXml.Contains('=HYPERLINK') -and $sheetXml -notmatch '<f(?:\s|>)') 'Formula-like assessment values remain inline text'
        Assert ($sheetXml.Contains('00123') -and $sheetXml.Contains('12345678901234567890')) 'Numeric-looking identifiers retain their text representation'
        Assert ($sheetXml -match '<c r="E2"><v>25</v></c>' -and $sheetXml -match '<c r="F2"><v>12\.34</v></c>') 'Risk scores use sortable numeric Excel cells'
        Assert ($sheetXml -notmatch '<c r="G2"(?:\s|>)') 'Empty data values are omitted rather than serialized as text'
        Assert ($sheetXml -match '<c r="H2" t="b"><v>1</v></c>') 'Coverage indicators after blank cells use boolean cells at explicit references'
        Assert ($sheetXml -match '<c r="C2" t="inlineStr"><is><t>1234567890123456</t></is></c>') 'Integers beyond Excel precision remain text'
        Assert ($sheetXml -match '<c r="F2" t="inlineStr"><is><t>12345678901234\.56</t></is></c>') 'Decimals beyond Excel precision remain text'
        $dataSheet=[xml](Read-ZipEntryText $excelArchive 'xl/worksheets/sheet2.xml')
        Assert ($dataSheet.OuterXml -notmatch '<c r="[EFG]3"(?:\s|>)') 'All three unassessed risk-score columns remain truly blank'
        Assert ($dataSheet.OuterXml -match '<c r="C3"><v>0</v></c>') 'A numeric zero remains present rather than becoming a blank'
        $formulaText=$dataSheet.SelectSingleNode("//*[local-name()='c' and @r='A2']/*[local-name()='is']/*[local-name()='t']").InnerText
        $headerText=$dataSheet.SelectSingleNode("//*[local-name()='c' and @r='I1']/*[local-name()='is']/*[local-name()='t']").InnerText
        Assert ($formulaText.Contains('_x005F_x000D_') -and $headerText.Contains('_x005F_x0041_')) 'OOXML escape-like source text is escaped in data and headers'
        Assert ($formulaText.Contains('_x005F_x000D__x005F_x000A_')) 'Adjacent OOXML escape-like source tokens are each escaped'
        Assert ($formulaText.Contains('_x005F_x000D_x005F_x000A_x005F_x0041_')) 'Overlapping OOXML escape-like tokens each have their leading underscore escaped'
        Assert ((ConvertFrom-NtfsExcelXstring $formulaText) -ceq $excelRows[0].Value -and
            (ConvertFrom-NtfsExcelXstring $headerText) -ceq '_x0041_Header_x000D_x000A_') 'Escaped OOXML text decodes losslessly to original data and overlapping headers'
        foreach($entry in $sheetEntries){
            $xmlReader=[Xml.XmlReader]::Create([IO.StringReader]::new((Read-ZipEntryText $excelArchive $entry.FullName)))
            try{while($xmlReader.Read()){}}finally{$xmlReader.Dispose()}
        }
    }finally{
        if($null -ne $excelArchive){$excelArchive.Dispose()}
        $excelStream.Dispose()
    }

    $excelTokens=$null;$excelErrors=$null
    $excelAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'New-NtfsExcelReview.ps1'),[ref]$excelTokens,[ref]$excelErrors)
    if($excelErrors.Count -gt 0){throw ($excelErrors -join '; ')}
    $excelTypes=$excelAst.Find({param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.StartsWith("if (`$null -eq ('NtfsAssessment.ExcelReviewWorkbook'")
    },$true)
    . ([scriptblock]::Create($excelTypes.Extent.Text))
    $sourceLease=[NtfsAssessment.ExcelReviewDirectoryLease]::Open($excelSource+[IO.Path]::DirectorySeparatorChar)
    $directoryLease=$null
    $collisionFile=$null
    try{
        $filesystemRoot=[IO.Path]::GetPathRoot($testRoot)
        $rootLease=[NtfsAssessment.ExcelReviewDirectoryLease]::Open($filesystemRoot)
        try{
            Assert-Throws {
                [void][NtfsAssessment.ExcelReviewDirectoryLease]::CreateOutside([IO.Directory]::GetParent($testRoot).FullName,$rootLease)
            } 'Filesystem-root source lease contains every descendant output path'
        }finally{$rootLease.Dispose()}

        $nestedOutput=Join-Path (Join-Path $testRoot 'excel-new-parent') 'child'
        $directoryLease=[NtfsAssessment.ExcelReviewDirectoryLease]::CreateOutside($nestedOutput+[IO.Path]::DirectorySeparatorChar,$sourceLease)
        Assert ((Test-Path -LiteralPath $nestedOutput -PathType Container) -and -not $directoryLease.RoutesThrough($sourceLease)) 'Missing output-directory components are created and leased outside the source report'
        $forbiddenChild=Join-Path $excelSource 'must-not-create'
        Assert-Throws { [void][NtfsAssessment.ExcelReviewDirectoryLease]::CreateOutside($forbiddenChild,$sourceLease) } 'Source containment is checked before creating missing output directories' 'within or aliased'
        Assert (-not(Test-Path -LiteralPath $forbiddenChild)) 'Rejected output containment creates no source-report directories'

        if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
            Assert-Throws { [IO.Directory]::Move($nestedOutput,$nestedOutput+'-renamed') } 'Pinned output directory cannot be renamed before workbook creation' -ExpectedNativeCode 32
            $nestedAncestor=Split-Path $nestedOutput -Parent
            Assert-Throws { [IO.Directory]::Move($nestedAncestor,$nestedAncestor+'-renamed') } 'Pinned output ancestors cannot be replaced before workbook creation' -ExpectedNativeCode 32
            Assert-Throws { [IO.Directory]::Move($excelSource,$excelSource+'-renamed') } 'Pinned source directory cannot be replaced during export' -ExpectedNativeCode 32
            $driveRoot=[IO.Path]::GetPathRoot($excelSource)
            $rootLease=[NtfsAssessment.ExcelReviewDirectoryLease]::Open($driveRoot)
            try{
                Assert ($rootLease.Path -ceq $driveRoot) 'Trailing separator normalization preserves a native drive root'
            }finally{$rootLease.Dispose()}
        }

        $collisionPending=Join-Path $nestedOutput 'collision.pending'
        $collisionFinal=Join-Path $nestedOutput 'collision.xlsx'
        $collisionFile=[NtfsAssessment.ExcelReviewOutputFile]::Create($collisionPending,$collisionFinal,$directoryLease)
        $collisionFile.Stream.WriteByte(42)
        [IO.File]::WriteAllText($collisionFinal,'concurrent output')
        Assert-Throws { $collisionFile.Publish($directoryLease) } 'A final output created during generation blocks publication'
        Assert ([IO.File]::ReadAllText($collisionFinal) -ceq 'concurrent output') 'Publication never replaces a concurrently created output'

        if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
            Assert-Throws { [IO.File]::Move($collisionPending,$collisionPending+'-renamed') } 'Pending workbook cannot be replaced before handle-based publication' -ExpectedNativeCode 32
            $pinnedCsv=$null
            try{
                $pinnedCsv=[NtfsAssessment.ExcelReviewPinnedFile]::Open($excelPartFiles[0].FullName)
                Assert-Throws { [IO.File]::Move($excelPartFiles[0].FullName,$excelPartFiles[0].FullName+'.moved') } 'Pinned CSV cannot be swapped between parsing and hash validation' -ExpectedNativeCode 32
                Assert-Throws {
                    $writeProbe=[IO.File]::Open($excelPartFiles[0].FullName,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
                    $writeProbe.Dispose()
                } 'Pinned CSV rejects concurrent writers' -ExpectedNativeCode 32
            }finally{
                if($null -ne $pinnedCsv){$pinnedCsv.Dispose()}
            }
        }else{
            Write-Information 'Windows-native Excel directory, file-sharing, and publication assertions require a Windows run.' -InformationAction Continue
        }
    }finally{
        if($null -ne $collisionFile){$collisionFile.Dispose()}
        if($null -ne $directoryLease){$directoryLease.Dispose()}
        $sourceLease.Dispose()
    }
    if($nativeExcel){
        Assert (-not [IO.File]::Exists($collisionPending)) 'Disposing an unpublished Windows workbook deletes its owned file'
        [IO.File]::WriteAllText($collisionPending,'replacement after dispose')
        $collisionFile.Dispose()
        Assert ([IO.File]::ReadAllText($collisionPending) -ceq 'replacement after dispose') 'Repeated cleanup cannot delete a replacement pending-path entry'
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NtfsExcelJunctionProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool DeviceIoControl(SafeFileHandle file, uint code, byte[] input,
        uint inputLength, IntPtr output, uint outputLength, out uint returned, IntPtr overlapped);
    public static SafeFileHandle OpenWriter(string path) {
        SafeFileHandle file = CreateFileW(path, 0x40000000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (file.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            file.Dispose();
            throw new Win32Exception(error);
        }
        return file;
    }
    public static void Set(string path, string target) {
        byte[] substitute = Encoding.Unicode.GetBytes(@"\??\" + Path.GetFullPath(target));
        byte[] print = Encoding.Unicode.GetBytes(Path.GetFullPath(target));
        byte[] buffer = new byte[20 + substitute.Length + print.Length];
        Buffer.BlockCopy(BitConverter.GetBytes(0xA0000003u), 0, buffer, 0, 4);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)(buffer.Length - 8)), 0, buffer, 4, 2);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)substitute.Length), 0, buffer, 10, 2);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)(substitute.Length + 2)), 0, buffer, 12, 2);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)print.Length), 0, buffer, 14, 2);
        Buffer.BlockCopy(substitute, 0, buffer, 16, substitute.Length);
        Buffer.BlockCopy(print, 0, buffer, 18 + substitute.Length, print.Length);
        Control(path, 0x000900A4, buffer);
    }
    public static void Clear(string path) {
        byte[] buffer = new byte[8];
        Buffer.BlockCopy(BitConverter.GetBytes(0xA0000003u), 0, buffer, 0, 4);
        Control(path, 0x000900AC, buffer);
    }
    private static void Control(string path, uint code, byte[] buffer) {
        using (SafeFileHandle file = OpenWriter(path)) {
            uint returned;
            if (!DeviceIoControl(file, code, buffer, (uint)buffer.Length, IntPtr.Zero, 0, out returned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
        $junctionProbePath=Join-Path $testRoot 'inplace-junction'
        [void][IO.Directory]::CreateDirectory($junctionProbePath)
        $junctionLease=$null
        try{
            [NtfsExcelJunctionProbe]::Set($junctionProbePath,$excelSource)
            Assert (([IO.File]::GetAttributes($junctionProbePath) -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'Native probe can insert an in-place junction without renaming the directory'
            [NtfsExcelJunctionProbe]::Clear($junctionProbePath)
            $junctionLease=[NtfsAssessment.ExcelReviewDirectoryLease]::Open($junctionProbePath)
            $sourceEntriesBefore=@(Get-ChildItem -LiteralPath $excelSource -Force|Sort-Object Name|ForEach-Object Name) -join "`n"
            [NtfsExcelJunctionProbe]::Set($junctionProbePath,$excelSource)
            $redirectPending=Join-Path $junctionProbePath 'redirect.pending'
            $redirectFinal=Join-Path $junctionProbePath 'redirect.xlsx'
            Assert-Throws { [void][NtfsAssessment.ExcelReviewOutputFile]::Create($redirectPending,$redirectFinal,$junctionLease) } 'In-place junction insertion is rejected before pending-file creation' 'Reparse point inserted'
            Assert-Throws { $junctionLease.CreateChildDirectory('redirect-child') } 'In-place junction insertion after lease acquisition cannot redirect missing-child directory creation' 'Reparse point inserted'
            $sourceEntriesAfter=@(Get-ChildItem -LiteralPath $excelSource -Force|Sort-Object Name|ForEach-Object Name) -join "`n"
            Assert ($sourceEntriesBefore -ceq $sourceEntriesAfter) 'In-place output redirection creates neither directories nor pending files in the source report'
            [NtfsExcelJunctionProbe]::Clear($junctionProbePath)
        }finally{
            if($null -ne $junctionLease){$junctionLease.Dispose()}
            if(([IO.File]::GetAttributes($junctionProbePath) -band [IO.FileAttributes]::ReparsePoint) -ne 0){
                [NtfsExcelJunctionProbe]::Clear($junctionProbePath)
            }
        }
    }

    $exportScript=Join-Path $root 'New-NtfsExcelReview.ps1'
    $createLine=$excelAst.Find({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$outputFile' -and $node.Right.Extent.Text -like '*ExcelReviewOutputFile*'
    },$true).Extent.StartLineNumber
    $unownedDirectory=Join-Path $testRoot 'excel-unowned-pending'
    $unownedOutput=Join-Path $unownedDirectory 'review.xlsx'
    $collisionProbe=[pscustomobject]@{Path=''}
    $collisionPs=[powershell]::Create()
    try{
        [void]$collisionPs.AddScript(@'
param($scriptPath,$report,$output,$line,$probe)
$global:excelCollisionProbe=$probe
$null=Set-PSBreakpoint -Script $scriptPath -Line $line -Action {
    $global:excelCollisionProbe.Path=$pendingPath
    [IO.File]::WriteAllText($pendingPath,'unowned pending collision')
}
& $scriptPath -InputReportFolder $report -OutputPath $output -Dataset XmlStrings.csv
'@).AddArgument($exportScript).AddArgument($excelSource).AddArgument($unownedOutput).AddArgument($createLine).AddArgument($collisionProbe)
        $null=$collisionPs.Invoke()
        Assert ($collisionProbe.Path -ne '' -and $collisionPs.HadErrors) 'CreateNew collision is injected before export acquires the pending handle'
        Assert (-not [IO.File]::Exists($unownedOutput)) 'CreateNew collision never publishes a workbook'
        Assert ([IO.File]::ReadAllText($collisionProbe.Path) -ceq 'unowned pending collision') 'Failed pending-file creation never deletes the unowned pathname'
    }finally{$collisionPs.Dispose()}

    $cancelLine=$excelAst.Find({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$usedSheetNames'
    },$true).Extent.StartLineNumber
    $cancelDirectory=Join-Path $testRoot 'excel-cancelled'
    $cancelOutput=Join-Path $cancelDirectory 'review.xlsx'
    $cancelReady=[Threading.ManualResetEventSlim]::new($false)
    $cancelRelease=[Threading.ManualResetEventSlim]::new($false)
    $cancelPs=[powershell]::Create()
    try{
        [void]$cancelPs.AddScript(@'
param($scriptPath,$report,$output,$line,$ready,$release)
$global:excelCancelReady=$ready
$global:excelCancelRelease=$release
$null=Set-PSBreakpoint -Script $scriptPath -Line $line -Action {
    $global:excelCancelReady.Set()
    $global:excelCancelRelease.Wait()
}
& $scriptPath -InputReportFolder $report -OutputPath $output -Dataset XmlStrings.csv
'@).AddArgument($exportScript).AddArgument($excelSource).AddArgument($cancelOutput).AddArgument($cancelLine).AddArgument($cancelReady).AddArgument($cancelRelease)
        $cancelInvocation=$cancelPs.BeginInvoke()
        Assert ($cancelReady.Wait([TimeSpan]::FromSeconds(60))) 'Cancellation reaches a live workbook and owned pending output'
        $cancelPending=@(Get-ChildItem -LiteralPath $cancelDirectory -File -Force -Filter '.ntfs-excel-*.pending')
        Assert ($cancelPending.Count -eq 1) 'Cancellation occurs before publication with exactly one owned pending file'
        $cancelStop=$cancelPs.BeginStop($null,$null)
        $cancelRelease.Set()
        $cancelPs.EndStop($cancelStop)
        $wasStopped=$false
        try{$null=$cancelPs.EndInvoke($cancelInvocation)}catch{
            if($_.Exception.GetBaseException() -is [Management.Automation.PipelineStoppedException]){$wasStopped=$true}else{throw}
        }
        Assert ($wasStopped -and $cancelPs.InvocationStateInfo.State -eq 'Stopped') 'PowerShell.Stop cancels the real exporter pipeline'
        Assert (-not [IO.File]::Exists($cancelOutput)) 'Cancellation never publishes a partial workbook'
        if($nativeExcel){
            Assert (-not [IO.File]::Exists($cancelPending[0].FullName)) 'Cancellation deletes the Windows pending file through its owned handle'
        }else{
            Assert ([IO.File]::Exists($cancelPending[0].FullName)) 'Offline cancellation preserves the pending file without pathname deletion'
        }
        $cancelRenamed=$cancelDirectory+'-renamed'
        [IO.Directory]::Move($cancelDirectory,$cancelRenamed)
        [IO.Directory]::Move($cancelRenamed,$cancelDirectory)
        Assert ([IO.Directory]::Exists($cancelDirectory)) 'Cancellation releases output-directory leases before returning'
    }finally{
        $cancelRelease.Set()
        if($cancelPs.InvocationStateInfo.State -in @('Running','Stopping')){$cancelPs.Stop()}
        $cancelPs.Dispose()
        $cancelReady.Dispose()
        $cancelRelease.Dispose()
    }

    $mergeScript=Join-Path $root 'Merge-NtfsAssessment.ps1'
    $mergeTokens=$null;$mergeErrors=$null
    $mergeAst=[Management.Automation.Language.Parser]::ParseFile($mergeScript,[ref]$mergeTokens,[ref]$mergeErrors)
    if($mergeErrors.Count -gt 0){throw ($mergeErrors -join '; ')}
    $mergeCleanupLine=$mergeAst.Find({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$cleanupErrors'
    },$true).Extent.StartLineNumber
    $finalSaveCommand=$mergeAst.Find({param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Save-State' -and
        $node.Extent.Text -match '-Finalized\s+\$true'
    },$true)
    if($null -eq $finalSaveCommand){throw 'Could not locate final merge state publication for regression injection.'}
    $finalSaveLine=$finalSaveCommand.Extent.StartLineNumber
    $finalExitStatement=$mergeAst.Find({param($node)
        $node -is [Management.Automation.Language.ExitStatementAst] -and
        $node.Extent.Text -match 'exit\s+\$exitCode'
    },$true)
    if($null -eq $finalExitStatement){throw 'Could not locate merge exit statement for failure-code regression.'}
    $finalExitLine=$finalExitStatement.Extent.StartLineNumber
    $gateReport=Join-Path $testRoot 'merge-finalization-gate'
    $gateWorkbook=Join-Path $testRoot 'gate-review.xlsx'
    $mergeReady=[Threading.ManualResetEventSlim]::new($false)
    $mergeRelease=[Threading.ManualResetEventSlim]::new($false)
    $mergePs=[powershell]::Create()
    try{
        [void]$mergePs.AddScript(@'
param($scriptPath,$inputRoot,$output,$line,$ready,$release)
$global:mergeGateReady=$ready
$global:mergeGateRelease=$release
$null=Set-PSBreakpoint -Script $scriptPath -Line $line -Action {
    $lateWriter=[pscustomobject]@{}
    Add-Member -InputObject $lateWriter -MemberType ScriptMethod -Name Dispose -Value {throw 'Synthetic late cleanup failure'}
    [void]$script:OwnedWriters.Add($lateWriter)
    $global:mergeGateReady.Set()
    $global:mergeGateRelease.Wait()
}
& $scriptPath -InputRoot $inputRoot -OutputFolder $output -ThrottleLimit 1
'@).AddArgument($mergeScript).AddArgument($inputRoot).AddArgument($gateReport).AddArgument($mergeCleanupLine).AddArgument($mergeReady).AddArgument($mergeRelease)
        $mergeInvocation=$mergePs.BeginInvoke()
        Assert ($mergeReady.Wait([TimeSpan]::FromSeconds(60))) 'Merge reaches cleanup after report generation but before finalization'
        $gateStatePath=Join-Path $gateReport 'merge-state.json'
        $gateState=Get-Content -LiteralPath $gateStatePath -Raw|ConvertFrom-Json
        Assert ($gateState.Status -eq 'Running' -and -not $gateState.Finalized) 'Merge cannot advertise completion while cleanup can still change QA warnings'
        $beforeGateLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $exportScript `
            -InputReportFolder $gateReport -OutputPath $gateWorkbook -Dataset NTFS_Findings.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 2 -and -not [IO.File]::Exists($gateWorkbook)) 'Export started during merge cleanup refuses the unfinished report'
        $mergeRelease.Set()
        Assert ($mergeInvocation.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(60))) 'Merge completes final cleanup and warning reconciliation'
        $null=$mergePs.EndInvoke($mergeInvocation)
        $gateState=Get-Content -LiteralPath $gateStatePath -Raw|ConvertFrom-Json
        $gateQa=Get-Content -LiteralPath (Join-Path $gateReport 'NTFS_QA.json') -Raw|ConvertFrom-Json
        Assert ($gateState.Status -eq 'CompletedWithWarnings' -and $gateState.Finalized -eq $true) 'Final completion barrier is published after cleanup warnings are persisted'
        Assert (($gateQa.Warnings -join "`n") -match 'Synthetic late cleanup failure') 'Final source QA includes the cleanup warning'
        $afterGateLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $exportScript `
            -InputReportFolder $gateReport -OutputPath $gateWorkbook -Dataset NTFS_Findings.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($gateWorkbook)) "Finalized merge exports successfully: $($afterGateLog -join "`n")"
        $gateStream=[IO.File]::OpenRead($gateWorkbook)
        $gateArchive=$null
        try{
            $gateArchive=[IO.Compression.ZipArchive]::new($gateStream,[IO.Compression.ZipArchiveMode]::Read,$false)
            Assert ((Read-ZipEntryText $gateArchive 'xl/worksheets/sheet1.xml').Contains('Synthetic late cleanup failure')) 'Overview includes warnings added by merge cleanup before finalization'
        }finally{
            if($null -ne $gateArchive){$gateArchive.Dispose()}
            $gateStream.Dispose()
        }
        $gateState.PSObject.Properties.Remove('Finalized')
        $gateState|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $gateStatePath -Encoding UTF8
        $legacyWorkbook=Join-Path $testRoot 'legacy-state-review.xlsx'
        $legacyLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $exportScript `
            -InputReportFolder $gateReport -OutputPath $legacyWorkbook -Dataset NTFS_Findings.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 2 -and -not [IO.File]::Exists($legacyWorkbook)) 'Legacy completed status without a cleanup-finalization barrier is not sufficient to export'
        Assert (($legacyLog -join "`n") -match 'regenerate older reports') 'Missing finalization signal gives explicit report-regeneration guidance'
    }finally{
        $mergeRelease.Set()
        if($mergePs.InvocationStateInfo.State -in @('Running','Stopping')){$mergePs.Stop()}
        $mergePs.Dispose()
        $mergeReady.Dispose()
        $mergeRelease.Dispose()
    }

    $failedFinalizationOutput=Join-Path $testRoot 'merge-final-state-write-failure'
    $failedFinalizationPs=[powershell]::Create()
    $failedFinalizationProbe=[pscustomobject]@{ExitCode=$null}
    try{
        [void]$failedFinalizationPs.AddScript(@'
param($scriptPath,$inputRoot,$output,$line,$exitLine,$probe)
$global:failedFinalizationProbe=$probe
$null=Set-PSBreakpoint -Script $scriptPath -Line $line -Action {
    $logPath=Join-Path $OutputFolder 'merge-stage.log'
    [IO.File]::Delete($logPath)
    [void][IO.Directory]::CreateDirectory($logPath)
}
$null=Set-PSBreakpoint -Script $scriptPath -Line $exitLine -Action {
    $global:failedFinalizationProbe.ExitCode=$exitCode
}
& $scriptPath -InputRoot $inputRoot -OutputFolder $output -ThrottleLimit 1
'@).AddArgument($mergeScript).AddArgument($inputRoot).AddArgument($failedFinalizationOutput).AddArgument($finalSaveLine).AddArgument($finalExitLine).AddArgument($failedFinalizationProbe)
        $null=$failedFinalizationPs.Invoke()
        $failedFinalizationMessages=@(
            @($failedFinalizationPs.Streams.Error|ForEach-Object{[string]$_})
            @($failedFinalizationPs.Streams.Information|ForEach-Object{[string]$_.MessageData})
        )
        $failedFinalizationState=Get-Content -LiteralPath (Join-Path $failedFinalizationOutput 'merge-state.json') -Raw|ConvertFrom-Json
        Assert ($failedFinalizationState.Status -eq 'Failed' -and -not $failedFinalizationState.Finalized) 'Failed final-state log append cannot leave a finalized completed state'
        Assert (($failedFinalizationMessages -join "`n") -match 'Merge: Failed\.' -and
            ($failedFinalizationMessages -join "`n") -match 'Could not finalize the merge state') 'Final-state persistence failure still emits failure guidance'
        Assert ($failedFinalizationProbe.ExitCode -eq 2) 'Final-state persistence failure selects documented exit code 2'
        Assert ($failedFinalizationPs.InvocationStateInfo.State -eq 'Completed') 'Final-state persistence failure is handled without terminating the completion pipeline'
    }finally{$failedFinalizationPs.Dispose()}

    $typedExcel=Join-Path $testRoot 'excel-types-and-xml.xlsx'
    $typedLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
        -InputReportFolder $excelSource -OutputPath $typedExcel -Dataset XmlStrings.csv 2>&1 })
    Assert ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $typedExcel -PathType Leaf)) "Boolean and XML-forbidden text export succeeds: $($typedLog -join "`n")"
    $typedStream=[IO.File]::OpenRead($typedExcel)
    $typedArchive=$null
    try{
        $typedArchive=[IO.Compression.ZipArchive]::new($typedStream,[IO.Compression.ZipArchiveMode]::Read,$false)
        $booleanXml=Read-ZipEntryText $typedArchive 'xl/worksheets/sheet2.xml'
        Assert ($booleanXml -match '<c r="A2" t="b"><v>1</v></c>' -and $booleanXml -match '<c r="A3" t="b"><v>0</v></c>') 'Findings Inherited values are true Boolean cells'
        Assert ($booleanXml -match '<c r="B2" t="b"><v>0</v></c>' -and $booleanXml -match '<c r="B3" t="b"><v>1</v></c>') 'ACE IsInherited values retain matching Boolean typing'
        $xmlSheet=[xml]$booleanXml
        $xmlCells=@($xmlSheet.SelectNodes("//*[local-name()='c' and starts-with(@r,'C')]/*[local-name()='is']/*[local-name()='t']"))
        Assert ($xmlCells.Count -eq $xmlValues.Count+1) 'XML-safe OOXML worksheet contains every original header and value'
        Assert ((ConvertFrom-NtfsExcelXstring $xmlCells[0].InnerText) -ceq $xmlHeader) 'XML-forbidden header and overlapping literal tokens round-trip losslessly'
        for($index=0;$index -lt $xmlValues.Count;$index++){
            Assert ((ConvertFrom-NtfsExcelXstring $xmlCells[$index+1].InnerText) -ceq $xmlValues[$index]) "XML-forbidden text and valid Unicode round-trip losslessly for row $index"
        }
    }finally{
        if($null -ne $typedArchive){$typedArchive.Dispose()}
        $typedStream.Dispose()
    }

    $excelQa=Get-Content -LiteralPath $excelQaPath -Raw|ConvertFrom-Json
    $emptySummary=@($excelQa.Datasets|Where-Object Name -eq 'NTFS_FindingsSummary.csv')
    Assert ($emptySummary.Count -eq 1 -and $emptySummary[0].Rows -eq 0) 'Empty merge summary is present in the QA inventory'
    $emptySummary[0].Columns=$null
    $excelQa.Warnings=$null
    $excelQa|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $excelQaPath -Encoding UTF8

    $defaultExcel=Join-Path $testRoot 'excel-default.xlsx'
    $defaultLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
        -InputReportFolder $excelSource -OutputPath $defaultExcel 2>&1 })
    Assert ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $defaultExcel -PathType Leaf)) "Default Excel review succeeds: $($defaultLog -join "`n")"
    Assert (($defaultLog -join "`n") -match 'Excel review: Completed\.' -and ($defaultLog -join "`n") -notmatch 'CompletedWithWarnings') 'Null QA warnings remain an empty collection'
    $defaultStream=[IO.File]::Open($defaultExcel,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $defaultArchive=$null
    try{
        $defaultArchive=[IO.Compression.ZipArchive]::new($defaultStream,[IO.Compression.ZipArchiveMode]::Read,$false)
        $defaultWorkbook=[xml](Read-ZipEntryText $defaultArchive 'xl/workbook.xml')
        $defaultSheets=@($defaultWorkbook.workbook.sheets.sheet|ForEach-Object{$_.name})
        Assert ($defaultSheets -contains 'Findings' -and $defaultSheets -notcontains 'All ACEs' -and $defaultSheets -notcontains 'Folders') 'Default Excel review excludes raw ACE and folder datasets'
    }finally{
        if($null -ne $defaultArchive){$defaultArchive.Dispose()}
        $defaultStream.Dispose()
    }

    $emptyExcel=Join-Path $testRoot 'excel-empty.xlsx'
    $emptyLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
        -InputReportFolder $excelSource -OutputPath $emptyExcel -Dataset NTFS_FindingsSummary.csv 2>&1 })
    Assert ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $emptyExcel -PathType Leaf)) "Empty summary export succeeds: $($emptyLog -join "`n")"

    $qaBeforeErrors=[IO.File]::ReadAllBytes($excelQaPath)
    $statePath=Join-Path $excelSource 'merge-state.json'
    $stateBeforeErrors=[IO.File]::ReadAllBytes($statePath)
    try{
        $errorOnlyQa=Get-Content -LiteralPath $excelQaPath -Raw|ConvertFrom-Json
        $errorOnlyQa.Errors=2
        $errorOnlyQa.Warnings=@()
        $errorOnlyQa|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $excelQaPath -Encoding UTF8
        $errorOnlyState=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
        $errorOnlyState.Status='CompletedWithWarnings'
        $errorOnlyState|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $statePath -Encoding UTF8
        $errorOnlyOutput=Join-Path $testRoot 'excel-source-errors.xlsx'
        $errorOnlyLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $exportScript `
            -InputReportFolder $excelSource -OutputPath $errorOnlyOutput -Dataset NTFS_FindingsSummary.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($errorOnlyOutput)) 'Error-only source report still creates a warning-qualified review copy'
        $errorOnlyText=$errorOnlyLog -join "`n"
        Assert ($errorOnlyText -match 'Excel review: CompletedWithWarnings\.' -and $errorOnlyText -match 'Review 2 source merge error') 'QA.Errors supplies an explicit warning reason and review requirement without QA.Warnings'
        Assert ($errorOnlyText.Contains((Join-Path $excelSource 'NTFS_ScanErrors.csv'))) 'Source error guidance points to the original scan-error report'
        $errorOnlyStream=[IO.File]::OpenRead($errorOnlyOutput)
        $errorOnlyArchive=$null
        try{
            $errorOnlyArchive=[IO.Compression.ZipArchive]::new($errorOnlyStream,[IO.Compression.ZipArchiveMode]::Read,$false)
            $errorOnlyOverview=Read-ZipEntryText $errorOnlyArchive 'xl/worksheets/sheet1.xml'
            Assert ($errorOnlyOverview.Contains('2 source merge error(s)') -and $errorOnlyOverview.Contains('NTFS_ScanErrors.csv')) 'Overview preserves error-only source review guidance'
        }finally{
            if($null -ne $errorOnlyArchive){$errorOnlyArchive.Dispose()}
            $errorOnlyStream.Dispose()
        }
    }finally{
        [IO.File]::WriteAllBytes($excelQaPath,$qaBeforeErrors)
        [IO.File]::WriteAllBytes($statePath,$stateBeforeErrors)
    }

    $longNameRoot=if($nativeExcel -and $env:RUNNER_TEMP){$env:RUNNER_TEMP}else{$testRoot}
    $longNameDirectory=Join-Path $longNameRoot ('Nex_'+[guid]::NewGuid().ToString('N').Substring(0,8))
    $longNameOutput=Join-Path $longNameDirectory (('x'*209)+'.xlsx')
    if(-not $nativeExcel -or $longNameOutput.Length -lt 260){
        try{
            $longNameLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $exportScript `
                -InputReportFolder $excelSource -OutputPath $longNameOutput -Dataset NTFS_FindingsSummary.csv 2>&1 })
            if($nativeExcel){
                Assert ($LASTEXITCODE -eq 2 -and -not [IO.Directory]::Exists($longNameDirectory)) 'Filesystem-valid 214-character leaf is rejected before directory creation when its Windows full path exceeds Excel limits'
                Assert (($longNameLog -join "`n") -match '218-character full-path limit.*shorter') 'Long Windows output path reports actionable Excel compatibility guidance'
                $longNameOutput=Join-Path $longNameDirectory (('x'*(218-$longNameDirectory.Length-6))+'.xlsx')
                $boundaryLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $exportScript `
                    -InputReportFolder $excelSource -OutputPath $longNameOutput -Dataset NTFS_FindingsSummary.csv 2>&1 })
                Assert ($longNameOutput.Length -eq 218 -and $LASTEXITCODE -eq 0 -and [IO.File]::Exists($longNameOutput)) "Windows output at Excel's exact 218-character path boundary succeeds: $($boundaryLog -join "`n")"
            }else{
                Assert ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($longNameOutput)) "Offline 214-character workbook leaf exports using a short independent pending name: $($longNameLog -join "`n")"
            }
        }finally{
            if([IO.Directory]::Exists($longNameDirectory)){Remove-Item -LiteralPath $longNameDirectory -Recurse -Force -ErrorAction Stop}
        }
    }else{
        Write-Information 'Long-leaf regression requires a short temporary root to stay within Windows PowerShell 5.1 MAX_PATH.' -InformationAction Continue
    }

    $longFailureDirectory=Join-Path $testRoot 'excel-cell-limit-failure'
    $longOutput=Join-Path $longFailureDirectory 'review.xlsx'
    $longLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
        -InputReportFolder $excelSource -OutputPath $longOutput -Dataset TooLong.csv 2>&1 })
    Assert ($LASTEXITCODE -eq 2 -and -not(Test-Path -LiteralPath $longOutput -PathType Leaf)) 'Excel cell-limit failure does not publish a partial workbook'
    Assert (($longLog -join "`n") -match '32,767-character') 'Excel cell-limit failure identifies the unsupported value'
    $longPending=@(Get-ChildItem -LiteralPath $longFailureDirectory -File -Force -Filter '.ntfs-excel-*.pending')
    Assert ($longPending.Count -eq $(if($nativeExcel){0}else{1})) 'Cell-limit failure uses owned-handle deletion on Windows and conservative offline preservation elsewhere'
    $lineFeedCsv=Join-Path $excelSource 'LineFeeds.csv'
    Export-NtfsCsvData @([pscustomobject][ordered]@{Id='excessive';Value=("line`n"*254)}) $lineFeedCsv
    $lineFeedQa=Get-Content -LiteralPath $excelQaPath -Raw|ConvertFrom-Json
    $lineFeedQa.Datasets=@(Get-NtfsDatasetInventory $excelSource)
    $lineFeedQa|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $excelQaPath -Encoding UTF8
    $lineFeedOutput=Join-Path $testRoot 'excel-line-feed-limit.xlsx'
    $lineFeedLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $exportScript `
        -InputReportFolder $excelSource -OutputPath $lineFeedOutput -Dataset LineFeeds.csv 2>&1 })
    Assert ($LASTEXITCODE -eq 2 -and -not [IO.File]::Exists($lineFeedOutput)) 'More than 253 line feeds below the text-length limit cannot publish a workbook'
    Assert (($lineFeedLog -join "`n") -match "Cell B2 exceeds Excel's 253-line-feed limit") 'Excessive line-feed failure identifies the precise source cell and limit'

    $adsOutput=Join-Path $testRoot 'excel:stream.xlsx'
    $adsLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
        -InputReportFolder $excelSource -OutputPath $adsOutput -Dataset ExcelParts.csv 2>&1 })
    Assert ($LASTEXITCODE -eq 2 -and -not(Test-Path -LiteralPath $adsOutput -PathType Leaf)) 'Alternate data stream output names are refused'
    Assert (($adsLog -join "`n") -match 'alternate-data-stream') 'Alternate data stream failure explains the unsafe leaf name'
    if($nativeExcel){
        $bracketDirectory=Join-Path $testRoot '[excel-output]'
        $bracketOutput=Join-Path $bracketDirectory 'review.xlsx'
        $bracketLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $exportScript `
            -InputReportFolder $excelSource -OutputPath $bracketOutput -Dataset ExcelParts.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 2 -and -not [IO.Directory]::Exists($bracketDirectory)) 'Windows output paths with square brackets fail before creating output directories'
        Assert (($bracketLog -join "`n") -match 'cannot contain square brackets.*Excel for Windows') 'Bracket rejection explains Excel path compatibility'
    }

    $apostropheExcel=Join-Path $testRoot 'excel-apostrophe.xlsx'
    $apostropheLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
        -InputReportFolder $excelSource -OutputPath $apostropheExcel -Dataset "'Odd.csv" 2>&1 })
    Assert ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $apostropheExcel -PathType Leaf)) "Apostrophe-bound dataset name exports safely: $($apostropheLog -join "`n")"
    $apostropheStream=[IO.File]::Open($apostropheExcel,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $apostropheArchive=$null
    try{
        $apostropheArchive=[IO.Compression.ZipArchive]::new($apostropheStream,[IO.Compression.ZipArchiveMode]::Read,$false)
        $apostropheWorkbook=[xml](Read-ZipEntryText $apostropheArchive 'xl/workbook.xml')
        $apostropheNames=@($apostropheWorkbook.workbook.sheets.sheet|ForEach-Object{$_.name})
        Assert ($apostropheNames -contains 'Odd' -and $apostropheNames -notcontains "'Odd") 'Apostrophe-bound dataset name becomes a legal worksheet name'
    }finally{
        if($null -ne $apostropheArchive){$apostropheArchive.Dispose()}
        $apostropheStream.Dispose()
    }

    $excelInputLink=Join-Path $testRoot 'excel-report-link'
    $linkCreated=$false
    try{
        [void](New-Item -ItemType SymbolicLink -Path $excelInputLink -Target $excelSource -ErrorAction Stop)
        $linkCreated=$true
    }catch{
        try{
            [void](New-Item -ItemType Junction -Path $excelInputLink -Target $excelSource -ErrorAction Stop)
            $linkCreated=$true
        }catch{}
    }
    if($linkCreated){
        $linkedOutput=Join-Path $excelSource 'excel-linked-input.xlsx'
        $linkedLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
            -InputReportFolder $excelInputLink -OutputPath $linkedOutput -Dataset ExcelParts.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 2 -and -not(Test-Path -LiteralPath $linkedOutput -PathType Leaf)) 'A linked input report cannot bypass source containment'
        Assert (($linkedLog -join "`n") -match 'reparse point') 'Linked input failure identifies the reparse point'
    }

    $outputLink=Join-Path $testRoot 'excel-output-link'
    try{
        [void](New-Item -ItemType SymbolicLink -Path $outputLink -Target $excelSource -ErrorAction Stop)
        $outputLinkCreated=$true
    }catch{
        try{
            [void](New-Item -ItemType Junction -Path $outputLink -Target $excelSource -ErrorAction Stop)
            $outputLinkCreated=$true
        }catch{$outputLinkCreated=$false}
    }
    if($outputLinkCreated){
        $aliasedOutput=Join-Path $outputLink 'excel-aliased-output.xlsx'
        $aliasedLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
            -InputReportFolder $excelSource -OutputPath $aliasedOutput -Dataset ExcelParts.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 2 -and -not(Test-Path -LiteralPath (Join-Path $excelSource 'excel-aliased-output.xlsx') -PathType Leaf)) 'An aliased output directory cannot bypass source containment'
        Assert (($aliasedLog -join "`n") -match 'reparse point|aliased') 'Aliased output failure identifies the namespace mismatch'
    }

    $metadataLinkedReport=Join-Path $testRoot 'excel-metadata-link-report'
    [void](New-Item -ItemType Directory -Path $metadataLinkedReport)
    Copy-Item -LiteralPath @(Get-ChildItem -LiteralPath $excelSource -Force|ForEach-Object FullName) -Destination $metadataLinkedReport -Recurse
    $metadataQaLink=Join-Path $metadataLinkedReport 'NTFS_QA.json'
    Remove-Item -LiteralPath $metadataQaLink -Force -ErrorAction Stop
    $disposableQa=Join-Path $outsideSource 'metadata-copy.json'
    Copy-Item -LiteralPath $excelQaPath -Destination $disposableQa
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
        [void](New-Item -ItemType HardLink -Path $metadataQaLink -Target $disposableQa -ErrorAction Stop)
        $metadataLinkCreated=$true
    }else{
        $metadataLinkCreated=New-NtfsTestFileLink $metadataQaLink $disposableQa
    }
    if($metadataLinkCreated){
        $metadataOutput=Join-Path $testRoot 'excel-linked-metadata.xlsx'
        $metadataLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
            -InputReportFolder $metadataLinkedReport -OutputPath $metadataOutput -Dataset ExcelParts.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 2 -and -not(Test-Path -LiteralPath $metadataOutput -PathType Leaf)) 'Linked JSON metadata is refused before workbook publication'
        Assert (($metadataLog -join "`n") -match 'Reparse-point|Hard-linked') 'Linked JSON failure identifies the unsafe leaf file'
    }
    $originalQa=[NtfsAssessment.ExcelReviewPinnedFile]::Open($excelQaPath)
    try{
        Assert ($originalQa.Length -gt 0) 'Linked metadata fixture leaves the original QA file independently readable'
    }finally{$originalQa.Dispose()}

    $linkedCsv=Join-Path $excelSource 'Linked.csv'
    Remove-Item -LiteralPath $linkedCsv -Force -ErrorAction Stop
    $csvLinkCreated=New-NtfsTestFileLink $linkedCsv (Join-Path $outsideSource 'Linked.csv')
    if($csvLinkCreated){
        $linkedCsvOutput=Join-Path $testRoot 'excel-linked-csv.xlsx'
        $linkedCsvLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
            -InputReportFolder $excelSource -OutputPath $linkedCsvOutput -Dataset Linked.csv 2>&1 })
        Assert ($LASTEXITCODE -eq 2 -and -not(Test-Path -LiteralPath $linkedCsvOutput -PathType Leaf)) 'QA-matching linked CSV data is refused'
        Assert (($linkedCsvLog -join "`n") -match 'Reparse-point|Hard-linked|Linked source CSV') 'Linked CSV failure identifies the unsafe leaf file'
    }

    $tamperPath=$excelPartFiles[0].FullName
    $beforeTamperLength=(Get-Item -LiteralPath $tamperPath).Length
    $tamperText=[IO.File]::ReadAllText($tamperPath)
    Assert ($tamperText.Contains('=HYPERLINK')) 'Tamper fixture contains the expected same-length marker'
    [IO.File]::WriteAllText($tamperPath,$tamperText.Replace('=HYPERLINK','=HYPERLJNK'),[Text.UTF8Encoding]::new($true))
    Assert ((Get-Item -LiteralPath $tamperPath).Length -eq $beforeTamperLength) 'Tamper fixture preserves CSV byte length'
    $tamperDirectory=Join-Path $testRoot 'excel-hash-failure'
    $tamperOutput=Join-Path $tamperDirectory 'review.xlsx'
    $tamperLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsExcelReview.ps1') `
        -InputReportFolder $excelSource -OutputPath $tamperOutput -Dataset ExcelParts.csv 2>&1 })
    Assert ($LASTEXITCODE -eq 2 -and -not(Test-Path -LiteralPath $tamperOutput -PathType Leaf)) 'QA hash or size mismatch blocks workbook publication'
    $tamperPending=@(Get-ChildItem -LiteralPath $tamperDirectory -File -Force -Filter '.ntfs-excel-*.pending')
    Assert ($tamperPending.Count -eq $(if($nativeExcel){0}else{1})) 'Hash failure cleans only owned Windows output and preserves offline pending evidence'
    Assert (($tamperLog -join "`n") -match 'hash mismatch') 'Excel tamper failure is detected from the exact parsed stream'
    $script:TestArea='Merger'

    $manifest=Get-Content -LiteralPath (Join-Path $emptyRun 'manifest.json') -Raw|ConvertFrom-Json
    $manifest.FatalError='Synthetic failure';$manifest|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $emptyRun 'manifest.json')
    [void](Invoke-Merge $historyRoot 'fatal-out' 1 'LatestSuccessful' 2)

    $tampered=New-Run 'tampered/run' 'tampered' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'tamper' 'Everyone' 'Read')) @((New-Folder 'data'))
    Add-Content -LiteralPath (Join-Path $tampered 'NtfsAcls.csv') -Value 'bad'
    [void](Invoke-Merge (Split-Path $tampered -Parent) 'tampered-out' 1 'LatestSuccessful' 2)
    $missing=New-Run 'missing/run' 'missing' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'missing' 'Everyone' 'Read')) @((New-Folder 'data'))
    Remove-Item -LiteralPath (Join-Path $missing 'NtfsAcls.csv')
    [void](Invoke-Merge (Split-Path $missing -Parent) 'missing-out' 1 'LatestSuccessful' 2)
    $filtered=Invoke-Merge $inputRoot 'filter-out' 1 'LatestSuccessful' 0 @('-ShareFilter','data.one')
    Assert (@(Rows $filtered 'NTFS_AllAces.csv').Count -eq 1 -and @(Rows $filtered 'NTFS_Shares.csv').Count -eq 1) 'ShareFilter consistently scopes raw and analytical reports'
    $workerFailure=New-Run 'worker-failure/run' 'worker-failure' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'invalidmask' 'Everyone' '4294967296')) @((New-Folder 'data'))
    [void](Invoke-Merge (Split-Path $workerFailure -Parent) 'worker-failure-out' 2 'LatestSuccessful' 2)
    $legacy=New-Run 'legacy/run' 'legacy' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'legacy' 'Everyone' 'Read')) @((New-Folder 'data'))
    $manifest=Get-Content -LiteralPath (Join-Path $legacy 'manifest.json') -Raw|ConvertFrom-Json
    $manifest.PSObject.Properties.Remove('Scopes');$manifest.PSObject.Properties.Remove('Datasets')
    $manifest.SchemaVersion='1.2';$manifest.ToolkitVersion='1.6.0'
    $manifest|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $legacy 'manifest.json')
    [void](Invoke-Merge (Split-Path $legacy -Parent) 'legacy-out' 1 'LatestSuccessful' 1)
    $noInventory=New-Run 'no-inventory/run' 'no-inventory' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'unverified' 'Everyone' 'Read')) @((New-Folder 'data'))
    $manifest=Get-Content -LiteralPath (Join-Path $noInventory 'manifest.json') -Raw|ConvertFrom-Json
    $manifest.PSObject.Properties.Remove('Datasets')
    $manifest|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $noInventory 'manifest.json')
    [void](Invoke-Merge (Split-Path $noInventory -Parent) 'no-inventory-out' 1 'LatestSuccessful' 2)
    $splitAces=@(1..9|ForEach-Object{New-Ace 'data' '' "split$_" 'Everyone' 'Read'})
    $splitRun=New-Run 'split/run' 'split' '2026-10-29T12:00:00Z' $splitAces @((New-Folder 'data'))
    Remove-Item -LiteralPath (Join-Path $splitRun 'NtfsAcls.csv')
    Export-NtfsCsvData $splitAces (Join-Path $splitRun 'NtfsAcls.csv') 1000
    Write-RunManifest $splitRun 'split' '2026-10-29T12:00:00Z' @([pscustomobject]@{Server='server';Share='data';ScanRoot='\\server\data'}) 'CompleteDirectoriesOnly' 9 1
    $splitOut=Invoke-Merge (Split-Path $splitRun -Parent) 'split-out'
    Assert (@(Rows $splitOut 'NTFS_AllAces.csv').Count -eq 9) 'All input CSV parts consumed'
    Remove-Item -LiteralPath (Join-Path $splitRun 'NtfsAcls_2.csv')
    [void](Invoke-Merge (Split-Path $splitRun -Parent) 'split-missing-out' 1 'LatestSuccessful' 2)
    $conflictAces=@((New-Ace 'data' '' 'conflict' 'Everyone' 'Read'))
    $conflictFolders=@((New-Folder 'data'))
    $conflictFolders[0].DescriptorHash='different'
    $conflictRun=New-Run 'conflict/run' 'conflict' '2026-10-29T12:00:00Z' $conflictAces $conflictFolders
    [void](Invoke-Merge (Split-Path $conflictRun -Parent) 'conflict-out' 2 'LatestSuccessful' 2)
    $script:TestArea='Collector end-to-end'
    $completeOutput=Join-Path $testRoot "complete collector O'Brien"
    $completeLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $completeOutput -LocalScan 2>&1 })
    $completeCode=$LASTEXITCODE
    Assert ($completeCode -eq 0) "Complete local collector succeeds: $($completeLog -join "`n")"
    $completeRun=@(Get-ChildItem -LiteralPath $completeOutput -Directory)[0].FullName
    $completeConsole=$completeLog -join "`n"
    $escapedRun=$completeRun.Replace("'","''")
    Assert ($completeConsole.Contains('Assessment: Completed.') -and $completeConsole.Contains("-RunSelection 'Explicit'") -and $completeConsole.Contains("-RunFolder '$($escapedRun)'")) 'Complete assessment gives a correctly quoted command selecting the actual snapshot'
    Assert ($completeConsole.Contains("Output: $($completeRun)") -and $completeConsole.Contains((Join-Path $completeRun 'ShareCoverage.csv'))) 'Complete assessment shows its actual output and coverage paths'
    Assert (-not $completeConsole.Contains('Resolve/review:')) 'Complete assessment does not ask to resolve zero issues'
    $mockOutput=Join-Path $testRoot 'mocked-collector'
    $mockLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $mockOutput 2>&1 })
    $code=$LASTEXITCODE
    $mockLog|Set-Content -LiteralPath (Join-Path $testRoot 'mocked-collector.log')
    Assert ($code -eq 1) "Full mocked collector exits with partial coverage: $code : $($mockLog -join "`n")"
    Assert (($mockLog -join "`n").Contains('Assessment: CompletedWithWarnings.') -and ($mockLog -join "`n").Contains('Resolve collection gaps') -and ($mockLog -join "`n").Contains("-RunSelection 'Explicit'")) 'Partial assessment still offers supported offline merging while requiring gaps to be resolved before claiming completeness'
    $mockRun=@(Get-ChildItem -LiteralPath $mockOutput -Directory)[0].FullName
    $mockManifest=Get-Content -LiteralPath (Join-Path $mockRun 'manifest.json') -Raw|ConvertFrom-Json
    $mockConsole=($mockLog -join "`n") -replace '\s+',' '
    foreach($category in @(
        @{Count=$mockManifest.Counts.Errors;Label='collection error records'},
        @{Count=$mockManifest.Counts.SkippedPaths;Label='skipped-path records'}
    )){
        Assert ($mockConsole.Contains("$($category.Count) $($category.Label)") -eq ($category.Count -gt 0)) "Assessment guidance includes only positive $($category.Label) counts"
    }
    Assert ($mockConsole.Contains('- (') -and $mockConsole -notmatch '\b0 incomplete group expansions\b') 'Assessment reports recorded reasons without zero-count group-expansion actions'
    Assert ($mockManifest.ToolkitVersion -eq $script:NtfsVersions.Assessment) 'Collector manifest uses registered version'
    Assert-VersionLog (Join-Path $mockRun 'run.log') Assessment
    Assert ($mockManifest.Counts.NtfsAces -eq 1 -and $mockManifest.Counts.Folders -eq 1) 'Full collector finalization retains rows/counts'
    Assert ($mockManifest.CoverageStatus -eq 'Partial') 'Full collector never marks depth-limited scan complete'
    Assert (@(Rows $mockRun 'Identities.csv')[0].PSObject.Properties.Name -contains 'ObjectClass') 'Collector exports fixed identity schema'
    Assert (@(Rows $mockRun 'NtfsAcls.csv')[0].PropagationFlags -eq 'InheritOnly') 'Collector preserves inheritance flags'
    Assert (@(Get-ChildItem -LiteralPath (Join-Path $mockRun 'PerShare') -File).Count -eq 2) 'Collector split-by-share copies created'
    [void](Invoke-Merge $mockOutput 'mocked-collector-merge-out' 2 'LatestSuccessful' 1)
    $failedOutput=Join-Path $testRoot 'failed-collector'
    $failureLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $failedOutput -FailChecksum 2>&1 })
    $failureCode=$LASTEXITCODE
    Assert ($failureCode -eq 2) "Checksum finalization failure exits 2: $($failureLog -join "`n")"
    Assert (($failureLog -join "`n").Contains('Assessment: Failed.') -and ($failureLog -join "`n").Contains('Do not merge or compare') -and -not ($failureLog -join "`n").Contains("-RunSelection 'Explicit'")) 'Failed assessment points to diagnostics without recommending a downstream command'
    Assert (@(Get-ChildItem -LiteralPath $failedOutput -Recurse -File -Filter 'manifest.json').Count -eq 0) 'Checksum failure never publishes a selectable manifest'

    $script:TestArea='Comparison'
    # Snapshot comparison uses semantic evidence, not changing run IDs/hashes/ordinals.
    $compareRoot=Join-Path $testRoot 'compare'
    $oldAces=@(
        (New-Ace 'data' '' 'root-old' 'Everyone' 'Read')
        (New-Ace 'data' '\same' 'same-old' 'TEST\User' '262144')
        (New-Ace 'data' '\rights' 'rights-old' 'Everyone' 'Modify')
        (New-Ace 'data' '\flags' 'flags-old' 'Everyone' 'Write')
        (New-Ace 'data' '\deny' 'deny-old' 'Everyone' 'Read' 'Deny')
        (New-Ace 'data' '\duplicate' 'dup-old-0' 'Everyone' 'Read')
        (New-Ace 'data' '\duplicate' 'dup-old-1' 'Everyone' 'Read')
        (New-Ace 'data.one' '' 'collision-old-1' 'Everyone' 'Read')
        (New-Ace 'data$one' '' 'collision-old-2' 'Everyone' 'Read')
        (New-Ace 'data' '\quoted' 'quoted-old' "TEST\Quoted,`"name`r`nsecond" 'Read')
    )
    $newAces=@(
        (New-Ace 'data' '' 'root-new' 'Everyone' 'Read')
        (New-Ace 'data' '\same' 'same-new' 'TEST\RenamedUser' 'ChangePermissions')
        (New-Ace 'data' '\rights' 'rights-new' 'Everyone' 'Read')
        (New-Ace 'data' '\flags' 'flags-new' 'Everyone' 'Write' 'Allow' 'False' 'InheritOnly')
        (New-Ace 'data' '\duplicate' 'dup-new' 'Everyone' 'Read')
        (New-Ace 'data.one' '' 'collision-new-1' 'Everyone' 'Read')
        (New-Ace 'data$one' '' 'collision-new-2' 'Everyone' 'Modify')
        (New-Ace 'data' '\quoted' 'quoted-new' "TEST\Quoted,`"name`r`nsecond" 'Write')
    )
    Set-FixtureOrdinals $oldAces;Set-FixtureOrdinals $newAces
    $oldFolders=@('','\same','\rights','\flags','\deny','\duplicate','\removed','\owner','\quoted'|ForEach-Object{New-Folder 'data' $_})+@((New-Folder 'data.one'),(New-Folder 'data$one'))
    $newFolders=@('','\same','\rights','\flags','\deny','\duplicate','\added','\owner','\quoted'|ForEach-Object{New-Folder 'data' $_})+@((New-Folder 'data.one'),(New-Folder 'data$one'))
    foreach($f in $oldFolders){$f|Add-Member -NotePropertyName Owner -NotePropertyValue 'TEST\Owner' -Force}
    foreach($f in $newFolders){$f|Add-Member -NotePropertyName Owner -NotePropertyValue 'TEST\Owner' -Force}
    $ownerFolder=@($newFolders|Where-Object Path -eq '\\server\data\owner')[0]
    $ownerFolder.Owner='TEST\NewOwner';$ownerFolder.InheritanceProtected='False';$ownerFolder.SDDL='D:P'
    $oldRun=New-Run 'compare/old' 'compare-old' '2026-10-28T12:00:00Z' $oldAces $oldFolders
    $newRun=New-Run 'compare/new' 'compare-new' '2026-10-29T12:00:00Z' $newAces $newFolders
    [void](New-Run 'compare/oldest' 'compare-oldest' '2026-10-27T12:00:00Z' @((New-Ace 'data' '' 'oldest' 'Everyone' 'FullControl')) @((New-Folder 'data')))
    $newShareAces=@(Rows $newRun 'SharePermissions.csv')
    foreach($a in $newShareAces){if($a.Share -eq 'data'){$a.AccessRight='Read'}}
    Write-FixtureDataset $newRun 'SharePermissions.csv' $newShareAces
    $compareOut=Invoke-Comparison 'compare-latest-out' 0 @('-InputRoot',$compareRoot)
    $deltas=@(Rows $compareOut 'NTFS_Changes.csv')
    $selection=@(Rows $compareOut 'NTFS_ComparisonRuns.csv')
    Assert ($selection[0].RunId -eq 'compare-old' -and $selection[1].RunId -eq 'compare-new') 'Default comparison selects last two manifest completion times'
    Assert ([datetimeoffset]$selection[0].CompletedUtc -eq [datetimeoffset]'2026-10-28T12:00:00Z') 'Completion time preserves its original UTC instant'
    Assert (@($deltas|Where-Object{ $_.EntityType -eq 'NTFSACE' -and $_.Path -eq '\\server\data\same' }).Count -eq 0) 'SID stability and exact numeric/named rights prevent rename-only permission changes'
    Assert (@($deltas|Where-Object{ $_.EntityType -eq 'NTFSACE' -and $_.Path -eq '\\server\data\rights' }).Count -eq 2) 'Permission replacement reported as exact ACE removal plus addition'
    Assert (@($deltas|Where-Object{ $_.EntityType -eq 'NTFSACE' -and $_.Path -eq '\\server\data\flags' }).Count -eq 2) 'Propagation-only ACE changes are visible'
    $duplicateDelta=@($deltas|Where-Object Path -eq '\\server\data\duplicate')
    Assert ($duplicateDelta.Count -eq 1 -and $duplicateDelta[0].BeforeCount -eq '2' -and $duplicateDelta[0].AfterCount -eq '1') 'ACE multiset retains duplicate occurrence changes'
    Assert (@($deltas|Where-Object{ $_.Path -eq '\\server\data\deny' -and $_.ChangeType -eq 'Removed' }).Count -eq 1) 'Deny removal is reported without treating it as a grant'
    Assert (@($deltas|Where-Object{ $_.Path -eq '\\server\data\removed' -and $_.EntityType -eq 'Folder' -and $_.ChangeType -eq 'Removed' }).Count -eq 1) 'Missing folder is a confirmed inventory removal only with complete matched scopes'
    Assert (@($deltas|Where-Object{ $_.Path -eq '\\server\data\added' -and $_.ChangeType -eq 'Added' }).Count -eq 1) 'New folder appears in complete inventory'
    $ownerDelta=@($deltas|Where-Object Path -eq '\\server\data\owner')[0]
    Assert ($ownerDelta.ChangedFields -eq 'Owner;InheritanceProtected;SDDL') 'Owner/protection/descriptor changes retain before and after fields'
    Assert (@($deltas|Where-Object{ $_.Share -eq 'data.one' -and $_.EntityType -eq 'NTFSACE' }).Count -eq 0 -and @($deltas|Where-Object{ $_.Share -eq 'data$one' -and $_.EntityType -eq 'NTFSACE' }).Count -eq 2) 'Comparison share spools avoid punctuation collisions'
    Assert (@($deltas|Where-Object{ $_.Identity -eq "TEST\Quoted,`"name`r`nsecond" }).Count -eq 2) 'Multiline/quoted identities survive delta CSV and embedded JSON'
    Assert (@($deltas|Where-Object EntityType -eq 'SharePermission').Count -eq 2) 'Collected SMB allow/deny changes are compared'
    $explicitOut=Invoke-Comparison 'compare-explicit-out' 0 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$newRun)
    Assert (@(Rows $explicitOut 'NTFS_Changes.csv').Count -eq $deltas.Count) 'Explicit folder pair matches default result'
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
        $longOut=Invoke-Comparison ('compare-long-'+('x'*70)) 0 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$newRun)
        Assert (@(Rows $longOut 'NTFS_Changes.csv').Count -eq $deltas.Count) 'Long comparison staging paths preserve all differences'
        Assert (@(Get-ChildItem -LiteralPath $longOut -Directory -Filter '_temp_*').Count -eq 0) 'Long comparison staging paths are cleaned up'
    }
    $reverseOut=Invoke-Comparison 'compare-reverse-out' 0 @('-OldRunFolder',$newRun,'-NewRunFolder',$oldRun)
    Assert (@(Rows $reverseOut 'NTFS_Changes.csv'|Where-Object{ $_.Path -eq '\\server\data\added' -and $_.ChangeType -eq 'Removed' }).Count -eq 1) 'Explicit direction is respected, including reverse comparison'
    $sameRun=New-Run 'compare-identical/run' 'identical' '2026-10-30T12:00:00Z' $oldAces $oldFolders
    $identicalOut=Invoke-Comparison 'compare-identical-out' 0 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$sameRun)
    Assert (@(Rows $identicalOut 'NTFS_Changes.csv').Count -eq 0) 'Run/time-only changes yield zero differences'
    [void](Invoke-Comparison 'compare-guard-out' 2 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$newRun,'-MaxRowsPerShare','1'))
    $partialAces=@((New-Ace 'data' '' 'partial' 'Everyone' 'Read'))
    $partial=New-Run 'compare-partial/run' 'compare-partial' '2026-10-30T12:00:00Z' $partialAces @((New-Folder 'data')) 'PartialDirectoriesOnly'
    $partialOut=Invoke-Comparison 'compare-partial-out' 1 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$partial)
    Assert (@(Rows $partialOut 'NTFS_Changes.csv'|Where-Object{ $_.Path -eq '\\server\data\removed' -and $_.ChangeType -eq 'Removed' }).Count -eq 0) 'Partial scan never confirms missing-folder removal'
    Assert (@(Rows $partialOut 'NTFS_Changes.csv'|Where-Object{ $_.Path -eq '\\server\data\removed' -and $_.ChangeType -eq 'ObservedOnlyBefore' }).Count -ge 1) 'Missing records under partial coverage are observed-only'
    $failedRead=New-Run 'compare-read-failure/run' 'compare-read-failure' '2026-10-30T12:00:00Z' @() @((New-Folder 'data'))
    Write-FixtureDataset $failedRead 'ScanErrors.csv' @([pscustomobject]@{RunId='compare-read-failure';Stage='ReadAccessRules';Path='\\server\data'})
    $readFailureOut=Invoke-Comparison 'compare-read-failure-out' 1 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$failedRead)
    Assert (@(Rows $readFailureOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'NTFSACE' -and $_.Path -eq '\\server\data' }).Count -eq 0) 'Failure after folder/partial ACE export never implies an ACE removal'
    Assert (@(Rows $readFailureOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'Folder' -and $_.ChangeType -eq 'NotCompared' -and $_.Path -eq '\\server\data' }).Count -eq 1) 'Failed ACL reads have explicit comparison status'
    $subFolder=New-Folder 'data' '\subtree';$subFolder.ScanRoot='\\server\data\subtree'
    $subRun=New-Run 'compare-subtree/run' 'compare-subtree' '2026-10-30T12:00:00Z' @() @($subFolder)
    $subOut=Invoke-Comparison 'compare-subtree-out' 1 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$subRun)
    Assert (@(Rows $subOut 'NTFS_Changes.csv'|Where-Object EntityType -eq 'NTFSACE').Count -eq 0) 'Different scan roots are not fabricated ACL removals'
    Assert (@(Rows $subOut 'NTFS_ComparisonCoverage.csv'|Where-Object Status -eq 'NotCompared').Count -eq 3) 'Different/absent shares explicitly marked NotCompared'
    $unknownShare=New-Run 'compare-share-unknown/run' 'compare-share-unknown' '2026-10-30T12:00:00Z' @((New-Ace 'data' '' 'share-unknown' 'Everyone' 'Read')) @((New-Folder 'data'))
    $rows=@(Rows $unknownShare 'Shares.csv');$rows[0].ShareMetadataStatus='NotCollected_NAS'
    Write-FixtureDataset $unknownShare 'Shares.csv' $rows
    Write-FixtureDataset $unknownShare 'SharePermissions.csv' @()
    $unknownOut=Invoke-Comparison 'compare-share-unknown-out' 1 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$unknownShare)
    Assert (@(Rows $unknownOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'SharePermission' -and $_.ChangeType -eq 'Removed' }).Count -eq 0) 'Uncollected share permissions never mean revoked access'
    [void](Invoke-Comparison 'compare-tampered-out' 2 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$tampered))
    [void](Invoke-Comparison 'compare-missing-out' 2 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$missing))
    [void](Invoke-Comparison 'compare-same-folder-out' 2 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$oldRun))
    [void](Invoke-Comparison 'compare-fatal-latest-out' 2 @('-InputRoot',$historyRoot))
    [void](New-Item -ItemType Directory -Path (Join-Path $compareRoot 'ASSESS_unfinished'))
    [void](Invoke-Comparison 'compare-unfinished-out' 2 @('-InputRoot',$compareRoot))
    [void](Invoke-Comparison 'compare-explicit-unfinished-out' 0 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$newRun))
    $reordered=@($oldAces);[array]::Reverse($reordered);Set-FixtureOrdinals $reordered
    foreach($a in $reordered){$a.AceHash='recomputed-'+$a.AceHash}
    $reorderedRun=New-Run 'compare-order/run' 'reordered' '2026-10-30T12:00:00Z' $reordered $oldFolders
    $reorderedOut=Invoke-Comparison 'compare-order-out' 0 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$reorderedRun)
    Assert (@(Rows $reorderedOut 'NTFS_Changes.csv').Count -eq 0) 'Row ordering, ordinal reassignment and recomputed ACE hashes are not ACL changes'
    $signed=New-Run 'compare-mask/old' 'signed' '2026-10-30T12:00:00Z' @((New-Ace 'data' '' 'signed' 'Everyone' '-2147483648')) @((New-Folder 'data'))
    $unsigned=New-Run 'compare-mask/new' 'unsigned' '2026-10-31T12:00:00Z' @((New-Ace 'data' '' 'unsigned' 'Everyone' '2147483648')) @((New-Folder 'data'))
    $maskOut=Invoke-Comparison 'compare-mask-out' 0 @('-BaselineRunFolder',$signed,'-ComparisonRunFolder',$unsigned)
    Assert (@(Rows $maskOut 'NTFS_Changes.csv').Count -eq 0) 'Signed and unsigned representations of the same access mask compare equally'
    $emptyRun=New-Run 'compare-empty/run' 'empty-partial' '2026-10-31T12:00:00Z' @() @((New-Folder 'data')) 'PartialDirectoriesOnly'
    Write-FixtureDataset $emptyRun 'Folders.csv' @()
    $manifestPath=Join-Path $emptyRun 'manifest.json'
    $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json;$m.Counts.Folders=0
    $m|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $emptyOut=Invoke-Comparison 'compare-empty-out' 1 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$emptyRun)
    Assert (@(Rows $emptyOut 'NTFS_Changes.csv'|Where-Object ChangeType -eq 'Removed').Count -eq 0) 'Empty partial snapshot never confirms removals or backfills old permissions'
    $legacyCompare=New-Run 'compare-legacy/run' 'legacy-compare' '2026-10-31T12:00:00Z' $reordered $oldFolders
    $manifestPath=Join-Path $legacyCompare 'manifest.json'
    $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    $m.SchemaVersion='1.2';$m.ToolkitVersion='1.6.3';$m.PSObject.Properties.Remove('Datasets')
    $m|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $legacyOut=Invoke-Comparison 'compare-legacy-out' 1 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$legacyCompare)
    Assert (@(Rows $legacyOut 'NTFS_Changes.csv').Count -eq 0) 'Legacy snapshots compare observed rows without inventing differences'
    $badRows=New-Run 'compare-bad-rows/run' 'bad-rows' '2026-10-31T12:00:00Z' @((New-Ace 'data' '' 'bad-rows' 'Everyone' 'Read')) @((New-Folder 'data'))
    $manifestPath=Join-Path $badRows 'manifest.json'
    $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    @($m.Datasets|Where-Object Name -eq 'NtfsAcls.csv')[0].Rows=2
    $m|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $manifestPath -Encoding UTF8
    [void](Invoke-Comparison 'compare-bad-rows-out' 2 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$badRows))
    $noInventory=New-Run 'compare-no-inventory/run' 'no-inventory' '2026-10-31T12:00:00Z' @() @((New-Folder 'data'))
    $manifestPath=Join-Path $noInventory 'manifest.json'
    $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json;$m.PSObject.Properties.Remove('Datasets')
    $m|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $manifestPath -Encoding UTF8
    [void](Invoke-Comparison 'compare-no-inventory-out' 2 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$noInventory))
    [void](New-Run 'compare-ties/first' 'tie-first' '2026-10-31T12:00:00Z' @() @((New-Folder 'data')))
    [void](New-Run 'compare-ties/second' 'tie-second' '2026-10-31T12:00:00Z' @() @((New-Folder 'data')))
    [void](Invoke-Comparison 'compare-ties-out' 2 @('-InputRoot',(Join-Path $testRoot 'compare-ties')))
    [void](Invoke-Comparison 'compare-single-out' 2 @('-InputRoot',(Split-Path $noInventory)))
    $beforeOutputHash=(Get-FileHash -LiteralPath (Join-Path $compareOut 'NTFS_Changes.csv') -Algorithm SHA256).Hash
    [void](Invoke-Comparison 'compare-latest-out' 2 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$newRun))
    Assert ((Get-FileHash -LiteralPath (Join-Path $compareOut 'NTFS_Changes.csv') -Algorithm SHA256).Hash -eq $beforeOutputHash) 'Existing comparison reports are not overwritten'
    $sidRows=@(Rows $unsigned 'NtfsAcls.csv');$sidRows[0].SID=''
    Write-FixtureDataset $unsigned 'NtfsAcls.csv' $sidRows
    $sidOut=Invoke-Comparison 'compare-sid-unavailable-out' 1 @('-BaselineRunFolder',$signed,'-ComparisonRunFolder',$unsigned)
    Assert (@(Rows $sidOut 'NTFS_Changes.csv'|Where-Object EntityType -eq 'NTFSACE').Count -eq 0) 'SID-resolution availability never fabricates permission replacements'
    Assert (@(Rows $sidOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'NTFSACL' -and $_.ChangeType -eq 'NotCompared' }).Count -eq 1) 'Unstable principal identities are explicitly uncomparable'
    $legacyAces=@(Rows $legacyCompare 'NtfsAcls.csv'|Where-Object Path -ne '\\server\data')
    foreach($part in @(Get-NtfsCsvFiles $legacyCompare 'NtfsAcls.csv')){Remove-Item -LiteralPath $part.FullName}
    Export-NtfsCsvData $legacyAces (Join-Path $legacyCompare 'NtfsAcls.csv')
    $manifestPath=Join-Path $legacyCompare 'manifest.json'
    $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json;$m.Counts.NtfsAces=$legacyAces.Count
    $m|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Remove-Item -LiteralPath (Join-Path $legacyCompare 'ScanErrors.csv')
    $legacyPartialOut=Invoke-Comparison 'compare-legacy-incomplete-out' 1 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$legacyCompare)
    Assert (@(Rows $legacyPartialOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'NTFSACE' -and $_.ChangeType -eq 'Removed' }).Count -eq 0) 'Legacy folder/SDDL presence without error inventory never confirms removed ACEs'
    Assert (@(Rows $legacyPartialOut 'NTFS_Changes.csv'|Where-Object{ $_.Path -eq '\\server\data' -and $_.ChangeType -eq 'ObservedOnlyBefore' }).Count -eq 1) 'Legacy missing ACE remains observed-only even when the folder exists on both sides'
    [void](New-Run 'compare-output-name/old' 'output-old' '2026-10-28T12:00:00Z' @() @((New-Folder 'data')))
    [void](New-Run 'compare-output-name/new' 'output-new' '2026-10-29T12:00:00Z' @() @((New-Folder 'data')))
    [void](New-Item -ItemType Directory -Path (Join-Path $testRoot 'compare-output-name/ASSESS_diff'))
    [void](Invoke-Comparison 'compare-output-name/ASSESS_diff' 0 @('-InputRoot',(Join-Path $testRoot 'compare-output-name')))
    [void](Invoke-Comparison 'compare/old/rejected-output' 2 @('-BaselineRunFolder',$oldRun,'-ComparisonRunFolder',$newRun))
    Assert (-not(Test-Path -LiteralPath (Join-Path $oldRun 'rejected-output'))) 'Rejected output inside a source does not create or alter any source directory'
    $descriptionOld=New-Run 'compare-description/old' 'description-old' '2026-10-28T12:00:00Z' @() @((New-Folder 'data'))
    $descriptionNew=New-Run 'compare-description/new' 'description-new' '2026-10-29T12:00:00Z' @() @((New-Folder 'data'))
    $s=@(Rows $descriptionOld 'Shares.csv');$s[0]|Add-Member -NotePropertyName Description -NotePropertyValue 'Description removed'
    Write-FixtureDataset $descriptionOld 'Shares.csv' $s
    $s=@(Rows $descriptionNew 'Shares.csv');$s[0]|Add-Member -NotePropertyName Description -NotePropertyValue ''
    Write-FixtureDataset $descriptionNew 'Shares.csv' $s
    $descriptionOut=Invoke-Comparison 'compare-description-out' 0 @('-BaselineRunFolder',$descriptionOld,'-ComparisonRunFolder',$descriptionNew)
    Assert (@(Rows $descriptionOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'Share' -and $_.ChangedFields -eq 'Description' }).Count -eq 1) 'Empty share description is a real metadata change, not unavailable data'
    $s=@(Rows $descriptionNew 'Shares.csv');$s[0].ShareMetadataStatus='NotCollected_NAS'
    Write-FixtureDataset $descriptionNew 'Shares.csv' $s
    Write-FixtureDataset $descriptionOld 'SharePermissions.csv' @()
    Write-FixtureDataset $descriptionNew 'SharePermissions.csv' @()
    $shareUnavailableOut=Invoke-Comparison 'compare-empty-share-acl-out' 1 @('-BaselineRunFolder',$descriptionOld,'-ComparisonRunFolder',$descriptionNew)
    Assert ((Get-Content -LiteralPath (Join-Path $shareUnavailableOut 'comparison-state.json') -Raw|ConvertFrom-Json).Limitations.Count -gt 0) 'Both share ACE inventories empty still disclose uncollected share ACLs'
    $s=@(Rows $descriptionNew 'Shares.csv');$conflict=$s[0].PSObject.Copy();$conflict.Description='Conflicting second observation'
    Write-FixtureDataset $descriptionNew 'Shares.csv' @($s[0],$conflict)
    [void](Invoke-Comparison 'compare-share-conflict-out' 2 @('-BaselineRunFolder',$descriptionOld,'-ComparisonRunFolder',$descriptionNew))

    $script:TestArea='Reporting hardening'
    $historyOld=New-Run 'unfinished-history/ASSESS_old' 'unfinished-old' '2026-10-28T12:00:00Z' @((New-Ace 'data' '' 'unfinished' 'Everyone' 'Read')) @((New-Folder 'data'))
    $unfinishedRoot=Split-Path $historyOld -Parent
    [void](New-Item -ItemType Directory -Path (Join-Path $unfinishedRoot 'ASSESS_new_unfinished'))
    foreach($selection in @('LatestSuccessful','AllSuccessful')){
        [void](Invoke-Merge $unfinishedRoot "unfinished-$selection-out" 1 $selection 2)
    }
    $explicitMerge=Invoke-Merge $unfinishedRoot 'unfinished-explicit-out' 1 'Explicit' 0 @('-RunFolder',$historyOld)
    Assert (@(Rows $explicitMerge 'NTFS_AllAces.csv')[0].SourceRunId -eq 'unfinished-old') 'Explicit merger selection can intentionally choose a completed run beside an unfinished run'
    [void](New-Item -ItemType Directory -Path (Join-Path $testRoot 'merge-output-name/ASSESS_diff') -Force)
    [void](New-Run 'merge-output-name/ASSESS_source' 'merge-output-source' '2026-10-29T12:00:00Z' @() @((New-Folder 'data')))
    [void](Invoke-Merge (Join-Path $testRoot 'merge-output-name') 'merge-output-name/ASSESS_diff')
    $inputInventory=@(Get-ChildItem -LiteralPath $historyOld -Recurse -File|ForEach-Object{"$($_.FullName):$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)"})
    [void](Invoke-Merge $unfinishedRoot 'unfinished-history/ASSESS_old/rejected-output' 1 'Explicit' 2 @('-RunFolder',$historyOld))
    Assert (-not(Test-Path -LiteralPath (Join-Path $historyOld 'rejected-output'))) 'Merger rejects source-nested output before creating any files'
    $afterInventory=@(Get-ChildItem -LiteralPath $historyOld -Recurse -File|ForEach-Object{"$($_.FullName):$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)"})
    Assert (($inputInventory -join "`n") -ceq ($afterInventory -join "`n")) 'Merger source separation preserves every input file byte-for-byte'
    [void](Invoke-Merge $historyOld 'unfinished-history/ASSESS_old/rejected-auto-output' 1 'LatestSuccessful' 2)
    Assert (-not(Test-Path -LiteralPath (Join-Path $historyOld 'rejected-auto-output'))) 'Automatic merger selection also rejects source-nested output without creating it'

    $riskFolders=@((New-Folder 'data'),(New-Folder 'data' '\failed'),(New-Folder 'data' '\unknown'))
    foreach($f in $riskFolders){$f.InheritanceProtected='False'}
    $riskFolders[2].CollectionStatus=''
    $riskAces=@((New-Ace 'data' '' 'risk-complete' 'Everyone' 'Modify'),(New-Ace 'data' '\failed' 'risk-partial' 'Everyone' 'Write'))
    $riskRun=New-Run 'risk-incomplete/ASSESS_run' 'risk-incomplete' '2026-10-29T12:00:00Z' $riskAces $riskFolders 'PartialDirectoriesOnly'
    Write-FixtureDataset $riskRun 'ScanErrors.csv' @(
        [pscustomobject]@{RunId='risk-incomplete';Stage='ReadACL';Path='\\?\UNC\server\data\failed'}
        [pscustomobject]@{RunId='risk-incomplete';Stage='ReadACL';Path='\\server\data\never-exported'}
    )
    foreach($throttle in @(1,2)){
        $riskOut=Invoke-Merge (Split-Path $riskRun) "risk-incomplete-out-$throttle" $throttle 'LatestSuccessful' 1
        $risks=@(Rows $riskOut 'NTFS_RiskByFolder.csv')
        $unassessed=@($risks|Where-Object RiskLevel -eq 'NotAssessed')
        Assert ($unassessed.Count -eq 2 -and @($unassessed|Where-Object RiskScore -ne '').Count -eq 0) 'Failed and unknown folder ACLs have blank scores, never reassuring zero risk'
        Assert (@($unassessed|Where-Object AssessmentStatus -ne 'IncompleteOrUnverified').Count -eq 0) 'Unassessed risk rows carry explicit assessment status'
        $shareRisk=@(Rows $riskOut 'NTFS_RiskByShare.csv')[0]
        $assessed=@($risks|Where-Object AssessmentStatus -eq 'Assessed')[0]
        Assert ($shareRisk.AssessedFolders -eq '1' -and $shareRisk.NotAssessedFolders -eq '2') 'Share risk counts distinguish assessed and unassessed folders'
        Assert ([double]$shareRisk.AverageRiskScore -eq [double]$assessed.RiskScore) 'Risk average excludes unassessed folders'
        Assert ($shareRisk.UnreportedAclFailures -eq '1' -and $shareRisk.UnknownDirectoryCoverage -eq 'True') 'Failed paths with no exported folder and unknown subtree coverage remain visible'
        $findings=@(Rows $riskOut 'NTFS_Findings.csv')
        Assert (@($findings|Where-Object{ $_.Path -eq '\\server\data\failed' -and $_.FindingType -eq 'BroadAccessMissingGroups' }).Count -eq 0) 'Partial ACLs never assert absence of purpose-built groups'
        Assert (@($findings|Where-Object{ $_.Path -eq '\\server\data\failed' -and $_.FindingType -eq 'BroadPrincipalWrite' }).Count -eq 1) 'Directly observed positive findings survive incomplete ACL risk suppression'
        $exec=Get-Content -LiteralPath (Join-Path $riskOut 'NTFS_ExecutiveSummary.json') -Raw|ConvertFrom-Json
        Assert ($exec.AssessedFolders -eq 1 -and $exec.NotAssessedFolders -eq 2 -and $exec.UnreportedAclFailures -eq 1) 'Executive summary exposes assessment uncertainty'
    }
    $unreachable=New-Run 'risk-unreachable/ASSESS_run' 'unreachable' '2026-10-29T12:00:00Z' @() @((New-Folder 'data')) 'PartialDirectoriesOnly'
    Write-FixtureDataset $unreachable 'Folders.csv' @()
    Write-FixtureDataset $unreachable 'ScanErrors.csv' @([pscustomobject]@{RunId='unreachable';Stage='ValidateUNC';Path='\\server\data'})
    $manifestPath=Join-Path $unreachable 'manifest.json'
    $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json;$m.Counts.Folders=0
    $m|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $unreachableOut=Invoke-Merge (Split-Path $unreachable) 'unreachable-out' 1 'LatestSuccessful' 1
    $unreachableRisk=@(Rows $unreachableOut 'NTFS_RiskByShare.csv')[0]
    Assert ($unreachableRisk.AverageRiskScore -eq '' -and $unreachableRisk.MaxRiskScore -eq '') 'No assessed folders produces blank average and maximum, not zero'
    Assert ($unreachableRisk.Folders -eq '0' -and $unreachableRisk.UnreportedAclFailures -eq '1') 'Unreachable roots do not invent folder counts'
    $legacyRiskOut=Invoke-Merge (Split-Path $legacy) 'legacy-risk-out' 1 'LatestSuccessful' 1
    Assert (@(Rows $legacyRiskOut 'NTFS_RiskByFolder.csv'|Where-Object RiskLevel -ne 'NotAssessed').Count -eq 0) 'Unverified legacy ACLs cannot receive reassuring risk scores'

    $guardRun=New-Run 'guard/ASSESS_run' 'guard' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'guard-root' 'Everyone' 'Read'),(New-Ace 'data' '\child' 'guard-child' 'Everyone' 'Read')) @((New-Folder 'data'),(New-Folder 'data' '\child'))
    foreach($throttle in @(1,2)){
        $guardOut=Invoke-Merge (Split-Path $guardRun) "guard-boundary-out-$throttle" $throttle 'LatestSuccessful' 0 @('-MaxRowsPerShare','5')
        Assert (@(Rows $guardOut 'NTFS_AllAces.csv').Count -eq 2) 'Combined memory guard accepts exactly its limit across folders, NTFS and share ACEs'
        [void](Invoke-Merge (Split-Path $guardRun) "guard-exceeded-out-$throttle" $throttle 'LatestSuccessful' 2 @('-MaxRowsPerShare','4'))
        $guardState=Get-Content -LiteralPath (Join-Path $testRoot "guard-exceeded-out-$throttle/merge-state.json") -Raw|ConvertFrom-Json
        Assert ($guardState.Error -match 'exceeds MaxRowsPerShare=4') 'Memory guard failures are explicit and actionable'
    }
    $perShareGuard=New-Run 'guard-per-share/ASSESS_run' 'guard-per-share' '2026-10-29T12:00:00Z' @((New-Ace 'one' '' 'guard-one' 'Everyone' 'Read'),(New-Ace 'two' '' 'guard-two' 'Everyone' 'Read')) @((New-Folder 'one'),(New-Folder 'two'))
    [void](Invoke-Merge (Split-Path $perShareGuard) 'guard-per-share-out' 2 'LatestSuccessful' 0 @('-MaxRowsPerShare','3'))
    $shareRows=@(Rows $guardRun 'SharePermissions.csv')
    Write-FixtureDataset $guardRun 'SharePermissions.csv' @($shareRows[0],$shareRows[0],$shareRows[0])
    [void](Invoke-Merge (Split-Path $guardRun) 'guard-share-first-out' 1 'LatestSuccessful' 2 @('-MaxRowsPerShare','2'))

    $duplicateShare=New-Run 'share-duplicates/ASSESS_run' 'share-duplicates' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'duplicate-share' 'Everyone' 'Read')) @((New-Folder 'data'))
    $shareRows=@(Rows $duplicateShare 'SharePermissions.csv')
    Write-FixtureDataset $duplicateShare 'SharePermissions.csv' @($shareRows[0],$shareRows[0])
    $duplicateShareOut=Invoke-Comparison 'share-duplicates-out' 0 @('-BaselineRunFolder',$historyOld,'-ComparisonRunFolder',$duplicateShare)
    Assert (@(Rows $duplicateShareOut 'NTFS_Changes.csv'|Where-Object EntityType -eq 'SharePermission').Count -eq 0) 'Historical repeated share ACE observations never fabricate new permissions'
    Import-Functions (Join-Path $root 'Invoke-NtfsAssessment.ps1') @('Get-UniqueSharePermissions','Get-AclPropertySafe')
    $shareOne=[pscustomobject]@{Server='server';Share='one';AccountName='TEST\User';AccessControlType='Allow';AccessRight='Full';Source='WindowsSmbShare';Vserver=''}
    $shareTwo=$shareOne.PSObject.Copy();$shareTwo.Share='two'
    $shareDeny=$shareOne.PSObject.Copy();$shareDeny.AccessControlType='Deny'
    $shareAlias=$shareOne.PSObject.Copy();$shareAlias.AccessRight='FULL_CONTROL';$shareAlias.Server='SERVER'
    $shareSvm=$shareOne.PSObject.Copy();$shareSvm.Vserver='other-svm'
    $uniqueShareRows=@(Get-UniqueSharePermissions @($shareOne,$shareTwo,$shareDeny,$shareAlias,$shareSvm))
    Assert ($uniqueShareRows.Count -eq 4) 'Share deduplication retains distinct shares, SVMs and deny rules while normalizing repeated evidence'
    $duplicateOutput=Join-Path $testRoot 'duplicate-collector'
    $duplicateLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $duplicateOutput -DuplicateScopes 2>&1 })
    Assert ($LASTEXITCODE -eq 1) "Duplicate-scope collector stays offline and reports depth limitations: $($duplicateLog -join "`n")"
    $duplicateRun=@(Get-ChildItem -LiteralPath $duplicateOutput -Directory)[0].FullName
    $duplicateManifest=Get-Content -LiteralPath (Join-Path $duplicateRun 'manifest.json') -Raw|ConvertFrom-Json
    Assert ($duplicateManifest.Counts.Folders -eq 1 -and $duplicateManifest.Counts.NtfsAces -eq 1) 'Repeated UNC variants and overlapping parent/child roots never double-count physical evidence'
    Assert (@(Rows $duplicateRun 'ShareCoverage.csv').Count -eq 1 -and $duplicateManifest.Scopes.Count -eq 1) 'Duplicate scopes and covered children do not duplicate share metadata or coverage'

    $script:TestArea='Validated share identity and scope boundaries'
    $identityOld=New-Run 'identity-old/ASSESS_run' 'identity-old' '2026-10-28T12:00:00Z' @((New-Ace 'data' '' 'identity' 'Everyone' 'Read')) @((New-Folder 'data'))
    $identityNew=New-Run 'identity-new/ASSESS_run' 'identity-new' '2026-10-29T12:00:00Z' @((New-Ace 'data' '' 'identity' 'Everyone' 'Read')) @((New-Folder 'data'))
    function Set-ShareFixture($Directory,$Name,$SID='',$Svm='') {
        Write-FixtureDataset $Directory 'SharePermissions.csv' @([pscustomobject]@{
            Server='server';Share='data';AccountName=$Name;SID=$SID;AccessControlType='Deny';AccessRight='Full';Source='Fixture';Vserver=$Svm
        })
    }
    Set-ShareFixture $identityNew 'S-1-1-0'
    $identityOut=Invoke-Comparison 'identity-alias-out' 0 @('-BaselineRunFolder',$identityOld,'-ComparisonRunFolder',$identityNew)
    Assert (@(Rows $identityOut 'NTFS_Changes.csv'|Where-Object EntityType -eq 'SharePermission').Count -eq 0) 'Offline verified Everyone/SID aliases are the same share principal'
    Set-ShareFixture $identityOld 'TEST\OldName' 'S-1-5-21-1-2-3-1234'
    Set-ShareFixture $identityNew 'TEST\NewName' 'S-1-5-21-1-2-3-1234'
    $identityOut=Invoke-Comparison 'identity-rename-out' 0 @('-BaselineRunFolder',$identityOld,'-ComparisonRunFolder',$identityNew)
    Assert (@(Rows $identityOut 'NTFS_Changes.csv'|Where-Object EntityType -eq 'SharePermission').Count -eq 0) 'Collected SID survives share account rename without false replacement'
    $identityMerge=Invoke-Merge (Split-Path $identityNew) 'identity-merge-out'
    Assert (@(Rows $identityMerge 'NTFS_SharePermissions.csv')[0].SID -eq 'S-1-5-21-1-2-3-1234') 'Merger retains collected share principal SID'
    Set-ShareFixture $identityOld 'TEST\OldName'
    Set-ShareFixture $identityNew 'TEST\NewName'
    $identityOut=Invoke-Comparison 'identity-unknown-out' 1 @('-BaselineRunFolder',$identityOld,'-ComparisonRunFolder',$identityNew)
    $identityChanges=@(Rows $identityOut 'NTFS_Changes.csv'|Where-Object EntityType -eq 'SharePermission')
    Assert ($identityChanges.Count -eq 2 -and @($identityChanges|Where-Object ChangeType -ne 'NotCompared').Count -eq 0) 'Unverified name changes are NotCompared, never confirmed share replacements'
    Set-ShareFixture $identityOld 'Everyone' '' 'svm-a'
    Set-ShareFixture $identityNew 'Everyone' '' 'svm-b'
    $identityOut=Invoke-Comparison 'identity-svm-out' 1 @('-BaselineRunFolder',$identityOld,'-ComparisonRunFolder',$identityNew)
    Assert (@(Rows $identityOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'SharePermission' -and $_.ChangeType -ne 'NotCompared' }).Count -eq 0) 'Different SVMs are not compared as one share ACL'
    Set-ShareFixture $identityOld 'Everyone'
    $identityOut=Invoke-Comparison 'identity-blank-svm-out' 1 @('-BaselineRunFolder',$identityOld,'-ComparisonRunFolder',$identityNew)
    Assert (@(Rows $identityOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'SharePermission' -and $_.ChangeType -eq 'NotCompared' }).Count -eq 2) 'Blank SVM is not treated as an alias for a named SVM'
    Write-FixtureDataset $identityOld 'SharePermissions.csv' @()
    $identityOut=Invoke-Comparison 'identity-empty-svm-out' 1 @('-BaselineRunFolder',$identityOld,'-ComparisonRunFolder',$identityNew)
    Assert (@(Rows $identityOut 'NTFS_Changes.csv'|Where-Object{ $_.EntityType -eq 'SharePermission' -and $_.ChangeType -eq 'NotCompared' }).Count -eq 1) 'Empty share ACL without a recorded SVM cannot confirm a named-SVM permission addition'

    $mixedFolders=@((New-Folder 'data'),(New-Folder 'data'))
    $mixedFolders[1].ScanRoot='D:\Data';$mixedFolders[1].Path='D:\Data'
    $mixedRun=New-Run 'mixed/ASSESS_run' 'mixed' '2026-10-29T12:00:00Z' @() $mixedFolders
    [void](Invoke-Merge (Split-Path $mixedRun) 'mixed-merge-out' 1 'LatestSuccessful' 2)
    [void](Invoke-Comparison 'mixed-compare-out' 2 @('-BaselineRunFolder',$historyOld,'-ComparisonRunFolder',$mixedRun))
    $localRun=New-Run 'local-only/ASSESS_run' 'local-only' '2026-10-29T12:00:00Z' @() @($mixedFolders[1])
    [void](Invoke-Comparison 'mixed-pair-out' 2 @('-BaselineRunFolder',$historyOld,'-ComparisonRunFolder',$localRun))
    $overlapFolders=@((New-Folder 'data'),(New-Folder 'data' '\child'));$overlapFolders[1].ScanRoot='\\server\data\child'
    $overlapRun=New-Run 'overlap/ASSESS_run' 'overlap' '2026-10-29T12:00:00Z' @() $overlapFolders
    [void](Invoke-Merge (Split-Path $overlapRun) 'overlap-merge-out' 1 'LatestSuccessful' 2)
    [void](Invoke-Comparison 'overlap-compare-out' 2 @('-BaselineRunFolder',$historyOld,'-ComparisonRunFolder',$overlapRun))
    $disjointFolders=@((New-Folder 'data' '\one'),(New-Folder 'data' '\two'))
    foreach($folder in $disjointFolders){$folder.ScanRoot=$folder.Path}
    $disjointOld=New-Run 'disjoint-old/ASSESS_run' 'disjoint-old' '2026-10-28T12:00:00Z' @() $disjointFolders
    $disjointNew=New-Run 'disjoint-new/ASSESS_run' 'disjoint-new' '2026-10-29T12:00:00Z' @() $disjointFolders
    $disjointOut=Invoke-Merge (Split-Path $disjointNew) 'disjoint-merge-out' 1 'LatestSuccessful' 1
    Assert (@(Rows $disjointOut 'NTFS_Folders.csv').Count -eq 2) 'Distinct disjoint subtree inventories remain available'
    $disjointOut=Invoke-Comparison 'disjoint-compare-out' 0 @('-BaselineRunFolder',$disjointOld,'-ComparisonRunFolder',$disjointNew)
    Assert (@(Rows $disjointOut 'NTFS_Changes.csv').Count -eq 0) 'Matching disjoint subtree sets compare without false ambiguity'
    $outside=New-Run 'outside-share/ASSESS_run' 'outside-share' '2026-10-29T12:00:00Z' @() @((New-Folder 'data'))
    Write-FixtureDataset $outside 'SharePermissions.csv' @([pscustomobject]@{Server='outside';Share='other';AccountName='Everyone';AccessControlType='Allow';AccessRight='Read'})
    [void](Invoke-Merge (Split-Path $outside) 'outside-share-merge-out' 1 'LatestSuccessful' 2)

    $script:TestArea='Validated cleanup failure handling'
    foreach($tool in @('Merge','Compare')){
        foreach($failAnalysis in @($false,$true)){
            $faultOutput=Join-Path $testRoot "$tool-cleanup-$failAnalysis"
            $arguments=@('-Tool',$tool,'-InputPath',$historyOld,'-Baseline',$historyOld,'-Comparison',$identityNew,'-OutputFolder',$faultOutput)
            if($failAnalysis){$arguments+='-FailAnalysis'}
            $faultLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-FaultedNtfs.ps1') @arguments 2>&1 })
            $faultExit=$LASTEXITCODE
            Assert ($faultExit -eq $(if($failAnalysis){2}else{1})) "$tool cleanup failure preserves chosen analysis exit severity: $($faultLog -join "`n")"
            $stateName=if($tool -eq 'Merge'){'merge-state.json'}else{'comparison-state.json'}
            $faultState=Get-Content -LiteralPath (Join-Path $faultOutput $stateName) -Raw|ConvertFrom-Json
            Assert ($faultState.Status -eq $(if($failAnalysis){'Failed'}else{'CompletedWithWarnings'})) "$tool cleanup failure persists consistent completion state"
            $warnings=if($tool -eq 'Merge'){$faultState.Warnings}else{$faultState.Limitations}
            Assert (@($warnings|Where-Object{$_ -match 'Synthetic cleanup deletion failure'}).Count -eq 1) "$tool cleanup failure is recorded, not silently swallowed"
            if($failAnalysis){Assert ($faultState.Error -match 'MaxRowsPerShare') "$tool preserves the original analysis failure when cleanup also fails"}
        }
    }
    $cleanupProbe=@(Invoke-NtfsCleanup @({throw 'Synthetic dispose failure'},{'later cleanup ran'}))
    Assert ($cleanupProbe.Count -eq 2 -and $cleanupProbe[0] -match 'dispose failure' -and $cleanupProbe[1] -eq 'later cleanup ran') 'Disposal errors do not prevent subsequent cleanup actions'

    $script:TestArea='Validated collector import and output boundaries'
    Import-Functions (Join-Path $root 'Invoke-NtfsAssessment.ps1') @('Import-OntapPermissions','Add-ShareAndAclData','Invoke-UniqueScopeScan')
    $RunId='ontap-test';$CollectorHost='mock';$Shares=[Collections.ArrayList]::new();$ShareAcl=[Collections.ArrayList]::new();$localPathMappings=@()
    [void]$Shares.Add([pscustomobject]@{Server='server';Share='data';ScanRoot='\\server\data';CollectionMode='GenericSMB_UNC';ShareMetadataStatus='ExplicitUNC'})
    function Write-RunLog($Level,$Stage,$Message){}
    $ontapPath=Join-Path $testRoot 'ontap-import.csv'
    $ontapGood=[pscustomobject]@{smb_server='server';smb_share='data';user_or_group='Everyone';permission='read';vserver='svm-a';sid='S-1-1-0'}
    foreach($badKind in @('permission','outside','svm','blank-svm')){
        $bad=$ontapGood.PSObject.Copy()
        switch($badKind){
            'permission'{$bad.permission='bad'}
            'outside'{$bad.smb_share='outside'}
            'svm'{$bad.vserver='svm-b'}
            'blank-svm'{$bad.vserver=''}
        }
        Export-NtfsCsvData @($ontapGood,$bad) $ontapPath
        $pattern=if($badKind -eq 'permission'){'Unknown ONTAP permission'}elseif($badKind -eq 'outside'){'outside assessment scopes'}else{'across SVMs'}
        Assert-Throws {Import-OntapPermissions $ontapPath} "ONTAP $badKind fails entire staged import" $pattern
        Assert ($ShareAcl.Count -eq 0) "ONTAP $badKind leaves no partially imported ACLs"
        Remove-Item -LiteralPath $ontapPath
    }
    Export-NtfsCsvData @($ontapGood) $ontapPath
    $Shares[0].CollectionMode='LocalWindows'
    Assert-Throws {Import-OntapPermissions $ontapPath} 'Windows/ONTAP evidence is not silently combined' 'Conflicting Windows/ONTAP'
    $Shares[0].CollectionMode='GenericSMB_UNC'
    Import-OntapPermissions $ontapPath
    Assert ($ShareAcl.Count -eq 1 -and $ShareAcl[0].SID -eq 'S-1-1-0' -and $ShareAcl[0].Source -eq 'NetAppONTAP_CSV') 'Valid scoped ONTAP import retains SID, SVM and source'
    Assert ($Shares.Count -eq 1 -and $Shares[0].ShareMetadataStatus -eq 'ExplicitUNC') 'ONTAP imports never invent scopes or complete ACL coverage'
    $ontapOutput=Join-Path $testRoot 'ontap-collector'
    $ontapLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $ontapOutput -OntapCsv $ontapPath 2>&1 })
    Assert ($LASTEXITCODE -eq 1) "Scoped ONTAP explicit-UNC collector runs offline: $($ontapLog -join "`n")"
    $ontapRun=@(Get-ChildItem -LiteralPath $ontapOutput -Directory)[0].FullName
    Assert (@(Rows $ontapRun 'SharePermissions.csv').Count -eq 1 -and @(Rows $ontapRun 'ScanErrors.csv').Count -eq 0) 'ONTAP import validates after explicit UNC scopes are declared'
    $containmentOutput=Join-Path $testRoot 'rejected-local-output'
    $containmentLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $containmentOutput -LocalContainment 2>&1 })
    Assert ($LASTEXITCODE -ne 0 -and -not(Test-Path -LiteralPath $containmentOutput)) "Known local share containment rejected before any directory creation: $($containmentLog -join "`n")"
    $localExplicitOutput=Join-Path $testRoot 'rejected-local-explicit-output'
    $containmentLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $localExplicitOutput -LocalExplicitContainment 2>&1 })
    Assert ($LASTEXITCODE -ne 0 -and ($containmentLog -join "`n") -match 'outside assessed tree' -and -not(Test-Path -LiteralPath $localExplicitOutput)) 'Explicit UNC local-host alias discovers Windows mappings case-insensitively before output creation'
    $excludedOutput=Join-Path $testRoot 'excluded-share-output'
    $excludedLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $excludedOutput -ExcludedOnly 2>&1 })
    Assert ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $excludedOutput)) "Excluded administrative shares do not prohibit safe output on their volumes: $($excludedLog -join "`n")"
    $explicitOutput='\\server\data\assessment-output'
    $containmentLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $explicitOutput -ExplicitContainment 2>&1 })
    Assert ($LASTEXITCODE -ne 0 -and ($containmentLog -join "`n") -match 'outside assessed tree' -and ($containmentLog -join "`n") -notmatch 'forbidden directory creation') 'Explicit UNC containment is rejected before any directory creation attempt'
    $OutputRoot='D:\Data\reports';$beforeShares=$Shares.Count
    $smb=[pscustomobject]@{Path='D:\Data'}
    Assert-Throws {Add-ShareAndAclData 'server' 'data' '\\server\data' 'LocalWindows' 'Collected' $smb} 'Late-discovered local mapping rejects output containment before scanning' 'outside assessed tree'
    Assert ($Shares.Count -eq $beforeShares) 'Rejected late scope does not mutate share inventory'
    Assert-Throws {Invoke-UniqueScopeScan 'server' 'data' 'D:\Data' 'LocalWindows'} 'Scan entry point independently blocks generated output trees' 'outside assessed tree'
    Assert-Throws {Add-ShareAndAclData 'server' 'data' 'D:\Other' 'LocalWindows' 'Collected'} 'Collector rejects mixed local/UNC inventories for one share' 'Ambiguous mixed'
    $localPathMappings=@([pscustomobject]@{UNC='\\server\data';LocalPath='D:\Data'},[pscustomobject]@{UNC='\\localhost\alias';LocalPath='D:\Data'})
    Assert-Throws {Assert-NtfsOutputOutsideScope '\\localhost\alias\reports' '\\server\data' $localPathMappings} 'Verified Windows share aliases prevent output entering the assessed local tree' 'outside assessed tree'
    Assert-Throws {Assert-NtfsOutputOutsideScope 'D:\Data\child\reports' '\\server\data\child' $localPathMappings} 'Explicit UNC subtree uses known local Windows mapping for output containment' 'outside assessed tree'
    Assert ((ConvertTo-NtfsMappedPath '\\unknown\data' $localPathMappings) -eq '\\unknown\data') 'Arbitrary UNC server aliases are never assumed equivalent'
    Assert-Throws {ConvertTo-NtfsMappedPath '\\server\data' @($localPathMappings+@([pscustomobject]@{UNC='\\server\data';LocalPath='E:\Other'}))} 'Conflicting local Windows mappings are rejected rather than guessed' 'Conflicting known local share mappings'
    $localPathMappings=@();$OutputRoot=$testRoot
    Add-ShareAndAclData 'server' 'windows' '\\server\windows' 'RemoteWindowsCIM' 'Collected' $null @(
        [pscustomobject]@{AccountName='Everyone';AccessControlType='Allow';AccessRight='Read'}
        [pscustomobject]@{AccountName='TEST\Name';SID='S-1-5-21-1-2-3-1234';AccessControlType='Allow';AccessRight='Read'}
    )
    Assert ($ShareAcl[$ShareAcl.Count-2].SID -eq 'S-1-1-0' -and $ShareAcl[$ShareAcl.Count-1].SID -eq 'S-1-5-21-1-2-3-1234') 'Actual Windows share collector captures verified alias and supplied principal SIDs'

    $script:TestArea='Collector traversal and identity'
    # Isolate collector functions; no AD, SMB, ACL or native command is executed.
    Import-Functions (Join-Path $root 'Invoke-NtfsAssessment.ps1') @('Get-FolderQueue','Add-SkippedPath','Scan-UncRoot','Get-AclPropertySafe','Get-AclRulesSafe','ConvertTo-ExtendedPath','ConvertTo-DisplayPath','Get-Hash','Flush-LargeBuffers','Append-Safe')
    $RunId='mock';$CollectorHost='mock';$CurrentTarget='mock';$AdReady=$false;$SplitOutputByShare=$false
    $RunFolder=Join-Path $testRoot 'collector';[void](New-Item -ItemType Directory -Path $RunFolder)
    $script:TotalFolders=0;$script:TotalAces=0;$script:LargeBufferFlushes=0;$script:CsvWriters=@{}
    $Folders=[Collections.ArrayList]::new();$Aces=[Collections.ArrayList]::new();$GroupAces=[Collections.ArrayList]::new()
    $Errors=[Collections.ArrayList]::new();$SkippedPaths=[Collections.ArrayList]::new();$ShareCoverage=[Collections.ArrayList]::new();$Identities=@{}
    function Write-RunLog($Level,$Stage,$Message){}
    function Add-RunError($Stage,$Path,$Exception){throw $Exception}
    function Test-Path { [CmdletBinding()]param($LiteralPath) return $true }
    function Get-ChildItem { [CmdletBinding()]param($LiteralPath,[switch]$Directory,[switch]$Force) throw 'Enumeration should stop at configured limit.' }
    function Get-Item {
        [CmdletBinding()]param($LiteralPath,[switch]$Force)
        [pscustomobject]@{LastWriteTimeUtc=[datetime]::UtcNow;Attributes=[IO.FileAttributes]::Directory}
    }
    function Get-Acl {
        [CmdletBinding()]param($LiteralPath)
        [pscustomobject]@{Owner='TEST\Owner';AreAccessRulesProtected=$false;Sddl='';Access=@()}
    }
    $MaxFolders=1;$MaxDepth=10
    Scan-UncRoot 'server' 'data' '\\server\data' 'Mock'
    Assert ($ShareCoverage[0].Status -eq 'PartialDirectoriesOnly') 'Collector folder limit is not marked complete'
    Assert ($SkippedPaths[0].Reason -eq 'MaxFoldersReached') 'Collector records folder limit'
    $MaxFolders=100;$MaxDepth=0
    Scan-UncRoot 'server' 'data' '\\server\data' 'Mock'
    Assert ($SkippedPaths[1].Reason -eq 'MaxDepthReached') 'Collector records depth limit'
    $tree=Join-Path $testRoot 'tree'
    [void](New-Item -ItemType Directory -Path (Join-Path $tree 'child') -Force)
    [void](New-Item -ItemType Directory -Path (Join-Path $tree '~snapshot') -Force)
    $MaxFolders=100;$MaxDepth=10
    $queued=@(Get-FolderQueue $tree)
    Assert ($queued.Count -eq 2) 'Directory traversal streams actual ordinary child directories'
    Assert ($SkippedPaths[2].Reason -eq 'SnapshotFolderExcluded') 'Snapshot subtrees are explicitly excluded'
    # Force incremental flushes and check persisted + buffered counts rather than just the last buffer.
    $MaxDepth=10
    function Get-FolderQueue([string]$Root) { for($i=0;$i -lt 1002;$i++){[pscustomobject]@{Path="$Root\$i";Depth=1}} }
    Scan-UncRoot 'server' 'wide' '\\server\wide' 'Mock'
    Assert ($ShareCoverage[2].FoldersCollected -eq 1002) 'Collector counts survive mid-share buffer flush'
    Assert ($script:LargeBufferFlushes -ge 3) 'Collector flushes before a large share completes'
    foreach($state in $script:CsvWriters.Values){$state.Writer.Dispose()}
    foreach($name in @('Test-Path','Get-ChildItem','Get-Item','Get-Acl','Get-FolderQueue')){Remove-Item -LiteralPath "function:$name"}
    $script:TestArea='Validated collector path failures'
    Import-Functions (Join-Path $root 'Invoke-NtfsAssessment.ps1') @('Add-RunError')
    $rootFile=Join-Path $testRoot 'root-is-file.txt'
    [IO.File]::WriteAllText($rootFile,'Not a directory.')
    $beforeFolders=$script:TotalFolders+$Folders.Count
    Scan-UncRoot 'server' 'file' $rootFile 'Mock'
    Assert ($ShareCoverage[$ShareCoverage.Count-1].Status -eq 'SkippedCollectionError' -and ($script:TotalFolders+$Folders.Count) -eq $beforeFolders) 'Actual root files are rejected before directory ACL export'
    Assert ($Errors[$Errors.Count-1].Stage -eq 'ValidateUNC' -and $Errors[$Errors.Count-1].Error -match 'not a directory') 'Root-file rejection is recorded at validation stage'
    foreach($failureKind in @('PermissionDenied','Timeout','NetworkError','CollectionError','PathNotFound')){
        function Test-Path {
            [CmdletBinding()]param($LiteralPath)
            switch($failureKind){
                'PermissionDenied'{throw [UnauthorizedAccessException]::new('Synthetic permission failure')}
                'Timeout'{throw [TimeoutException]::new('Synthetic network timeout')}
                'NetworkError'{throw [Net.Sockets.SocketException]::new(10065)}
                'PathNotFound'{throw [IO.DirectoryNotFoundException]::new('Synthetic missing path')}
                default{throw [IO.IOException]::new('Network access transport failed')}
            }
        }
        Scan-UncRoot 'server' 'failure' '\\server\failure' 'Mock'
        Assert ($ShareCoverage[$ShareCoverage.Count-1].Status -eq "Skipped$failureKind") "Actual scan validation distinguishes $failureKind"
        Assert ($SkippedPaths[$SkippedPaths.Count-1].Reason -eq $failureKind) "Skipped-path evidence retains $failureKind without message-based access classification"
    }
    Remove-Item -LiteralPath 'function:Test-Path'
    function Get-FolderQueue([string]$Root){[pscustomobject]@{Path=$rootFile;Depth=1}}
    function Get-Acl { [CmdletBinding()]param($LiteralPath) throw 'File ACL reader must not be reached.' }
    Scan-UncRoot 'server' 'queued-file' $tree 'Mock'
    Assert (($script:TotalFolders+$Folders.Count) -eq $beforeFolders -and $Errors[$Errors.Count-1].Error -match 'Not a directory') 'File appearing in a directory queue is never exported as a folder'
    foreach($name in @('Get-FolderQueue','Get-Acl')){Remove-Item -LiteralPath "function:$name"}
    Import-Functions (Join-Path $root 'Invoke-NtfsAssessment.ps1') @('Expand-GroupRecursive')
    function Add-RunError($Stage,$Path,$Exception){[void]$Errors.Add([pscustomobject]@{Stage=$Stage;Path=$Path;Error=$Exception.Message})}
    function Get-ADGroupMember {
        [CmdletBinding()]
        param([string]$Identity,[string]$Server)
        if($Server -ne 'mock.domain'){throw 'Domain affinity was not preserved.'}
        if($Identity -eq 'CN=A'){
            return [pscustomobject]@{Name='B';SamAccountName='B';SID='S-1-5-21-1-2-3-2000';ObjectClass='group';DistinguishedName='CN=B'}
        }
        if($Identity -eq 'CN=B'){
            return [pscustomobject]@{Name='A';SamAccountName='A';SID='S-1-5-21-1-2-3-2001';ObjectClass='group';DistinguishedName='CN=A'}
        }
        if($Identity -eq 'CN=Empty'){return}
        if($Identity -eq 'CN=Users'){
            foreach($name in @('User1','User2')){[pscustomobject]@{Name=$name;SamAccountName=$name;SID='S-1-5-21-1-2-3-3000';ObjectClass='user';DistinguishedName="CN=$name"}}
            return
        }
        throw 'Synthetic group lookup failure.'
    }
    function Get-ADUser {
        [CmdletBinding()]
        param([string]$Identity,[string]$Server,[string[]]$Properties)
        if($Identity -notlike 'CN=User*' -or $Server -ne 'mock.domain'){throw 'User lookup must retain DN/domain affinity.'}
        [pscustomobject]@{Enabled=$true}
    }
    $Members=[Collections.ArrayList]::new();$MaxExpandedMembers=100
    $script:ExpandedCount=0;$script:ExpansionStatus='Complete'
    Expand-GroupRecursive 'TEST\A' 'CN=A' 'sid-a' 'A' 'mock.domain' 0 @{}
    Assert ($script:ExpansionStatus -eq 'PartialCycle' -and $script:ExpandedCount -eq 2) 'Nested group cycles are explicit and bounded'
    $script:ExpandedCount=0;$script:ExpansionStatus='Complete'
    Expand-GroupRecursive 'TEST\Empty' 'CN=Empty' 'sid-empty' 'Empty' 'mock.domain' 0 @{}
    Assert ($script:ExpansionStatus -eq 'Complete' -and $script:ExpandedCount -eq 0) 'Successful zero-member expansion distinguished from failure'
    $script:ExpandedCount=0;$script:ExpansionStatus='Complete';$MaxExpandedMembers=1
    Expand-GroupRecursive 'TEST\Users' 'CN=Users' 'sid-users' 'Users' 'mock.domain' 0 @{}
    Assert ($script:ExpansionStatus -eq 'PartialMemberLimit' -and $script:ExpandedCount -eq 1) 'Group member cap is explicit'
    $script:ExpandedCount=0;$script:ExpansionStatus='Complete'
    Expand-GroupRecursive 'TEST\Failed' 'CN=Failed' 'sid-failed' 'Failed' 'mock.domain' 0 @{}
    Assert ($script:ExpansionStatus -eq 'PartialLookupFailure') 'Group lookup failure is not empty success'
    Import-Functions (Join-Path $root 'Invoke-NtfsAssessment.ps1') @('Resolve-Identity')
    function New-Object {
        [CmdletBinding()]
        param([Parameter(Position=0)][string]$TypeName,[Parameter(Position=1)][object[]]$ArgumentList)
        if($TypeName -ne 'Security.Principal.NTAccount'){throw "Unexpected identity type: $TypeName"}
        $account=[pscustomobject]@{Value=[string]$ArgumentList[0]}
        $account|Add-Member -MemberType ScriptMethod -Name Translate -Value {
            param($TargetType)
            [pscustomobject]@{Value=$(if($this.Value -like 'BUILTIN\*'){'S-1-5-32-544'}else{'S-1-5-21-1-2-3-1001'})}
        }
        return $account
    }
    $script:directoryCalls=0
    function Get-ADObject {
        [CmdletBinding()]
        param([string]$Filter,[string]$Server,[string[]]$Properties)
        $script:directoryCalls++
        if($Filter -like '*S-1-5-32-*'){
            return [pscustomobject]@{ObjectClass='group';DistinguishedName='CN=Administrators,CN=Builtin';sAMAccountName='Administrators'}
        }
        throw 'Synthetic domain connectivity failure.'
    }
    $AdReady=$true;$DomainServers=@('mock.domain')
    $builtin=Resolve-Identity 'BUILTIN\Administrators'
    Assert ($script:directoryCalls -eq 0 -and $builtin.ObjectClass -eq 'Unknown') 'Builtin aliases never inherit membership from the AD Builtin container'
    $errorsBefore=$Errors.Count
    $failedIdentity=Resolve-Identity 'TEST\User'
    Assert ($failedIdentity.LookupStatus -eq 'DirectoryLookupFailed' -and $Errors.Count -eq $errorsBefore+1) 'Exhausted AD exceptions are persisted as collection errors'
    Assert ($failedIdentity.ObjectClass -eq 'Unknown') 'Failed directory lookup never becomes an empty group'
    Remove-Item -LiteralPath 'function:New-Object'
    Write-Host "PASS: $script:checks checks. Offline synthetic tests only; Windows PowerShell 5.1/AD/SMB integration still required."
    $script:SuiteCompleted=$true
}catch{
    $script:FailureMessage="$($_.Exception.Message) $($_.ScriptStackTrace)"
    throw
}finally{
    $cleanupCompleted=$false
    try{
    if(Get-Variable CsvWriters -Scope Script -ErrorAction SilentlyContinue){foreach($state in $script:CsvWriters.Values){$state.Writer.Dispose()}}
    if($KeepArtifacts){Write-Host "Artifacts: $testRoot"}
    else{Microsoft.PowerShell.Management\Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop}
    $cleanupCompleted=$true
    }finally{
        if($ResultsPath){
            [ordered]@{
                Completed=($script:SuiteCompleted -and $cleanupCompleted);Error=$script:FailureMessage
                CleanupCompleted=$cleanupCompleted;Checks=@($script:CheckResults)
            }|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $ResultsPath -Encoding UTF8
        }
    }
}
