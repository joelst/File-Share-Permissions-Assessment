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
$testRoot=Join-Path $PSScriptRoot ('NtfsAssessmentTests_'+[guid]::NewGuid().ToString('N'))
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
function Assert-Throws([scriptblock]$Action,[string]$Message,[string]$ExpectedPattern='') {
    $threw=$false
    try{& $Action}catch{$threw=-not $ExpectedPattern -or $_.Exception.Message -match $ExpectedPattern}
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
$registeredVersions=@(
    (Get-NtfsComponentVersion Assessment),(Get-NtfsComponentVersion Merge),
    (Get-NtfsComponentVersion Comparison),(Get-NtfsComponentVersion BestPractices),
    (Get-NtfsComponentVersion Permissions),(Get-NtfsComponentVersion PermissionValidation)
)
Assert (($registeredVersions -join '|') -eq '1.6.6|2.8.4|1.0.2|1.0.0|0.2.1-unqualified|0.1.0') 'Central registry preserves all component release versions'
$logPath=Join-Path $testRoot 'standard-log.log'
Write-NtfsLog $logPath Assessment ERROR Test "first line`nsecond`tfield"
$logFields=(Get-Content -LiteralPath $logPath -Raw).TrimEnd("`r","`n") -split "`t",6
Assert ($logFields.Count -eq 6 -and $logFields[1] -eq 'Assessment' -and $logFields[2] -eq '1.6.6' -and
    $logFields[3] -eq 'ERROR' -and $logFields[4] -eq 'Test' -and $logFields[5] -eq 'first line\nsecond\tfield') 'Standard text logs bind component versions and escape multiline fields'
function Invoke-Merge($InputPath,$OutputName,[int]$Throttle=1,[string]$Selection='LatestSuccessful',[int]$ExpectedExit=0,[string[]]$Extra=@()) {
    $output=Join-Path $testRoot $OutputName
    $log=@(& $engine -NoLogo -NoProfile -File (Join-Path $root 'Merge-NtfsAssessment.ps1') -InputRoot $InputPath -OutputFolder $output -ThrottleLimit $Throttle -RunSelection $Selection @Extra 2>&1)
    $code=$LASTEXITCODE
    $log|Set-Content -LiteralPath (Join-Path $testRoot ('merge-'+(Get-NtfsHash $OutputName)+'.log'))
    Assert ($code -eq $ExpectedExit) "Merge $OutputName exit=$code expected=$ExpectedExit : $($log -join "`n")"
    if(Test-Path -LiteralPath (Join-Path $output 'merge-stage.log')){
        Assert ((Get-Content -LiteralPath (Join-Path $output 'merge-stage.log') -Raw) -match "`tMerge`t2\.8\.4`t") 'Merge logs include component release metadata'
    }
    if($code -lt 2){
        $stateData=Get-Content -LiteralPath (Join-Path $output 'merge-state.json') -Raw|ConvertFrom-Json
        $summaryData=Get-Content -LiteralPath (Join-Path $output 'NTFS_ExecutiveSummary.json') -Raw|ConvertFrom-Json
        Assert ($stateData.ToolkitVersion -eq (Get-NtfsComponentVersion Merge) -and $summaryData.Version -eq (Get-NtfsComponentVersion Merge)) 'Merge state and summary use the centralized release version'
        Get-ChildItem -LiteralPath $output -File -Filter '*.csv'|ForEach-Object{
            Assert ($_.Length -le 100000000) "Output size: $($_.Name)"
            [void]@(Read-NtfsCsvFile $_.FullName)
        }
    }else{
        $state=Join-Path $output 'merge-state.json'
        if(Test-Path -LiteralPath $state){Assert ((Get-Content -LiteralPath $state -Raw|ConvertFrom-Json).Status -eq 'Failed') 'Failure does not claim successful completion'}
    }
    return $output
}
function Rows([string]$Directory,[string]$Name) {
    foreach($part in @(Get-NtfsCsvFiles $Directory $Name)){Read-NtfsCsvFile $part.FullName}
}
function Invoke-Comparison([string]$OutputName,[int]$ExpectedExit,[string[]]$Arguments) {
    $output=Join-Path $testRoot $OutputName
    $state=Join-Path $output 'comparison-state.json'
    $existingState=Test-Path -LiteralPath $state
    $log=@(& $engine -NoLogo -NoProfile -File (Join-Path $root 'Compare-NtfsAssessment.ps1') -OutputFolder $output @Arguments 2>&1)
    $code=$LASTEXITCODE
    $log|Set-Content -LiteralPath (Join-Path $testRoot ('comparison-'+(Get-NtfsHash $OutputName)+'.log'))
    Assert ($code -eq $ExpectedExit) "Comparison $OutputName exit=$code expected=$ExpectedExit : $($log -join "`n")"
    if(Test-Path -LiteralPath (Join-Path $output 'comparison.log')){
        Assert ((Get-Content -LiteralPath (Join-Path $output 'comparison.log') -Raw) -match "`tComparison`t1\.0\.2`t") 'Comparison logs include component release metadata'
    }
    if($code -lt 2){
        Assert ((Get-Content -LiteralPath $state -Raw|ConvertFrom-Json).Status -in @('Completed','CompletedWithWarnings')) 'Comparison completed state persisted'
        $summary=Get-Content -LiteralPath (Join-Path $output 'NTFS_ComparisonSummary.json') -Raw|ConvertFrom-Json
        Assert ($summary.Version -eq (Get-NtfsComponentVersion Comparison)) 'Comparison summary uses the centralized release version'
        Assert ($summary.DifferenceRows -eq @(Rows $output 'NTFS_Changes.csv').Count) 'Comparison counts reconcile'
        Get-ChildItem -LiteralPath $output -File -Filter '*.csv'|ForEach-Object{
            Assert ($_.Length -le 100000000) "Comparison CSV capped: $($_.Name)"
            [void]@(Read-NtfsCsvFile $_.FullName)
        }
    }elseif(-not $existingState -and (Test-Path -LiteralPath $state)){Assert ((Get-Content -LiteralPath $state -Raw|ConvertFrom-Json).Status -eq 'Failed') 'Comparison failure never claims completion'}
    return $output
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
    $mockOutput=Join-Path $testRoot 'mocked-collector'
    $mockLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $mockOutput 2>&1)
    $code=$LASTEXITCODE
    $mockLog|Set-Content -LiteralPath (Join-Path $testRoot 'mocked-collector.log')
    Assert ($code -eq 1) "Full mocked collector exits with partial coverage: $code : $($mockLog -join "`n")"
    $mockRun=@(Get-ChildItem -LiteralPath $mockOutput -Directory)[0].FullName
    $mockManifest=Get-Content -LiteralPath (Join-Path $mockRun 'manifest.json') -Raw|ConvertFrom-Json
    Assert ($mockManifest.Counts.NtfsAces -eq 1 -and $mockManifest.Counts.Folders -eq 1) 'Full collector finalization retains rows/counts'
    Assert ($mockManifest.CoverageStatus -eq 'Partial') 'Full collector never marks depth-limited scan complete'
    Assert (@(Rows $mockRun 'Identities.csv')[0].PSObject.Properties.Name -contains 'ObjectClass') 'Collector exports fixed identity schema'
    Assert (@(Rows $mockRun 'NtfsAcls.csv')[0].PropagationFlags -eq 'InheritOnly') 'Collector preserves inheritance flags'
    Assert (@(Get-ChildItem -LiteralPath (Join-Path $mockRun 'PerShare') -File).Count -eq 2) 'Collector split-by-share copies created'
    [void](Invoke-Merge $mockOutput 'mocked-collector-merge-out' 2 'LatestSuccessful' 1)
    $failedOutput=Join-Path $testRoot 'failed-collector'
    $failureLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $failedOutput -FailChecksum 2>&1)
    $failureCode=$LASTEXITCODE
    Assert ($failureCode -eq 2) "Checksum finalization failure exits 2: $($failureLog -join "`n")"
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
    $duplicateLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $duplicateOutput -DuplicateScopes 2>&1)
    Assert ($LASTEXITCODE -eq 1) "Duplicate-scope collector stays offline and reports depth limitations: $($duplicateLog -join "`n")"
    $duplicateRun=@(Get-ChildItem -LiteralPath $duplicateOutput -Directory)[0].FullName
    $duplicateManifest=Get-Content -LiteralPath (Join-Path $duplicateRun 'manifest.json') -Raw|ConvertFrom-Json
    Assert ($duplicateManifest.ToolkitVersion -eq (Get-NtfsComponentVersion Assessment)) 'Assessment manifest uses the centralized release version'
    Assert ((Get-Content -LiteralPath (Join-Path $duplicateRun 'run.log') -Raw) -match "`tAssessment`t1\.6\.6`t") 'Assessment log includes component release metadata'
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
            $faultLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-FaultedNtfs.ps1') @arguments 2>&1)
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
    $ontapLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $ontapOutput -OntapCsv $ontapPath 2>&1)
    Assert ($LASTEXITCODE -eq 1) "Scoped ONTAP explicit-UNC collector runs offline: $($ontapLog -join "`n")"
    $ontapRun=@(Get-ChildItem -LiteralPath $ontapOutput -Directory)[0].FullName
    Assert (@(Rows $ontapRun 'SharePermissions.csv').Count -eq 1 -and @(Rows $ontapRun 'ScanErrors.csv').Count -eq 0) 'ONTAP import validates after explicit UNC scopes are declared'
    $containmentOutput=Join-Path $testRoot 'rejected-local-output'
    $containmentLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $containmentOutput -LocalContainment 2>&1)
    Assert ($LASTEXITCODE -ne 0 -and -not(Test-Path -LiteralPath $containmentOutput)) "Known local share containment rejected before any directory creation: $($containmentLog -join "`n")"
    $localExplicitOutput=Join-Path $testRoot 'rejected-local-explicit-output'
    $containmentLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $localExplicitOutput -LocalExplicitContainment 2>&1)
    Assert ($LASTEXITCODE -ne 0 -and ($containmentLog -join "`n") -match 'outside assessed tree' -and -not(Test-Path -LiteralPath $localExplicitOutput)) 'Explicit UNC local-host alias discovers Windows mappings case-insensitively before output creation'
    $excludedOutput=Join-Path $testRoot 'excluded-share-output'
    $excludedLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $excludedOutput -ExcludedOnly 2>&1)
    Assert ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $excludedOutput)) "Excluded administrative shares do not prohibit safe output on their volumes: $($excludedLog -join "`n")"
    $explicitOutput='\\server\data\assessment-output'
    $containmentLog=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1') -OutputRoot $explicitOutput -ExplicitContainment 2>&1)
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
