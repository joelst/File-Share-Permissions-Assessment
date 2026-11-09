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
param([switch]$KeepArtifacts)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'NtfsAssessment.Common.ps1')
. (Join-Path $root 'NtfsAssessment.BestPractices.ps1')
$testRoot=Join-Path $PSScriptRoot ('NtfsBestPracticesTests_'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $testRoot)
$checks=0
function Assert($Condition,[string]$Message) {
    $script:checks++
    if(-not $Condition){throw "FAILED: $Message"}
}
function Get-CheckRows([string]$Path) { @(Read-NtfsCsvFile $Path) }
try {
    $script:TestArea='Strict policy schema'
    $policyPath=Join-Path $testRoot 'policy.json'
    '{"schemaVersion":1,"rules":[{"checkId":"SMB1Enabled","expectedValue":false},{"checkId":"ShareEncryptionEnabled","expectedValue":false},{"checkId":"BroadPrincipalWrite","expectedValue":false}]}' |
        Set-Content -LiteralPath $policyPath -Encoding UTF8
    $policy=Read-NtfsBestPracticesPolicy $policyPath
    Assert ($policy.Rules['SMB1Enabled'] -eq $false) 'JSON false remains a boolean policy value'
    foreach($invalid in @(
        '{"schemaVersion":1,"rules":[],"extra":true}',
        '{"schemaVersion":1,"rules":[{"checkId":"Arbitrary","expectedValue":true}]}',
        '{"schemaVersion":1,"rules":[{"checkId":"SMB1Enabled","expectedValue":"false"}]}',
        '{"schemaVersion":1,"rules":[{"checkId":"SMB1Enabled","expectedValue":false,"extra":1}]}',
        '{"schemaVersion":1,"rules":[{"checkId":"InheritanceProtected","expectedValue":false}]}',
        '{"schemaVersion":2,"rules":[]}',
        '{"schemaVersion":1,"rules":[{"checkId":"SMB1Enabled","expectedValue":false},{"checkId":"SMB1Enabled","expectedValue":true}]}'
    )) {
        Set-Content -LiteralPath $policyPath -Value $invalid -Encoding UTF8
        $threw=$false;try{Read-NtfsBestPracticesPolicy $policyPath|Out-Null}catch{$threw=$true}
        Assert $threw "Reject malformed policy: $invalid"
    }
    '{"schemaVersion":1,"rules":[{"checkId":"SMB1Enabled","expectedValue":false},{"checkId":"ShareEncryptionEnabled","expectedValue":false},{"checkId":"BroadPrincipalWrite","expectedValue":false}]}' |
        Set-Content -LiteralPath $policyPath -Encoding UTF8
    $policy=Read-NtfsBestPracticesPolicy $policyPath

    $script:TestArea='Evidence applicability and status'
    Assert ((Get-NtfsBpObservedBoolean $false) -eq $false) 'Boolean false is known evidence'
    Assert ($null -eq (Get-NtfsBpObservedBoolean 'NotAssessed')) 'NotAssessed remains unknown'
    Assert ((Get-NtfsBpStatus 'SMB1Enabled' $false $true $policy) -eq 'MeetsConfiguredPolicy') 'Known false can meet explicit false policy'
    Assert ((Get-NtfsBpStatus 'SMB1Enabled' $null $true $policy) -eq 'NotAssessed') 'Missing evidence cannot meet policy'
    Assert ((Get-NtfsBpStatus 'SMB1Enabled' $null $null $policy) -eq 'NotAssessed') 'Unknown NAS applicability is not NotApplicable'
    Assert ((Get-NtfsBpStatus 'SMB1Enabled' $null $false $policy) -eq 'NotApplicable') 'Known inapplicability is distinct'
    Assert ((Get-NtfsBpAuditPolicyEvidence 'No Auditing') -eq $false) 'Audit policy false is retained'
    Assert ($null -eq (Get-NtfsBpAuditPolicyEvidence 'No Auditar')) 'Unknown localized audit setting stays unknown'

    $run=Join-Path $testRoot 'source-run'
    [void](New-Item -ItemType Directory -Path $run)
    $shares=@(
        [pscustomobject]@{RunId='test';CollectorHost='collector';Server='local';CollectionMode='LocalWindows';Share='data';ScanRoot='C:\Shares\data';EncryptData='False';SMB1Enabled='False';RequireSecuritySignature='True';FolderEnumerationMode='AccessBased';ShareMetadataStatus='Collected'},
        [pscustomobject]@{RunId='test';CollectorHost='collector';Server='remote';CollectionMode='RemoteWindowsCIM';Share='data';ScanRoot='\\remote\data';EncryptData='NotCollected';SMB1Enabled='NotAssessed';RequireSecuritySignature='NotAssessed';FolderEnumerationMode='NotCollected';ShareMetadataStatus='Collected'},
        [pscustomobject]@{RunId='test';CollectorHost='collector';Server='nas';CollectionMode='NasServerSMB';Share='data';ScanRoot='\\nas\data';EncryptData='NotCollected';SMB1Enabled='NotAssessed';RequireSecuritySignature='NotAssessed';FolderEnumerationMode='NotCollected';ShareMetadataStatus='NotCollected_NAS'}
    )
    $acls=@(
        [pscustomobject]@{RunId='test';Server='local';Share='data';Path='C:\Shares\data\Everyone';Identity='Everyone';SID='S-1-1-0';Rights='Modify';RightsValue='';AccessControlType='Allow';Resolved='True'},
        [pscustomobject]@{RunId='test';Server='local';Share='data';Path='C:\Shares\data\Numeric';Identity='Everyone';SID='S-1-1-0';Rights='262144';RightsValue='262144';AccessControlType='Allow';Resolved='True'},
        [pscustomobject]@{RunId='test';Server='local';Share='data';Path='C:\Shares\data\Deny';Identity='Everyone';SID='S-1-1-0';Rights='FullControl';RightsValue='';AccessControlType='Deny';Resolved='True'},
        [pscustomobject]@{RunId='test';Server='local';Share='data';Path='C:\Shares\data\User';Identity='TEST\User';SID='S-1-5-21-1-2-3-1001';Rights='Read';RightsValue='';AccessControlType='Allow';Resolved='True'},
        [pscustomobject]@{RunId='test';Server='local';Share='data';Path='C:\Shares\data\Unknown';Identity='S-1-5-21-1-2-3-9999';SID='S-1-5-21-1-2-3-9999';Rights='Read';RightsValue='';AccessControlType='Deny';Resolved='False'}
    )
    $folders=@(
        [pscustomobject]@{RunId='test';Server='local';Share='data';Path='C:\Shares\data\child';CollectionStatus='Read';DaclState='Present';InheritanceProtected='True'},
        [pscustomobject]@{RunId='test';Server='local';Share='data';Path='C:\Shares\data\null';CollectionStatus='Read';DaclState='NullDacl';InheritanceProtected='False'}
    )
    $sharePermissions=@(
        [pscustomobject]@{RunId='test';Server='local';Share='data';AccountName='Everyone';SID='S-1-1-0';AccessControlType='Allow';AccessRight='Change';Vserver='';Source='WindowsSmbShare'},
        [pscustomobject]@{RunId='test';Server='local';Share='data';AccountName='Everyone';SID='S-1-1-0';AccessControlType='Deny';AccessRight='Full';Vserver='';Source='WindowsSmbShare'},
        [pscustomobject]@{RunId='test';Server='local';Share='data';AccountName='Everyone';SID='S-1-1-0';AccessControlType='Allow';AccessRight='Change';Vserver='svm01';Source='NetAppONTAP_CSV'}
    )
    $identities=@(
        [pscustomobject]@{Identity='TEST\User';ObjectClass='user';LookupStatus='DirectoryResolved';ResolvedBy='AD';DirectoryServer='dc01'},
        [pscustomobject]@{Identity='Everyone';ObjectClass='Unknown';LookupStatus='LocalResolved';ResolvedBy='WellKnown';DirectoryServer=''},
        [pscustomobject]@{Identity='S-1-5-21-1-2-3-9999';ObjectClass='Unknown';LookupStatus='Unresolved';ResolvedBy='None';DirectoryServer=''}
    )
    $audit=@([pscustomobject]@{Server='local';Share='data';FileShareSuccessPolicy='False';FileSystemSuccessPolicy='True';RootSaclStatus='Collected';RootSaclAuditRuleCount='0'})
    $coverage=@(
        [pscustomobject]@{RunId='test';Server='local';Share='data';Status='CompletedDirectoriesOnly';Errors=0;SkippedPaths=0},
        [pscustomobject]@{RunId='test';Server='remote';Share='data';Status='CompletedDirectoriesOnly';Errors=0;SkippedPaths=0},
        [pscustomobject]@{RunId='test';Server='nas';Share='data';Status='CompletedDirectoriesOnly';Errors=0;SkippedPaths=0}
    )
    Export-NtfsCsvData $shares (Join-Path $run 'Shares.csv')
    Export-NtfsCsvData $acls (Join-Path $run 'NtfsAcls.csv')
    Export-NtfsCsvData $folders (Join-Path $run 'Folders.csv')
    Export-NtfsCsvData $sharePermissions (Join-Path $run 'SharePermissions.csv')
    Export-NtfsCsvData $identities (Join-Path $run 'Identities.csv')
    Export-NtfsCsvData $audit (Join-Path $run 'AuditEvidence.csv')
    Export-NtfsCsvData $coverage (Join-Path $run 'ShareCoverage.csv')
    Export-NtfsCsvData @() (Join-Path $run 'ScanErrors.csv')
    Export-NtfsCsvData @() (Join-Path $run 'SkippedPaths.csv')
    $scopes=@($shares|Select-Object Server,Share,ScanRoot)
    [ordered]@{SchemaVersion='1.3';ToolkitVersion='test';RunId='test';ReadOnly=$true;CollectorHost='test';CompletedUtc=[datetime]::UtcNow.ToString('o');FatalError=$null;Scopes=$scopes;Datasets=@(Get-NtfsDatasetInventory $run)} |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $run 'manifest.json') -Encoding UTF8
    $sourceHash=(Get-FileHash -LiteralPath (Join-Path $run 'manifest.json') -Algorithm SHA256).Hash
    $output=Join-Path $testRoot 'report'
    $result=Invoke-NtfsBestPracticesOfflineReport $run $output $policyPath
    $rows=Get-CheckRows (Join-Path $output 'BestPracticeChecks.csv')
    Assert ($result.CheckCount -eq $rows.Count) 'Summary count reconciles with the CSV'
    foreach($status in @('NotAssessed','Review','DoesNotMeetConfiguredPolicy')){
        $diagnosticCount=($result.Diagnostics|Where-Object Status -eq $status|Measure-Object -Property Count -Sum).Sum
        Assert ($diagnosticCount -eq $result.StatusCounts[$status]) "Diagnostic reason groups reconcile with $($status) counts"
    }
    Assert (@($rows|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.Server -eq 'local' -and $_.Status -eq 'MeetsConfiguredPolicy'}).Count -eq 1) 'False SMB1 setting compares to explicit policy'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.Server -in @('remote','nas') -and $_.Status -eq 'NotAssessed'}).Count -eq 2) 'Remote and NAS unknown SMB settings remain NotAssessed'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'ShareEncryptionEnabled' -and $_.Server -eq 'local' -and $_.Status -eq 'MeetsConfiguredPolicy'}).Count -eq 1) 'Known false share encryption setting compares to policy'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'BroadPrincipalWrite' -and $_.Server -eq 'local' -and $_.Status -eq 'DoesNotMeetConfiguredPolicy'}).Count -eq 4) 'Broad write allow entries are reported for share and directory ACLs'
    Assert ($rows[0].PSObject.Properties.Name -notcontains 'Identity') 'Best-practice check schema does not invent an identity column'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'DirectUserAllow' -and $_.Evidence -like '*TEST\User*'}).Count -eq 1) 'Only confirmed user allow ACL is classified as direct user'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'UnresolvedPrincipal' -and $_.Status -eq 'Review' -and $_.Evidence -like '*LookupStatus=Unresolved; ResolvedBy=None*'}).Count -eq 1) 'Unresolved principal cites lookup status and source distinction'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'InheritanceProtected' -and $_.Status -eq 'Review'}).Count -eq 1) 'Protected inheritance is reported without blanket remediation'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'NullDacl' -and $_.Status -eq 'Review'}).Count -eq 1) 'Null DACL evidence is elevated for review'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'AuditFileShareSuccess' -and $_.Server -eq 'remote' -and $_.Status -eq 'NotAssessed'}).Count -eq 1) 'Local audit policy is not projected onto remote servers'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.RunId -eq 'test' -and $_.CollectorHost -eq 'collector' -and $_.EvidenceSource -eq 'Shares.csv'}).Count -eq 3) 'Checks link source machine, run, and dataset'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.PolicySource -like 'BestPracticesPolicy.json (SHA256 *' -and $_.PolicyExpectedValue -eq 'False'}).Count -eq 3) 'Policy checks preserve policy hash provenance and configured expectation'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'BroadPrincipalWrite' -and $_.Vserver -eq 'svm01' -and $_.EvidenceSource -eq 'SharePermissions.csv'}).Count -eq 1) 'Share ACL finding preserves NetApp SVM and source linkage'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'SMBRequireSecuritySignature' -and $_.Server -eq 'local' -and $_.ObservedValue -eq 'True' -and $_.Status -eq 'MeetsConfiguredPolicy' -and $_.PolicyExpectedValue -eq 'True' -and $_.PolicySource -like 'Built-in baseline v*'}).Count -eq 1) 'Custom policies retain the built-in signing expectation when omitted'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'DirectUserAllow' -and $_.Status -eq 'DoesNotMeetConfiguredPolicy' -and $_.PolicyExpectedValue -eq 'False' -and $_.PolicySource -like 'Built-in baseline v*'}).Count -eq 1) 'Custom policies retain the baseline against direct user grants'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'RootSaclPresent' -and $_.Server -eq 'local' -and $_.ObservedValue -eq 'False' -and $_.Evidence -like '*global/backend*'}).Count -eq 1) 'Empty root SACL does not imply no global/backend audit'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'AuditFileSystemSuccess' -and $_.Server -eq 'local' -and $_.ObservedValue -eq 'True'}).Count -eq 1) 'Audit policy and SACL evidence remain separate checks'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.Server -eq 'nas' -and $_.Status -eq 'NotAssessed' -and $_.Evidence -like '*inferred*'}).Count -eq 1) 'NAS configuration absence remains explicit unknown evidence'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'ShareAclEvidence' -and $_.Server -eq 'nas' -and $_.Status -eq 'NotAssessed'}).Count -eq 1) 'NAS ACL imports do not imply complete share ACL evidence'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'InheritanceProtected' -and $_.EvidenceSource -eq 'Folders.csv' -and $_.EvidenceSourceKey -like '*child*'}).Count -eq 1) 'Directory findings link back to source descriptor and path'
    Assert ((Get-FileHash -LiteralPath (Join-Path $run 'manifest.json') -Algorithm SHA256).Hash -eq $sourceHash) 'Offline report leaves source manifest immutable'
    Assert ((Get-FileHash -LiteralPath (Join-Path $output 'BestPracticesPolicy.json') -Algorithm SHA256).Hash -eq $policy.SHA256) 'Policy copy matches provenance hash'
    Assert ((Get-Item (Join-Path $output 'BestPracticeChecks.csv')).Length -le 100000000) 'Report CSV uses existing capped writer'
    Assert ((Get-Content -LiteralPath (Join-Path $output 'BestPracticesManifest.json') -Raw|ConvertFrom-Json).SourceManifestSHA256 -eq $sourceHash) 'Offline manifest anchors source run hash'
    Assert ((Get-Content -LiteralPath (Join-Path $output 'BestPracticesManifest.json') -Raw|ConvertFrom-Json).Version -eq $script:NtfsVersions.BestPractices) 'Offline manifest uses registered best-practices version'
    Assert ((Get-Content -LiteralPath (Join-Path $output 'BestPracticeSummary.json') -Raw|ConvertFrom-Json).Version -eq $script:NtfsVersions.BestPractices) 'Offline summary uses registered best-practices version'
    $reportLog=@(Get-Content -LiteralPath (Join-Path $output 'report.log'))
    Assert ($reportLog.Count -eq 2 -and @($reportLog|Where-Object { -not $_.Contains("Version=$($script:NtfsVersions.BestPractices)") }).Count -eq 0) 'Offline report logs its version without a versioned filename'
    $failedOutput=Join-Path $testRoot 'failed-report'
    $failed=$false;try{Invoke-NtfsBestPracticesOfflineReport (Join-Path $testRoot 'missing-run') $failedOutput ''|Out-Null}catch{$failed=$_.Exception.Message -like '*missing manifest*'}
    Assert $failed 'Invalid source report fails explicitly'
    $failureLog=Get-Content -LiteralPath (Join-Path $failedOutput 'report.log') -Raw
    Assert ($failureLog.Contains("Version=$($script:NtfsVersions.BestPractices)") -and $failureLog.Contains("ERROR`tFailed")) 'Failed report retains versioned log evidence'
    $outside=$false;try{Invoke-NtfsBestPracticesOfflineReport $run (Join-Path $run 'nested-output') ''|Out-Null}catch{$outside=$_.Exception.Message -like '*outside*'}
    Assert $outside 'Offline report refuses output nested within source'

    $script:TestArea='Built-in baseline and custom overrides'
    $overridePath=Join-Path $testRoot 'overrides.json'
    '{"schemaVersion":1,"rules":[{"checkId":"SMB1Enabled","expectedValue":true},{"checkId":"DirectUserAllow","expectedValue":true},{"checkId":"BroadPrincipalWrite","expectedValue":true},{"checkId":"AuditFileShareSuccess","expectedValue":false}]}' |
        Set-Content -LiteralPath $overridePath -Encoding UTF8
    $overrideOutput=Join-Path $testRoot 'override-report'
    $overrideResult=Invoke-NtfsBestPracticesOfflineReport $run $overrideOutput $overridePath
    $overrideRows=Get-CheckRows (Join-Path $overrideOutput 'BestPracticeChecks.csv')
    Assert (@($overrideRows|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.Server -eq 'local' -and $_.Status -eq 'DoesNotMeetConfiguredPolicy' -and $_.PolicyExpectedValue -eq 'True'}).Count -eq 1) 'Explicit true replaces a false built-in expectation'
    Assert (@($overrideRows|Where-Object {$_.CheckId -in @('DirectUserAllow','BroadPrincipalWrite') -and $_.Status -eq 'MeetsConfiguredPolicy' -and $_.PolicySource -like 'BestPracticesPolicy.json (SHA256 *'}).Count -eq 5) 'Custom exceptions override both directory and share grant expectations'
    Assert (@($overrideRows|Where-Object {$_.CheckId -eq 'AuditFileShareSuccess' -and $_.Server -eq 'local' -and $_.Status -eq 'MeetsConfiguredPolicy' -and $_.PolicyExpectedValue -eq 'False'}).Count -eq 1) 'Custom policies can add an audit expectation without a built-in default'
    Assert (@($overrideRows|Where-Object {$_.CheckId -eq 'AuditFileShareSuccess' -and $_.Server -eq 'remote' -and $_.Status -eq 'NotAssessed'}).Count -eq 1) 'An audit override does not invent remote policy evidence'
    Assert ($overrideResult.Baseline.Rules.SMBRequireSecuritySignature -eq $true -and $overrideResult.Baseline.Rules.SMB1Enabled -eq $true -and $overrideResult.Baseline.CustomOverrides.Count -eq 4) 'Summary records effective rules and which ones were overridden'
    $overrideManifest=Get-Content -LiteralPath (Join-Path $overrideOutput 'BestPracticesManifest.json') -Raw|ConvertFrom-Json
    Assert ($overrideManifest.Baseline.Rules.SMB1Enabled -eq $true -and $overrideManifest.Baseline.Version -eq $script:NtfsVersions.BestPractices) 'Offline manifest records baseline version and effective override'

    $baselineOutput=Join-Path $testRoot 'baseline-report'
    $baselineResult=Invoke-NtfsBestPracticesOfflineReport $run $baselineOutput ''
    $baselineRows=Get-CheckRows (Join-Path $baselineOutput 'BestPracticeChecks.csv')
    Assert (@($baselineRows|Where-Object {$_.Server -eq 'local' -and $_.CheckId -in @('SMB1Enabled','SMBRequireSecuritySignature','ShareABEEnabled') -and $_.Status -eq 'MeetsConfiguredPolicy'}).Count -eq 3) 'Default baseline evaluates captured SMB1, signing, and ABE settings'
    Assert (@($baselineRows|Where-Object {$_.Server -eq 'local' -and $_.CheckId -eq 'ShareEncryptionEnabled' -and $_.Status -eq 'DoesNotMeetConfiguredPolicy' -and $_.PolicyExpectedValue -eq 'True'}).Count -eq 1) 'Disabled encryption does not meet the built-in baseline'
    Assert (@($baselineRows|Where-Object {$_.CheckId -in @('DirectUserAllow','BroadPrincipalWrite') -and $_.Status -eq 'DoesNotMeetConfiguredPolicy' -and $_.PolicyExpectedValue -eq 'False'}).Count -eq 5) 'Custom grant exceptions do not leak into later baseline reports'
    Assert (@($baselineRows|Where-Object {$_.Server -in @('remote','nas') -and $_.CheckId -in @('SMB1Enabled','SMBRequireSecuritySignature','ShareEncryptionEnabled','ShareABEEnabled') -and $_.Status -eq 'NotAssessed' -and $_.PolicyExpectedValue -ne ''}).Count -eq 8) 'Built-in expectations never substitute for unavailable evidence'
    Assert (@($baselineRows|Where-Object {$_.CheckId -in @('InheritanceProtected','NullDacl','UnresolvedPrincipal') -and $_.Status -eq 'Review' -and $_.PolicyExpectedValue -eq ''}).Count -eq 3) 'Context-dependent directory findings remain review-only'
    Assert (@($baselineRows|Where-Object {$_.Server -eq 'local' -and $_.CheckId -in @('AuditFileShareSuccess','AuditFileSystemSuccess','RootSaclPresent') -and $_.Status -eq 'Review'}).Count -eq 3) 'Audit scope and root SACL presence require context rather than a blanket expectation'
    $savedBaseline=Get-Content -LiteralPath (Join-Path $baselineOutput 'BestPracticeSummary.json') -Raw|ConvertFrom-Json
    Assert ($savedBaseline.Baseline.Rules.SMB1Enabled -eq $false -and $savedBaseline.Baseline.CustomOverrides.Count -eq 0 -and $null -eq $savedBaseline.Policy) 'Default report persists its effective baseline separately from optional custom policy metadata'
    Assert ($baselineResult.CheckCount -eq $baselineRows.Count -and $baselineResult.StatusCounts.MeetsConfiguredPolicy -eq 3 -and $baselineResult.StatusCounts.DoesNotMeetConfiguredPolicy -eq 6) 'Default summary reconciles baseline pass and mismatch counts'
    $baselineManifest=Get-Content -LiteralPath (Join-Path $baselineOutput 'BestPracticesManifest.json') -Raw|ConvertFrom-Json
    Assert ($baselineManifest.Baseline.Version -eq $script:NtfsVersions.BestPractices -and $baselineManifest.PolicyCopySHA256 -eq '' -and $baselineManifest.SummarySHA256 -eq (Get-FileHash -LiteralPath (Join-Path $baselineOutput 'BestPracticeSummary.json') -Algorithm SHA256).Hash) 'Offline manifest anchors the default baseline through its summary hash'
    Assert ((Get-FileHash -LiteralPath (Join-Path $run 'manifest.json') -Algorithm SHA256).Hash -eq $sourceHash) 'Baseline and override reports preserve the source assessment'
    $emptyPolicyPath=Join-Path $testRoot 'empty-policy.json'
    '{"schemaVersion":1,"rules":[]}' | Set-Content -LiteralPath $emptyPolicyPath -Encoding UTF8
    $emptyOutput=Join-Path $testRoot 'empty-policy-report'
    $emptyResult=Invoke-NtfsBestPracticesOfflineReport $run $emptyOutput $emptyPolicyPath
    Assert ($emptyResult.StatusCounts.DoesNotMeetConfiguredPolicy -eq $baselineResult.StatusCounts.DoesNotMeetConfiguredPolicy -and $emptyResult.Baseline.CustomOverrides.Count -eq 0) 'An empty override list retains the built-in baseline'

    $script:TestArea='Collector opt-in and default-off behavior'
    $engine=(Get-Process -Id $PID).Path
    $collectorHarness=Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1'
    $collectorOutput=Join-Path $testRoot 'collector-opt-in'
    # Capture expected native stderr without PowerShell 5.1 stopping before exit-code checks.
    $log=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $collectorOutput -BestPractices -PolicyPath $policyPath -Audit 2>&1 })
    $exitCode=$LASTEXITCODE
    Assert ($exitCode -eq 0) "Mocked collector opt-in succeeds: $($log -join "`n")"
    Assert (($log -join "`n").Contains('Assessment: CompletedWithWarnings.') -and ($log -join "`n").Contains('BestPracticeChecks.csv') -and -not ($log -join "`n").Contains('StatusInterpretation')) 'Collector gives concise report guidance instead of dumping the summary object'
    $collectorRun=Get-ChildItem -LiteralPath $collectorOutput -Directory -Filter 'ASSESS_*'|Select-Object -First 1
    $collectorManifest=Get-Content -LiteralPath (Join-Path $collectorRun.FullName 'manifest.json') -Raw|ConvertFrom-Json
    Assert ($collectorManifest.BestPractices.Enabled -eq $true) 'Collector manifest records best-practices opt-in'
    Assert ($collectorManifest.BestPractices.Version -eq $script:NtfsVersions.BestPractices) 'Collector uses the same registered best-practices version'
    $collectorLog=Get-Content -LiteralPath (Join-Path $collectorRun.FullName 'run.log') -Raw
    Assert ($collectorLog.Contains("Component=Assessment`tVersion=$($script:NtfsVersions.Assessment)") -and $collectorLog.Contains("Component=BestPractices`tVersion=$($script:NtfsVersions.BestPractices)")) 'Collector logs both enabled component versions'
    Assert ($collectorManifest.BestPractices.AuditEvidenceCollected -eq $true) 'Collector manifest records explicit audit-evidence opt-in'
    Assert (@($collectorManifest.Datasets|Where-Object Name -eq 'BestPracticeChecks.csv').Count -eq 1) 'Collector inventories best-practice checks'
    Assert (@($collectorManifest.Datasets|Where-Object Name -eq 'AuditEvidence.csv').Count -eq 1) 'Collector inventories optional audit evidence'
    Assert (@($collectorManifest.Datasets|Where-Object Name -eq 'BestPracticesErrors.csv').Count -eq 1) 'Collector inventories optional evidence failures'
    Assert ((Get-FileHash -LiteralPath (Join-Path $collectorRun.FullName 'BestPracticesPolicy.json') -Algorithm SHA256).Hash -eq $policy.SHA256) 'Collector copies policy with matching hash'
    Assert ($collectorManifest.BestPractices.EvidenceStatus -eq 'PartialEvidence' -and $collectorManifest.BestPractices.EvidenceErrorCount -gt 0) 'Evidence failures are surfaced separately from ACL scan coverage'
    Assert (@(Read-NtfsCsvFile (Join-Path $collectorRun.FullName 'BestPracticeChecks.csv')).Count -gt 0) 'Collector produces populated checks'
    Assert ($collectorManifest.BestPractices.Baseline.Rules.ShareEncryptionEnabled -eq $false -and $collectorManifest.BestPractices.Baseline.Rules.SMBRequireSecuritySignature -eq $true) 'Collector manifest records custom expectations merged with the built-in baseline'
    $baselineCollectorOutput=Join-Path $testRoot 'collector-baseline'
    $baselineLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $baselineCollectorOutput -BestPractices 2>&1 })
    $baselineExit=$LASTEXITCODE
    Assert ($baselineExit -eq 0) "Collector uses baseline without a custom policy: $($baselineLog -join "`n")"
    $baselineRun=Get-ChildItem -LiteralPath $baselineCollectorOutput -Directory -Filter 'ASSESS_*'|Select-Object -First 1
    $inlineChecks=Get-CheckRows (Join-Path $baselineRun.FullName 'BestPracticeChecks.csv')
    Assert (@($inlineChecks|Where-Object {$_.CheckId -eq 'ShareEncryptionEnabled' -and $_.Status -eq 'DoesNotMeetConfiguredPolicy' -and $_.PolicySource -like 'Built-in baseline v*'}).Count -eq 1) 'Inline collection evaluates the built-in encryption baseline'
    $inlineManifest=Get-Content -LiteralPath (Join-Path $baselineRun.FullName 'manifest.json') -Raw|ConvertFrom-Json
    Assert ($inlineManifest.BestPractices.Baseline.Version -eq $script:NtfsVersions.BestPractices -and $inlineManifest.BestPractices.Baseline.Rules.ShareEncryptionEnabled -eq $true -and $null -eq $inlineManifest.BestPractices.PolicyFile) 'Collector persists baseline provenance without inventing a custom policy file'
    $cliOutput=Join-Path $testRoot 'cli-offline-report'
    $cliLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsBestPracticesReport.ps1') -InputRunFolder $run -OutputFolder $cliOutput 2>&1 })
    $cliExit=$LASTEXITCODE
    Assert ($cliExit -eq 0 -and ($cliLog -join "`n").Contains('Best practices: CompletedWithWarnings.') -and ($cliLog -join "`n").Contains((Join-Path $cliOutput 'BestPracticeChecks.csv')) -and ($cliLog -join "`n").Contains('Offline reporting cannot fill evidence gaps')) 'Offline report CLI points to actual findings and unavailable-evidence guidance'
    Assert (($cliLog -join "`n").Contains("Resolve or document $($baselineResult.StatusCounts.NotAssessed) missing evidence checks") -and ($cliLog -join "`n").Contains('- (') -and ($cliLog -join "`n").Contains('Invoke-NtfsAssessment.ps1')) 'Offline report names the next collection script and quantifies missing evidence with reasons'
    Assert (($cliLog -join "`n") -notmatch '\b0 (missing evidence checks|policy mismatches|contextual warnings|partial scopes|error records|skipped-path records)\b') 'Offline report action guidance excludes zero-count categories'
    $emptyCollectionOutput=Join-Path $testRoot 'collector-empty-scope'
    $ErrorActionPreference='Continue'
    try{
        $emptyCollectionLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $emptyCollectionOutput -ExcludedOnly -BestPractices 2>&1 })
        $emptyCollectionExit=$LASTEXITCODE
    }finally{$ErrorActionPreference='Stop'}
    $emptyCollectionText=($emptyCollectionLog -join ' ') -replace '\s+',' '
    Assert ($emptyCollectionExit -eq 0 -and $emptyCollectionText -match 'Assessment: CompletedWithWarnings\.' -and $emptyCollectionText -match 'zero selected assessment scopes') "Excluded-only collector completes with inline best-practices and identifies its empty scope: $($emptyCollectionLog -join "`n")"
    $emptyRun=Get-ChildItem -LiteralPath $emptyCollectionOutput -Directory -Filter 'ASSESS_*'|Select-Object -First 1
    $emptyInlineSummary=Get-Content -LiteralPath (Join-Path $emptyRun.FullName 'BestPracticeSummary.json') -Raw|ConvertFrom-Json
    Assert ($emptyInlineSummary.SourceCoverage.CoverageRows -eq 0 -and $emptyInlineSummary.CheckCount -eq 0) 'Inline best practices retain the empty-scope evidence without inventing checks'
    $emptyReportOutput=Join-Path $testRoot 'empty-scope-report'
    $ErrorActionPreference='Continue'
    try{
        $emptyReportLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsBestPracticesReport.ps1') -InputRunFolder $emptyRun.FullName -OutputFolder $emptyReportOutput 2>&1 })
        $emptyReportExit=$LASTEXITCODE
    }finally{$ErrorActionPreference='Stop'}
    Assert ($emptyReportExit -eq 0) "Empty-scope offline report completes: $($emptyReportLog -join "`n")"
    $emptyReportText=($emptyReportLog -join ' ') -replace '\s+',' '
    $emptyReportSummary=Get-Content -LiteralPath (Join-Path $emptyReportOutput 'BestPracticeSummary.json') -Raw|ConvertFrom-Json
    Assert ($emptyReportSummary.SourceCoverage.CoverageRows -eq 0 -and $emptyReportSummary.SourceCoverage.Errors -eq 0 -and $emptyReportSummary.SourceCoverage.SkippedPaths -eq 0 -and $emptyReportSummary.CheckCount -eq 0) 'Offline reporting retains the empty-scope evidence without inventing checks'
    Assert ($emptyReportText -match 'Best practices: CompletedWithWarnings\.' -and $emptyReportText -match 'Resolve 1 blocker: no assessment scopes' -and $emptyReportText -match 'Invoke-NtfsAssessment\.ps1' -and $emptyReportText -match 'New-NtfsBestPracticesReport\.ps1' -and $emptyReportText -notmatch 'No next (report )?script is required') 'Offline reporting identifies empty coverage and directs a new collection and report'
    $cliFailureOutput=Join-Path $testRoot 'cli-failed-report'
    $ErrorActionPreference='Continue'
    try{
        $cliFailure=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File (Join-Path $root 'New-NtfsBestPracticesReport.ps1') -InputRunFolder (Join-Path $testRoot 'absent-run') -OutputFolder $cliFailureOutput 2>&1 })
        $cliFailureExit=$LASTEXITCODE
    }finally{$ErrorActionPreference='Stop'}
    Assert ($cliFailureExit -eq 2 -and ($cliFailure -join "`n").Contains('Best practices: Failed.') -and ($cliFailure -join "`n").Contains((Join-Path $cliFailureOutput 'report.log'))) 'Offline report failure points to its diagnostic log'
    $failureOutput=Join-Path $testRoot 'collector-config-failure'
    $failureLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $failureOutput -BestPractices -PolicyPath $policyPath -FailServerConfiguration 2>&1 })
    Assert ($LASTEXITCODE -eq 0) "Server-configuration failure remains a non-mutating partial-evidence result: $($failureLog -join "`n")"
    $failureRun=Get-ChildItem -LiteralPath $failureOutput -Directory -Filter 'ASSESS_*'|Select-Object -First 1
    $failureChecks=Get-CheckRows (Join-Path $failureRun.FullName 'BestPracticeChecks.csv')
    Assert (@($failureChecks|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.Status -eq 'NotAssessed' -and $_.Evidence -like '*Synthetic access denied*'}).Count -eq 1) 'Configuration read failure has explicit NotAssessed reason'
    Assert (@(Read-NtfsCsvFile (Join-Path $failureRun.FullName 'BestPracticesErrors.csv')|Where-Object Stage -eq 'SMBServerConfiguration').Count -eq 1) 'Configuration read failure is preserved as coverage evidence'
    Assert (($failureLog -join "`n").Contains('Synthetic access denied') -and ($failureLog -join "`n").Contains("-RunSelection 'Explicit'")) 'Missing optional SMB configuration is explained but does not block the merge command'
    Assert (($failureLog -join "`n") -notmatch '\b0 (collection error records|skipped-path records|incomplete group expansions|missing evidence checks|policy mismatches|contextual warnings)\b') 'Collector best-practices action guidance excludes zero-count categories'
    foreach($withAudit in @($false,$true)){
        $uncOutput=Join-Path $testRoot "collector-unc-$($withAudit)"
        $auditArguments=@()
        if($withAudit){$auditArguments=@('-Audit')}
        $uncLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $uncOutput -BestPractices -ExplicitUnc @auditArguments 2>&1 })
        $uncExit=$LASTEXITCODE
        Assert ($uncExit -eq 1) "Nonempty UNC collector finalizes best practices with Audit=$($withAudit): $($uncLog -join "`n")"
        $uncRun=Get-ChildItem -LiteralPath $uncOutput -Directory -Filter 'ASSESS_*'|Select-Object -First 1
        $uncManifest=Get-Content -LiteralPath (Join-Path $uncRun.FullName 'manifest.json') -Raw|ConvertFrom-Json
        Assert (-not $uncManifest.FatalError -and $uncManifest.Counts.NtfsAces -eq 1 -and $uncManifest.Counts.Folders -eq 1) 'UNC finalization retains collected rows and publishes a nonfatal manifest'
        $uncChecks=Get-CheckRows (Join-Path $uncRun.FullName 'BestPracticeChecks.csv')
        Assert (@($uncChecks|Where-Object {$_.CheckId -eq 'InheritanceProtected' -and $_.EvidenceSource -eq 'Folders.csv'}).Count -eq 1) 'Inline report sees buffered folder evidence'
        Assert (@($uncChecks|Where-Object {$_.CheckId -eq 'UnresolvedPrincipal' -and $_.EvidenceSource -eq 'NtfsAcls.csv'}).Count -eq 1) 'Inline report sees buffered ACE evidence'
        Assert ($uncManifest.BestPractices.AuditEvidenceCollected -eq $withAudit) 'UNC manifest preserves audit opt-in'
        foreach($dataset in @($uncManifest.Datasets)){
            foreach($part in @($dataset.Parts)){
                $partPath=Join-Path $uncRun.FullName $part.Name
                Assert ((Get-FileHash -LiteralPath $partPath -Algorithm SHA256).Hash -eq $part.SHA256) 'UNC manifest hashes finalized CSV data'
            }
        }
        $uncHashes=@(Read-NtfsCsvFile (Join-Path $uncRun.FullName 'SHA256SUMS.csv'))
        Assert (@($uncHashes|Where-Object { $_.Hash -ne (Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash }).Count -eq 0) 'UNC output hashes include the completed report and manifest'
        Assert (@(Get-ChildItem -LiteralPath (Join-Path $uncRun.FullName 'PerShare') -File).Count -eq 2) 'UNC finalization preserves per-share copies'
    }
    $defaultOutput=Join-Path $testRoot 'collector-default-off'
    $defaultLog=@(& { $ErrorActionPreference='Continue'; & $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $defaultOutput 2>&1 })
    $defaultExit=$LASTEXITCODE
    Assert ($defaultExit -eq 1) "Default collector preserves its existing partial-coverage exit: $($defaultLog -join "`n")"
    $defaultRun=Get-ChildItem -LiteralPath $defaultOutput -Directory -Filter 'ASSESS_*'|Select-Object -First 1
    $defaultManifest=Get-Content -LiteralPath (Join-Path $defaultRun.FullName 'manifest.json') -Raw|ConvertFrom-Json
    Assert (-not ($defaultManifest.PSObject.Properties.Name -contains 'BestPractices')) 'Default-off manifest remains free of BP metadata'
    Assert (-not (Test-Path -LiteralPath (Join-Path $defaultRun.FullName 'BestPracticeChecks.csv'))) 'Default-off collector emits no BP dataset'
    "PASS: $checks focused best-practices assertions"
} finally {
    if(-not $KeepArtifacts -and (Test-Path -LiteralPath $testRoot)){Remove-Item -LiteralPath $testRoot -Recurse -Force}
}
