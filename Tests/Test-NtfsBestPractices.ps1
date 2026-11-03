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
    $offlineManifest=Get-Content -LiteralPath (Join-Path $output 'BestPracticesManifest.json') -Raw|ConvertFrom-Json
    Assert ($offlineManifest.Version -eq (Get-NtfsComponentVersion BestPractices)) 'Offline manifest uses the centralized release version'
    Assert ((Get-Content -LiteralPath (Join-Path $output 'best-practices.log') -Raw) -match "`tBestPractices`t1\.0\.0`tINFO`tComplete`t") 'Offline log records component and release version'
    $rows=Get-CheckRows (Join-Path $output 'BestPracticeChecks.csv')
    Assert ($result.CheckCount -eq $rows.Count) 'Summary count reconciles with the CSV'
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
    Assert (@($rows|Where-Object {$_.CheckId -eq 'SMBRequireSecuritySignature' -and $_.Server -eq 'local' -and $_.ObservedValue -eq 'True' -and $_.Status -eq 'Review'}).Count -eq 1) 'Captured server signing configuration is reviewed as an actual setting'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'RootSaclPresent' -and $_.Server -eq 'local' -and $_.ObservedValue -eq 'False' -and $_.Evidence -like '*global/backend*'}).Count -eq 1) 'Empty root SACL does not imply no global/backend audit'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'AuditFileSystemSuccess' -and $_.Server -eq 'local' -and $_.ObservedValue -eq 'True'}).Count -eq 1) 'Audit policy and SACL evidence remain separate checks'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.Server -eq 'nas' -and $_.Status -eq 'NotAssessed' -and $_.Evidence -like '*inferred*'}).Count -eq 1) 'NAS configuration absence remains explicit unknown evidence'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'ShareAclEvidence' -and $_.Server -eq 'nas' -and $_.Status -eq 'NotAssessed'}).Count -eq 1) 'NAS ACL imports do not imply complete share ACL evidence'
    Assert (@($rows|Where-Object {$_.CheckId -eq 'InheritanceProtected' -and $_.EvidenceSource -eq 'Folders.csv' -and $_.EvidenceSourceKey -like '*child*'}).Count -eq 1) 'Directory findings link back to source descriptor and path'
    Assert ((Get-FileHash -LiteralPath (Join-Path $run 'manifest.json') -Algorithm SHA256).Hash -eq $sourceHash) 'Offline report leaves source manifest immutable'
    Assert ((Get-FileHash -LiteralPath (Join-Path $output 'BestPracticesPolicy.json') -Algorithm SHA256).Hash -eq $policy.SHA256) 'Policy copy matches provenance hash'
    Assert ((Get-Item (Join-Path $output 'BestPracticeChecks.csv')).Length -le 100000000) 'Report CSV uses existing capped writer'
    Assert ((Get-Content -LiteralPath (Join-Path $output 'BestPracticesManifest.json') -Raw|ConvertFrom-Json).SourceManifestSHA256 -eq $sourceHash) 'Offline manifest anchors source run hash'
    $outside=$false;try{Invoke-NtfsBestPracticesOfflineReport $run (Join-Path $run 'nested-output') ''|Out-Null}catch{$outside=$_.Exception.Message -like '*outside*'}
    Assert $outside 'Offline report refuses output nested within source'

    $script:TestArea='Collector opt-in and default-off behavior'
    $engine=(Get-Process -Id $PID).Path
    $collectorHarness=Join-Path $PSScriptRoot 'Invoke-MockedCollector.ps1'
    $collectorOutput=Join-Path $testRoot 'collector-opt-in'
    $log=@(& $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $collectorOutput -BestPractices -PolicyPath $policyPath -Audit 2>&1)
    $exitCode=$LASTEXITCODE
    Assert ($exitCode -eq 0) "Mocked collector opt-in succeeds: $($log -join "`n")"
    $collectorRun=Get-ChildItem -LiteralPath $collectorOutput -Directory -Filter 'ASSESS_*'|Select-Object -First 1
    $collectorManifest=Get-Content -LiteralPath (Join-Path $collectorRun.FullName 'manifest.json') -Raw|ConvertFrom-Json
    Assert ($collectorManifest.BestPractices.Enabled -eq $true) 'Collector manifest records best-practices opt-in'
    Assert ($collectorManifest.BestPractices.AuditEvidenceCollected -eq $true) 'Collector manifest records explicit audit-evidence opt-in'
    Assert (@($collectorManifest.Datasets|Where-Object Name -eq 'BestPracticeChecks.csv').Count -eq 1) 'Collector inventories best-practice checks'
    Assert (@($collectorManifest.Datasets|Where-Object Name -eq 'AuditEvidence.csv').Count -eq 1) 'Collector inventories optional audit evidence'
    Assert (@($collectorManifest.Datasets|Where-Object Name -eq 'BestPracticesErrors.csv').Count -eq 1) 'Collector inventories optional evidence failures'
    Assert ((Get-FileHash -LiteralPath (Join-Path $collectorRun.FullName 'BestPracticesPolicy.json') -Algorithm SHA256).Hash -eq $policy.SHA256) 'Collector copies policy with matching hash'
    Assert ($collectorManifest.BestPractices.EvidenceStatus -eq 'PartialEvidence' -and $collectorManifest.BestPractices.EvidenceErrorCount -gt 0) 'Evidence failures are surfaced separately from ACL scan coverage'
    Assert (@(Read-NtfsCsvFile (Join-Path $collectorRun.FullName 'BestPracticeChecks.csv')).Count -gt 0) 'Collector produces populated checks'
    $failureOutput=Join-Path $testRoot 'collector-config-failure'
    $failureLog=@(& $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $failureOutput -BestPractices -PolicyPath $policyPath -FailServerConfiguration 2>&1)
    Assert ($LASTEXITCODE -eq 0) "Server-configuration failure remains a non-mutating partial-evidence result: $($failureLog -join "`n")"
    $failureRun=Get-ChildItem -LiteralPath $failureOutput -Directory -Filter 'ASSESS_*'|Select-Object -First 1
    $failureChecks=Get-CheckRows (Join-Path $failureRun.FullName 'BestPracticeChecks.csv')
    Assert (@($failureChecks|Where-Object {$_.CheckId -eq 'SMB1Enabled' -and $_.Status -eq 'NotAssessed' -and $_.Evidence -like '*Synthetic access denied*'}).Count -eq 1) 'Configuration read failure has explicit NotAssessed reason'
    Assert (@(Read-NtfsCsvFile (Join-Path $failureRun.FullName 'BestPracticesErrors.csv')|Where-Object Stage -eq 'SMBServerConfiguration').Count -eq 1) 'Configuration read failure is preserved as coverage evidence'
    $defaultOutput=Join-Path $testRoot 'collector-default-off'
    $defaultLog=@(& $engine -NoLogo -NoProfile -File $collectorHarness -OutputRoot $defaultOutput 2>&1)
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
