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
Pure Windows SMB and local NTFS permission planning, handle-pinned Apply, and optional Revert.
.DESCRIPTION
Release version: NtfsAssessment.Common.ps1, Permissions entry in NtfsVersions.

Executes read-only permission planning (-Mode Plan) as well as handle-pinned
permission changes (-Mode Apply) and optional evidence-bound rollback (-Mode Revert)
across direct local fixed Windows NTFS, Windows SMB shares, NetApp ONTAP SMB shares,
generic NAS SMB shares, and mapped drives (frozen once into canonical UNC) without
requiring ONTAP CLI, ONTAP REST APIs, or a prior full-server assessment.

Supported operations in -Mode Apply:
- Add (default): Adds explicit allow ACEs for one or more AD security groups/SIDs.
- Remove: Removes matching allow ACEs for -RemovePrincipal (Everyone, SID, or AD group)
  within the selected unprotected scope while preserving unrelated ACEs and protected branches.
- Replace: Removes matching allow ACEs for -RemovePrincipal and inserts replacement allow
  ACEs preserving each removed ACE's inheritance flags.

Standard Apply creates a fresh handle-pinned preimage plan in the same invocation,
pins every in-scope handle with zero share access, writes exact self-relative DACL
control flags via ntdll!NtSetSecurityObject (preventing SE_DACL_AUTO_INHERITED drift
on NetApp WAFL SMB), verifies every path's descriptor and file identifier before and
after writes, and emits receipt.json, events.jsonl, and permissions-before-after.csv.
Use -WhatIf on -Mode Apply to preview without mutating target ACLs.
Review-only plans created by -Mode Plan (-PlanPath) remain non-executable snapshots.

Requires Windows, RSAT ActiveDirectory group reads and sufficient read access.
SMB plans read Windows-style filesystem ACLs on Windows, NetApp or generic NAS;
they never modify SMB share permissions or use ONTAP APIs. TargetPlatform is an
explicit operator declaration, not backend proof. Auto treats UNC as generic SMB,
never inferring NetApp from a hostname. Missing elevated drive mappings fail;
use direct UNC instead. Local targets must be actual fixed NTFS volumes.
Fixed volumes are not trusted identities: plans bind the originating host and
observed volume ID/serial/filesystem, but stable object identity and infrastructure
trust remain unproven. Adapter profile and missing backend/security-style proof
are bound in the plan; a NAS NTFS advertisement is never used as Windows proof.
Mapped drive subdirectories are frozen into canonical UNC once; Apply/Revert do
not resolve drive mappings again. Local plans are rejected on another host.
DOMAIN\group names are resolved as AD groups; if the
directory requires distinguished names or SIDs, use those. DFS, aliases, backend
identity, stable file IDs, and infrastructure trust are NOT proven by this release.
Client AD resolution does not validate target authority, trust or SVM-local groups.
Machine/SVM-local groups are unsupported; unknown authority fails closed.
NoOp means unconditional matching-SID ACL coverage, not effective-access proof.
Proposals are abstract intent models, NOT computed post-propagation descriptors.

Review-only plans created by -Mode Plan (-PlanPath / -PlanSHA256) are abstract intent
snapshots without pinned physical file IDs or computed post-propagation descriptors, so
invoking -Mode Apply or -Mode Revert with -PlanPath always emits Blocked / NotQualified
without target writes. Instead, invoke -Mode Apply directly with -TargetPath (building a
fresh handle-pinned plan in the same run) and invoke -Mode Revert with -ReceiptPath,
-ReceiptSHA256, and -ReviewedApplyJournalSHA256. WhatIf never changes target permissions;
local audit/evidence is still written. Approvals are not identity authorization; SHA256
and a local hash chain are not tamper-proof. Archive receipts, plans, manifests, source
hashes and journals externally under enterprise access control. Audit/run locks are local
only, not distributed locks. Output must be on a trusted local volume which is not the
share's backing directory. Known same-named local SMB backing paths are checked and mapped
output drives are rejected. The caller must independently validate remaining physical
mappings (aliases, subst/8.3/DFS); this tool cannot prove them. Named target mutexes
coordinate this host only (not aliases or other hosts). Toolkit assessment reports use
the 100,000,000-byte CSV part cap; the verified before/after audit is a single streamed CSV.

Each Apply creates a fresh plan in that same invocation; it cannot consume a previous
plan or WhatIf preview. It persists exact native preimages and desired states before
writes, then returns a receipt and Apply journal hashes. Retain the receipt hash
independently and review the source-bound journal before Revert; hashes are not
authentication. Revert requires the same source, the saved record, the receipt, its
retained hash and the reviewed Apply journal hash. Recovery evidence does not expire
after 24 hours. Partial Apply recovery additionally requires -ReviewedPartialApplyRecovery.
Separate fresh audit directories are created; no automatic rollback or overwrite is
performed. Failures stop, preserve evidence and require explicit recovery review; never
retry or auto-rollback. Torn journal tails are Indeterminate and retained unchanged.
For local Windows NTFS and Windows SMB targets, all inventoried paths outside protected
branches must carry the DACL auto-inherited control flag before a write; NetApp ONTAP SMB
and generic NAS SMB shares routinely omit that flag on WAFL/NAS descriptors and are
written via ntdll!NtSetSecurityObject so exact DACL control flags are preserved without
introducing SE_DACL_AUTO_INHERITED drift. Legacy -DisposableLocalLab +
-DisposableAcknowledgement remains backward-compatible and restricted to direct local
fixed Windows NTFS.
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Plan -TargetPath 'Z:\share\folder' -TargetPlatform Windows -GroupName 'DOMAIN\Readers' -Permissions ReadAndExecute -OutputDirectory C:\NtfsAudit
Z: must be verified as fixed NTFS or an available mapped UNC in this logon context.
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Plan -TargetPath '\\SERVER1\Share1\Folder\Subfolder' -GroupName 'S-1-5-21-1-2-3-1001' -Permissions ReadAndExecute -OutputDirectory C:\NtfsAudit
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Plan -ShareName '\\FILER1\Data\Department\Folder' -TargetPlatform NetApp -GroupName 'DOMAIN\Readers' -Permissions Read -Scope ThisFolderOnly -OutputDirectory C:\NtfsAudit
Read-only Windows-style filesystem ACL plan, not share permissions or ONTAP writes.
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Plan -TargetPath '\\SERVER1\Share1\Folder' -GroupPermissionsJson '[{"GroupName":"DOMAIN\\Readers","Permissions":"ReadAndExecute"}]' -OutputDirectory C:\NtfsAudit
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Apply -PlanPath C:\NtfsAudit\Permissions_RUN\plan.json -PlanSHA256 REVIEWED_SHA256 -ChangeTicket CHG123 -OutputDirectory C:\NtfsAudit
This records Blocked/NotQualified; no target ACL write is possible.
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Apply -DisposableLocalLab -DisposableAcknowledgement -TargetPath C:\DisposableLab\Fixture -GroupName 'DOMAIN\LabReaders' -Permissions Read -ChangeTicket LAB123 -OutputDirectory C:\LabEvidence -WhatIf
Preview only. Remove -WhatIf only in an independently approved disposable lab.
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Revert -DisposableLocalLab -DisposableAcknowledgement -ReceiptPath C:\LabEvidence\Permissions_RUN\receipt.json -ReceiptSHA256 RETAINED_RECEIPT_SHA256 -ReviewedApplyJournalSHA256 REVIEWED_APPLY_JOURNAL_SHA256 -ChangeTicket LAB123 -OutputDirectory C:\LabEvidence
Review and retain the Apply evidence and hashes independently before Revert.
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Apply -DisposableLocalLab -DisposableAcknowledgement -Operation Replace -RemovePrincipal Everyone -TargetPath C:\DisposableLab\Fixture -GroupName 'DOMAIN\LabReaders' -Permissions ReadAndExecute -Scope ThisFolderSubfoldersAndFiles -ChangeTicket LAB123 -OutputDirectory C:\LabEvidence -WhatIf
Preview replacing explicit Everyone allow entries with the selected group.
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Apply -TargetPath '\\FILER1\Assessment\Finance' -TargetPlatform NetApp -Operation Replace -RemovePrincipal Everyone -GroupName 'DOMAIN\Finance-Modify' -Permissions Modify -ChangeTicket CHG123 -OutputDirectory C:\NtfsAudit -WhatIf
Preview replacing Everyone allow ACEs over standard Windows SMB on NetApp (no ONTAP CLI/API required).
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Apply -TargetPath '\\FILER1\Assessment\Finance' -TargetPlatform NetApp -Operation Replace -RemovePrincipal Everyone -GroupName 'DOMAIN\Finance-Modify' -Permissions Modify -ChangeTicket CHG123 -OutputDirectory C:\NtfsAudit -Confirm:$false
Execute handle-pinned Replace over SMB and write receipt.json, events.jsonl, and permissions-before-after.csv.
.EXAMPLE
.\Add-FileSharePermissions.ps1 -Mode Revert -ReceiptPath C:\NtfsAudit\Permissions_RUN\receipt.json -ReceiptSHA256 RETAINED_RECEIPT_SHA256 -ReviewedApplyJournalSHA256 REVIEWED_APPLY_JOURNAL_SHA256 -ChangeTicket CHG123-REV -OutputDirectory C:\NtfsAudit -Confirm:$false
Optional rollback using retained Apply receipt and journal SHA256 hashes.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Plan','Apply','Revert')][string]$Mode,
    [Alias('ShareName')][string]$TargetPath,
    [ValidateSet('Auto','Windows','NetApp','Nas')][string]$TargetPlatform = 'Auto',
    [string]$GroupName,
    [string]$Permissions,
    [string]$GroupPermissionsJson,
    [string]$GroupPermissionsFile,
    [ValidateSet('Add','Remove','Replace')][string]$Operation = 'Add',
    [string]$RemovePrincipal,
    [ValidateSet('ThisFolderSubfoldersAndFiles','ThisFolderOnly')][string]$Scope = 'ThisFolderSubfoldersAndFiles',
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$PlanPath,
    [string]$PlanSHA256,
    [string]$ChangeTicket,
    [string]$RecoveryManifestPath,
    [string]$RecoveryJournalPath,
    [string]$RecoveryJournalSHA256,
    [switch]$DisposableLocalLab,
    [switch]$DisposableAcknowledgement,
    [string]$ReceiptPath,
    [string]$ReceiptSHA256,
    [string]$ReviewedApplyJournalSHA256,
    [switch]$ReviewedPartialApplyRecovery,
    [ValidateRange(1,100000)][int]$MaxPaths = 10000,
    [ValidateRange(1,24)][int]$MaxPlanAgeHours = 24
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'NtfsPermissions.Common.ps1')

if ($DisposableLocalLab) {
    . (Join-Path $PSScriptRoot 'NtfsPermissions.Local.ps1')
    $labArguments = @{
        Mode=$Mode; TargetPath=$TargetPath; TargetPlatform=$TargetPlatform; GroupName=$GroupName
        Permissions=$Permissions; GroupPermissionsJson=$GroupPermissionsJson; GroupPermissionsFile=$GroupPermissionsFile
        Operation=$Operation; RemovePrincipal=$RemovePrincipal
        Scope=$Scope; OutputDirectory=$OutputDirectory; ChangeTicket=$ChangeTicket; MaxPaths=$MaxPaths
        DisposableAcknowledgement=$DisposableAcknowledgement; ReceiptPath=$ReceiptPath; ReceiptSHA256=$ReceiptSHA256
        ReviewedApplyJournalSHA256=$ReviewedApplyJournalSHA256
        ReviewedPartialApplyRecovery=$ReviewedPartialApplyRecovery; Preview=[bool]$WhatIfPreference
        CallerConfirmPreference=[string]$ConfirmPreference
        BoundParameters=$PSBoundParameters
    }
    $labResult = Invoke-NpDisposableLab @labArguments
    $labResult
    if ($labResult.Status -in @('Blocked','Indeterminate')) { exit 2 }
    exit 0
}
if ($DisposableAcknowledgement) {
    throw 'DisposableAcknowledgement requires -DisposableLocalLab; omit both for standard Apply or Revert.'
}
$hasPreparedPlanArgs = (
    $PSBoundParameters.ContainsKey('PlanPath') -or
    $PSBoundParameters.ContainsKey('PlanSHA256') -or
    $PSBoundParameters.ContainsKey('RecoveryManifestPath') -or
    $PSBoundParameters.ContainsKey('RecoveryJournalPath') -or
    $PSBoundParameters.ContainsKey('RecoveryJournalSHA256')
)
if ($Mode -in @('Apply','Revert') -and -not $hasPreparedPlanArgs) {
    . (Join-Path $PSScriptRoot 'NtfsPermissions.Local.ps1')
    $writeArguments = @{
        Mode=$Mode; TargetPath=$TargetPath; TargetPlatform=$TargetPlatform; GroupName=$GroupName
        Permissions=$Permissions; GroupPermissionsJson=$GroupPermissionsJson; GroupPermissionsFile=$GroupPermissionsFile
        Operation=$Operation; RemovePrincipal=$RemovePrincipal
        Scope=$Scope; OutputDirectory=$OutputDirectory; ChangeTicket=$ChangeTicket; MaxPaths=$MaxPaths
        ReceiptPath=$ReceiptPath; ReceiptSHA256=$ReceiptSHA256
        ReviewedApplyJournalSHA256=$ReviewedApplyJournalSHA256
        ReviewedPartialApplyRecovery=$ReviewedPartialApplyRecovery; Preview=[bool]$WhatIfPreference
        CallerConfirmPreference=[string]$ConfirmPreference
        BoundParameters=$PSBoundParameters
    }
    $writeResult = Invoke-NpPermissionWrite @writeArguments
    $writeResult
    if ($writeResult.Status -in @('Blocked','Indeterminate')) { exit 2 }
    exit 0
}
if ($ReceiptPath -or $ReceiptSHA256 -or $ReviewedApplyJournalSHA256 -or $ReviewedPartialApplyRecovery) {
    throw 'Receipt and partial-Apply recovery options apply only to direct Apply/Revert runs without -PlanPath.'
}
if ($Operation -ne 'Add' -or $PSBoundParameters.ContainsKey('RemovePrincipal')) {
    throw 'Remove and Replace are executed with -Mode Apply (use -WhatIf to preview), not review-only -Mode Plan.'
}

# Parse/hash a supplied plan only once. Defer errors until safe local audit exists.
$plan = $null
$preflightError = ''
$targetHint = ''
$targetDescriptor = $null
try {
    if ($Mode -eq 'Plan') {
        $targetHint = ConvertTo-NpPath $TargetPath
        $targetDescriptor = Resolve-NpTarget $TargetPath $TargetPlatform
        $targetHint = $targetDescriptor.CanonicalPath
    }
    elseif ($PlanPath -and $PlanSHA256) {
        $plan = Read-NpPlan $PlanPath $PlanSHA256 (Get-NpSourceHash) $MaxPlanAgeHours
        $targetHint = $plan.Target
    }
} catch { $preflightError = $_.Exception.Message }
$run = New-NpRun $OutputDirectory $targetHint
$journal = New-NpJournal $run $Mode $ChangeTicket $PlanSHA256 $TargetPath
$lock = $null
$runLock = $null
$status = 'Failed'
$reason = ''
try {
    $runLock = [IO.FileStream]::new((Join-Path $run 'run.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    Write-NpEvent $journal 'Start' 'Started' @("Mode=$Mode; Scope=$Scope; MaxPaths=$MaxPaths; WhatIf=$WhatIfPreference")
    if ($preflightError) { throw $preflightError }
    if ($Mode -eq 'Plan') {
        if ($PlanPath -or $PlanSHA256 -or $RecoveryManifestPath -or $RecoveryJournalPath -or $RecoveryJournalSHA256) { throw 'Plan input cannot include reviewed recovery evidence.' }
        $target = $targetDescriptor.CanonicalPath
        $journal.Target = $target
    } else {
        if ($TargetPath -or $GroupName -or $Permissions -or $GroupPermissionsJson -or $GroupPermissionsFile -or $PSBoundParameters.ContainsKey('Scope') -or $PSBoundParameters.ContainsKey('TargetPlatform')) { throw 'Apply/Revert accept only the bound plan, ticket and output options; platform cannot be overridden.' }
        if (-not $PlanPath -or -not $PlanSHA256 -or [string]::IsNullOrWhiteSpace($ChangeTicket) -or $ChangeTicket -match '[\x00-\x1f]') { throw 'Apply/Revert require PlanPath, reviewed PlanSHA256 and ChangeTicket.' }
        $target = $plan.Target
        $targetDescriptor = $plan.TargetDescriptor
        $journal.Target = $target
    }
    Assert-NpExecutionHost $targetDescriptor
    $lock = Enter-NpTargetLock $target
    if ($Mode -ne 'Plan') {
        if ($RecoveryManifestPath -or $RecoveryJournalPath -or $RecoveryJournalSHA256) {
            if ($Mode -ne 'Revert' -or -not $RecoveryManifestPath -or -not $RecoveryJournalPath -or -not $RecoveryJournalSHA256) { throw 'Revert recovery review requires manifest, source journal and reviewed journal SHA256 together.' }
            $recovery = Read-NpRecoveryEvidence $RecoveryManifestPath $PlanSHA256 $RecoveryJournalPath $RecoveryJournalSHA256 (Get-NpSourceHash)
            Write-NpEvent $journal 'RecoveryEvidence' $recovery.Status @("ManifestSHA256=$($recovery.ManifestSHA256)")
        }
        $status = 'Blocked'
        $reason = "MutationNotQualified/$($targetDescriptor.QualificationScope): live Apply/Revert disabled; no qualified native ACL writer is connected to this entry point. Qualify this exact platform separately; Windows tests never qualify NetApp/NAS."
        Write-NpEvent $journal 'QualificationGate' 'Blocked/NotQualified' @("QualificationScope=$($targetDescriptor.QualificationScope); MutationNotQualified")
    } else {
        Write-Progress -Activity 'NTFS plan' -Status 'Validate every group before ACL inventory'
        $grants = @(Get-NpGrants $GroupName $Permissions $GroupPermissionsJson $GroupPermissionsFile ${function:Resolve-NpWindowsGroup})
        Write-NpEvent $journal 'ClientADGroupsResolved' 'TargetAuthorityUnverified' @($grants | ForEach-Object { "$($_.SID):$($_.Permissions)" })
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows read-only NTFS planning adapter required. No live mutation is available on any platform.' }
        $inventory = Get-NpWindowsInventory $target $Scope $MaxPaths
        $plan = New-NpPlan $target $grants $Scope $inventory (Get-NpSourceHash) $targetDescriptor
        $planFile = Join-Path $run 'plan.json'
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes((Get-NpCanonicalJson $plan))
        $planStream = [IO.FileStream]::new($planFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
        try { $planStream.Write($bytes,0,$bytes.Length); $planStream.Flush($true) } finally { $planStream.Dispose() }
        $journal.PlanHash = Get-NpBytesHash $bytes
        $rows = foreach ($entry in $plan.Entries) {
            [pscustomobject][ordered]@{
                Path=$entry.Before.Path; Kind=$entry.Before.Kind; Identity=$entry.Before.Identity
                Protected=$entry.Before.Protected; Boundary=$entry.Boundary; NoOpIntent=$entry.Proposal.NoOp
                BeforeSHA256=(Get-NtfsHash (Get-NpCanonicalJson $entry.Before))
                IntentSHA256=(Get-NtfsHash (Get-NpCanonicalJson $entry.Proposal.Intent))
                BeforeDescriptor=$entry.Before.Descriptor; Status='ReviewOnly/NotQualified'
            }
        }
        if (@($rows).Count) { Export-NtfsCsvData @($rows) (Join-Path $run 'before-and-intent.csv') }
        $manifest = [ordered]@{
            Schema='NtfsPermissionsEvidence/1'; PlanSHA256=$journal.PlanHash; SourceHash=$plan.SourceHash
            Files=@(Get-ChildItem -LiteralPath $run -File | Where-Object { $_.Name -eq 'plan.json' -or $_.Extension -eq '.csv' } | ForEach-Object {
                [ordered]@{ Name=$_.Name; SHA256=(Get-NpBytesHash ([IO.File]::ReadAllBytes($_.FullName))) }
            })
        }
        [IO.File]::WriteAllText((Join-Path $run 'manifest.json'),(Get-NpCanonicalJson $manifest),[Text.UTF8Encoding]::new($false))
        $status = if (-not $plan.CoverageComplete) { 'Blocked' } elseif ($WhatIfPreference) { 'WhatIf' } else { 'Planned' }
        $reason = $plan.Reasons -join '; '
        Write-NpEvent $journal 'PlanSaved' 'Planned' @("Paths=$($plan.Entries.Count); CoverageComplete=$($plan.CoverageComplete)")
        Write-Host ("Before evidence: {0} paths, {1} boundaries. Scope: {2}" -f $plan.Entries.Count,$plan.Boundaries.Count,$plan.Scope)
        $grants | Format-Table GroupName,SID,Permissions | Out-Host
        $rows | Select-Object Path,Kind,Protected,Boundary,BeforeDescriptor,NoOpIntent | Format-List | Out-Host
        Write-Host "Reviewed plan SHA256: $($journal.PlanHash)"
    }
    Write-NpEvent $journal 'Complete' $status
} catch {
    $reason = $_.Exception.Message
    # Any public failure is pre-mutation: native target setter does not exist.
    $status = 'Blocked'
    try { Write-NpEvent $journal 'Stopped' 'Blocked/NotQualified' } catch { $reason += '; AUDIT FAILURE: ' + $_.Exception.Message }
} finally {
    Write-Progress -Activity 'NTFS plan' -Completed
    if ($null -ne $lock) { $lock.ReleaseMutex(); $lock.Dispose() }
    if ($null -ne $runLock) { $runLock.Dispose() }
}
$completion=@{
    component='Permission planning';status=$status;outputPath=$run
    summary="Mode=$($Mode); TargetWrites=0; WriterQualification=NotQualified. $($reason)"
    reviewPath=@((Join-Path $run 'events.jsonl'))
    requirements=$(if($status -eq 'Blocked'){
        'Resolve/review 1 blocked result using the reason below; live mutation has 1 non-bypassable qualification restriction, not a bypassable missing parameter.'
    }else{
        $planningActions=@(
            if($plan.Reasons.Count -gt 0){"Review $($plan.Reasons.Count) planning/qualification warnings."}
            if($plan.Boundaries.Count -gt 0){"Review $($plan.Boundaries.Count) protected boundaries."}
            'Live mutation has 1 non-bypassable qualification blocker.'
        )
        $planningActions -join ' '
    })
    reasonSummary=@(
        if($Mode -eq 'Plan' -and $null -ne $plan){
            $plan.Reasons|Group-Object|ForEach-Object{[pscustomobject]@{Count=$_.Count;Reason=$_.Name}}
        }elseif($reason){[pscustomobject]@{Count=1;Reason=$reason}}
    )
    nextStep=$(if($status -eq 'Blocked'){
        'Preserve the journal. If planning inputs/coverage were invalid, next script: Add-FileSharePermissions.ps1 -Mode Plan after resolving them. Live Apply/Revert are disabled; no next script in this toolkit can perform the change.'
    }else{
        'No next executable change script is available. Review plan.json and before-and-intent.csv. Invoke-NtfsPermissionValidation.ps1 is only for a separately approved disposable-lab evidence workflow, not production Apply/Revert.'
    })
}
if($Mode -eq 'Plan' -and $status -ne 'Blocked'){$completion.reviewPath+=@((Join-Path $run 'plan.json'),(Join-Path $run 'before-and-intent.csv'))}
Write-NtfsCompletion @completion
[pscustomobject]@{
    Version=$script:NtfsVersions.Permissions
    Status=$status; PlanningStatus='PlanningSupported'; MutationStatus='MutationNotQualified'
    Qualification='NotQualified'; TargetDescriptor=$targetDescriptor
    Mode=$Mode; RunDirectory=$run; PlanSHA256=$journal.PlanHash; Reason=$reason; TargetWrites=0
}
if ($status -eq 'Blocked') { exit 2 }
exit 0
