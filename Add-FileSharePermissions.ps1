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
Read-only NTFS permission planning with audited, DISABLED live Apply/Revert.
.DESCRIPTION
Release version is recorded in plan and audit evidence.

Matches the shared permissions engine and evidence version.
Plan validates all security groups and snapshots a local fixed Windows NTFS
directory, verified mapped drive (converted to UNC), or deep direct UNC and affected
folders AND files. Default scope is ThisFolderSubfoldersAndFiles through existing
inheritance only. Protected descendant boundaries are recorded, not traversed.
No SMB share ACLs, inheritance toggles, or recursive explicit grants are written.
Plans are review-only/Blocked, not executable. Native mutation is absent.

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

Apply/Revert require a reviewed SHA256 and ticket but always emit Blocked /
NotQualified before any target write, including with WhatIf/Confirm. WhatIf never
changes target permissions; local audit/evidence is still written. Approvals are not
identity authorization; SHA256 and a local hash chain are not tamper-proof.
Archive plans, manifests, source hashes and journals externally under enterprise
access control. Audit/run locks are local only, not distributed locks. Output
must be on a trusted local volume which is not the share's backing directory.
Known same-named local SMB backing paths are checked and mapped output drives
are rejected. The caller must independently validate remaining physical mappings
(aliases, subst/8.3/DFS); this tool cannot prove them.
Named target mutexes coordinate this host only (not aliases or other hosts).
Reports use the toolkit's 100,000,000-byte CSV part cap.
Revert can additionally review RecoveryManifestPath, RecoveryJournalPath and
RecoveryJournalSHA256 together. This verifies source/evidence bindings only;
it never authorizes or executes restoration.

PlanningSupported does not mean writable support. MutationNotQualified applies
independently to LocalWindows, WindowsSMB, NetAppSMB and GenericSMB; Windows tests
cannot qualify NetApp/NAS. Apply/Revert exit nonzero after recording Blocked.
Old plans without addressing/platform/recovery bindings require replanning.
Qualification still required on disposable Windows NTFS and each isolated SMB backend:
identity-bound handles and stable volume/file IDs; direct backend/DFS rejection;
controlled propagation for both scopes; exclusive handle availability (fail if
unavailable), consequences for SMB clients, and SetSecurityInfo inheritance vs
exclusive-handle propagation suppression; concurrent administrator drift; exact
DACL/owner/group/control and identity verification on every affected path; guarded
per-path rollback under propagation, protected boundaries and crashes/timeouts.
SetKernelObjectSecurity is unsupported for files and is never used.
No Force/experimental bypass exists. Offline mocks do NOT qualify this release.
Failures stop, preserve evidence and require explicit recovery review; never retry
or auto-rollback. Torn journal tails are Indeterminate and retained unchanged.
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
    [ValidateSet('ThisFolderSubfoldersAndFiles','ThisFolderOnly')][string]$Scope = 'ThisFolderSubfoldersAndFiles',
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$PlanPath,
    [string]$PlanSHA256,
    [string]$ChangeTicket,
    [string]$RecoveryManifestPath,
    [string]$RecoveryJournalPath,
    [string]$RecoveryJournalSHA256,
    [ValidateRange(1,100000)][int]$MaxPaths = 10000,
    [ValidateRange(1,24)][int]$MaxPlanAgeHours = 24
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'NtfsPermissions.Common.ps1')

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
        $reason = "MutationNotQualified/$($targetDescriptor.QualificationScope): live Apply/Revert disabled; no native ACL writer exists. Qualify this exact platform separately; Windows tests never qualify NetApp/NAS."
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
Write-Host "$status : $reason"
[pscustomobject]@{
    Version=$script:NtfsPermissionsVersion
    Status=$status; PlanningStatus='PlanningSupported'; MutationStatus='MutationNotQualified'
    Qualification='NotQualified'; TargetDescriptor=$targetDescriptor
    Mode=$Mode; RunDirectory=$run; PlanSHA256=$journal.PlanHash; Reason=$reason; TargetWrites=0
}
if ($status -eq 'Blocked') { exit 2 }
exit 0
