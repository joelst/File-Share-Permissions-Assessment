# NetApp SMB validation runbook

This is an execution and defect-response plan, not a qualification certificate.
It covers the public assessment, reporting and permission-planning workflows and
the safety gates of the unfinished writer. Some live read-only cases have been
exercised on a specific empty share; the complete matrix remains unfinished.
The existing scripts and Pester preflight are executable; the case matrix below
also contains operator-executed checks which are not automated. Record Pass,
Fail, Blocked or NotRun for every applicable case. A pass requires the stated
evidence, not just a zero exit code.

## Safety and scope

- Use only a separately approved, isolated, disposable SMB share and AD objects.
  No production data, production identities or shared namespace. The operator
  must independently verify the actual SVM, volume, security style, direct
  backend, share and backup; `-TargetPlatform NetApp` is only a declaration.
- The toolkit's default Apply and Revert are blocked. Its disposable writer is
  **local fixed Windows NTFS only**. Never enable, bypass, adapt or run that
  writer against UNC, mapped, SMB or NetApp paths. NetApp mutation is not
  qualified. External fixture changes below require a separate change approval,
  an independent recovery procedure and a verified backup.
- Do not reboot, disrupt network/storage, revoke service access, touch unrelated
  accounts or share settings, or inject host/storage faults in a shared system.
  Destructive concurrency, outage and failover experiments need a separately
  isolated environment and explicit approval.
- Output and sensitive evidence stay on trusted, access-restricted local fixed
  storage outside the checkout, assessed namespace and its backing storage.
  Independently check DFS, aliases, mappings and physical separation. Names,
  ACLs, identities, paths, transcripts and ONTAP exports are sensitive. Do not
  commit them, passwords or credentials to Git. Archive evidence and hashes
  independently; local hashes are not authentication.

## Before starting billable NAS time

1. Freeze the checkout, record commit and dirty diff and hash every script used.
   Preserve the exact source archive outside the target. Install PowerShell 5.1,
   PowerShell 7, RSAT ActiveDirectory and Pester 5.2+ through an approved process
   beforehand. Run the existing offline assessment, best-practices and permission
   regressions in both editions; keep their results and fix failures first.
2. Prepare a domain-joined Windows collector and, if effective access is tested,
   a separate Windows SMB client. Check DNS, clock, AD connectivity, network,
   Kerberos/SMB policy and local evidence capacity. Use a fresh logon/token after
   group membership changes. Record the negotiated dialect, signing/encryption
   and authentication from the client and backend, without capturing secrets.
3. Allocate a uniquely named disposable share, direct UNC and NTFS security
   style. For Azure NetApp Files, record region, service/volume and endpoint,
   delegated subnet, connectivity and Active Directory integration; record the
   SVM only if the service exposes it. For self-managed ONTAP, record cluster,
   SVM and volume. Do not assume ONTAP CLI/API access exists in a managed
   service. Independently document any DNS alias, DFS, junction, tier or backend
   features used. Prepare a small known tree with root, two nested directories,
   files, an explicit allow, an inherited allow, an applicable deny, a protected
   child with sentinel, and a separate inaccessible branch outside Case1. Include a directory
   whose name exercises Unicode/CSV escaping and one longer path supported by
   the environment. If possible add a separately approved reparse point which
   resolves only within a disposable namespace. Record exact owner, group, DACL,
   ACE SIDs, types, masks, inheritance/propagation flags and expected scope by
   path independently, plus file hashes. Record branch creation and permission
   changes as external actions; do not assume Windows and ONTAP interpret all
   controls identically.
4. Prepare isolated AD security groups and distinct allowed, denied and control
   accounts, including a nested group and a resolvable group with no members.
   Record SIDs and memberships without passwords. Arrange least-privilege
   collector and an authorized administrator to collect ONTAP share ACL/config
   and an independent Windows `Get-Acl`/`icacls` baseline. An inaccessible branch
   must truly be inaccessible to the collector; validate with its actual token.
5. If authoritative share-permission export is available, prepare a scoped
   ONTAP CSV containing only the selected server/share, with
   `smb_server,smb_share,user_or_group,permission` and, where available, `sid`
   and `vserver`. Valid permissions are `read`, `change`, `full`, `full control`
   and `no access` (underscores are accepted). Retain the authoritative raw
   export and conversion procedure. CSV import does not prove completeness.
   Prepare separate malformed, outside-scope and ambiguous-SVM copies locally.
   If unavailable, record N06/N07 as Blocked and omit
   `-OntapSharePermissionsCsv` from collection rather than fabricating evidence.
6. Preassign an operator and independent reviewer, case IDs, ticket, evidence
   locations, approved external action/recovery steps and go/no-go budget. The
   minimum live window consists of preflight, baseline, one controlled change,
   second capture, recovery and final capture. Reports, CSV-corruption tests and
   most defect analysis can run offline after evidence is archived. Stop the
   resource only after recovery is independently verified, pending cases and
   evidence are recorded, and the owner approves deallocation. Estimates depend
   on provisioning and permissions; do not promise a fixed completion time.

## Live collection commands

Use a **new empty evidence parent per edition**, run from the frozen checkout,
and record console output, exact commands, start/end UTC and each exit code. The
following examples deliberately do not create or modify the NAS fixture.
Replace every placeholder; `$Target` is the share root and `$Case` is its
approved test subtree. Set local ACLs on the evidence parent independently.

```powershell
$Server = 'NETAPP-SMB-NAME'
$Share = 'DISPOSABLE-SHARE'
$Target = "\\$Server\$Share"
$Case = "$Target\Case1"
$Evidence = 'C:\RestrictedNetAppEvidence\PS51' # use a different parent for PS7
$Group = 'LAB\DisposableReaders'
$Ticket = 'LAB-CHANGE-ID'
$OntapCsv = 'C:\RestrictedNetAppEvidence\ontap-scoped.csv'

git status --short
git rev-parse HEAD
@(Get-ChildItem -File | Where-Object Extension -in '.ps1', '.cs'
  Get-Item .\Tests\NtfsPermissions.WindowsQualification.Tests.ps1) |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv -NoTypeInformation -Path (Join-Path $Evidence 'source-hashes.csv')

# Baseline: same target and limits must be used for comparison.
.\Invoke-NtfsAssessment.ps1 -UncPath $Target -OutputRoot (Join-Path $Evidence 'before') `
    -ResolveActiveDirectory -BestPractices -CollectAuditEvidence -HashOutputs `
    -SplitOutputByShare -OntapSharePermissionsCsv $OntapCsv
$beforeExit = $LASTEXITCODE

# Select the ONLY run in this new dedicated parent, after checking the count.
$runs = @(Get-ChildItem -LiteralPath (Join-Path $Evidence 'before') -Directory -Filter 'ASSESS_*')
if ($runs.Count -ne 1) { throw 'Expected exactly one baseline run; preserve and inspect evidence.' }
$Before = $runs[0].FullName
$beforeExit

# Preserve the original run in place while checking its absolute-path hash list.
foreach ($row in Import-Csv -LiteralPath (Join-Path $Before 'SHA256SUMS.csv')) {
    if (-not (Test-Path -LiteralPath $row.Path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $row.Path -Algorithm SHA256).Hash -ne $row.Hash) {
        throw "Missing or mismatched assessment output: $($row.Path)"
    }
}
```

Inspect the baseline before further stages: `manifest.json`, `run.log`,
`ShareCoverage.csv`, `ScanErrors.csv`, `SkippedPaths.csv`, `GroupExpansion.csv`
and all hash/part files. The expected inaccessible branch makes that specific
run partial; to also validate complete coverage use an independently prepared
accessible subtree as a separate scope/run. A fatal error, wrong target, missing
scope or unexpected gap is a stop, not a pass. Independently record per-case
descriptors and file hashes before any approved external action.

For comparison, repeat the same collection after the one approved external
change and again after independently approved recovery. Execute this block once
per stage after setting `$stage` to `after` or `recovered` at the appropriate
checkpoint; record the returned path as `$After` or `$Recovered`, respectively.
Apply the same hash verification and coverage review as for the baseline.

```powershell
$stage = 'after' # use 'recovered' only after independently approved recovery
.\Invoke-NtfsAssessment.ps1 -UncPath $Target -OutputRoot (Join-Path $Evidence $stage) `
    -ResolveActiveDirectory -BestPractices -CollectAuditEvidence -HashOutputs `
    -SplitOutputByShare -OntapSharePermissionsCsv $OntapCsv
$stageExit = $LASTEXITCODE
$runs = @(Get-ChildItem -LiteralPath (Join-Path $Evidence $stage) -Directory -Filter 'ASSESS_*')
if ($runs.Count -ne 1) { throw 'Expected exactly one run; preserve and inspect evidence.' }
$stageRun = $runs[0].FullName
$stageExit
$stageRun
```

Do not compare unlike scopes or editions as if they were identical runs. Keep a
second unchanged before snapshot as a separate run if testing repeatability. Do
not alter source runs.

```powershell
.\Merge-NtfsAssessment.ps1 -InputRoot (Join-Path $Evidence 'before') `
    -RunSelection Explicit -RunFolder $Before -ThrottleLimit 1 `
    -OutputFolder (Join-Path $Evidence 'merge')
$mergeExit = $LASTEXITCODE
.\New-NtfsBestPracticesReport.ps1 -InputRunFolder $Before `
    -OutputFolder (Join-Path $Evidence 'best-practices')
$bpExit = $LASTEXITCODE
.\Compare-NtfsAssessment.ps1 -BaselineRunFolder $Before -ComparisonRunFolder $After `
    -OutputFolder (Join-Path $Evidence 'change-comparison')
$compareExit = $LASTEXITCODE
.\Compare-NtfsAssessment.ps1 -BaselineRunFolder $Before -ComparisonRunFolder $Recovered `
    -OutputFolder (Join-Path $Evidence 'recovery-comparison')
$recoveryCompareExit = $LASTEXITCODE
$mergeExit, $bpExit, $compareExit, $recoveryCompareExit

# Planning is read-only and writes only local evidence.
$plan = .\Add-FileSharePermissions.ps1 -Mode Plan -TargetPath $Case `
    -TargetPlatform NetApp -GroupName $Group -Permissions ReadAndExecute `
    -Scope ThisFolderSubfoldersAndFiles -OutputDirectory (Join-Path $Evidence 'plans')
$planExit = $LASTEXITCODE
$plan | Format-List
$planExit
```

Save and review `merge-state.json`, `MergeSourceRuns.csv`,
`NTFS_ExecutiveSummary.json`, `NTFS_QA.json`, detailed findings and coverage,
best-practices checks/summary/manifest, and each `comparison-state.json`,
summary, coverage and changes. Comparison differences are not themselves an
error. Exit 1 for assessment/merge/comparison denotes partial or limited output;
2 denotes failure. Best-practices report exit 0 does not mean all evidence is
assessed. Inspect plan `Status`, `Reason`, `plan.json`, `before-and-intent.csv`,
`manifest.json`, events and source/plan hashes; `NoOp` is not effective access.

To run the existing read-only preflight against the prepared accessible fixture
with a file and protected boundary, in each edition:

```powershell
$env:NTFS_PERMISSION_QUALIFICATION_TARGET = $Case
$env:NTFS_PERMISSION_QUALIFICATION_PLATFORM = 'NetApp'
$env:NTFS_PERMISSION_QUALIFICATION_DISPOSABLE = 'YES'
$cfg = New-PesterConfiguration
$cfg.Run.Path = (Resolve-Path .\Tests\NtfsPermissions.WindowsQualification.Tests.ps1).Path
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'Detailed'
$cfg.TestResult.Enabled = $true
$cfg.TestResult.OutputPath = Join-Path $Evidence 'netapp-preflight.xml'
$result = Invoke-Pester -Configuration $cfg
$result | Format-List Result, PassedCount, FailedCount, SkippedCount, NotRunCount
Remove-Item Env:\NTFS_PERMISSION_QUALIFICATION_TARGET, Env:\NTFS_PERMISSION_QUALIFICATION_PLATFORM, Env:\NTFS_PERMISSION_QUALIFICATION_DISPOSABLE
```

All four preflight tests must actually run and pass. It remains a read-only
scaffold, not a writer or backend qualification. A skipped suite is NotRun.

### Additional executable collection and gate cases

Use distinct new output directories; save each exit code and inspect its run
before proceeding. These commands do not change the target.

```powershell
# N03: discovery is allowed to find only the exact disposable share.
.\Invoke-NtfsAssessment.ps1 -NasServer $Server -IncludeShare $Share `
    -OutputRoot (Join-Path $Evidence 'discovery') -HashOutputs
$LASTEXITCODE

# N04: list-only mode isolates the Enabled flag from discovery.
$shareList = Join-Path $Evidence 'nas-list.csv'
[pscustomobject]@{ NasServer=$Server; ShareName=$Share; Enabled='True' } |
    Export-Csv -NoTypeInformation -Path $shareList
.\Invoke-NtfsAssessment.ps1 -NasShareListCsv $shareList -IncludeShare $Share `
    -OutputRoot (Join-Path $Evidence 'list-enabled') -HashOutputs
$LASTEXITCODE
[pscustomobject]@{ NasServer=$Server; ShareName=$Share; Enabled='False' } |
    Export-Csv -NoTypeInformation -Path (Join-Path $Evidence 'nas-list-disabled.csv')
.\Invoke-NtfsAssessment.ps1 -NasShareListCsv (Join-Path $Evidence 'nas-list-disabled.csv') `
    -IncludeShare $Share -OutputRoot (Join-Path $Evidence 'list-disabled') -HashOutputs
$LASTEXITCODE

# N10: bounded scans should expose omitted coverage.
.\Invoke-NtfsAssessment.ps1 -UncPath $Target -MaxDepth 0 `
    -OutputRoot (Join-Path $Evidence 'depth-limit') -HashOutputs
$LASTEXITCODE
.\Invoke-NtfsAssessment.ps1 -UncPath $Target -MaxFolders 1 `
    -OutputRoot (Join-Path $Evidence 'folder-limit') -HashOutputs
$LASTEXITCODE
```

For N07, provide each separately prepared invalid CSV as
`-OntapSharePermissionsCsv` to an otherwise identical scoped assessment; use a
fresh output for each and inspect `ScanErrors.csv` and `SharePermissions.csv`.
For N09, the CSV needs a `DomainServer`, `Server`, or `Domain` column containing
directory-server names; include it with `-ResolveActiveDirectory`.

For N24, first review the plan result, source and hash from the same frozen
checkout. If it is blocked or lacks a plan, record this case Blocked; do not
substitute another plan. The default operations below should be blocked and
must never write the target:

```powershell
$PlanPath = Join-Path $plan.RunDirectory 'plan.json'
$PlanHash = $plan.PlanSHA256
if ($planExit -ne 0 -or -not $PlanHash -or -not (Test-Path -LiteralPath $PlanPath)) {
    throw 'No reviewable plan; stop and retain evidence.'
}
foreach ($mode in 'Apply', 'Revert') {
    foreach ($preview in @($true, $false)) {
        $gate = .\Add-FileSharePermissions.ps1 -Mode $mode -PlanPath $PlanPath `
            -PlanSHA256 $PlanHash -ChangeTicket $Ticket `
            -OutputDirectory (Join-Path $Evidence "gate-$mode-$preview") -WhatIf:$preview
        $gateExit = $LASTEXITCODE
        $gate | Format-List
        if ($gateExit -eq 0 -or $gate.Status -ne 'Blocked' -or $gate.TargetWrites -ne 0) {
            throw "Unexpected $mode gate result; preserve evidence and stop."
        }
    }
}
```

## Case matrix

Run each applicable live case in **both PowerShell editions**; capture fixture
version, actor/token, UTC, command, exit/status, expected/actual and evidence
paths. Perform independent descriptor and access observations from a separate
client where specified. If an option needs a second share/alias/account or an
independently approved fixture change and it is not available, mark Blocked.
The case IDs are review records, not an existing automated test selector.

| ID | Feature and execution | Required observation |
| --- | --- | --- |
| N01 | Direct UNC baseline; compare to the independent tree and ONTAP metadata. | Intended server/share/root only; directory ACL SIDs, masks, types, inheritance and ownership match; no invented file ACL coverage. |
| N02 | Scan an accessible child directly and compare to matching baseline subtree. | Declared scope and matching records agree; no siblings claimed. |
| N03 | `-NasServer $Server -IncludeShare $Share` in a new run. | Discovery results and any failure are visible; only the selected share is assessed. No assumption that SMB discovery is complete. |
| N04 | Run with a local `NasServer,ShareName,Enabled` CSV, first enabled then disabled, without `-NasServer`; include the test share. | Enabled row scanned; disabled row not selected. Discovery can independently find a disabled CSV share if `-NasServer` is also supplied. |
| N05 | Exact include/exclude filters, duplicate and overlapping root paths. | Exclusions are honored, overlap is reported/handled without double-counting or claiming unseen coverage. Zero selected scopes is not a successful assessment. |
| N06 | Import authoritative scoped ONTAP CSV; compare every entry to its source. | Principal, optional SID/SVM, allow/deny and permission preserved; share metadata/ACL completeness remains unknown. |
| N07 | Run separate invalid, out-of-scope, blank, unsupported-permission and mixed-SVM CSVs, each with a fresh output. | Import fails atomically with recorded `OntapCsvImport` error/partial status; no partial imported rows or cross-scope attribution. |
| N08 | Baseline with and without `-ResolveActiveDirectory`; test nested, empty and unresolved group identities. | SID/identity evidence and group expansion statuses reflect actual outcomes. Unresolved, partial, limits, cycles or missing AD never become complete membership claims. |
| N09 | Test `-DomainServerCsv` with an approved reachable directory server, then a deliberately unreachable server; vary `-MaxExpandedMembers` with a known larger group. | Correct lookup or explicit resolution/expansion limitation; truncation never appears complete. The CSV is a list of servers, not a domain-to-server mapping. Preserve CSV and errors. |
| N10 | Re-run with low `-MaxDepth` and `-MaxFolders`, each separately. | Omitted descendants/limit reasons appear in coverage and skipped/error records; no complete-coverage claim. |
| N11 | Inaccessible branch, protected inheritance, optional approved reparse point and `~snapshot` directory, long path and unusual names. | Compare actual observed tree to coverage/errors; inaccessible or unsupported paths are not silently treated as assessed; reparse and `~snapshot` are not traversed. `-FollowReparsePoints` is rejected. |
| N12 | `-HashOutputs` and `-SplitOutputByShare`; verify every SHA256 row at its recorded path and dataset parts/counts. | All hashes match; per-share copies agree with scoped originals, all parts retained. Move/copying evidence can make recorded absolute paths require review. |
| N13 | Compare Windows 5.1 and 7 baseline records after excluding run IDs/timestamps/order. | Equivalent scoped ACL multisets and coverage, or document backend/client-dependent differences; neither edition proves effective access. |
| N14 | Built-in `-BestPractices -CollectAuditEvidence`, then offline report. | Known DACL findings and baseline expectations match fixtures; unsupported NAS configuration/audit is `NotAssessed`, not inferred from collector. Explicit UNC root SACL is at most a sample. |
| N15 | Offline best-practices custom policy override, then invalid policy. | Only specified allowlisted rules change; policy hash and expectation source recorded. Invalid schema/type/check rejected without changing source. |
| N16 | Merge baseline with `Explicit`, `LatestSuccessful`, `AllSuccessful`; use separate output folders. | Source selection and limitations are correct; overlapping historical snapshots are rejected where required, not combined or backfilled. Check detailed findings, risk and QA against known ACEs. |
| N17 | Offline merge filters, long-path threshold, throttle and row guard. | Filtered scopes correct, long paths reported, supported throttle produces consistent findings; low `MaxRowsPerShare` fails explicitly rather than truncating silently. |
| N18 | Unchanged snapshot comparison, then approved one-ACE change and recovery snapshots. | No material changes for unchanged comparable scopes; changed ACE appears as remove/add, recovery agrees within observed coverage; partial areas remain limited. Validate against independent descriptors. |
| N19 | Offline comparison using incompatible roots, partial scope, mismatched SVM/identity, missing evidence and a low row guard. | Failure or explicit `NotCompared`/limitations as applicable; absent records never imply deletion/revocation. |
| N20 | On copies only, corrupt a manifest, dataset/hash/part, and supply a nonempty/overlapping output folder to each offline report. | Integrity/containment failures are explicit; no fabricated report, source mutation or silent success. Original evidence remains unchanged. |
| N21 | Plan both scopes, `Read`, `ReadAndExecute`, `Modify`, `FullControl`; single group and multi-group JSON/file inputs on the disposable case. | Correct canonical UNC, declared NetApp adapter, requested abstract intent, files and folders/boundaries, source/hash binding; no target changes. Check valid and invalid inputs separately. |
| N22 | Plan via verified mapped path and direct deep UNC; repeat `Auto`, `NetApp`, `Nas`, and only where meaningful `Windows`. | Mapping is frozen to UNC, Auto is generic SMB, declarations do not establish backend authority or writable support; equivalent observed scope matches. |
| N23 | Plan with a protected child, inaccessible object, unsupported/reparse path, `MaxPaths` limit, and unresolved/unsupported local or SVM group. | Errors/boundaries and unassessed authority explicit; blocked/incomplete plans do not imply authorization or complete coverage. |
| N24 | With the reviewed plan/hash and ticket, test default Apply and Revert, including `-WhatIf`, in new local audit directories. | Each returns nonzero and `Blocked`/`NotQualified`, `TargetWrites=0`; independent before/after descriptors and file hashes unchanged. Recovery evidence verification does not restore. |
| N25 | In disposable-lab mode, attempt NAS/UNC and a verified mapped UNC with `-WhatIf`, then without it only under explicit negative-test approval. | Rejected before target write regardless of acknowledgement; preserve audit/error and independently compare descriptors. Do not test by bypassing the gate. |
| N26 | `Remove`/`Replace` against NAS through the public/default entry, plus invalid grant combinations. | Rejected; no target changes. Add/Remove/Replace real writes are only available for the distinct local fixed-NTFS lab candidate. |
| N27 | Initialize and CaptureBefore with `Invoke-NtfsPermissionValidation.ps1` on an approved disposable case, both scopes. | Frozen NetApp declaration, source/ticket/target binding, files and folders captured twice, boundaries and incomplete coverage reported. No target writes. |
| N28 | Separately approved external one-ACE apply, CaptureAfterApply, independently guarded external recovery, CaptureAfterRevert, Report. | Reviewed stages and external observations retain hashes. Unchanged is `NoChangeObserved`; restored descriptor is observational, not proof of atomicity or complete recovery. `WriterQualification` stays `NotQualified`. |
| N29 | Validation report with external copy of manual matrix; also report an unfinished new case. | Case/source/platform bindings enforced; submitted declarations are not execution proof; missing actions remain `NotRun`/incomplete. Sealed case is never edited. |
| N30 | Actual separate-client allowed, denied and control tokens: list/read and, only in a dedicated approved disposable write subtree, create/modify/delete and verify cleanup. | Record exact operations, identity, status, timestamps and resulting contents before/after the approved external change/recovery. Separate share and directory permission effects; do not infer general effective access. |
| N31 | Optional controlled concurrent descriptor/namespace edits, alias/DFS/backend movement and reconnect. | Only on an isolated disposable environment with an independent controller and approved stop/recovery plan. Capture both timelines and show incomplete/drift or safe refusal; otherwise NotRun. |
| N32 | Optional crash, power loss, storage failure, SVM failover and interrupted recovery. | No injection on shared infrastructure. Requires isolated fault lab, independently verified backups and recovery, preserved journals and independent review; otherwise NotRun. Current toolkit has no qualified NAS writer to crash-test. |

`-ComputerName`, CIM credentials, local `-UseIcaclsVerify`,
`-CaptureAclBackup`, local-group enumeration and local candidate provisioning
are Windows-oriented features, not a route to NAS-native evidence. Cover them
in the separate Windows qualification; confirm NAS use does not misrepresent
their outputs. `-OntapCredential` is intentionally rejected. ONTAP configuration,
native ACL completeness, file ACL collection in assessment, complete SACLs,
effective access and SVM-local group authority are not implemented claims.

## Validation walkthrough for the external change

Only after separate approval and complete, reviewed baseline:

```powershell
$init = .\Invoke-NtfsPermissionValidation.ps1 -Stage Initialize -TargetPath $Case `
    -TargetPlatform NetApp -GroupName $Group -Permissions Read `
    -ChangeTicket $Ticket -EvidenceDirectory (Join-Path $Evidence 'validation') `
    -DisposableAcknowledgement -NonInteractive
$init | Format-List
if ($init.Status -ne 'Observed') { throw 'Initialization not observed; preserve the case and stop.' }
$CasePath = $init.CasePath
$beforeStage = .\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureBefore -CasePath $CasePath -NonInteractive
$beforeStage | Format-List
if ($beforeStage.Status -ne 'Observed') { throw 'Baseline incomplete; preserve the case and stop.' }
```

Stop and independently review baseline completeness and approval. Only after
the external apply and independent access observations, run:

```powershell
$afterStage = .\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureAfterApply `
    -CasePath $CasePath -ManualActionAcknowledgement -NonInteractive
$afterStage | Format-List
if ($afterStage.Status -ne 'Observed') { throw 'After-apply capture incomplete; preserve the case and stop.' }
```

Stop and independently approve and perform external recovery; inspect the
resulting descriptors before running:

```powershell
$revertStage = .\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureAfterRevert `
    -CasePath $CasePath -ManualActionAcknowledgement -NonInteractive
$revertStage | Format-List
if ($revertStage.Status -ne 'Observed') { throw 'After-revert capture incomplete; preserve the case and stop.' }
.\Invoke-NtfsPermissionValidation.ps1 -Stage Report -CasePath $CasePath -NonInteractive
```

Archive each returned commit hash externally. If any stage fails, is incomplete
or is interrupted, preserve case, locks and all source/evidence and stop; do not
delete locks, retry automatically or assume restoration. Follow the README
validation workflow to copy and submit the manual matrix outside the sealed case.

## Defect response, retest and release decision

1. Stop on wrong target, unexpected mutation, descriptor drift, integrity failure,
   failed recovery or any unexplained access result. Do not continue with a new
   writer, retry, rollback or clean up evidence. Escalate to the owner; preserve
   original source, exact commands, logs, status, fixture/SVM configuration,
   baseline and after-state, independent hashes and time-ordered observations.
2. Record severity, affected feature/case, reproducible steps, expected vs actual,
   coverage, impact, whether credentials/data are exposed, edition and source
   hashes. Missing evidence is Blocked/NotRun or Incomplete, not a pass. Separate
   product defects from environment/unsupported behavior; do not weaken safety
   gates to make a case pass.
3. Freeze and export minimal sanitized evidence. Reproduce offline with mocks or
   a local isolated fixture where possible; add a focused regression that fails
   before the fix. Fix the root cause, run affected regression plus both editions'
   relevant suites and analyzer, then independently review. Protect unredacted
   logs and never publish sensitive lab values.
4. Assign a new source hash and new immutable output folders. Retest the original
   failing case and directly affected cases, including negative/safety behavior;
   preserve old/new results. Recollect live evidence only when backend behavior
   must be verified, grouping fixes into one approved short NAS window. Never
   resume an old source-bound validation case or recovery receipt under new code.
5. Release review requires traceability for every applicable public feature,
   expected limitations and all open defects; require no unresolved high-impact
   correctness/safety defect and explicit owner acceptance of remaining gaps.
   NetApp read-only interoperability is separate from Windows SMB and local NTFS.
   Passing this plan does not qualify NAS mutation, establish full effective
   access, or make the suite production-ready.
