# Permission modification: testing and evidence guide

## Start here: there is no enable switch

**The public toolkit cannot modify target permissions.** There is no qualified
production writer, and `Add-FileSharePermissions.ps1 -Mode Apply` and `-Mode Revert`
are deliberately blocked. Tickets, reviewed hashes, successful tests, and completed
validation reports do not unlock them. Do not remove the gate to start testing.

An internal local-NTFS candidate now exists in `NtfsPermissions.Local.ps1` /
`NtfsPermissions.Local.cs`. Its disposable integration tests are described in
the README. It is not connected to public modes, has unresolved qualification
gaps, and does not qualify any backend merely by passing tests.

## Targeted server lab runner

For an initial corporate-style fixture, see the README's
**creating a corporate-style disposable lab** workflow and
`Tests\New-NtfsLabFixture.ps1`. It creates real disposable AD objects, AGDLP
memberships, placeholder files, NTFS cases and an SMB share. It is separate from
the evidence runner below, which does not provision users, groups or a share.
The fixture does not replace dedicated crash, reparse, unsupported-ACL or
backend-specific experiments.

Run `Tests\Invoke-NtfsLabEvidence.ps1` on an **approved nonproduction file
server**, preferably not a production domain controller. It collects useful
diagnostics without requiring a target. Run separately on the file server and,
if needed, a domain-joined management host; a domain-controller run alone does
not qualify file-server or SMB behavior.

1. Copy the **complete current working tree**, including the untracked local
   candidate files, `Tests` directory, and this runner, to a dedicated local NTFS
   checkout. A checkout of `main` alone does not include uncommitted changes.
   Do not place the checkout inside a production share or assessed tree.
2. Sign in with an authorized account. Use Windows PowerShell 5.1 and, if
   available, PowerShell 7 in **separate runs**. Pester 5.2+ is required only for
   the optional suites; install it through an approved process if missing.
   The RSAT ActiveDirectory module and domain access are required only for an
   optional real security-group lookup. The runner does not install modules.
3. Choose trusted local fixed-volume output storage outside the checkout's
   `Tests` directory and the selected target, including its backing paths.
   Independently verify DFS, aliases, and physical separation. The runner makes
   a new `Permissions_<id>` directory with a restrictive ACL; it does not
   change the parent directory's ACL.
4. First collect the environment and source baseline:

   ```powershell
   .\Tests\Invoke-NtfsLabEvidence.ps1 -outputRoot C:\NtfsLabEvidence
   ```

5. To inspect an **approved disposable fixture** and resolve an existing lab
   security group, replace the example values:

   ```powershell
   .\Tests\Invoke-NtfsLabEvidence.ps1 `
       -outputRoot C:\NtfsLabEvidence `
       -groupName 'LAB\Readers' `
       -readOnlyTarget 'D:\DisposableLab\Case1' `
       -targetPlatform Windows `
       -readOnlyScope ThisFolderSubfoldersAndFiles `
       -maxPaths 1000
   ```

   The default scope is `ThisFolderOnly`; the recursive scope includes files
   and folders, stops at protected boundaries, and reports limits/errors.
   Target access is read-only. Group resolution does not change AD membership,
   prove target authority/trust, or test effective access. `targetPlatform` is
   an operator declaration, not backend proof.

6. With separate approval for **disposable fixtures**, run the targeted Pester
   suites:

   ```powershell
   .\Tests\Invoke-NtfsLabEvidence.ps1 `
       -outputRoot C:\NtfsLabEvidence `
       -runSyntheticTests `
       -runDisposableCandidateTests `
       -disposableAcknowledgement
   ```

   Both switches require the acknowledgement. The tests create files, change
   ACLs, and exercise failure/recovery cases in their own generated directories
   beneath the checkout's `Tests` directory. Synthetic fixtures are removed;
   the candidate fixture is **preserved** for review, including failures.
   They never use `readOnlyTarget` as a write target. The suites require a local
   fixed NTFS checkout with permission to set fixture ACLs. They use synthetic SIDs,
   not actual test-account access. Do not run these suites from a production
   share, a domain controller without explicit approval, or a checkout that is
   not disposable. Review and retain the generated fixture and logs before any
   separately approved cleanup; do not delete locks to retry a failed operation.

Each invocation creates a separate evidence directory and prints `EvidencePath`.
Start with `summary.json`, `environment.json`, `source-hashes.csv`,
`SHA256SUMS.csv`, and `transcript.txt`. Requested tests also create
`pester-summary.json` and `pester-results.xml`; the candidate suite also records
`candidate-fixture.json` and copies its available journals/locks into
`candidate-audits`. The original fixture remains at the path recorded in
`candidate-fixture.json`. Optional probes create
`ad-group.json` or `read-only-inventory.json`. A normal Windows run of the
synthetic suite skips one non-Windows-only test; other skips are reported as
incomplete. If a probe or suite fails, the runner retains the evidence, reports
`AttentionRequired`, and throws with the summary path. If evidence storage cannot
be created, the error is only on the console.

**Before sending logs:** review them for sensitive server names, accounts, SIDs,
paths, ACLs and error text. Never include credentials. Use an approved secure
transfer method; archive the originals and hashes under your controls. Redaction
changes file hashes, so identify redacted copies separately. Provide the full
relevant log rather than trimming individual errors.

These are targeted initial tests, not full qualification. They do not test real
account access, concurrent administrators, real crashes/disconnects, or manual
recovery. Public `Apply`/`Revert` remain blocked.

This guide has two milestones:

1. **Now:** verify read-only behavior and collect evidence around separately
   approved manual changes in a disposable lab.
2. **Before a future writable release:** implement an identity-bound writer and
   guarded recovery, test that exact implementation on each supported backend,
   and obtain independent approval for a narrowly defined release.

Manual ACL changes can characterize a backend, but cannot prove how a future
writer will behave. Repeat applicable experiments against the actual candidate
writer before approving it. Nothing here authorizes production changes.

## 1. Approve the scope and prepare the lab

Use a disposable target, isolated test accounts/groups, an approved change ticket,
and an independently tested backup/recovery procedure. Do not use production
directories or real business data for access, crash, or rollback experiments.

Keep these qualification tracks separate:

| Track | Example | Required independent evidence |
| --- | --- | --- |
| Local Windows NTFS | `D:\DisposableLab\Case1` | Execution host, fixed volume identity, filesystem, stable object identities |
| Windows SMB | `\\LABFS01\DisposableLab\Case1` | Client/server versions, direct share backing path, SMB configuration, server/volume/object identities |
| NetApp SMB | Direct lab share on a named SVM | ONTAP version, SVM/share/volume bindings, security style, directory authority/trust |
| Generic NAS SMB | Direct lab share on a named appliance | Vendor/model/firmware, share/backend bindings, security style, identity authority |

`-TargetPlatform Windows`, `NetApp`, or `Nas` is a declaration, not verification.
Local Windows results do not qualify Windows SMB, and Windows SMB results do not
qualify NAS. Record backend proof using independently approved server/vendor
administration tools. Generic NAS evidence must identify the specific product.

Prepare a fixture with a root, inheriting subfolders, files at several depths,
a protected descendant directory, and sentinel files beneath that protected
directory. Prepare separate fixtures for denies, unreadable objects, reparse
points, unsupported ACLs, large ACLs, long paths, and inventory limits. Do not
mix failure experiments into the successful baseline case.

Use trusted local fixed-volume evidence storage outside the target and its
physical backing paths. Independently check mapped drives, DFS, aliases, `subst`,
and share backing paths. The toolkit does not prove all mappings.

**Save:** ticket and approvals; fixture layout; intended grants and expected
allowed/denied operations; environment inventory; backend/namespace proof;
account/group SID and membership evidence; recovery procedure and rehearsal
results. Restrict evidence access. Do not include passwords, tokens, or keys.

## 2. Freeze the code and start an evidence record

Use the same source files, host, and operator throughout each validation case.
Changing source files or case bindings prevents resumption.

Create a new evidence folder for this exercise, outside all assessed trees.
The following examples use `C:\NtfsQualification` for ancillary evidence and
`C:\NtfsEvidence` for toolkit cases; independently verify storage separation.

```powershell
$reviewRoot = 'C:\NtfsQualification\Run01'
New-Item -ItemType Directory -Path $reviewRoot -ErrorAction Stop
Start-Transcript -Path (Join-Path $reviewRoot 'operator-transcript.txt')

git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Unable to record source commit.' }
git status --short
if ($LASTEXITCODE -ne 0) { throw 'Unable to record worktree status.' }

$PSVersionTable | Out-String |
    Set-Content -LiteralPath (Join-Path $reviewRoot 'powershell-version.txt')
Get-Module -ListAvailable Pester, PSScriptAnalyzer, ActiveDirectory |
    Select-Object Name, Version, Path |
    Export-Csv -LiteralPath (Join-Path $reviewRoot 'modules.csv') -NoTypeInformation
Get-ChildItem -LiteralPath . -Recurse -File |
    Where-Object { $_.Extension -in @('.ps1', '.cs') } |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv -LiteralPath (Join-Path $reviewRoot 'source-sha256.csv') -NoTypeInformation
```

Retain the exact source tree, including any uncommitted differences, alongside
the recorded commit and hashes. Record OS/backend versions and UTC start/end
times. A commit ID alone does not identify modified working files.

Archive each stage's reported `CommitSHA256` externally as the case progresses.
Local hashes detect inconsistencies, not malicious rewriting; keep an independently
controlled archive and reviewer record.

## 3. Run existing regressions and static analysis

Run from the repository root. Use Windows PowerShell 5.1 and each additional
PowerShell version intended for support, in separate evidence runs.
Pester requires version 5.2 or later. Record missing prerequisites explicitly and
install approved dependencies only when needed.

```powershell
.\Tests\Test-NtfsAssessment.ps1 `
    -ResultsPath (Join-Path $reviewRoot 'assessment-results.json')
.\Tests\Test-NtfsBestPractices.ps1

$pesterParameters = @{
    Path = @(
        '.\Tests\NtfsPermissions.Tests.ps1'
        '.\Tests\NtfsPermissionValidation.Tests.ps1'
        '.\Tests\NtfsPermissions.Local.Tests.ps1'
    )
    Output = 'Detailed'
    PassThru = $true
}
$testResult = Invoke-Pester @pesterParameters
if ($null -eq $testResult) { throw 'Pester did not return regression results.' }
$testResult | Export-Clixml -LiteralPath (Join-Path $reviewRoot 'pester-results.xml')
$inconclusiveCount = @($testResult.Tests | Where-Object Result -ceq 'Inconclusive').Count
if ($testResult.Result -cne 'Passed' -or $testResult.FailedCount -gt 0 -or
    $testResult.PassedCount -eq 0 -or $testResult.NotRunCount -gt 0 -or
    $inconclusiveCount -gt 0) {
    throw 'Permission regressions failed or were incomplete.'
}

$analysis = @(Invoke-ScriptAnalyzer -Path . -Recurse)
$analysis | Export-Clixml -LiteralPath (Join-Path $reviewRoot 'script-analysis.xml')
$analysis | Format-Table RuleName, Severity, ScriptName, Line, Message -Wrap
if (@($analysis | Where-Object Severity -eq 'Error').Count -gt 0) {
    throw 'Script analysis reported errors.'
}
```

Review skipped tests and warnings; passing counts alone are not sufficient.
`NtfsAssessment.Tests.ps1` is a Pester wrapper around the assessment harness, so
it need not be repeated when that harness was already run successfully.

**Acceptance:** no failing regressions or analyzer errors; warnings minimized
and dispositioned. Preserve logs of failures before correcting and rerunning.
The existing planner/validation tests use synthetic fixtures/mocks. The local
candidate tests modify only their own generated disposable NTFS fixtures.
Neither qualifies production writes.

## 4. Collect a live read-only baseline and plan

Confirm Windows/RSAT AD prerequisites, CIM connectivity where applicable, and
filesystem read access. CIM credentials do not supply a separate SMB login.

For a Windows lab server, collect the approved share:

```powershell
.\Invoke-NtfsAssessment.ps1 `
    -ComputerName LABFS01 `
    -IncludeShare 'DisposableLab' `
    -OutputRoot C:\NtfsQualification\Assessments `
    -ResolveActiveDirectory `
    -HashOutputs

.\Add-FileSharePermissions.ps1 `
    -Mode Plan `
    -TargetPath '\\LABFS01\DisposableLab\Case1' `
    -TargetPlatform Windows `
    -GroupName 'LAB\Readers' `
    -Permissions ReadAndExecute `
    -Scope ThisFolderSubfoldersAndFiles `
    -OutputDirectory C:\NtfsQualification\Plans
```

Use the README's local, explicit UNC, or NAS collection options for other tracks.
Preserve the entire assessment and plan directories. Review assessment
`manifest.json`, `run.log`, `ShareCoverage.csv`, `ScanErrors.csv`, and
`SkippedPaths.csv`; review plan `plan.json`, `before-and-intent.csv`,
`manifest.json`, and `events.jsonl`.

**Acceptance:** the positive fixture is fully readable within its declared scope,
all requested groups resolve to the intended SIDs, and boundaries/exclusions are
understood. Failure fixtures must report their omissions rather than appear complete.
Resolve accidental collection limits before proceeding.

The assessment collects directory ACLs, not individual file ACLs or effective
access. The plan includes files within its scope, but is abstract intent rather
than an exact expected post-propagation descriptor. A review-only plan remains
unqualified even with complete coverage.

## 5. Run the opt-in live preflight

Use a prepared positive fixture containing files and protected descendant
boundaries. Set these variables separately in each PowerShell session:

```powershell
$env:NTFS_PERMISSION_QUALIFICATION_TARGET = '\\LABFS01\DisposableLab\Case1'
$env:NTFS_PERMISSION_QUALIFICATION_PLATFORM = 'Windows'
$env:NTFS_PERMISSION_QUALIFICATION_DISPOSABLE = 'YES'

$preflight = Invoke-Pester `
    -Path .\Tests\NtfsPermissions.WindowsQualification.Tests.ps1 `
    -Output Detailed -PassThru
if ($null -eq $preflight) { throw 'Pester did not return live preflight results.' }
$preflight | Export-Clixml -LiteralPath (Join-Path $reviewRoot 'preflight-results.xml')
$preflightInconclusive = @($preflight.Tests | Where-Object Result -ceq 'Inconclusive').Count
if ($preflight.Result -cne 'Passed' -or $preflight.FailedCount -gt 0 -or
    $preflight.PassedCount -eq 0 -or $preflight.SkippedCount -gt 0 -or
    $preflight.NotRunCount -gt 0 -or $preflightInconclusive -gt 0) {
    throw 'Live preflight failed, was skipped, or was incomplete.'
}
```

**Save:** results and transcript, target/platform declaration, fixture layout,
and independently captured sentinel evidence beneath protected boundaries.

This scaffold reads real descriptors and checks conservative inventory behavior.
It deliberately confirms that mutation and physical identity remain unqualified.
It performs no permission changes, propagation experiments, or rollback.

## 6. Create one immutable validation case per scenario

Use a fresh target fixture/case for each independently approved experiment.
Do not reuse a completed stage or change the source while a case is open.

```powershell
$initializeParameters = @{
    Stage = 'Initialize'
    TargetPath = '\\LABFS01\DisposableLab\Case1'
    TargetPlatform = 'Windows'
    GroupName = 'LAB\Readers'
    Permissions = 'ReadAndExecute'
    Scope = 'ThisFolderSubfoldersAndFiles'
    MaxPaths = 10000
    ChangeTicket = 'LAB-CHG-001'
    EvidenceDirectory = 'C:\NtfsEvidence'
    DisposableAcknowledgement = $true
    NonInteractive = $true
}
$case = .\Invoke-NtfsPermissionValidation.ps1 @initializeParameters
$casePath = $case.CasePath
$case | Export-Clixml -LiteralPath (Join-Path $reviewRoot 'initialize-result.xml')

.\Invoke-NtfsPermissionValidation.ps1 `
    -Stage CaptureBefore -CasePath $casePath -NonInteractive

$observationsPath = Join-Path $reviewRoot 'manual-observations.json'
Copy-Item -LiteralPath (Join-Path $casePath 'Initialize\manual-matrix.json') `
    -Destination $observationsPath -ErrorAction Stop
```

Inspect `CaptureBefore\inventory.json`, `intent-review.json`, `comparison.json`,
and stage manifests/logs. **Stop external actions if the baseline is incomplete,
failed, or has unresolved intent failures.** Applicable denies, unsupported
descriptors, missing paths, and capture churn need explicit review.

The case captures files and folders for either scope, but never traverses protected
descendant branches. Collect independent read-only evidence for those branches.
Two matching reads are not an atomic snapshot or propagation-completion proof.

## 7. Execute and document the approved external experiment

This is a manual checkpoint, **not an `Apply` command for this toolkit**.
Use only the separately reviewed lab change procedure. Document exact commands
or GUI steps, parameters, actual outcomes, error/exit codes, account/token context,
and UTC intervals. Keep the administrator performing ACL changes separate from
the standard accounts used to test access.

For each case, observe the baseline, approved change, settled after-state,
guarded recovery decision, and resulting recovered state. Use independent
descriptor and namespace checks in addition to toolkit captures.

| Experiment / manual matrix entries | What to test and evidence to retain |
| --- | --- |
| `SingleGroup`, `MultipleGroups` | Correct SIDs and aggregate grants; preserve unrelated ACEs, owner/group and control state. Save ordered before/after descriptors for every affected file/folder. |
| `ThisFolderOnly`, `ThisFolderSubfoldersAndFiles` | Root-only changes leave all descendants unchanged; inheritable changes reach only eligible files/folders. Save propagation observations, completion criteria, and full affected-path comparisons. |
| `NoOp` | An already satisfied request performs no setter call and does not alter metadata. Save writer instrumentation when a candidate exists; matching ACLs alone do not prove no write. |
| `ProtectedBoundaryAndUntraversedBranch` | No unintended changes to the protected boundary or its contents. Retain independent sentinel/descriptor evidence from inside the untraversed branch. |
| `ApplicableDenies`, `UnreadablePaths`, `ReparsePoints`, `MaxPathsLimit` | Unsupported or incomplete input fails before any write; preserve the failure reason and independent zero-write evidence. Never weaken live guards to force a pass. |
| `WhatIfZeroTargetWrites`, `DeclinedConfirmationZeroTargetWrites` | Candidate writer performs zero target writes for simulation or refusal. Local evidence writes are allowed; capture actual writer activity, not just final ACL equality. |
| `ConcurrentAdminDrift` | Changes to identity, owner/group, DACL/control, or descendants between review and use are detected. Preserve the competing change and proof it was not overwritten. |
| `NamespaceAdd`, `NamespaceDelete`, `NamespaceRename` | Namespace changes invalidate stale assumptions; test delete/recreate with identical ACLs too. Preserve stable identities and before/after path sets. |
| `AuditFailureStopsBeforeWrite` | Unavailable/full evidence storage or failed durable intent prevents setter execution. Save fault timing, storage errors, and writer-call trace. |
| `CrashDisconnectPartialApply`, `InterruptedRollback` | Approved lab process termination, SMB loss, timeouts and interrupted propagation/recovery leave explicit failed/indeterminate states. Preserve journals, locks, surviving descriptors and operator recovery decisions; no automatic retry or rollback. |
| `ParentRollbackMustNotModifyDriftRefusedDescendants` | A parent restore must not indirectly propagate into a descendant whose drift makes rollback unsafe. Save per-path guards, propagation trace, and proof unrelated administrator changes survived. |
| `TestAccountRead`, `TestAccountCreate`, `TestAccountModify`, `TestAccountDelete` | Run actual operations with approved standard test accounts against disposable content, both allowed and denied cases. Save group/token context, share ACLs, commands, outcomes, and before/after recovery results. Read-only grants must deny create/modify/delete; a denial can be the expected successful test outcome. |
| `StableIdentityBoundHandles` | Prove stable volume/file identity and handle binding through the actual write, not path strings or timestamps. Test rename/replacement races; save native instrumentation and identity evidence. |
| `ControlledInheritanceAndExclusiveHandleAvailability` | Measure inheritance with the exact candidate API and handle-sharing mode, including unavailable exclusive handles and effects on other SMB clients. Save client behavior and descendant propagation evidence; fail closed when required handles cannot be obtained. |
| `DirectBackendDfsAliasAndSecurityStyleProof` | Independently verify backend, direct namespace, NTFS security style, target identity authority/trust and evidence separation. Exercise DFS/referral/alias/backend substitutions; reject unsupported or unproved bindings. |

Also cover large/long-path inventories, descriptor/ACE size limits, unsupported
ACE forms, empty versus null DACLs, host/mapping changes, tampered/stale plans,
and lost privileges. Record expected fail-closed results, not just happy paths.
The existing synthetic tests cover many of these models; candidate behavior
must still be verified live.

For functional access tests, include an intended reader, an intended writer in a
separate approved grant case, and an unauthorized control account. Use a fresh
logon/SMB session after membership changes and record token context. Share ACLs
and group membership can change effective access without changing NTFS ACLs.
Do not infer effective access from the presence of an allow ACE.

Writer-only experiments cannot be completed through the public entry points.
Some can now be exercised against the internal local candidate in an independently
approved disposable environment; its fixture tests do not complete this matrix.
Leave them `NotRun` or explicitly `NotAssessed` with a reason; manual substitute
operations must be described as backend observations, not writer qualification.

## 8. Capture after apply, review recovery, then capture after revert

After the external apply and independent propagation review:

```powershell
.\Invoke-NtfsPermissionValidation.ps1 `
    -Stage CaptureAfterApply -CasePath $casePath `
    -ManualActionAcknowledgement -NonInteractive
```

Review the stage inventory/comparison, unexpected changes, incomplete paths,
and independent evidence. An unchanged capture is `NoChangeObserved`, not
successful apply. A matching requested grant is not proof of effective access.

Before an external revert, compare each object's current identity and full
captured state with the actual verified after-state. Refuse restoration where
identity/state drift occurred. Do not blindly restore a parent whose inheritance
could overwrite drift-refused descendants. If safe recovery cannot be established,
stop, preserve evidence, and follow the independently approved recovery procedure.

After the separately approved guarded recovery:

```powershell
.\Invoke-NtfsPermissionValidation.ps1 `
    -Stage CaptureAfterRevert -CasePath $casePath `
    -ManualActionAcknowledgement -NonInteractive
```

**Acceptance:** independent verification establishes the expected recovered
owner, group, ordered DACL, relevant control bits, object identities, and namespace
for every affected path; protected branches and unrelated changes are preserved.
Repeat actual account access checks. Retain original and recovered evidence.

Toolkit captures cover owner/group/DACL only; SACLs, untraversed branch contents,
physical identity and atomicity are not proven. If a future writer can affect
additional descriptor sections, capture and verify them independently.
`icacls` DACL backups alone are not a complete recovery package.

## 9. Complete the external manual matrix and seal the report

Edit only the copy at `$observationsPath`, never the sealed case template.
Retain all 27 entries and the exact schema/case/source/platform bindings.

| Field | What to record |
| --- | --- |
| `Status` | `Observed` for a performed test with its expected outcome; `Failed` for an unmet expectation; `NotRun` for unperformed work; `NotAssessed` when proof is unavailable. No `Passed` status exists. |
| `Command` | Actual approved command or detailed GUI/native test procedure; distinguish external manual actions from candidate writer calls. |
| `ActualResult` | Expected versus actual behavior, counts, error/exit codes, drift and limitations; reference separately archived evidence by identifier/hash. |
| `Account` | Test identity and relevant token/session context; no credentials. |
| `Utc` | Actual observation time in UTC, ending in `Z` or `+00:00`, within the initialized case lifetime. |
| `Reviewer` | Independent reviewer for the observation. |
| `SourceHashes`, `Platform` | Preserve the template values exactly. Archive candidate writer build/source hashes separately if it is an external implementation. |
| `EvidenceAttachments` | Leave as `[]`; the importer does not import attachments. Archive supporting evidence separately. |

`Observed` and `Failed` require nonempty command/result/account/UTC/reviewer fields.
Use a separate case-specific copy for each case; do not transplant another case's
matrix or report historical tests as observations from a newly initialized case.
The import is limited to 1 MiB.

Submit only after the observations are complete and reviewed:

```powershell
.\Invoke-NtfsPermissionValidation.ps1 `
    -Stage Report -CasePath $casePath `
    -ManualObservationsFile $observationsPath -NonInteractive

Stop-Transcript
```

Inspect `Report\report.json`, `manual-observations.json` when submitted, manifests,
stage logs, commit records and returned diagnostics. Save the entire case, the
external matrix, supporting attachments, source tree, approvals and reported hashes
in the independent archive.

`Report` can seal an unfinished case, but records missing stages as incomplete.
It cannot be reopened or repaired. Preserve failed/interrupted cases and locks;
do not delete artifacts or retry stages to manufacture a successful report.

**Important:** report `TargetWrites=0` describes this toolkit, not the external
manual actions. `ManualMatrixStatus=Observed` does not mean every entry ran;
review each entry. `FunctionalAccess=Observed` reflects submitted declarations,
not independent execution proof. `WriterQualification` always stays `NotQualified`.
`NativeWriter=Absent` refers to the read-only validation workflow, not the separate
internal candidate code.

## 10. Requirements before implementing/enabling a writable release

The evidence above informs implementation; it does not replace it. Before
enabling any platform, all of the following must be implemented and independently
verified against the exact proposed writer build:

| Release gate | Required proof |
| --- | --- |
| Native writer and scope | Reviewed implementation using supported file-security APIs; explicitly bounded grant semantics, platforms and scopes. No SMB share ACL writes, inheritance toggles, or recursive explicit grants added implicitly. `SetKernelObjectSecurity` is not supported for files. |
| Identity and authority | Stable object/volume identities, identity-bound handles, backend/security-style and group-authority/trust proof; reliable rejection of unsupported DFS/aliases and namespace substitutions. Current `UNQUALIFIED` observations are insufficient. |
| Propagation and concurrency | Exact expected post-propagation states, both scopes and folders/files, tested handle availability/sharing, protected/reparse boundaries, drift detection and SMB client impact. Host-local mutexes are not distributed target locks. |
| Durable intent and recovery | Durable per-operation audit before writes, unambiguous interruption states, per-path verified preimages and actual after-states, drift-refused recovery, and no unsafe parent propagation into refused descendants. No silent retries, force override or automatic rollback. |
| Regression and live qualification | Existing regressions preserved, candidate writer-specific tests added, full fault/access matrix completed on every enabled backend/runtime, no skipped critical tests or unresolved missing evidence. |
| Independent release approval | Reviewed design and implementation, protected evidence archive with hashes, reviewer sign-off, supported/unsupported configuration list, operating and recovery procedures, and explicitly approved pilot/release boundaries. |

The current repository has **no automatic qualification importer or approval
switch**. A future code change must implement the writer and enforce its
qualification boundaries; merely changing `MutationNotQualified` or removing
the public gate is not an acceptable implementation.

Keep unqualified backends blocked. Start any independently approved pilot with
a narrow, backed-up noncritical target and explicit stop/recovery criteria.
Production authorization is a separate organizational decision.

## Evidence handoff checklist

- Exact source commit, working-tree differences/source archive, SHA256s, runtime
  and dependency versions; candidate writer build and instrumentation when available.
- Ticket, scope, approvals, environment/backend/namespace/authority proof, fixture
  inventory, expected outcomes and independent recovery rehearsal.
- Regression/analyzer/preflight results, including failures, warnings and skips.
- Entire assessment, plan and immutable case directories; externally archived
  stage commit hashes and original/recovered per-object evidence.
- Actual test-account operations, propagation/drift/fault/recovery observations,
  external manual matrices and independently archived supporting attachments.
- Per-track gap list, reviewer decisions and narrowly bounded release approval.

**Stop criteria:** missing identity/backend proof, incomplete affected-path
coverage, failed intent/access/recovery checks, unexpected drift, unsupported ACLs
or namespaces, audit failure, unsafe propagation, or unqualified writer behavior.
Preserve evidence and keep writes disabled until the cause is resolved and the
relevant candidate tests are rerun under a new approved case.
