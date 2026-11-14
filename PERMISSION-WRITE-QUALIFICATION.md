# Permission modification: testing and evidence guide

## Start here: no production enable switch

There is **no qualified production writer**. Default
`Add-FileSharePermissions.ps1 -Mode Apply` and `-Mode Revert` are deliberately
blocked. The explicitly acknowledged `-DisposableLocalLab` option can perform
real changes only for independently approved disposable direct local fixed NTFS
experiments, never production or SMB/NAS; it is not a production enable switch.
Tickets, hashes and passing tests do not qualify a backend.

An internal local-NTFS candidate now exists in `NtfsPermissions.Local.ps1` /
`NtfsPermissions.Local.cs`. Its disposable integration tests are described in
the README. The explicit disposable-lab path uses this candidate; it has
unresolved qualification gaps and does not qualify any backend merely by passing
tests.

## Independent targeted changes in disposable local labs

The in-progress targeted Add/Remove/Replace workflow is independent of the
assessment, reporting, manual validation and qualification exercises below.
No assessment, previous plan, or Revert is required. Use only a separately
approved, quiescent, disposable local fixed NTFS target and verified backup;
the explicit acknowledgement is not itself approval.

In the `-Mode Apply -DisposableLocalLab -DisposableAcknowledgement` path,
`-Operation` defaults to `Add`. `Remove` and `Replace` take `-RemovePrincipal`
as `Everyone` (`S-1-1-0`), an exact SID including an orphaned SID, or an AD
security group. Replace also needs `-GroupName` and `-Permissions` (or the
existing JSON grant forms); Remove rejects all replacement grants.

```powershell
$lab = @{
    Mode = 'Apply'
    DisposableLocalLab = $true
    DisposableAcknowledgement = $true
    TargetPath = 'D:\DisposableLab\Case1'
    Scope = 'ThisFolderSubfoldersAndFiles'
    ChangeTicket = 'LAB-123'
    OutputDirectory = 'D:\NtfsEvidence'
}
.\Add-FileSharePermissions.ps1 @lab -Operation Replace -RemovePrincipal Everyone `
    -GroupName 'LAB\Readers' -Permissions ReadAndExecute -WhatIf
.\Add-FileSharePermissions.ps1 @lab -Operation Remove -RemovePrincipal Everyone -WhatIf
```

Use an existing approved fixture and group, and trusted local evidence storage
outside the target and its backing paths. After independent approval, invoke the
chosen command again without `-WhatIf`. Every Apply builds its own plan and
preserves prewrite recovery evidence in that invocation; a preview cannot later
be executed, and the new Apply may differ. Preview creates local evidence but
does not change target permissions.

Remove/Replace removes matching allow ACEs from all selected nonprotected paths,
including explicit descendant entries in recursive scope. Protected branches stay
unchanged; a warning identifies exclusions and `ExcludedPathCount` counts the
excluded objects. A matching inherited source ACE at the target is refused:
inspect its parent or ancestors; the candidate does not intentionally disable
inheritance. Matching source deny ACEs in the selected scope are refused.
`ThisFolderOnly` refuses removing an inheritable source allow ACE; use an approved
recursive scope or manual review.
Descriptors that cannot be represented losslessly, including their control flags,
ACL revision and ACE bytes, are refused.
Before any candidate write, every inventoried path outside protected branches
must have the DACL auto-inherited control flag, even outside a folder-only scope.
Without that flag Windows was observed to alter descendant inheritance despite
zero-share handles. A no-op remains available; this guard does not establish
general propagation safety or qualify the writer.
Replace refuses a source/replacement SID match and cannot create access when the
source allow is absent at the target: an already-satisfied request can be `NoOp`,
otherwise it blocks. Replacement ACEs are added only where source allow ACEs
exist, with their inheritance and propagation flags preserved. Requested rights
can exceed the source rights, and existing destination grants are not reduced.

After a `Verified` or `NoOp` Apply or optional Revert, `AuditReportPath` and
`AuditReportSHA256` identify the verified `permissions-before-after.csv`. Its
rows include `OperationId`, `Host`, `Mode`, `Operation`, `Actor`, `ChangeTicket`,
`VerifiedUtc`, `Path`, `Kind`, `Scope`, `Result`, before/after descriptors,
`BeforeAces`/`AfterAces`, and JSON multiset `RemovedAces`/`AddedAces` differences.
The report is generated after final verification of writes, or of unchanged state
for `NoOp`; WhatIf and declined operations do not produce it. An interrupted
report write retains a `.pending` file; a later journal failure can leave a
completed CSV, so also check the returned status and completion journal. Archive
its hash independently. It covers NTFS DACLs, not share permissions, SACLs, or
effective access.

This audit CSV is streamed as a single UTF-8-with-BOM file, not split at the
toolkit's 100,000,000-byte part cap. Formula-like `ChangeTicket` values are
prefixed with an apostrophe in the CSV; the journal retains the original ticket.

Revert is optional and requires the original source version, receipt and retained
receipt hash, plus the independently reviewed original Apply journal and hash.
For partial failure, preserve prewrite evidence and review the existing
intent/verification journal against the live state; do not assume a complete
post-state report. There is no automatic rollback. Explicit partial recovery is a
separately reviewed operation, subject to the same evidence and drift checks.
See the README's [targeted workflow](README.md#separate-workflow-targeted-disposable-lab-permission-changes)
for an actual Apply, report review, and optional Revert.

### Current targeted lab observations

On November 13, 2026, a disposable fixture whose DACL lacked the auto-inherited
control flag produced an indeterminate Replace: the root control flags changed,
and an unprotected child became protected despite the pinned handles. Its
original source snapshot, fixture and journal are retained for independent
review; no automatic recovery was attempted. The current candidate now blocks
this observed configuration before a write.

With source fingerprint
`7a902ff30826a4b6b72d2d489f3751eec45cc91953275dbe362c2350644e759e`,
separate Windows PowerShell 5.1 and PowerShell 7 runs on new local NTFS fixtures
each verified nine checks using an existing AD security group read-only. These
included previews, fresh Remove/Replace Applies, audit reports, protected
boundaries, no-op and refusal cases, and optional Reverts. The original fixture
states and evidence hashes were verified after each successful run.
No member/nonmember access tokens were supplied, so effective-access checks
were not run. These observations do not qualify production, SMB/NAS, concurrent
administrator activity, host crashes, power loss or storage failure.

## Completed local access qualification

**Historical, source-specific evidence:** the grant/Revert cases and regression
results below belong to their respective earlier source snapshots. They do not
qualify the in-progress Remove/Replace operations or the current source.

The disposable AD DS/file-server lab has completed **36 real-account cases and
6,480 access observations**, with zero mismatched expectations. The direct
membership matrix covers Read, ReadAndExecute, Modify and FullControl, both
scopes, an existing ReadAndExecute baseline versus a first grant, and Windows
PowerShell 5.1 versus PowerShell 7. Four additional cases exercise nested
account-to-global-to-domain-local-to-NTFS membership. Every case checks allowed
and negative-control accounts locally and from a separate domain-joined client,
before Apply, after Apply and after Revert. The separate client was the lab DC;
this is not qualification of other client operating systems.

The retry revision's full regression suite passed **1,716 tests per PowerShell edition**,
with zero failures, zero NotRun tests and one Windows-inapplicable skip per
edition. The standalone best-practices harness passed 145 assertions per
edition. Static analysis reported zero errors and zero candidate/runner
findings; existing repository warnings and informational findings are retained,
not described as a clean warning-free baseline. Live collection, AD expansion,
planning, merge, comparison and validation captures also completed on both
editions: comparison showed the applied ACL differences and zero differences
after exact Revert. The public mutation gate was verified without changing it.
The 36-case access/reporting archive identifies its earlier source snapshot;
retry qualification has its own new source-bound evidence and handoff. Historical
access observations are not relabeled as runs of the revised writer.

An independent evidence audit verified complete Apply/Revert journals, source
and evidence hashes, all observations, exact current fixture identities,
descriptors and contents, absence of generated shares, and removal of 148
generated AD objects. The original 227-object corporate fixture retains its
exact ACL baseline. Four additional controlled failures exercised share-creation
failure after Apply and unexpected probe-content drift, on both editions.
Failed evidence is retained; reviewed recovery was a separate operation, not
automatic rollback.

This testing corrected runner expectations for already-satisfied grants
(`NoOp`) and file-versus-parent delete authorization. The native marker-checked
handle probe also requires file read access; it does not isolate a file DELETE
ACE. Dedicated regression tests cover that distinction.

### Remaining work is not an enable checklist

| Gap | Current boundary | Concrete next step |
| --- | --- | --- |
| Concurrent administrator/namespace changes | ACL comparison and writing are not an atomic compare-and-set. Exclusive file handles do not exclude security-only administrator edits, and namespace observations do not cover every replacement. | Review and implement enforceable concurrency/quiescence and namespace guarantees for a narrowly supported writer. Repeat adversarial drift and propagation tests against that exact implementation. More passing tests alone cannot close this design gap. |
| OS crash, power loss and storage failure (deferred) | Current work prioritizes safe explicit retries, not crash durability. Host/storage failures were not induced, and retries do not prove their behavior. | No host-fault testing is required for the current retry work. If crash-durability qualification is later requested, use an isolated disposable VM and external controller, never a shared development host. |
| SMB/NAS mutation and backend authority | Real SMB access was observed, but shares were removed before local candidate writes. This is not a Windows SMB, DFS or NAS writer qualification. | Implement a separately bounded backend writer; obtain actual backend/volume/security-style/trust proof and test direct shares, referrals, aliases, disconnects, propagation and recovery on the supported appliance/server versions. |
| Broader configurations | Results apply to the observed host/runtime/storage and selected token/share-access combinations. Long-path failures before writes are documented below. | Declare a supported matrix, then repeat against the additional OS/runtime/filesystem versions, long-path settings, scale limits, explicit-deny/share-deny and token combinations actually intended for support. |
| Case-bound manual evidence and release approval | Automated tests and separately archived access observations are not an independently approved manual matrix. Historical results cannot be copied into a new case as fresh observations. | Rehearse missing entries within each new case's lifetime and bindings, retain honest NotRun/NotAssessed statuses, archive original evidence independently, and obtain a real independent review and explicit release authorization. |

Read-only assessment and validation success does not close these gaps.
`WriterQualification` remains `NotQualified`, and default public Apply/Revert
remain blocked. The lab-specific evidence index and fresh handoff should be retained
with the exact tested source archive; they are not portable qualification
certificates.

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
`candidate-audits`, including process-interruption requests, boundary records and
child output when present. The original fixture remains at the path recorded in
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
recovery. Default public `Apply`/`Revert` remain blocked.

## Real-account disposable candidate runner

`Tests\Invoke-NtfsCandidateLabValidation.ps1` performs **real ACL writes and
Revert** using the internal local candidate. It automatically runs a candidate
WhatIf first, but the overall script is **not a dry run** and does not pause for
review of each generated plan. Review the script and authorize its complete
disposable-lab workflow before starting. The resulting observations do not
qualify a writer or enable public Apply/Revert.

### Prepare

1. Use an approved nonproduction Windows member file server with a direct local
   fixed NTFS volume, Windows PowerShell 5.1 or supported PowerShell 7, RSAT
   ActiveDirectory, domain connectivity, and an authorized operator able to
   create directories, set ACLs and use the necessary logon/SMB facilities.
   The checkout and candidate source files, including
   `Tests\NtfsCandidateLabProbe.cs`, must be present on the server. `Add-Type`
   must be permitted on the server and, if used, the client.
2. Provide an **existing, dedicated disposable parent directory** on that local
   volume and separate trusted local evidence storage outside the fixture and
   its physical backing paths. Check aliases and ensure the test identities can
   traverse the parent. The runner creates a new `CandidateValidation_<id>`
   directory; it cannot select an existing target. Do not use production data
   or allow other processes to add, replace or modify files in the fixture.
3. Prepare one dedicated existing AD security group, an allowed domain account
   in that group, and a distinct negative-control domain account outside it.
   Both must be nonadministrators on every test host. Use only disposable
   accounts, allow time for group membership replication, and arrange
   independently verified backup and recovery. The runner does not create,
   disable, delete or change AD objects or memberships.
4. For separate-client checks, use a distinct domain-joined Windows lab client,
   preferably not a domain controller. Configure approved WinRM access for the
   operator and SMB connectivity with encryption. The runner creates a
   uniquely named encrypted share on the server for its fixture, grants the
   test accounts share access, and removes that share before candidate writes.
   It does not close unrelated SMB sessions. Without `clientComputerName`, only
   local account access is tested and the held-SMB-file check is not run.

### Run both scopes

From the repository root, replace the example values. Enter passwords through
the credential prompts, not in commands or evidence files.

```powershell
$allowed = Get-Credential 'LAB\CandidateAllowed'
$control = Get-Credential 'LAB\CandidateControl'
$parameters = @{
    fixtureParent = 'D:\NtfsCandidateFixtures'
    evidenceRoot = 'D:\NtfsCandidateEvidence'
    groupName = 'LAB\CandidateWriters'
    allowedCredential = $allowed
    controlCredential = $control
    changeTicket = 'LAB-123'
    clientComputerName = 'LABCLIENT01' # Omit for local-only observations.
    disposableAcknowledgement = $true
}
foreach ($permission in 'Read', 'ReadAndExecute', 'Modify', 'FullControl') {
    foreach ($scope in 'ThisFolderOnly', 'ThisFolderSubfoldersAndFiles') {
        foreach ($firstGrant in $false, $true) {
            $result = & .\Tests\Invoke-NtfsCandidateLabValidation.ps1 @parameters `
                -scope $scope -permissions $permission -startWithoutGroupGrant:$firstGrant
            $result | Format-List
            Get-Content -LiteralPath (Join-Path $result.EvidencePath 'summary.json') -Raw |
                ConvertFrom-Json | Format-List
        }
    }
}
```

Repeat with each PowerShell edition being evaluated; every invocation creates a
separate fixture and case. Use `-permissions Read`, `ReadAndExecute`, `Modify`,
or `FullControl` to select the grant under test. By default the group starts with ReadAndExecute; the
`startWithoutGroupGrant` cases start the access matrix without a group grant,
so Revert should remove the first grant. With a separate client, these cases
create `Child\held.txt` with an explicit read grant to the allowed account solely
for the held-SMB-handle check; that file is not part of the access matrix.
The runner checks real read, create, modify, marker-checked handle deletion and
name-based deletion for the allowed and control accounts before Apply, after Apply and
after Revert, including an inheriting child and a protected branch. It checks
exact fixture identities, descriptors and contents, and verifies that the
candidate WhatIf journal has no write intents. With a client it also verifies
that a held SMB file blocks the candidate before writes. The temporary share is
removed for writes: this does **not** prove mutation on an active customer share
or qualify an SMB/NAS writer.

The runner creates uniquely marked probes without overwriting existing files.
Modification, deletion and cleanup check those markers through exclusive file
handles; unexpected contents, hard links and busy handles cause failure rather
than cleanup. These checks do not exclude every concurrent replacement, so the
fixture must remain dedicated and quiescent.

`DeleteExisting` opens the file with GENERIC_READ and DELETE access so that it can
check the marker before deleting through the handle. `DeleteChild` separately
calls the Windows name-based delete API without first opening the file for DELETE,
then verifies whether the generated marked probe disappeared. Both APIs can
obtain deletion permission through file DELETE or parent `FILE_DELETE_CHILD`;
neither isolates the file ACL's DELETE grant. The handle probe additionally needs
file read access, while the name-based probe does not.
For FullControl, a folder-only grant is expected to allow deleting an immediate
child by name even though that child's ACL is unchanged; the recursive grant
also allows the inheriting child, while the protected branch remains denied.
The name-based API can also succeed through the file's own DELETE permission:
recursive Modify therefore permits both deletion probes on inheriting files.
`DeleteChild` is not an isolated measurement of the parent right when the file
already grants DELETE. For folder-only FullControl, an existing ReadAndExecute
baseline also permits the marker-checked handle deletion of an immediate child.
Without that baseline, handle deletion fails its read requirement but name-based
deletion still succeeds.
The fixture must remain quiescent: a path replacement between marker inspection
and name-based deletion is not excluded by this experiment.

The negative control has no fixture grant; it is not an explicit-deny test.
Candidate planning rejects applicable deny ACEs overlapping the proposed grant,
including denies for another SID whose group-token overlap cannot be determined.
Protected or otherwise unchanged descendants retain their ACLs, but that is not
proof of effective-access isolation. For example, a folder-only FullControl
grant can allow deletion of immediate child files through the parent directory
even when the files' ACLs are unchanged. The name-based probe observes that
outcome; it does not isolate the authorization source or prove all effective
access, deny, share-ACL or token combinations.

### Review and failure handling

Inspect `summary.json` and `state.json`, not just the process exit code. An
observed complete run records `CandidateApply=Verified`,
`CandidateRevert=Verified`, `BaselineRestored=true`, zero failed checks, and
90 local-only or 180 local-plus-client access checks. The case also contains
the plan, candidate journals, exact fixture snapshots, access observations,
environment and source hashes, and `SHA256SUMS.csv`. If the requested grant is
already satisfied, both candidate results are instead `NoOp`; the runner still
verifies the complete before/after state,
access matrix and successful journals. NoOp is not a failed write or a reason
to remove an existing grant on Revert. Preserve the original
evidence and independently archive its hashes; hashes are not signatures.
Evidence can contain account names, SIDs, hostnames, paths, ACLs and errors.
Review it before any approved secure transfer. The script does not intentionally
write credentials to evidence, but credentials are used in process memory for
Windows authentication; run only on trusted lab hosts.

Failures stop without automatic rollback or retry. Preserve the fixture, case,
and any candidate locks and journals. An early refusal, such as an unavailable
target handle, can occur before a candidate lock or journal is created; retain
the runner's available state, result and console diagnostics. A missing journal
alone does not prove that no write occurred. Inspect whether Apply completed, whether
Revert began, and whether the recorded temporary share still exists and points
to the generated fixture. Share cleanup is attempted, not guaranteed after a
failure or interruption. Do not close unrelated shares or sessions, delete locks,
or rerun the failed case. Ordinary Revert requires review of a complete successful
Apply journal. Explicit reviewed partial-Apply recovery has the additional
durable-intent and source-lock checks described below. Both require exact current
identities and descriptors, source/plan bindings, quiescence, and independent
approval. Torn/unverifiable evidence, drift, unavailable handles or uncertain
state remain refused. The Apply freshness guard does not expire saved recovery
records; there is no automatic recovery API.
The runner preserves its
fixture and does not remove customer-managed test identities.
Controlled process termination alone does not establish recovery after an OS
crash, storage failure, power loss, or a disconnected remote backend.

The disposable local candidate suite now terminates an owned child PowerShell
process at three synchronized boundaries in both Apply and Revert: after durable
write intent, after the first native write but before its audit proof, and after
the first durable per-path proof. It checks the exact surviving identities and
descriptors, unchanged file contents, retained lock and journal, and refusal to
reuse the interrupted audit. A hash-consistent journal prefix is not completed
Apply evidence: interrupted Apply remains ineligible for ordinary Revert.
The explicit partial-recovery path is separately tested, followed by a fresh
Apply and exact Revert. Interrupted Revert is retried in a new audit using the
original Apply evidence; conflicting administrator edits refuse the entire
restoration before writes. These are controlled internal experiments, not
permission to retry a failed customer case.
Only the owned child is terminated; no host restart or unrelated process is used.

### Safe retries in the disposable local candidate

The historical retry observations below are bound to their tested source
revisions, not qualification of the in-progress Remove/Replace operations.

The current priority is repeatable, evidence-preserving retries rather than
host/power/storage fault injection. There is **no automatic retry loop**, force
override, production writer, or resumption of an old audit. Each Apply creates
its own fresh plan inside the writer invocation and uses a restrictive
`New-NpRun` audit directory; previously prepared plans and previews cannot be
supplied. The 24-hour Apply freshness check is a defensive guard on that
same-invocation plan.
Revert does not expire the saved recovery record after 24 hours: it requires the
same source binding and fresh live identity, namespace and descriptor checks.

| Observed state | Permitted retry |
| --- | --- |
| Transient refusal before any write, with the entire fixture still exactly at Before | Fix the transient cause, such as a held handle or audit failure. Use a fresh journal and re-run Apply; full preflight must pass again. |
| Complete successful Apply | Preserve its completion evidence rather than blindly repeating Apply. Ordinary Revert uses that evidence; repeating completed Revert in a fresh audit is a verified NoOp. |
| Failed/interrupted Apply with a valid immutable journal prefix | Independently review and invoke internal Revert with `-ReviewedPartialApplyRecovery`, the original `-ApplyJournalPath` and reviewed `-ApplyJournalSHA256`, and a fresh Revert journal. Only after exact baseline restoration may a fresh Apply attempt run. |
| Interrupted Revert, including explicit partial-Apply recovery | Use a fresh Revert audit and the same original Apply evidence and recovery mode. Already restored paths are NoOp; only exact recorded after-states may be restored. |
| Drift, identity/namespace changes, missing intent, unavailable source lock, invalid hash/torn journal, expired plan for Apply, or changed source | Stop without writes. Preserve evidence and investigate; do not retry around the refusal or substitute newly invented preimages. |

Partial recovery exclusively opens the original `candidate.lock` **read-only**
before reading its journal, refusing an active attempt or a missing/unavailable
lock. It holds that handle throughout recovery and does not alter or delete the
original lock. The journal must be a hash-verified Apply prefix bound to the exact
plan, source, execution host and target. Every path must equal its exact original
Before or Desired snapshot. A path at Desired may be restored only if that
original Apply recorded a matching durable write intent for that path. A proof
missing after a write is not treated as proof that no write happened.

All paths and the full namespace are checked before the first restoration.
The new audit records `CandidatePartialApplyRecovery` with the original journal
path/hash. It records only restoration writes actually attempted, never invented
Apply completion. Original failed journals and locks remain untouched, including
when recovery itself is interrupted. Ordinary Revert still refuses incomplete
Apply evidence unless this explicit, separately reviewed mode is selected.

The native tests exercise transient handle/intent refusal then successful retry,
caught post-write audit failure, Apply interruptions at intent/write/proof,
interrupted recovery at the same boundaries, repeated Revert NoOp, and refusal
for an active source lock, administrator drift, missing per-path intent and wrong
hash. Success requires exact baseline descriptors/identities and unchanged file
contents, not merely a successful return code. This does not resolve the
non-atomic administrator/namespace limitations or establish crash durability.

Long paths remain unqualified. On one lab host with `LongPathsEnabled=0`, paths
of 248 and 259 characters completed Apply/Revert; existing paths of 260, 261,
300 and 320 characters failed native opening during planning, before writes.
This is not a universal length limit or a reason to change host-wide policy.

This guide has two milestones:

1. **Now:** verify read-only behavior, collect evidence around separately
   approved manual changes, and exercise the internal candidate only in
   independently approved disposable labs.
2. **Before a future writable release:** implement an identity-bound writer and
   guarded recovery, test that exact implementation on each supported backend,
   and obtain independent approval for a narrowly defined release.

Manual ACL changes can characterize a backend, but cannot prove how a future
writer will behave. Repeat applicable experiments against the actual candidate
writer before approving it. Nothing here authorizes production changes.

## 1. Approve the scope and prepare the lab

The numbered stages below are an optional qualification/manual-evidence
exercise, not prerequisites for the targeted disposable-lab workflow above.
Their apply/revert experiments do not make Revert mandatory for targeted changes.

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

This is an optional qualification exercise, not a prerequisite for targeted Apply.

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

Writer-only experiments cannot be completed through the default public mutation
modes or the manual validation entry point. Some can be exercised against the
local candidate in an independently approved disposable environment, including
through the explicit lab opt-in; its fixture tests do not complete this matrix.
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
