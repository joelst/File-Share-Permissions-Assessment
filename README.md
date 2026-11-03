# File Share Permissions Assessment

PowerShell tools for collecting SMB share and NTFS directory permissions, producing
offline review reports, comparing snapshots, and gathering read-only evidence for
permission-change planning.

**This is an assessment and evidence toolkit, not a production remediation tool.**
`Add-FileSharePermissions.ps1` can prepare review-only plans, but its `Apply` and
`Revert` modes are deliberately blocked. No native permission writer exists.
Passing tests or completing a validation walkthrough does not enable writes or
qualify a platform for remediation.

## Scripts and their roles

| Script | Purpose | When to run |
|---|---|---|
| `Invoke-NtfsAssessment.ps1` | Collects Windows server/share metadata, available SMB share permissions, and NTFS **directory** ACLs. Optional identity/group expansion and best-practices evidence. | First, to create each assessment snapshot. |
| `Merge-NtfsAssessment.ps1` | Reads collected runs and produces consolidated findings, folder/share risk indicators, group reports, coverage reports, and executive summaries. | After collection; does not collect live data. |
| `New-NtfsBestPracticesReport.ps1` | Generates a best-practices report from one verified assessment run, optionally against a JSON policy. | After collection; independent of merge. |
| `Compare-NtfsAssessment.ps1` | Compares two original assessment snapshots for directory ACL, owner/inheritance, share metadata, and share ACL differences. | After two snapshots exist; merge is not a prerequisite. |
| `Add-FileSharePermissions.ps1` | Resolves AD security groups and inventories folders/files to create an abstract permission plan and audit journal. | Optional, separate planning workflow after review. Never an automatic next step from findings. |
| `Invoke-NtfsPermissionValidation.ps1` | Creates a sealed case and records before/after observations around separately approved external manual actions. | Optional disposable-lab workflow; not a permission-change executor. |

Keep all top-level `.ps1` files together. These supporting scripts are loaded by
the entry points rather than run as standalone workflows:

| Shared script | Responsibility |
|---|---|
| `NtfsAssessment.Common.ps1` | Version registry, versioned logging, CSV reading/writing and size caps, dataset integrity, hashing, and path/scope checks. |
| `NtfsAssessment.BestPractices.ps1` | Policy validation, evidence-based checks, and best-practices report generation. |
| `NtfsPermissions.Common.ps1` | Read-only planning, target/group validation, journals, and recovery-evidence checks. |
| `NtfsPermissions.Validation.ps1` | Immutable validation stages, capture comparisons, case integrity, and manual-observation validation. |

## Requirements and safety

- Scripts require PowerShell 5.1 or later. Run live collection, planning, and
  validation on Windows. Some offline report and synthetic-test workflows also run
  under PowerShell 7 on other operating systems; that is not Windows qualification.
- Windows discovery uses SMB and CIM cmdlets. Remote Windows discovery requires
  CIM connectivity and authorization; reading remote filesystem ACLs also requires
  SMB access in the running user's context. `-CimCredential` supplies CIM
  credentials, not a separate SMB login.
- AD enrichment (`-ResolveActiveDirectory`) and permission planning/validation
  group resolution require the RSAT `ActiveDirectory` module and directory access.
  `-IncludeLocalGroups` optionally collects local group membership during assessment.
- Use an account authorized to read the selected shares and security descriptors.
  Reading SACLs or audit policy may require additional privileges. Missing evidence
  is reported; do not assume unavailable data means a secure or empty configuration.
- Store output outside every assessed tree and its backing paths. Planning and
  validation require trusted local fixed-volume evidence storage, not mapped SMB
  output drives. Independently check aliases, DFS, substituted paths, and physical
  backing-storage separation; automated checks do not prove all mappings.
- Evidence contains sensitive paths, identities, permissions, and possibly operator
  declarations. Restrict access and archive evidence and hashes under organizational
  controls. Hashes and local hash chains are not protection against malicious rewriting.
- Read-only refers to the **target**. Scripts create local reports, logs, locks, and
  evidence; planning/validation may restrict local evidence-directory ACLs.
  `-WhatIf` does not suppress those local evidence writes.

Run commands from this repository's directory. Replace example hosts, groups,
paths, and tickets with approved values. These commands do not grant authorization
to assess a system or make changes.

## Recommended assessment order

### 1. Collect a baseline

Choose a collection method appropriate to the target.

```powershell
# Discover shares on a Windows server and collect directory ACLs.
.\Invoke-NtfsAssessment.ps1 `
    -ComputerName FS01 `
    -OutputRoot D:\AssessmentRuns `
    -ResolveActiveDirectory `
    -HashOutputs

# Read directory ACLs beneath an explicitly selected UNC path.
.\Invoke-NtfsAssessment.ps1 `
    -UncPath '\\FS01\Data\Department' `
    -OutputRoot D:\AssessmentRuns `
    -HashOutputs

# Discover NAS shares over SMB, then read Windows-style directory ACLs.
.\Invoke-NtfsAssessment.ps1 `
    -NasServer FILER01 `
    -OutputRoot D:\AssessmentRuns
```

With no target options, collection defaults to the local computer. Remote Windows
mode can query SMB share permissions through CIM. Explicit UNC/NAS scans do not
automatically provide the same share metadata or share-permission coverage.

Each invocation creates an `ASSESS_<host>_<timestamp>_<id>` directory. Preserve that
entire directory, not just selected CSV files. The manifest binds datasets to their
parts, columns, row counts, sizes, and hashes.

Important collection controls:

| Option | Behavior |
|---|---|
| `-MaxDepth` / `-MaxFolders` | Default depth is 10 and folder limit is 100,000 per scan. Limits can produce partial coverage; review recorded exclusions. |
| `-IncludeShare` / `-ExcludeShare` | Filter selected shares. Mandatory exclusions also include `ADMIN$`, `C$`, `D$`, `IPC$`, `print$`, and runner-name share patterns when available. |
| `-NasShareListCsv` | Supplies `NasServer,ShareName` rows; optional `Enabled=False` excludes a row. Useful when discovery is insufficient. |
| `-OntapSharePermissionsCsv` | Imports scoped share-permission evidence with `smb_server,smb_share,user_or_group,permission` columns and optional `sid,vserver`. Does not establish complete share ACL or directory coverage. |
| `-SplitOutputByShare` | Adds per-share output copies. Keep the original run intact for downstream processing. |
| `-UseIcaclsVerify` / `-CaptureAclBackup` | Optional local-Windows-share operations only. The DACL backup is not a complete rollback package. |

`-FollowReparsePoints` is intentionally rejected. `-OntapCredential` is also
rejected: unstructured ONTAP SSH tables are not supported; use the CSV import.

### 2. Review collection status before reporting

Start with `manifest.json`, `run.log`, `ShareCoverage.csv`, `ScanErrors.csv`, and
`SkippedPaths.csv`. Review `FatalError`, `CoverageStatus`, counts, and each scope.
An exit code of zero establishes only the declared directory-collection scope,
not complete file permission coverage or effective access.

Typical collected datasets include:

- `Servers.csv`, `Shares.csv`, `SharePermissions.csv`
- `Folders.csv`, `NtfsAcls.csv`
- `Identities.csv`, `GroupMemberships.csv`, `LocalGroupMemberships.csv`,
  `GroupExpansion.csv`, `GroupAcesFound.csv`
- Coverage/error datasets and, with `-HashOutputs`, `SHA256SUMS.csv`

Do not edit source CSVs or manifests in place. Downstream integrity checks may
reject modified, incomplete, or mismatched datasets. Recollect into a new run
instead of filling missing evidence with assumptions.

### 3. Generate consolidated reports

```powershell
.\Merge-NtfsAssessment.ps1 `
    -InputRoot D:\AssessmentRuns `
    -OutputFolder D:\AssessmentReports\Baseline `
    -RunSelection LatestSuccessful `
    -ThrottleLimit 1
```

Use a new or empty output directory, separate from the input run directories.
`LatestSuccessful` selects the newest eligible snapshot per server/share, including
partial snapshots. It does not repair gaps using older permissions. `AllSuccessful`
and `Explicit` reject overlapping snapshots rather than unioning historical ACLs.
For explicit selection, pass `-RunSelection Explicit -RunFolder <run1>,<run2>`.

Read `merge-state.json`, `merge-stage.log`, `MergeSourceRuns.csv`,
`NTFS_ExecutiveSummary.json`, and `NTFS_QA.json` first. Detailed outputs include
`NTFS_Findings.csv`, `NTFS_RiskByFolder.csv`, `NTFS_RiskByShare.csv`,
`NTFS_GroupReport.csv`, `NTFS_ShareVsNtfs.csv`, and coverage/error reports.

Risk indicators and recommendations require contextual review. They are not
effective-access calculations or approved remediation instructions. Incomplete
folder ACLs have no risk score and are excluded from risk averages.

### 4. Optionally collect and report best-practices evidence

Enable evidence at collection time when you need server configuration, signing,
SMB1, encryption, or audit-related checks:

```powershell
.\Invoke-NtfsAssessment.ps1 `
    -ComputerName FS01 `
    -OutputRoot D:\AssessmentRuns `
    -BestPractices `
    -CollectAuditEvidence
```

`-CollectAuditEvidence` and `-BestPracticesPolicyPath` require `-BestPractices`.
Best-practices collection also generates checks and a summary in the source run.
Audit policy is collected locally only; remote policy is not inferred from the
collector. Root SACL evidence is a sample, not descendant SACL coverage. NAS
configuration that is not queried remains unassessed.

To generate a separate offline report, use the actual run directory from collection:

```powershell
$baselineRun = 'D:\AssessmentRuns\ASSESS_FS01_<timestamp>_<id>'
.\New-NtfsBestPracticesReport.ps1 `
    -InputRunFolder $baselineRun `
    -OutputFolder D:\AssessmentReports\BestPractices
```

The output must be new or empty and outside the source run. Outputs include
`BestPracticeChecks.csv`, `BestPracticeSummary.json`,
`BestPracticesManifest.json`, and `report.log`.

An optional policy file has this shape:

```json
{
  "schemaVersion": 1,
  "rules": [
    { "checkId": "SMBRequireSecuritySignature", "expectedValue": true },
    { "checkId": "ShareEncryptionEnabled", "expectedValue": true }
  ]
}
```

Pass its path using `-BestPracticesPolicyPath` to collection or the offline report.
Keys are validated strictly, expected values must be booleans, and check IDs must
be allowlisted by the shared engine. `MeetsConfiguredPolicy` means one observed
setting matched one configured rule, not that the server/share is compliant.
Offline reporting cannot collect evidence missing from the source run.

### 5. Collect again, then compare original snapshots

Repeat collection with comparable targets, addressing, filters, and limits.
Choose the two actual run directories explicitly to avoid accidentally comparing
unrelated recent runs:

```powershell
$baselineRun = 'D:\AssessmentRuns\ASSESS_FS01_<baseline-timestamp>_<id>'
$comparisonRun = 'D:\AssessmentRuns\ASSESS_FS01_<later-timestamp>_<id>'
.\Compare-NtfsAssessment.ps1 `
    -BaselineRunFolder $baselineRun `
    -ComparisonRunFolder $comparisonRun `
    -OutputFolder D:\AssessmentReports\Changes
```

Alternatively, `-InputRoot D:\AssessmentRuns` selects the two newest runs by
manifest completion time. Comparison consumes collected runs, **not merge output**.

Review `comparison-state.json`, `comparison-stage.log`,
`NTFS_ComparisonSummary.json`, `NTFS_ComparisonCoverage.csv`, and
`NTFS_Changes.csv`. `NTFS_ComparisonRuns.csv` records the selected sources.
Missing records do not prove deletion or revoked access. Partial coverage,
unverified identity changes, incompatible roots, and unavailable share ACL evidence
can limit or prevent comparison. Individual file ACLs and group memberships are not
compared.

## Separate workflow: permission planning

Planning does not require merge output and does not consume findings as automatic
change instructions. It reads the live target and resolves the requested AD groups.

```powershell
.\Add-FileSharePermissions.ps1 `
    -Mode Plan `
    -TargetPath '\\FS01\Data\LabFolder' `
    -TargetPlatform Windows `
    -GroupName 'CONTOSO\Readers' `
    -Permissions ReadAndExecute `
    -Scope ThisFolderSubfoldersAndFiles `
    -OutputDirectory C:\NtfsAudit
```

Local fixed NTFS directories, verified mapped paths, and deep direct UNC paths
are supported for read-only planning. Mapped targets are frozen to UNC; local
targets remain bound to the originating host. `TargetPlatform` is an operator
declaration, not backend verification; `Auto` treats UNC as generic SMB.
Machine-local and SVM-local groups are unsupported.

Review the generated `Permissions_<id>` directory, including `plan.json`,
`before-and-intent.csv` when present, `manifest.json`, and `events.jsonl`.
Plans inventory affected folders and files within the chosen scope, record
protected boundaries without traversing them, and contain abstract intent rather
than computed post-propagation descriptors. `NoOp` is not effective-access proof.

**Do not use `Apply` or `Revert` as remediation steps.** They record
`Blocked/NotQualified` and exit nonzero without target writes, even with reviewed
hashes, tickets, `-WhatIf`, or `-Confirm`. Recovery-evidence verification does not
execute restoration. There is no force or experimental bypass.

## Separate workflow: disposable-lab validation

This workflow records observations only. Any external manual apply/revert requires
its own approval and operating procedure. It is not authorized by these examples.

Run the stages in this order:

| Order | Stage/action | Meaning |
|---|---|---|
| 1 | `Initialize` | Freeze target, platform, groups, scope, operator/host, ticket, and source hashes. |
| 2 | `CaptureBefore` | Capture baseline evidence and abstract intent. Review completeness before proceeding. |
| 3 | External manual apply | Only a separately approved action outside this toolkit. |
| 4 | `CaptureAfterApply` | Record observations after that external action. |
| 5 | External guarded revert | Only a separately approved recovery action outside this toolkit. |
| 6 | `CaptureAfterRevert` | Observe the resulting descriptors; not proof of complete physical restoration. |
| 7 | `Report` | Seal the report and any submitted manual observations. |

```powershell
.\Invoke-NtfsPermissionValidation.ps1 `
    -Stage Initialize `
    -TargetPath '\\FS01\DisposableLab\Case1' `
    -TargetPlatform Windows `
    -GroupName 'CONTOSO\Readers' `
    -Permissions Read `
    -ChangeTicket CHG123 `
    -EvidenceDirectory C:\NtfsEvidence `
    -DisposableAcknowledgement `
    -NonInteractive

# Use the CasePath returned by Initialize.
$casePath = 'C:\NtfsEvidence\Permissions_<id>'
.\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureBefore -CasePath $casePath -NonInteractive

# Stop here unless separately approved external actions and evidence review permit
# continuing. These captures do not perform apply or revert.
.\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureAfterApply -CasePath $casePath -ManualActionAcknowledgement -NonInteractive
.\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureAfterRevert -CasePath $casePath -ManualActionAcknowledgement -NonInteractive
.\Invoke-NtfsPermissionValidation.ps1 -Stage Report -CasePath $casePath -NonInteractive
```

Resume with `CasePath` and stage/checkpoint options only; do not override the
frozen initialization parameters. Captures inspect files and folders even for
`ThisFolderOnly`, to observe unintended descendant changes. Each capture reads
twice; matching reads still do not establish atomicity or convergence.

Stages and their hash-bound evidence, including `stage.log`, are immutable.
Do not edit or delete case artifacts or locks to retry a failed stage. Preserve
interrupted, torn, or drifted cases for review. `Report` may close an unfinished
case, recording missing evidence as incomplete.

To submit manual observations, copy `Initialize/manual-matrix.json` **outside**
the case, fill the external copy while retaining its full schema and bindings,
and supply it to `Report` with `-ManualObservationsFile`. Archive supporting
attachments separately. Declarations are not proof that commands ran; unperformed
matrix entries remain `NotRun`.

Inspect the returned `Status`, `NextStep`, report, and commit hashes, not just
process exit status. `WriterQualification` always remains `NotQualified`.
Archive evidence and each reported commit hash externally.

## Status, limits, and versions

| Entry point | Exit/status interpretation |
|---|---|
| Assessment | `0`: completed within the declared directory scope; `1`: partial collection; `2`: fatal failure. Inspect coverage and manifest details. |
| Merge and comparison | `0`: completed; `1`: completed with warnings/limitations; `2`: invalid input or failure. Inspect the state JSON before consuming reports. Differences alone do not make comparison fail. |
| Best-practices report | `0`: report generated; `2`: failure. A generated report can still contain `NotAssessed` evidence. |
| Permission planner | `0`: planning path completed; `2`: blocked. Review-only plans can still be marked blocked; neither result enables mutation. |
| Validation | Inspect result/report status and completeness explicitly; successful invocation is not change success or writer qualification. |

CSV files rotate at **100,000,000 bytes per part**, including encoding/header
overhead. Keep all parts together. Merge/comparison default to a
`MaxRowsPerShare` guard of 1,000,000 input rows; increasing it requires sufficient
memory. Merge parallel workers multiply per-share memory use, so start with
`-ThrottleLimit 1`.

Release versions are defined once in `$script:NtfsVersions` in
`NtfsAssessment.Common.ps1`. Entry points and shared engines use the corresponding
component entry for logs and output metadata. Schema versions and compatibility
thresholds are separate and must not be changed merely to bump a release.
Script and generated output filenames do not include release versions. Text logs
record component/version fields; permission audit events record their version in
`events.jsonl`.

## Tests

Run synthetic regression harnesses from the repository root:

```powershell
.\Tests\Test-NtfsAssessment.ps1
.\Tests\Test-NtfsBestPractices.ps1
```

The assessment harness exercises collection mocks, merge/comparison, integrity,
coverage, CSV size limits, and logging. The best-practices harness covers policy
validation, evidence handling, reports, and collector opt-in behavior.

With Pester 5 or later installed:

```powershell
Invoke-Pester -Path .\Tests\NtfsAssessment.Tests.ps1, .\Tests\NtfsPermissions.Tests.ps1, .\Tests\NtfsPermissionValidation.Tests.ps1 -Output Detailed
```

`NtfsAssessment.Tests.ps1` wraps the assessment harness in Pester.
`Invoke-MockedCollector.ps1` and `Invoke-FaultedNtfs.ps1` are test helpers, not
operator entry points.

`Tests/NtfsPermissions.WindowsQualification.Tests.ps1` is an opt-in, read-only
preflight scaffold for an independently prepared disposable Windows target. It
expects files and protected descendant boundaries in that fixture. Its environment
variables are documented in the test file. It neither performs mutation tests nor
qualifies a writer.

## Work still required

The following are current gaps or required qualification work, not capabilities
enabled by configuration switches:

| Area | Remaining work |
|---|---|
| Live platform validation | Exercise real Windows PowerShell 5.1, AD, CIM, SMB, permissions/privileges, and large/long-path inventories. Synthetic tests do not establish live interoperability. Qualify Windows local NTFS, Windows SMB, NetApp SMB, and generic NAS separately. |
| Target identity and namespace proof | Establish stable volume/file identities, identity-bound handles, direct backend/security-style proof, target group authority/trust, and reliable DFS/alias/backend rejection before any writable implementation. Current path and volume observations are insufficient. |
| Native permission writer | Design and implement a qualified writer before enabling `Apply`/`Revert`. The current release intentionally has none. Do not remove the qualification gate as a shortcut. |
| Propagation and concurrency safety | Validate both scopes across folders/files, protected/reparse boundaries, existing inheritance, exclusive-handle availability and SMB client impact, propagation behavior, and concurrent administrator changes. |
| Recovery qualification | Demonstrate exact owner/group/DACL/control and identity verification per affected path, drift-refused guarded rollback, and safe behavior under crashes, timeouts, partial propagation, and interrupted journals. DACL-only `icacls` backups are insufficient. |
| Manual validation evidence | Complete the external test matrix with actual approved commands/results, accounts, UTC times, reviewers, platform bindings, and archived source/evidence hashes. Passing read-only preflight or matching captured descriptors is not qualification. |
| Assessment scope | Individual file ACL inventory and true effective-access calculations are outside the current assessment/comparison scope. Plan/validation file capture does not add those capabilities to the collector. Any expansion needs separate implementation and validation. |
| Additional backend/audit evidence | Remote audit policy, full descendant SACL coverage, NAS-native configuration/authority verification, and machine/SVM-local group support are not established. Unsupported evidence must remain explicit rather than inferred. |

## Disclaimer

Provided **AS IS**, without warranty, technical support, maintenance, or service-level
commitment. This is not an official Microsoft product or supported Microsoft
service. Review and test in nonproduction, maintain independently verified backups,
and obtain required approvals. Reports and examples do not authorize changes.
