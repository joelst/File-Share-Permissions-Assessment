# File Share Permissions Assessment

This PowerShell toolkit collects read-only file-share and NTFS permission evidence, produces offline review reports, and provides a separate permission-planning and validation workflow. It does not calculate effective access or make permission changes.

## Components and workflow

1. **Collect evidence** with `Invoke-NtfsAssessment.ps1`. It records share metadata and permissions, directory ACLs, coverage, errors, and optional identity/group and best-practices evidence. Collection is read-only.
2. **Review one or more runs** with `Merge-NtfsAssessment.ps1`. This combines selected assessment runs into offline findings and risk-prioritization reports.
3. **Compare two snapshots** with `Compare-NtfsAssessment.ps1`. The comparison is offline and directional; it reports differences in collected evidence, not proven creations, deletions, or effective-access changes.
4. **Optionally assess observed settings** with `-BestPractices` during collection or `New-NtfsBestPracticesReport.ps1` against an existing run. Policy matches apply only to the individual observed setting; they are not compliance certification.
5. **Plan permissions separately** with `Add-FileSharePermissions.ps1`. Planning is read-only. `Apply` and `Revert` remain blocked.
6. **Use the validation walkthrough only for qualification evidence** with `Invoke-NtfsPermissionValidation.ps1`. Its ordered stages record local, hash-bound observations. After-action captures require a separately approved external action; this toolkit has no native writer.

The usual reporting order is **collect → merge and/or compare → review limitations**. Best-practices reports can be generated during collection or offline afterward. Permission planning and validation are separate workflows and do not authorize changes.

## Prerequisites

- Windows PowerShell 5.1 is the target runtime. Offline and synthetic regression checks also run under PowerShell 7.
- Run collection from a host with access to the selected Windows SMB shares. Remote Windows SMB configuration collection uses CIM; Active Directory name and membership resolution requires the ActiveDirectory module and suitable directory access.
- Optional NAS permission evidence is imported from a supplied CSV; it does not qualify NAS collection or establish complete share ACL coverage.
- `Invoke-NtfsPermissionValidation.ps1` requires Windows and a trusted, restrictive local evidence directory outside assessed target data. Its public validation stages are unavailable on non-Windows systems.
- Install Pester 5 or later to run the Pester suites. No external runtime package is required by the assessment scripts.

## Examples

Collect a local or remote Windows target:

```powershell
.\Invoke-NtfsAssessment.ps1 -OutputRoot C:\NtfsRuns -ComputerName FS01
```

Collect an explicit share and include best-practices and audit-policy evidence:

```powershell
.\Invoke-NtfsAssessment.ps1 -OutputRoot C:\NtfsRuns -UncPath '\\FS01\Projects' `
  -BestPractices -CollectAuditEvidence
```

Merge selected runs:

```powershell
.\Merge-NtfsAssessment.ps1 -InputRoot C:\NtfsRuns -OutputFolder C:\NtfsReports\Merged
```

Compare the two latest runs, or select a specific directional pair:

```powershell
.\Compare-NtfsAssessment.ps1 -InputRoot C:\NtfsRuns -OutputFolder C:\NtfsReports\LatestDiff
.\Compare-NtfsAssessment.ps1 -BaselineRunFolder C:\NtfsRuns\ASSESS_old `
  -ComparisonRunFolder C:\NtfsRuns\ASSESS_new -OutputFolder C:\NtfsReports\SelectedDiff
```

Generate a best-practices report from a completed run:

```powershell
.\New-NtfsBestPracticesReport.ps1 -InputRunFolder C:\NtfsRuns\ASSESS_FS01 `
  -OutputFolder C:\NtfsReports\BestPractices
```

Create a read-only permission plan (this does not modify the target):

```powershell
.\Add-FileSharePermissions.ps1 -Mode Plan -TargetPath '\\FS01\Projects\Team' `
  -GroupName 'DOMAIN\Readers' -Permissions ReadAndExecute -OutputDirectory C:\NtfsAudit
```

The validation workflow starts with a separately approved disposable target and a trusted local evidence directory:

```powershell
.\Invoke-NtfsPermissionValidation.ps1 -Stage Initialize -TargetPath '\\FS01\Lab\Disposable' `
  -TargetPlatform Windows -GroupName 'DOMAIN\Readers' -Permissions Read `
  -ChangeTicket CHG123 -EvidenceDirectory C:\NtfsEvidence -DisposableAcknowledgement
```

Resume later stages using only the returned `CasePath`. After-apply and after-revert captures require explicit acknowledgements of external actions. The tool itself has no qualified writer and performs no target writes.

Run regression suites from the repository root:

```powershell
Invoke-Pester -Path ./Tests/NtfsAssessment.Tests.ps1
Invoke-Pester -Path ./Tests/NtfsPermissions.Tests.ps1
Invoke-Pester -Path ./Tests/NtfsPermissionValidation.Tests.ps1
pwsh -NoLogo -NoProfile -File ./Tests/Test-NtfsBestPractices.ps1
```

## Outputs and interpretation

Assessment run folders contain `manifest.json`, `run.log`, and CSV datasets. Use `manifest.json` to identify the component release, schema version, run status, coverage, and dataset hashes. `ShareCoverage.csv`, `ScanErrors.csv`, and `SkippedPaths.csv` are essential context: missing records in a partial scan are not proof that permissions or paths are absent.

Merge and comparison folders contain JSON summaries, CSV reports, and stage logs (`merge-stage.log` and `comparison.log`). Log records are tab-separated UTC timestamp, component, component version, level, stage, and message. Embedded tabs and line breaks in messages are escaped. Release versions are stored in `NtfsAssessment.Common.ps1`; output filenames are not versioned.

Offline best-practices reports contain `BestPracticesManifest.json`, `BestPracticeSummary.json`, CSV evidence, and `best-practices.log`. Validation stages contain `validation-stage.log` in each stage directory; its hash is recorded in that stage's manifest and commit chain. Preserve sealed case artifacts and review them independently.

Exit codes are generally `0` for completion, `1` for completion with limitations or partial evidence, and `2` for invalid input or failure. Check the relevant state JSON, manifests, coverage data, and limitations before relying on outputs.

## Qualification limits

All automated checks are offline or synthetic. Real Windows PowerShell 5.1, Active Directory, CIM, SMB, and backend qualification remain outstanding. In particular:

- Directory ACL collection does not cover individual file ACLs, and incomplete coverage is not treated as absence.
- Reports do not calculate effective access, authorize remediation, or prove that a change succeeded.
- NAS and NetApp evidence requires separate backend qualification; imported data is not proof of completeness.
- Permission Apply/Revert are blocked. The validation workflow has no native writer and does not qualify a Windows SMB, NetApp SMB, or generic SMB writer.
- Validation snapshots are non-atomic observations; hashes detect inconsistencies but do not prove authenticity, stable object identity, backend authority, or physical reversion.
