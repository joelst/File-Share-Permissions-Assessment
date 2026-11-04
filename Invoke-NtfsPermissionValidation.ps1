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
Read-only permission validation and evidence walkthrough.
.NOTES
Release version: NtfsAssessment.Common.ps1, PermissionValidation entry in NtfsVersions.

.DESCRIPTION
Stages: Initialize, CaptureBefore, CaptureAfterApply, CaptureAfterRevert, Report.
Initialize creates a restrictive local case directory under EvidenceDirectory.
Resume with CasePath only: target, platform, grants, scope, ticket, host and source
hashes are frozen. Mapped targets resolve to UNC ONCE. TargetPlatform accepts
Auto/Windows/NetApp/Nas using the existing planner's explicit platform declarations.
No target ACL or content writes occur. WhatIf still writes LOCAL evidence, including
restrictive evidence-directory ACLs. It does not simulate or perform target changes.

Use only a disposable, independently approved environment. The operator must verify
that the trusted local evidence volume is physically separate from the target,
including aliases/DFS/share backing paths. Hash chains detect inconsistencies, not
malicious rewriting; archive each commit hash and evidence externally under enterprise
access control. The local exclusive case lock is not a distributed target lock.
Interrupted stages/locks/orphan artifacts fail closed and must be preserved for
manual review: no automatic retry, deletion, recovery or rollback.

All captures inventory folders AND files, even for ThisFolderOnly, to observe
unintended descendant changes. Protected descendants are captured but not traversed.
Coverage is bounded by MaxPaths; errors/reparse/unsupported ACLs make it Incomplete.
Each capture reads twice, recording both intervals. Observed churn makes it
Incomplete; matching observations are never an atomic/convergence proof.
No stable physical object identity, DFS/backend or target group authority is proven.
Exact revert matches are observational only, within the captured namespace; they do
not prove protected branch contents or absence of concurrent/transient changes.
SDDL is compared ordinally without DACL reordering. SACL auditing is not assessed.
Captured descriptor sections are explicitly owner, group and DACL only; unknown
or uncollected sections are never reported as equal.
Apply intent is abstract, NOT an expected post-propagation descriptor. Observed
allow grants are NOT effective-access tests. An unchanged capture is NoChangeObserved,
never change success. WriterQualification is ALWAYS NotQualified.

After CaptureBefore, perform ONLY a separately approved EXTERNAL manual apply;
after CaptureAfterApply perform ONLY a separately approved EXTERNAL guarded revert.
Add-FileSharePermissions Apply/Revert remain blocked. This walkthrough supplies no
writer, setter, destructive access tests, permission to act, or qualification bypass.
The JSON manual matrix remains NotRun: collect actual commands/results, test account,
time, platform and validated source hashes externally for independent review.
Copy Initialize/manual-matrix.json OUTSIDE the sealed case, fill the external copy,
and supply it to Report with ManualObservationsFile. Submitted observations are
strictly source/platform/case-bound but are operator declarations, not execution proof.
Optional OperatorMetadataJson is an object containing exactly Session, Volume, Nas,
Backend, SecurityStyle, Namespace and EvidenceStorage string fields (unverified).
.EXAMPLE
.\Invoke-NtfsPermissionValidation.ps1 -Stage Initialize -TargetPath '\\server\lab\case1' -TargetPlatform Windows -GroupName 'DOMAIN\Readers' -Permissions Read -ChangeTicket CHG123 -EvidenceDirectory C:\NtfsEvidence -DisposableAcknowledgement
.EXAMPLE
.\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureBefore -CasePath C:\NtfsEvidence\Permissions_CASE -NonInteractive
.EXAMPLE
.\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureAfterApply -CasePath C:\NtfsEvidence\Permissions_CASE -ManualActionAcknowledgement -NonInteractive
.EXAMPLE
.\Invoke-NtfsPermissionValidation.ps1 -Stage CaptureAfterRevert -CasePath C:\NtfsEvidence\Permissions_CASE -ManualActionAcknowledgement -NonInteractive
.EXAMPLE
.\Invoke-NtfsPermissionValidation.ps1 -Stage Report -CasePath C:\NtfsEvidence\Permissions_CASE -NonInteractive
Report may close an unfinished case, recording missing stages as Incomplete.
.EXAMPLE
.\Invoke-NtfsPermissionValidation.ps1 -Stage Report -CasePath C:\NtfsEvidence\Permissions_CASE -ManualObservationsFile C:\Review\observations.json -NonInteractive
Observations must be from an externally edited copy of the case's manual matrix.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [ValidateSet('Initialize','CaptureBefore','CaptureAfterApply','CaptureAfterRevert','Report')]
    [string]$Stage = 'Initialize',
    [string]$EvidenceDirectory,
    [string]$CasePath,
    [string]$TargetPath,
    [ValidateSet('Auto','Windows','NetApp','Nas')][string]$TargetPlatform = 'Auto',
    [string]$GroupName,
    [string]$Permissions,
    [string]$GroupPermissionsJson,
    [string]$GroupPermissionsFile,
    [ValidateSet('ThisFolderSubfoldersAndFiles','ThisFolderOnly')]
    [string]$Scope = 'ThisFolderSubfoldersAndFiles',
    [ValidateRange(1,100000)][int]$MaxPaths = 10000,
    [string]$ChangeTicket,
    [string]$OperatorMetadataJson,
    [string]$ManualObservationsFile,
    [switch]$DisposableAcknowledgement,
    [switch]$ManualActionAcknowledgement,
    [switch]$NonInteractive
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'NtfsPermissions.Validation.ps1')

try {
    Assert-NvWindows
    if ($Stage -eq 'Initialize') {
        if ($CasePath -or $ManualActionAcknowledgement -or $ManualObservationsFile) { throw 'Initialize requires a NEW case, not CasePath, observations or a manual-action acknowledgement.' }
        if (-not $DisposableAcknowledgement -and -not $NonInteractive) {
            $DisposableAcknowledgement = (Read-Host 'Type DISPOSABLE to acknowledge independent approval and a disposable target') -ceq 'DISPOSABLE'
        }
        if (-not $DisposableAcknowledgement) { throw 'DisposableAcknowledgement is required; this is not approval to mutate.' }
        if ([string]::IsNullOrWhiteSpace($ChangeTicket) -or $ChangeTicket -match '[\x00-\x1f]' -or -not $EvidenceDirectory) {
            throw 'EvidenceDirectory and a nonempty ChangeTicket without control characters are required.'
        }
        $descriptor = Resolve-NpTarget $TargetPath $TargetPlatform
        $grants = @(Get-NpGrants $GroupName $Permissions $GroupPermissionsJson $GroupPermissionsFile ${function:Resolve-NpWindowsGroup})
        $binding = New-NvBinding $descriptor $grants $Scope $MaxPaths $ChangeTicket
        if ($OperatorMetadataJson) { $binding.Metadata.OperatorDeclarations=ConvertTo-NvOperatorMetadata $OperatorMetadataJson }
        # WhatIf is target-only by contract; evidence ACL creation must not be suppressed.
        $CasePath = & { $WhatIfPreference=$false; $ConfirmPreference='None'; New-NpRun $EvidenceDirectory $descriptor.CanonicalPath }
        $result = Invoke-NvStage $CasePath Initialize $binding -WhatIfRecorded ([bool]$WhatIfPreference)
    } else {
        foreach ($name in @('EvidenceDirectory','TargetPath','TargetPlatform','GroupName','Permissions','GroupPermissionsJson',
            'GroupPermissionsFile','Scope','MaxPaths','ChangeTicket','DisposableAcknowledgement','OperatorMetadataJson')) {
            if ($PSBoundParameters.ContainsKey($name)) { throw "Resume accepts CasePath, Stage and checkpoint options only; cannot override $name." }
        }
        if (-not $CasePath) { throw 'CasePath is required to resume.' }
        if ($ManualObservationsFile -and $Stage -cne 'Report') { throw 'ManualObservationsFile is accepted only by Report.' }
        if ($Stage -in @('CaptureAfterApply','CaptureAfterRevert')) {
            if (-not $ManualActionAcknowledgement -and -not $NonInteractive) {
                $ManualActionAcknowledgement = (Read-Host 'Type EXTERNAL to acknowledge separately approved external action/recovery review; this tool made NO target changes') -ceq 'EXTERNAL'
            }
            if (-not $ManualActionAcknowledgement) { throw 'ManualActionAcknowledgement is required for this external-action checkpoint.' }
        } elseif ($ManualActionAcknowledgement) { throw 'ManualActionAcknowledgement is valid only for after-action captures.' }
        $result = Invoke-NvStage $CasePath $Stage -ManualAcknowledged ([bool]$ManualActionAcknowledgement) -WhatIfRecorded ([bool]$WhatIfPreference) -ManualObservationsFile $ManualObservationsFile
    }
    $actions=@(
        if($result.Diagnostics.MissingEvidence -gt 0){"Resolve $($result.Diagnostics.MissingEvidence) missing evidence records."}
        if($result.Diagnostics.Warnings -gt 0){"Review $($result.Diagnostics.Warnings) validation warnings."}
    )
    if($actions.Count){$actions+='Records may overlap across checks/stages and verification reads. Writer qualification has 1 non-bypassable restriction.'}
    $completion=@{
        component='Permission validation';status=$result.Status;outputPath=$result.CasePath
        summary="Stage=$($result.Stage); TargetWrites=0; WriterQualification=NotQualified. Archive commit SHA256 $($result.CommitSHA256) externally."
        reviewPath=@((Join-Path (Join-Path $result.CasePath $Stage) 'manifest.json'))
        requirements=($actions -join ' ')
        reasonSummary=$result.Diagnostics.Reasons
        nextStep=$result.NextStep
    }
    if($Stage -eq 'Report'){
        $completion.reviewPath+=@(Join-Path $result.CasePath 'Report\report.json')
        $completion.nextStep='No next script is required for this sealed report. '+$result.NextStep
    }elseif($Stage -ne 'Initialize'){
        $stageDirectory=Join-Path $result.CasePath $Stage
        $completion.reviewPath+=@((Join-Path $stageDirectory 'inventory.json'),(Join-Path $stageDirectory 'comparison.json'))
        if($Stage -eq 'CaptureBefore'){$completion.reviewPath+=@(Join-Path $stageDirectory 'intent-review.json')}
    }
    if($result.Status -eq 'Observed'){
        if($Stage -ne 'Report'){
            $completion.nextScriptPath=Join-Path $PSScriptRoot 'Invoke-NtfsPermissionValidation.ps1'
            $completion.nextParameters=[ordered]@{
                Stage=$(switch($Stage){
                    Initialize {'CaptureBefore'}
                    CaptureBefore {'CaptureAfterApply'}
                    CaptureAfterApply {'CaptureAfterRevert'}
                    CaptureAfterRevert {'Report'}
                })
                CasePath=$result.CasePath
            }
        }
    }else{
        $completion.nextStep+=' Resolve the counted issues before any external action. Invoke-NtfsPermissionValidation.ps1 -Stage Report can only close an unfinished case; a sealed report requires a separately approved new case, never automatic retry.'
    }
    Write-NtfsCompletion @completion
    $result
} catch {
    $completion=@{
        component='Permission validation';status='Failed'
        requirements='Resolve 1 failed validation invocation; preserved locks or immutable stages may require independent recovery review.'
        reasonSummary=@([pscustomobject]@{Count=1;Reason=$_.Exception.Message})
        nextStep='Stop external actions. Preserve any case, lock, and stage evidence for independent review; do not delete locks or automatically retry.'
    }
    if($CasePath){$completion.outputPath=$CasePath}
    Write-NtfsCompletion @completion
    throw
}
