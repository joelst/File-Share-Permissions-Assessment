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
  Creates a read-only best-practices review report from a verified assessment run.
.EXAMPLE
  .\Invoke-NtfsAssessment.ps1 -OutputRoot D:\AssessmentRuns -BestPractices
.EXAMPLE
  .\Invoke-NtfsAssessment.ps1 -OutputRoot D:\AssessmentRuns -ComputerName FS01 -BestPractices -CollectAuditEvidence -BestPracticesPolicyPath .\policy.json
.EXAMPLE
  .\New-NtfsBestPracticesReport.ps1 -InputRunFolder D:\AssessmentRuns\ASSESS_FS01_... -OutputFolder D:\Reports\FS01-BP
.NOTES
  Release version: NtfsAssessment.Common.ps1, BestPractices entry in NtfsVersions.
  Matches the shared best-practices engine and report evidence version.
  Uses the built-in baseline by default. Custom policy rules override individual
  baseline expectations; omitted rules retain their built-in expectations.
  Policy JSON schema (exact keys; values are booleans; check IDs are allowlisted):
  {"schemaVersion":1,"rules":[{"checkId":"SMBRequireSecuritySignature","expectedValue":true},{"checkId":"ShareEncryptionEnabled","expectedValue":true}]}
  A policy match applies only to that observed setting, not overall compliance.
  Output must be a new or empty folder outside the source run. This report does not
  collect live settings, change configuration, certify compliance, or calculate access.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$InputRunFolder,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputFolder,
    [string]$BestPracticesPolicyPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'NtfsAssessment.Common.ps1')
. (Join-Path $PSScriptRoot 'NtfsAssessment.BestPractices.ps1')

$reportDirectory=$null
try {
    $reportDirectory=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFolder)
    $result=Invoke-NtfsBestPracticesOfflineReport $InputRunFolder $reportDirectory $BestPracticesPolicyPath
    $coverage=$result.SourceCoverage
    $noScopes=$coverage.CoverageRows -eq 0
    $incomplete=$noScopes -or $result.StatusCounts.NotAssessed -gt 0 -or $coverage.PartialRows -gt 0 -or
        $coverage.ScanErrors -gt 0 -or $coverage.SkippedPathRows -gt 0 -or $coverage.BestPracticesEvidenceErrors -gt 0
    $sourceIssues=@(
        if($coverage.PartialRows -gt 0){"$($coverage.PartialRows) partial scopes"}
        if($coverage.ScanErrors -gt 0){"$($coverage.ScanErrors) error records"}
        if($coverage.SkippedPathRows -gt 0){"$($coverage.SkippedPathRows) skipped-path records"}
        if($coverage.BestPracticesEvidenceErrors -gt 0){"$($coverage.BestPracticesEvidenceErrors) best-practices evidence error records"}
    )
    $actions=@(
        if($noScopes){'Resolve 1 blocker: no assessment scopes are recorded in ShareCoverage.csv. Check target names and share filters.'}
        if($result.StatusCounts.NotAssessed -gt 0){"Resolve or document $($result.StatusCounts.NotAssessed) missing evidence checks."}
        if($result.StatusCounts.DoesNotMeetConfiguredPolicy -gt 0){"Review $($result.StatusCounts.DoesNotMeetConfiguredPolicy) policy mismatches."}
        if($result.StatusCounts.Review -gt 0){"Review $($result.StatusCounts.Review) contextual warnings."}
        if($sourceIssues.Count){"Source coverage: $($sourceIssues -join ', ')."}
    )
    $completion=@{
        component='Best practices';status=$(if($incomplete){'CompletedWithWarnings'}else{'Completed'})
        summary="Checks=$($result.CheckCount); Matches=$($result.StatusCounts.MeetsConfiguredPolicy); Mismatches=$($result.StatusCounts.DoesNotMeetConfiguredPolicy); Review=$($result.StatusCounts.Review); NotAssessed=$($result.StatusCounts.NotAssessed)."
        outputPath=$reportDirectory
        reviewPath=@((Join-Path $reportDirectory 'BestPracticeChecks.csv'),(Join-Path $reportDirectory 'BestPracticeSummary.json'))
        requirements=($actions -join ' ')
        reasonSummary=@($result.Diagnostics)
        nextStep=$(if($noScopes){
            'No scopes were recorded. Run Invoke-NtfsAssessment.ps1 with corrected targets or share filters, then New-NtfsBestPracticesReport.ps1 on the new run. Do not treat this report as an assessment of access.'
        }elseif($incomplete){
            'No next report script is required. To resolve collection gaps, next script: Invoke-NtfsAssessment.ps1 using a collection mode that supports the missing evidence, then New-NtfsBestPracticesReport.ps1 on the new run. Offline reporting cannot fill evidence gaps.'
        }else{
            'No next script is required: reporting is complete. Review BestPracticeChecks.csv; after approved policy exceptions, rerun New-NtfsBestPracticesReport.ps1 with -BestPracticesPolicyPath. Matches do not establish overall compliance.'
        })
    }
    Write-NtfsCompletion @completion
    exit 0
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    $completion=@{
        component='Best practices';status='Failed'
        requirements='Resolve 1 report-generation failure.'
        reasonSummary=@([pscustomobject]@{Count=1;Reason=$_.Exception.Message})
        nextStep='Next script: New-NtfsBestPracticesReport.ps1, after resolving the recorded input, policy, output, or integrity error. Do not treat partial output as a completed report.'
    }
    if($reportDirectory){
        $reportLog=Join-Path $reportDirectory 'report.log'
        if(Test-Path -LiteralPath $reportLog -PathType Leaf){$completion.reviewPath=@($reportLog)}
    }
    Write-NtfsCompletion @completion
    exit 2
}
