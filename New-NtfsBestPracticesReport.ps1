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

try {
    $result=Invoke-NtfsBestPracticesOfflineReport $InputRunFolder $OutputFolder $BestPracticesPolicyPath
    Write-Host "Best-practices report written to $OutputFolder"
    Write-Host "Checks: $($result.CheckCount); source run: $($result.RunFolder)"
    exit 0
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 2
}
