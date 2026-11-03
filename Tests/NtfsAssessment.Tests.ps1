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

#requires -Modules @{ModuleName='Pester';ModuleVersion='5.0.0'}
<#
.SYNOPSIS
  Pester coverage for all offline toolkit behavior, including the actual 100 MB cap.
.DESCRIPTION
  Run: Invoke-Pester -Path ./Tests/NtfsAssessment.Tests.ps1 -Output Detailed
  The fixtures run once in an isolated PowerShell process so AD/ACL mocks cannot
  leak into Pester or contact real servers. Each recorded assertion is a Pester case.
  Windows AD/SMB integration is not exercised by these synthetic tests.
#>
BeforeDiscovery {
    $engine=(Get-Process -Id $PID).Path
    $resultsPath=Join-Path $PSScriptRoot ('NtfsPester_'+[guid]::NewGuid().ToString('N')+'.json')
    $cases=@()
    $completed=$false
    $details=''
    try{
        $log=@(& $engine -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'Test-NtfsAssessment.ps1') -ResultsPath $resultsPath 2>&1)
        $code=$LASTEXITCODE
        if(Test-Path -LiteralPath $resultsPath){
            $report=Get-Content -LiteralPath $resultsPath -Raw|ConvertFrom-Json
            $cases=@($report.Checks)
            $completed=$code -eq 0 -and $report.Completed -and $report.CleanupCompleted -and $cases.Count -gt 0
        }
        $details="Child exit=$code; output: $($log -join "`n")"
    }finally{
        if(Test-Path -LiteralPath $resultsPath){Remove-Item -LiteralPath $resultsPath -ErrorAction Stop}
    }
    $caseData=@(foreach($case in $cases){
        @{CaseName=('{0:D4} [{1}] {2}' -f [int]$case.Id,$case.Area,$case.Message);Passed=[bool]$case.Passed;Reason=$case.Message}
    })
    $caseData+=@{CaseName='Harness completed all scenarios and cleanup successfully';Passed=$completed;Reason=$details}
}

Describe 'NTFS assessment offline regression coverage' {
    It '<CaseName>' -ForEach $caseData {
        $Passed | Should -BeTrue -Because $Reason
    }
}
