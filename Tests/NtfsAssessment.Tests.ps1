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

    Describe 'Workflow completion output' {
        BeforeAll {
            . (Join-Path (Split-Path $PSScriptRoot -Parent) 'NtfsAssessment.Common.ps1')
        }
        It 'keeps human guidance off the success stream' {
            $success=@(Write-NtfsCompletion -component Assessment -status Completed -outputPath 'C:\Evidence' -nextStep 'Review coverage.' -InformationVariable messages)
            $success.Count | Should -Be 0
            ($messages.MessageData -join "`n") | Should -Match 'Output: C:\\Evidence'
            ($messages.MessageData -join "`n") | Should -Match 'Next:\r?\n  Review coverage\.'
        }
        It 'quotes actual command paths and parameters without interpreting their contents' {
            $path="C:\Evidence\O'Brien `$case"
            $parameters=[ordered]@{RunSelection='Explicit';RunFolder=$path;OutputFolder="$($path)\reports"}
            $records=@(Write-NtfsCompletion -component Assessment -status Completed -nextStep 'Merge this snapshot:' -nextScriptPath "C:\Tools\O'Brien\Merge-NtfsAssessment.ps1" -nextParameters $parameters 6>&1)
            $command=[string]$records[-1].MessageData
            $tokens=$null;$errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseInput($command,[ref]$tokens,[ref]$errors)
            $errors.Count | Should -Be 0
            $commandAst=$ast.EndBlock.Statements[0].PipelineElements[0]
            $commandAst.CommandElements[0].Value | Should -Be "C:\Tools\O'Brien\Merge-NtfsAssessment.ps1"
            $commandAst.CommandElements[4].Value | Should -BeExactly $path
            $commandAst.CommandElements[6].Value | Should -BeExactly "$($path)\reports"
        }
        It 'prioritizes missing evidence and bounds displayed reason groups without hiding totals' {
            $reasons=@([pscustomobject]@{Status='NotAssessed';Count=1;Reason='SMB configuration was not collected.'})
            $reasons+=@(1..6|ForEach-Object{[pscustomobject]@{Count=10;Reason="Contextual warning $($_)"}})
            $records=@(Write-NtfsCompletion -component Assessment -status CompletedWithWarnings -requirements 'Resolve 1 missing evidence check; review 60 warnings.' -reasonSummary $reasons -nextStep 'Run Merge-NtfsAssessment.ps1 for observed evidence.' 6>&1)
            $lines=@($records.MessageData|ForEach-Object{[string]$_})
            $lines | Should -Contain 'Resolve/review:'
            $lines | Should -Contain '  Resolve 1 missing evidence check; review 60 warnings.'
            $reasonLines=@($lines|Where-Object{$_ -like '  - (*'})
            $reasonLines.Count | Should -Be 5
            $reasonLines[0] | Should -Match 'SMB configuration was not collected'
            ($lines -join "`n") | Should -Match '2 additional groups'
        }
        It 'separates sections and wraps prose without truncating paths or changing the next command' {
            $longPath='C:\Evidence\'+('long-folder-name'*10)+'\BestPracticeChecks.csv'
            $summary='Folders=7894; ACEs=31576. '+('Collected directory evidence requires contextual review. '*4)
            $records=@(Write-NtfsCompletion -component Assessment -status CompletedWithWarnings -summary $summary -outputPath 'C:\Evidence' -reviewPath $longPath -requirements 'Resolve 7 missing evidence checks.' -reasonSummary @([pscustomobject]@{Count=1;Reason=('Audit evidence needs careful contextual review '*6).Trim()+'.'}) -nextStep 'Merge this snapshot.' -nextScriptPath 'C:\Tools\Merge-NtfsAssessment.ps1' -nextParameters ([ordered]@{RunSelection='Explicit';RunFolder='C:\Evidence'}) 6>&1)
            $rendered=$records.MessageData -join "`n"
            foreach($heading in @('Output: C:\Evidence','Review:','Resolve/review:','Reasons:','Next:')){
                $rendered | Should -Match ("`n`n"+[regex]::Escape($heading))
            }
            $rendered | Should -Match 'Assessment: CompletedWithWarnings\.\r?\n  Folders=7894'
            $rendered | Should -Match ([regex]::Escape($longPath))
            $rendered | Should -Match '- \(1 record\):'
            $prose=@($records.MessageData|Where-Object{$_ -like '  Folders=*' -or $_ -like '  - (*'})
            @($prose[-1] -split "`n").Count | Should -BeGreaterThan 1
            foreach($message in $prose){
                foreach($line in ([string]$message -split "`n")){$line.Length | Should -BeLessOrEqual 100}
            }
            $command=[string]$records[-1].MessageData
            $command | Should -Match ('`'+"`n    -RunSelection 'Explicit'")
            $command | Should -Match ('`'+"`n    -RunFolder 'C:\\Evidence'")
        }
        It 'shows counts, status and plain reasons without changing report diagnostics' {
            $diagnostic=[pscustomobject]@{
                Status='NotAssessed';CheckId='AuditFileShareSuccess';Count=2
                Reason='AuditFileShareSuccess [NotAssessed]: Explicit UNC audit policy was not queried.'
            }
            $original=$diagnostic.Reason
            $records=@(Write-NtfsCompletion -component Assessment -status CompletedWithWarnings -reasonSummary @(
                $diagnostic,
                [pscustomobject]@{Status='NotAssessed';Count=1;Reason='SMB configuration was not collected.'},
                [pscustomobject]@{Count=3;Reason='Recorded collection warning.'}
            ) -nextStep 'Review the reports.' 6>&1)
            $lines=@($records.MessageData|ForEach-Object{[string]$_})
            $lines | Should -Contain '  - (2 records): NotAssessed: Explicit UNC audit policy was not queried.'
            $lines | Should -Contain '  - (1 record): NotAssessed: SMB configuration was not collected.'
            $lines | Should -Contain '  - (3 records): Recorded collection warning.'
            ($lines -join "`n") | Should -Not -Match 'AuditFileShareSuccess|Reason \('
            $diagnostic.Reason | Should -BeExactly $original
        }
    }
}
