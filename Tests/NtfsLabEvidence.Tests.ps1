#requires -Version 5.1
<#
.SYNOPSIS
Regression tests for the Windows lab evidence runner.
.DESCRIPTION
Creates only uniquely named evidence directories under the current user's local
temporary directory. The runner's candidate tests are not invoked by this file.
Requires Windows and Pester 5.2 or later.
#>
[CmdletBinding()]
param()

Describe 'Lab evidence runner safety and reporting' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    BeforeAll {
        $script:labRunner = Join-Path $PSScriptRoot 'Invoke-NtfsLabEvidence.ps1'
        $script:labTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('NtfsLabRunnerTests_' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($script:labTestRoot)
        . (Join-Path (Split-Path $PSScriptRoot -Parent) 'NtfsPermissions.Common.ps1')
    }

    AfterAll {
        if ($script:labTestRoot -and (Test-Path -LiteralPath $script:labTestRoot)) {
            Remove-Item -LiteralPath $script:labTestRoot -Recurse -Force -ErrorAction Stop
        }
    }

    It 'requires acknowledgement before creating evidence for <Suite>' -ForEach @(
        @{ Suite = 'Synthetic'; Parameters = @{ runSyntheticTests = $true } }
        @{ Suite = 'Candidate'; Parameters = @{ runDisposableCandidateTests = $true } }
    ) {
        $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
        { & $script:labRunner -outputRoot $root @Parameters } | Should -Throw '*DisposableAcknowledgement*'
        Test-Path -LiteralPath $root | Should -BeFalse
    }

    It 'records a protected baseline and explicit unperformed checks' {
        $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
        $result = & $script:labRunner -outputRoot $root
        $result.Status | Should -Be 'Collected'
        $summary = Get-Content -LiteralPath $result.SummaryPath -Raw | ConvertFrom-Json
        $summary.WriterQualification | Should -Be 'NotQualified'
        ($summary.Checks | Where-Object Name -ceq 'Pester').Status | Should -Be 'NotRun'
        ($summary.Checks | Where-Object Name -ceq 'ReadOnlyTarget').Status | Should -Be 'NotRun'
        ($summary.Checks | Where-Object Name -ceq 'ActiveDirectoryGroup').Status | Should -Be 'NotRun'
        foreach ($name in @('transcript.txt', 'environment.json', 'summary.json', 'source-hashes.csv', 'SHA256SUMS.csv')) {
            Test-Path -LiteralPath (Join-Path $result.EvidencePath $name) | Should -BeTrue
        }
        foreach ($entry in @(Import-Csv -LiteralPath (Join-Path $result.EvidencePath 'SHA256SUMS.csv'))) {
            (Get-FileHash -LiteralPath $entry.Path -Algorithm SHA256).Hash | Should -BeExactly $entry.Hash
        }
        $acl = Get-Acl -LiteralPath $result.EvidencePath
        $acl.AreAccessRulesProtected | Should -BeTrue
        @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])).Count | Should -Be 1
    }

    It 'keeps evidence and reports incomplete inspection for a nonexistent target' {
        $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
        $missingTarget = Join-Path $script:labTestRoot ('missing_' + [guid]::NewGuid().ToString('N'))
        { & $script:labRunner -outputRoot $root -readOnlyTarget $missingTarget -targetPlatform Windows } |
            Should -Throw '*Evidence requires review*'
        $run = @(Get-ChildItem -LiteralPath $root -Directory)
        $run.Count | Should -Be 1
        $summary = Get-Content -LiteralPath (Join-Path $run[0].FullName 'summary.json') -Raw | ConvertFrom-Json
        $summary.Status | Should -Be 'AttentionRequired'
        ($summary.Checks | Where-Object Name -ceq 'ReadOnlyTarget').Status | Should -BeIn @('Incomplete', 'Failed')
        Test-Path -LiteralPath (Join-Path $run[0].FullName 'SHA256SUMS.csv') | Should -BeTrue
    }

    It 'records a bounded read-only target inventory without modifying its ACL' {
        $target = New-NpRun -OutputDirectory (Join-Path $script:labTestRoot 'fixture')
        $before = (Get-Acl -LiteralPath $target).Sddl
        $result = & $script:labRunner -outputRoot (Join-Path $script:labTestRoot 'evidence') `
            -readOnlyTarget $target -targetPlatform Windows
        $summary = Get-Content -LiteralPath $result.SummaryPath -Raw | ConvertFrom-Json
        $inventory = Get-Content -LiteralPath (Join-Path $result.EvidencePath 'read-only-inventory.json') -Raw | ConvertFrom-Json
        ($summary.Checks | Where-Object Name -ceq 'ReadOnlyTarget').Status | Should -Be 'Observed'
        $inventory.Scope | Should -Be 'ThisFolderOnly'
        @($inventory.Snapshots).Count | Should -Be 1
        (Get-Acl -LiteralPath $target).Sddl | Should -BeExactly $before
    }

    It 'preserves logs and reports a rejected local group lookup' {
        $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
        { & $script:labRunner -outputRoot $root -groupName '.\NotAnADGroup' } |
            Should -Throw '*Evidence requires review*'
        $run = @(Get-ChildItem -LiteralPath $root -Directory)
        $run.Count | Should -Be 1
        $summary = Get-Content -LiteralPath (Join-Path $run[0].FullName 'summary.json') -Raw | ConvertFrom-Json
        ($summary.Checks | Where-Object Name -ceq 'ActiveDirectoryGroup').Status | Should -Be 'Failed'
        Test-Path -LiteralPath (Join-Path $run[0].FullName 'transcript.txt') | Should -BeTrue
    }

    It 'rejects evidence storage inside the test fixture tree' {
        { & $script:labRunner -outputRoot (Join-Path $PSScriptRoot 'unsafe-evidence') } |
            Should -Throw '*outside assessed tree*'
    }

    It 'restores the candidate environment variable after a Pester failure' {
        Mock Invoke-Pester {
            if ([Environment]::GetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', 'Process') -cnotmatch '^[a-f0-9]{32}$') {
                throw 'Expected a temporary candidate ID.'
            }
            throw 'Injected Pester failure.'
        }
        $previousId = [Environment]::GetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', 'Process')
        try {
            [Environment]::SetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', 'previous-value', 'Process')
            $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
            { & $script:labRunner -outputRoot $root -runDisposableCandidateTests -disposableAcknowledgement } |
                Should -Throw '*Evidence requires review*'
            [Environment]::GetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', 'Process') | Should -BeExactly 'previous-value'
            $run = @(Get-ChildItem -LiteralPath $root -Directory)
            $summary = Get-Content -LiteralPath (Join-Path $run[0].FullName 'summary.json') -Raw | ConvertFrom-Json
            ($summary.Checks | Where-Object Name -ceq 'Pester').Detail | Should -Match 'Injected Pester failure'
        } finally {
            [Environment]::SetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', $previousId, 'Process')
        }
    }

    It 'reports failed Pester discovery even when no individual test failed' {
        Mock Invoke-Pester {
            [pscustomobject]@{
                Result = 'Failed'
                PassedCount = 1
                FailedCount = 0
                SkippedCount = 0
                InconclusiveCount = 0
                NotRunCount = 0
                Tests = @([pscustomobject]@{ Result = 'Passed'; ExpandedPath = 'Passing test' })
            }
        }
        $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
        { & $script:labRunner -outputRoot $root -runSyntheticTests -disposableAcknowledgement } |
            Should -Throw '*Evidence requires review*'
        $run = @(Get-ChildItem -LiteralPath $root -Directory)
        $summary = Get-Content -LiteralPath (Join-Path $run[0].FullName 'summary.json') -Raw | ConvertFrom-Json
        $pesterSummary = Get-Content -LiteralPath (Join-Path $run[0].FullName 'pester-summary.json') -Raw | ConvertFrom-Json
        $summary.Status | Should -Be 'AttentionRequired'
        ($summary.Checks | Where-Object Name -ceq 'Pester').Status | Should -Be 'Failed'
        $pesterSummary.Result | Should -Be 'Failed'
        $pesterSummary.Failed | Should -Be 0
    }

    It 'supports passing results without the newer inconclusive-count property' {
        Mock Invoke-Pester {
            [pscustomobject]@{
                Result = 'Passed'
                PassedCount = 1
                FailedCount = 0
                SkippedCount = 0
                NotRunCount = 0
                Tests = @([pscustomobject]@{ Result = 'Passed'; ExpandedPath = 'Passing test' })
            }
        }
        $result = & $script:labRunner -outputRoot (Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))) `
            -runSyntheticTests -disposableAcknowledgement
        $summary = Get-Content -LiteralPath (Join-Path $result.EvidencePath 'pester-summary.json') -Raw | ConvertFrom-Json
        $result.Status | Should -Be 'Collected'
        $summary.Inconclusive | Should -Be 0
    }
}
