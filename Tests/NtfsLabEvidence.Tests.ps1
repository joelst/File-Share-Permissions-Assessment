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

Describe 'Candidate audit copying and preservation' {
    BeforeAll {
        $script:copiedAuditFiles = [Collections.Generic.List[string]]::new()
        $runnerAst = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot 'Invoke-NtfsLabEvidence.ps1'), [ref]$null, [ref]$null)
        foreach ($name in @('Copy-LabCandidateAudit', 'Write-LabJson', 'Add-LabCheck')) {
            $definition = $runnerAst.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true)
            . ([scriptblock]::Create($definition.Extent.Text))
        }
        $collection = $runnerAst.Find({
            param($node)
            $node -is [Management.Automation.Language.IfStatementAst] -and
                $node.Clauses[0].Item1.Extent.Text -eq '$runDisposableCandidateTests' -and
                $node.Extent.Text.Contains('$fixtureSummaries =')
        }, $true)
        $script:collectCandidateEvidence = [scriptblock]::Create($collection.Clauses[0].Item2.Extent.Text.Trim('{}'))
        $suiteAst = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot 'NtfsPermissions.RemoveReplace.Tests.ps1'), [ref]$null, [ref]$null)
        $script:cleanupHooks = @{}
        foreach ($hook in @('AfterEach', 'AfterAll')) {
            $command = $suiteAst.Find({
                param($node)
                $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq $hook
            }, $true)
            $script:cleanupHooks[$hook] = [scriptblock]::Create($command.CommandElements[1].ScriptBlock.Extent.Text.Trim('{}'))
        }
        function Get-FixtureIdentity { 'fixture-identity' }
    }

    BeforeEach {
        $script:copiedAuditFiles.Clear()
        $script:auditTestRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($script:auditTestRoot)
    }

    It 'copies recovery and interruption evidence without changing the source' {
        $source = Join-Path $script:auditTestRoot 'evidence'
        $audit = Join-Path $source ('Permissions_' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($audit)
        $names = @('events.jsonl', 'orchestration.jsonl', 'receipt.json', 'candidate-plan.json',
            'preparation.json', 'permissions-before-after.csv', 'candidate.lock', 'interruption.json',
            'interruption-request.clixml', 'child-stdout.txt', 'child-stderr.txt')
        foreach ($name in $names) { [IO.File]::WriteAllText((Join-Path $audit $name), "fixture-$name") }
        $destination = Join-Path $script:auditTestRoot 'copied'
        Copy-LabCandidateAudit -evidenceDirectory $source -destinationRoot $destination
        $script:copiedAuditFiles.Count | Should -Be $names.Count
        foreach ($copy in $script:copiedAuditFiles) {
            $original = Join-Path $audit ([IO.Path]::GetFileName($copy))
            (Get-FileHash -LiteralPath $copy).Hash | Should -BeExactly (Get-FileHash -LiteralPath $original).Hash
        }
    }

    It 'rejects unexpected audit directories' {
        $source = Join-Path $script:auditTestRoot 'evidence'
        [void][IO.Directory]::CreateDirectory((Join-Path $source 'unrelated'))
        { Copy-LabCandidateAudit -evidenceDirectory $source -destinationRoot (Join-Path $script:auditTestRoot 'copied') } |
            Should -Throw '*Unexpected candidate audit directory*'
        $script:copiedAuditFiles.Count | Should -Be 0
    }

    It 'requires audits from both preserved suites with missing suite=<MissingSuite>' -ForEach @(
        @{ MissingSuite = '' }
        @{ MissingSuite = 'Local' }
        @{ MissingSuite = 'RemoveReplace' }
    ) {
        $run = Join-Path $script:auditTestRoot 'run'
        [void][IO.Directory]::CreateDirectory($run)
        $checks = [Collections.Generic.List[object]]::new()
        $candidateFixtures = @(
            [pscustomobject]@{ Suite = 'Local'; Path = (Join-Path $script:auditTestRoot 'LocalCandidateTests_fixture') }
            [pscustomobject]@{ Suite = 'RemoveReplace'; Path = (Join-Path $script:auditTestRoot 'RemoveReplace_fixture') }
        )
        foreach ($fixture in $candidateFixtures) {
            [void][IO.Directory]::CreateDirectory($fixture.Path)
            if ($fixture.Suite -eq $MissingSuite) { continue }
            $parent = if ($fixture.Suite -eq 'Local') { $fixture.Path } else { Join-Path $fixture.Path 'case_0123456789ab' }
            $audit = Join-Path (Join-Path $parent 'evidence') ('Permissions_' + [guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($audit)
            foreach ($name in @('events.jsonl', 'receipt.json')) {
                [IO.File]::WriteAllText((Join-Path $audit $name), "$($fixture.Suite)-$name")
            }
        }
        . $script:collectCandidateEvidence
        $manifest = Get-Content -LiteralPath (Join-Path $run 'candidate-fixture.json') -Raw | ConvertFrom-Json
        $expectedStatus = if ($MissingSuite) { 'Incomplete' } else { 'Observed' }
        ($checks | Where-Object Name -eq 'CandidateFixtureEvidence').Status | Should -Be $expectedStatus
        @($manifest.Fixtures).Count | Should -Be 2
        foreach ($fixture in $manifest.Fixtures) {
            $fixture.Status | Should -Be 'Preserved'
            $expectedCount = if ($fixture.Suite -eq $MissingSuite) { 0 } else { 2 }
            $fixture.AuditFilesCopied | Should -Be $expectedCount
        }
        foreach ($copy in $script:copiedAuditFiles) {
            [IO.File]::ReadAllText($copy) | Should -Match '(Local|RemoveReplace)-(events.jsonl|receipt.json)'
        }
    }

    It 'keeps per-case journals and receipts through both cleanup hooks when preservation=<Preserve>' -ForEach @(
        @{ Preserve = $true }
        @{ Preserve = $false }
    ) {
        $script:work = Join-Path $script:auditTestRoot 'RemoveReplace_fixture'
        $script:caseWork = Join-Path $script:work 'case_fixture'
        [void][IO.Directory]::CreateDirectory($script:caseWork)
        foreach ($name in @('events.jsonl', 'receipt.json')) {
            [IO.File]::WriteAllText((Join-Path $script:caseWork $name), 'retained audit')
        }
        $script:caseIdentity = $script:workIdentity = 'fixture-identity'
        $script:unsafeCleanup = $false
        $script:preserveLabEvidence = $Preserve
        & $script:cleanupHooks.AfterEach
        & $script:cleanupHooks.AfterAll
        Test-Path -LiteralPath $script:work | Should -Be $Preserve
        foreach ($name in @('events.jsonl', 'receipt.json')) {
            Test-Path -LiteralPath (Join-Path $script:caseWork $name) | Should -Be $Preserve
        }
    }
}

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

    It 'records the native lab probe source in the evidence hashes' {
        $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
        $result = & $script:labRunner -outputRoot $root
        $probe = Join-Path $PSScriptRoot 'NtfsCandidateLabProbe.cs'
        $entries = @(Import-Csv -LiteralPath (Join-Path $result.EvidencePath 'source-hashes.csv') |
            Where-Object Path -eq $probe)
        $entries.Count | Should -Be 1
        $entries[0].Hash | Should -BeExactly (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash
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

    It 'includes targeted remove and replace tests in the candidate suite' {
        Mock Invoke-Pester {
            param($Configuration)
            $paths = @($Configuration.Run.Path.Value)
            if ($paths -notcontains (Join-Path $PSScriptRoot 'NtfsPermissions.Local.Tests.ps1') -or
                $paths -notcontains (Join-Path $PSScriptRoot 'NtfsPermissions.RemoveReplace.Tests.ps1')) {
                throw 'Candidate test paths are incomplete.'
            }
            [pscustomobject]@{
                Result = 'Passed'; PassedCount = 1; FailedCount = 0; SkippedCount = 0
                InconclusiveCount = 0; NotRunCount = 0
                Tests = @([pscustomobject]@{ Result = 'Passed'; ExpandedPath = 'Passing test' })
            }
        }
        $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
        { & $script:labRunner -outputRoot $root -runDisposableCandidateTests -disposableAcknowledgement } |
            Should -Throw '*Evidence requires review*'
        $run = @(Get-ChildItem -LiteralPath $root -Directory)
        $summary = Get-Content -LiteralPath (Join-Path $run[0].FullName 'summary.json') -Raw | ConvertFrom-Json
        ($summary.Checks | Where-Object Name -ceq 'Pester').Status | Should -Be 'Observed'
        ($summary.Checks | Where-Object Name -ceq 'CandidateFixtureEvidence').Status | Should -Be 'Incomplete'
    }

    It 'collects both suites after Pester failure and rejects missing remove/replace evidence=<MissingRemoveReplace>' -ForEach @(
        @{ MissingRemoveReplace = $false }
        @{ MissingRemoveReplace = $true }
    ) {
        $script:omitRemoveReplace = $MissingRemoveReplace
        $script:createdFixtures = [Collections.Generic.List[string]]::new()
        Mock Invoke-Pester {
            $id = [Environment]::GetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', 'Process')
            foreach ($prefix in @('LocalCandidateTests_', 'RemoveReplace_')) {
                if ($prefix -eq 'RemoveReplace_' -and $script:omitRemoveReplace) { continue }
                $fixture = Join-Path $PSScriptRoot ($prefix + $id)
                $script:createdFixtures.Add($fixture)
                $parent = if ($prefix -eq 'RemoveReplace_') { Join-Path $fixture 'case_0123456789ab' } else { $fixture }
                $audit = Join-Path (Join-Path $parent 'evidence') ('Permissions_' + [guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($audit)
                foreach ($name in @('events.jsonl', 'receipt.json', 'candidate-plan.json', 'permissions-before-after.csv')) {
                    [IO.File]::WriteAllText((Join-Path $audit $name), "$prefix-$name")
                }
            }
            throw 'Injected failure after writing candidate audits.'
        }
        try {
            $root = Join-Path $script:labTestRoot ([guid]::NewGuid().ToString('N'))
            { & $script:labRunner -outputRoot $root -runDisposableCandidateTests -disposableAcknowledgement } |
                Should -Throw '*Evidence requires review*'
            $run = @(Get-ChildItem -LiteralPath $root -Directory)[0].FullName
            $summary = Get-Content -LiteralPath (Join-Path $run 'summary.json') -Raw | ConvertFrom-Json
            $manifest = Get-Content -LiteralPath (Join-Path $run 'candidate-fixture.json') -Raw | ConvertFrom-Json
            ($summary.Checks | Where-Object Name -ceq 'Pester').Status | Should -Be 'Failed'
            $expectedStatus = if ($MissingRemoveReplace) { 'Incomplete' } else { 'Observed' }
            ($summary.Checks | Where-Object Name -ceq 'CandidateFixtureEvidence').Status | Should -Be $expectedStatus
            @($manifest.Fixtures).Count | Should -Be 2
            $expectedCount = if ($MissingRemoveReplace) { 4 } else { 8 }
            $manifest.AuditFilesCopied | Should -Be $expectedCount
            $hashes = @(Import-Csv -LiteralPath (Join-Path $run 'SHA256SUMS.csv'))
            @($hashes | Where-Object Path -like '*candidate-audits*').Count | Should -Be $expectedCount
            foreach ($entry in $hashes) {
                (Get-FileHash -LiteralPath $entry.Path).Hash | Should -BeExactly $entry.Hash
            }
            foreach ($fixture in $script:createdFixtures) { Test-Path -LiteralPath $fixture | Should -BeTrue }
        } finally {
            foreach ($fixture in $script:createdFixtures) {
                Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction Stop
            }
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
