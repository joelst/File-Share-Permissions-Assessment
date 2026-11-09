#requires -Version 5.1
<#
.SYNOPSIS
Disposable local NTFS candidate integration and failure regression tests.
.DESCRIPTION
Creates and modifies only its own generated fixture under the Tests directory.
No existing target or environment-provided mutation path is accepted. Requires
Windows, local fixed NTFS, Pester 5.2+, Add-Type and permission to set fixture ACLs.
These tests do not qualify production use, AD authority, SMB or NAS.
#>
[CmdletBinding()]
param()

Describe 'Internal local NTFS candidate safeguards (not production qualification)' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    BeforeAll {
        . (Join-Path (Split-Path $PSScriptRoot -Parent) 'NtfsPermissions.Local.ps1')
        Initialize-NpLocalNative
        $fixtureId = [Environment]::GetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', 'Process')
        if ($fixtureId -and $fixtureId -cnotmatch '^[a-f0-9]{32}$') {
            throw 'Invalid lab candidate fixture identifier.'
        }
        if (-not $fixtureId) { $fixtureId = [guid]::NewGuid().ToString('N') }
        $script:localWork = Join-Path $PSScriptRoot ('LocalCandidateTests_' + $fixtureId)
        if (Test-Path -LiteralPath $script:localWork) { throw 'Candidate fixture directory already exists.' }
        [void][IO.Directory]::CreateDirectory($script:localWork)
        $script:localGrants = @(Get-NpGrants -GroupName 'FixtureReaders' -Permissions ReadAndExecute `
            -Resolve { 'S-1-5-21-100-200-300-400' })

        function New-LocalFixture {
            <#
            .SYNOPSIS
            Creates a fresh owned disposable fixture with a controlled simple ACL.
            #>
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test fixture creation only.')]
            [CmdletBinding()]
            param()
            $path = Join-Path $script:localWork ([guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($path)
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $acl.SetAccessRuleProtection($true, $false)
            $acl.SetOwner($sid)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
            $child = Join-Path $path 'child'
            [void][IO.Directory]::CreateDirectory($child)
            [IO.File]::WriteAllText((Join-Path $child 'file.txt'), 'disposable')
            [IO.File]::WriteAllText((Join-Path $path 'root-file.txt'), 'disposable')
            $protected = Join-Path $path 'protected'
            [void][IO.Directory]::CreateDirectory($protected)
            $protectedAcl = Get-Acl -LiteralPath $protected
            $protectedAcl.SetAccessRuleProtection($true, $true)
            Set-Acl -LiteralPath $protected -AclObject $protectedAcl -ErrorAction Stop
            [IO.File]::WriteAllText((Join-Path $protected 'sentinel.txt'), 'unchanged')
            return $path
        }

        function New-LocalJournal {
            <#
            .SYNOPSIS
            Creates separately protected local candidate audit storage.
            #>
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test audit fixture creation only.')]
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)] $plan,
                [ValidateSet('Apply', 'Revert')][string] $mode = 'Apply'
            )
            $run = New-NpRun -OutputDirectory (Join-Path $script:localWork 'evidence') -Target $plan.TargetDescriptor.CanonicalPath
            return New-NpJournal $run $mode 'DISPOSABLE-TEST' (Get-NtfsHash (Get-NpCanonicalJson $plan)) $plan.TargetDescriptor.CanonicalPath
        }

        function Get-LocalState {
            <#
            .SYNOPSIS
            Reads all pinned fixture identities/descriptors without mutation.
            #>
            [CmdletBinding()]
            [OutputType([object[]])]
            param(
                [Parameter(Mandatory = $true)] $plan
            )
            return @(Get-NpLocalInventory -targetPath $plan.TargetDescriptor.CanonicalPath)
        }
    }
    AfterAll {
        if ($script:localWork -and (Test-Path -LiteralPath $script:localWork)) {
            if ([Environment]::GetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', 'Process')) {
                Write-Warning "Preserved lab candidate fixture: $($script:localWork)"
            } else {
                Remove-Item -LiteralPath $script:localWork -Recurse -Force -ErrorAction Stop
            }
        }
    }

    It 'writes and exactly restores <Scope> with Multiple=<Multiple>, including protected branch sentinels' -ForEach @(
        @{ Scope = 'ThisFolderOnly'; Multiple = $false }
        @{ Scope = 'ThisFolderSubfoldersAndFiles'; Multiple = $false }
        @{ Scope = 'ThisFolderOnly'; Multiple = $true }
        @{ Scope = 'ThisFolderSubfoldersAndFiles'; Multiple = $true }
    ) {
        $target = New-LocalFixture
        $grants = if ($Multiple) {
            @(Get-NpGrants -Json '[{"GroupName":"FixtureReaders","Permissions":"ReadAndExecute"},{"GroupName":"FixtureWriters","Permissions":"Modify"}]' `
                -Resolve { param($name) if ($name -ceq 'FixtureReaders') { 'S-1-5-21-100-200-300-400' } else { 'S-1-5-21-100-200-300-401' } })
        } else { $script:localGrants }
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $grants -scope $Scope
        $hash = Get-NtfsHash (Get-NpCanonicalJson $plan)
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $hash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Verified' -Because $result.Error
        $result.WriterQualification | Should -Be 'NotQualified'
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Desired))
        foreach ($entry in @($plan.Entries | Where-Object Boundary)) {
            $entry.Desired.Descriptor | Should -BeExactly $entry.Before.Descriptor
        }
        $revertJournal = New-LocalJournal -plan $plan -mode Revert
        $revertParameters = @{
            Plan = $plan
            PlanSHA256 = $hash
            Journal = $revertJournal
            Mode = 'Revert'
            ApplyJournalPath = $journal.Path
            ApplyJournalSHA256 = (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path)))
            Confirm = $false
            DisposableAcknowledgement = $true
        }
        $reverted = Invoke-NpLocalCandidate @revertParameters
        $reverted.Status | Should -Be 'Verified' -Because $reverted.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
    }

    It 'performs no target changes for WhatIf or an already satisfied request' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -WhatIf
        $result.Status | Should -Be 'WhatIfOrDeclined'
        (Test-Path -LiteralPath (Join-Path (Split-Path $journal.Path -Parent) 'candidate.lock')) | Should -BeFalse
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        $ownerGrants = @(Get-NpGrants -GroupName 'FixtureOwner' -Permissions Read `
            -Resolve { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value })
        $noOpPlan = New-NpLocalCandidatePlan -targetPath $target -grants $ownerGrants
        $noOpJournal = New-LocalJournal -plan $noOpPlan
        $noOp = Invoke-NpLocalCandidate -plan $noOpPlan -planSHA256 $noOpJournal.PlanHash -journal $noOpJournal -DisposableAcknowledgement -Confirm:$false
        $noOp.Status | Should -Be 'NoOp' -Because $noOp.Error
        @((Read-NpJournal -Path $noOpJournal.Path).Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 0
    }

    It 'rejects tampered desired descriptors even with a newly reviewed hash' {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $plan.Entries[0].Desired.Descriptor = $plan.Entries[0].Before.Descriptor
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'reconstruction'
        (Test-Path -LiteralPath $journal.Path) | Should -BeFalse
    }

    It 'refuses renamed/recreated file identity before any parent write' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $file = Join-Path $target 'root-file.txt'
        Move-Item -LiteralPath $file -Destination (Join-Path $script:localWork 'retained-original.txt')
        [IO.File]::WriteAllText($file, 'replacement')
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'identity/descriptor drift'
        @((Read-NpJournal -Path $journal.Path).Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 0
    }

    It 'fails closed when an exclusive file handle cannot be acquired' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $stream = [IO.FileStream]::new((Join-Path $target 'root-file.txt'),
            [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
            $result.Status | Should -Be 'Blocked'
            $result.Error | Should -Match 'Cannot pin'
        } finally { $stream.Dispose() }
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
    }

    It 'detects namespace additions before any writer call' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        [IO.File]::WriteAllText((Join-Path $target 'unexpected.txt'), 'unapproved')
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'Namespace add/delete/rename drift'
        @((Read-NpJournal -Path $journal.Path).Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 0
    }

    It 'preserves administrator drift and refuses the entire parent recovery' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $apply = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $apply.Status | Should -Be 'Verified' -Because $apply.Error
        $file = Join-Path $target 'root-file.txt'
        $acl = Get-Acl -LiteralPath $file
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-401'), 'Read', 'Allow'))
        Set-Acl -LiteralPath $file -AclObject $acl -ErrorAction Stop
        $drifted = Get-NpCanonicalJson (Get-LocalState -plan $plan)
        $revertJournal = New-LocalJournal -plan $plan -mode Revert
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $revertJournal `
            -mode Revert -applyJournalPath $journal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) | Should -BeExactly $drifted
        @((Read-NpJournal -Path $revertJournal.Path).Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 0
    }

    It 'stops before writes when durable intent cannot be recorded' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        Mock Write-NpEvent {
            if ($Stage -ceq 'CandidateWriteIntent') { throw 'Injected durable intent failure' }
        }
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'durable intent failure'
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        (Test-Path -LiteralPath (Join-Path (Split-Path $journal.Path -Parent) 'candidate.lock')) | Should -BeTrue
    }

    It 'reports post-write audit failure as indeterminate without retry or rollback' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        Mock Write-NpEvent {
            if ($Stage -ceq 'CandidatePathVerified') { throw 'Injected post-write audit failure' }
        }
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Indeterminate'
        $result.Error | Should -Match 'post-write audit failure'
        $states = @(Get-LocalState -plan $plan)
        $states[0].Descriptor | Should -BeExactly $plan.Entries[0].Desired.Descriptor
        $states[1].Descriptor | Should -BeExactly $plan.Entries[1].Before.Descriptor
        (Test-Path -LiteralPath (Join-Path (Split-Path $journal.Path -Parent) 'candidate.lock')) | Should -BeTrue
    }

    It 'rejects incomplete path bounds and direct remote native handles' {
        $target = New-LocalFixture
        { New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants -maxPaths 1 } |
            Should -Throw '*path limit*'
        { [NtfsPermissions.LocalCandidate.Lease]::Open('\\SERVER\Share\Folder', $true) } |
            Should -Throw '*direct local*'
    }

    It 'rejects missing disposable acknowledgement without creating audit or target writes' {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'DisposableAcknowledgement'
        (Test-Path -LiteralPath $journal.Path) | Should -BeFalse
    }

    It 'refuses torn recovery evidence and preserves the verified after-state' {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $apply = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $apply.Status | Should -Be 'Verified' -Because $apply.Error
        [IO.File]::AppendAllText($journal.Path, '{"torn":')
        $revertJournal = New-LocalJournal -plan $plan -mode Revert
        $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $revertJournal `
            -mode Revert -applyJournalPath $journal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'indeterminate journal'
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Desired))
    }

    It 'rejects hard-link aliases and reparse branches during complete inventory' {
        $target = New-LocalFixture
        New-Item -ItemType HardLink -Path (Join-Path $target 'alias.txt') -Value (Join-Path $target 'root-file.txt') -ErrorAction Stop
        { New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants } | Should -Throw '*Hard-linked*'
        $junctionTarget = New-LocalFixture
        $junction = Join-Path $junctionTarget 'junction'
        New-Item -ItemType Junction -Path $junction -Value $target -ErrorAction Stop
        try {
            { New-NpLocalCandidatePlan -targetPath $junctionTarget -grants $script:localGrants } | Should -Throw '*Reparse*'
        } finally {
            [IO.Directory]::Delete($junction)
        }
    }
}
