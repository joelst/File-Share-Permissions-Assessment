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

        function Invoke-LocalCandidateWithInjectedPlan {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Forwards ShouldProcess preferences to the candidate.')]
            [CmdletBinding(SupportsShouldProcess = $true)]
            param(
                [Parameter(Mandatory = $true)] $plan,
                [Parameter(Mandatory = $true)][string] $planSHA256,
                [Parameter(Mandatory = $true)] $journal,
                [switch] $disposableAcknowledgement,
                [ValidateSet('Apply', 'Revert')][string] $mode = 'Apply',
                [string] $applyJournalPath,
                [string] $applyJournalSHA256,
                [switch] $reviewedPartialApplyRecovery
            )
            $parameters = @{
                journal = $journal; mode = $mode; disposableAcknowledgement = $disposableAcknowledgement
                WhatIf = [bool]$WhatIfPreference
            }
            if ($PSBoundParameters.ContainsKey('Confirm')) { $parameters.Confirm = $PSBoundParameters.Confirm }
            if ($mode -ceq 'Revert') {
                $parameters.plan = $plan
                $parameters.planSHA256 = $planSHA256
                $parameters.applyJournalPath = $applyJournalPath
                $parameters.applyJournalSHA256 = $applyJournalSHA256
                $parameters.reviewedPartialApplyRecovery = $reviewedPartialApplyRecovery
            } else {
                # Inject a snapshot only in these worker tests to simulate drift after planning.
                $script:injectedLocalPlan = $plan
                function New-NpLocalCandidatePlan {
                    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Injects test data without writes.')]
                    [CmdletBinding()]
                    param($targetPath, $grants, $scope, $maxPaths, $operation, $removal, $targetPlatform = 'Windows', $targetDescriptor = $null, [switch]$allowRemoteTarget)
                    $null = @($targetPlatform, $targetDescriptor, $allowRemoteTarget)
                    if ($targetPath -cne $script:injectedLocalPlan.TargetDescriptor.CanonicalPath -or
                        (Get-NpCanonicalJson $grants) -cne (Get-NpCanonicalJson $script:injectedLocalPlan.Grants) -or
                        $scope -cne $script:injectedLocalPlan.Scope -or $maxPaths -ne $script:injectedLocalPlan.MaxPaths) {
                        throw 'Injected snapshot does not match the Apply request.'
                    }
                    if ($script:injectedLocalPlan.Schema -ceq 'NtfsLocalCandidatePlan/2' -and
                        ($operation -cne $script:injectedLocalPlan.Operation -or
                        (Get-NpCanonicalJson $removal) -cne (Get-NpCanonicalJson $script:injectedLocalPlan.Removal))) {
                        throw 'Injected snapshot does not match the Apply operation or removal.'
                    }
                    return $script:injectedLocalPlan
                }
                $originalPlanHash = $journal.PlanHash
                $journal.PlanHash = ''
                $directory = Split-Path -Parent $journal.Path
                $audit = New-NpJournal $directory Apply $journal.Ticket '' $journal.Target
                $audit.Path = Join-Path $directory 'orchestration.jsonl'
                $parameters.applyTargetPath = $plan.TargetDescriptor.CanonicalPath
                $parameters.applyGrants = $plan.Grants
                if ($plan.Schema -ceq 'NtfsLocalCandidatePlan/2') {
                    $parameters.applyOperation = $plan.Operation
                    $parameters.applyRemoval = $plan.Removal
                }
                $parameters.applyScope = $plan.Scope
                $parameters.applyMaxPaths = $plan.MaxPaths
                $parameters.orchestration = $audit
                if ($applyJournalPath) { $parameters.applyJournalPath = $applyJournalPath }
                if ($applyJournalSHA256) { $parameters.applyJournalSHA256 = $applyJournalSHA256 }
                if ($reviewedPartialApplyRecovery) { $parameters.reviewedPartialApplyRecovery = $true }
            }
            try { return Invoke-NpLocalCandidate @parameters }
            finally {
                if ($mode -ceq 'Apply' -and -not $journal.PlanHash) { $journal.PlanHash = $originalPlanHash }
                $script:injectedLocalPlan = $null
            }
        }

        function Invoke-LocalProcessInterruption {
            <#
            .SYNOPSIS
            Terminates only the owned child at a synchronized candidate boundary.
            #>
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Owned disposable test process only.')]
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)] $plan,
                [Parameter(Mandatory = $true)] $journal,
                [Parameter(Mandatory = $true)][string] $stage,
                [switch] $beforeEvent,
                $applyJournal,
                [switch] $reviewedPartialApplyRecovery
            )
            $directory = Split-Path $journal.Path -Parent
            $requestPath = Join-Path $directory 'interruption-request.clixml'
            $eventName = 'Local\NtfsCandidateInterruption_' + [guid]::NewGuid().ToString('N')
            @{
                Repository = Split-Path $PSScriptRoot -Parent
                Plan = $plan
                Journal = $journal
                Stage = $stage
                BeforeEvent = [bool]$beforeEvent
                EventName = $eventName
                ApplyJournal = $applyJournal
                ReviewedPartialApplyRecovery = [bool]$reviewedPartialApplyRecovery
            } | Export-Clixml -LiteralPath $requestPath
            $command = @'
$ErrorActionPreference = 'Stop'
$request = Import-Clixml -LiteralPath '__REQUEST_PATH__'
. (Join-Path $request.Repository 'NtfsPermissions.Local.ps1')
$originalEventWriter = ${function:Write-NpEvent}
$ready = [Threading.EventWaitHandle]::OpenExisting($request.EventName)
function Write-NpEvent($Journal, [string]$Stage, [string]$Result, $Changes = @()) {
    if ($Stage -cne $request.Stage -or -not $request.BeforeEvent) {
        & $originalEventWriter $Journal $Stage $Result $Changes
    }
    if ($Stage -ceq $request.Stage) {
        $null = $ready.Set()
        [Threading.Thread]::Sleep([Threading.Timeout]::Infinite)
    }
}
$parameters = @{
    Journal = $request.Journal
    Mode = $request.Journal.Mode
    DisposableAcknowledgement = $true
    Confirm = $false
    ReviewedPartialApplyRecovery = $request.ReviewedPartialApplyRecovery
}
if ($request.Journal.Mode -ceq 'Apply') {
    $script:injectedLocalPlan = $request.Plan
    function New-NpLocalCandidatePlan {
        param($targetPath, $grants, $scope, $maxPaths, $operation, $removal, $targetPlatform = 'Windows', $targetDescriptor = $null, [switch]$allowRemoteTarget)
        return $script:injectedLocalPlan
    }
    $request.Journal.PlanHash = ''
    $directory = Split-Path -Parent $request.Journal.Path
    $audit = New-NpJournal $directory Apply $request.Journal.Ticket '' $request.Journal.Target
    $audit.Path = Join-Path $directory 'orchestration.jsonl'
    $parameters.ApplyTargetPath = $request.Plan.TargetDescriptor.CanonicalPath
    $parameters.ApplyGrants = $request.Plan.Grants
    if ($request.Plan.Schema -ceq 'NtfsLocalCandidatePlan/2') {
        $parameters.ApplyOperation = $request.Plan.Operation
        $parameters.ApplyRemoval = $request.Plan.Removal
    }
    $parameters.ApplyScope = $request.Plan.Scope
    $parameters.ApplyMaxPaths = $request.Plan.MaxPaths
    $parameters.Orchestration = $audit
} else {
    $parameters.Plan = $request.Plan
    $parameters.PlanSHA256 = $request.Journal.PlanHash
}
if ($request.ApplyJournal) {
    $parameters.ApplyJournalPath = $request.ApplyJournal.Path
    $parameters.ApplyJournalSHA256 = Get-NpBytesHash ([IO.File]::ReadAllBytes($request.ApplyJournal.Path))
}
$result = Invoke-NpLocalCandidate @parameters
throw "Candidate returned before interruption: $($result.Status): $($result.Error)"
'@
            $command = $command.Replace('__REQUEST_PATH__', $requestPath.Replace("'", "''"))
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            $executable = if ($PSVersionTable.PSEdition -ceq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
            $ready = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $eventName)
            $process = $null
            try {
                $process = Start-Process -FilePath (Join-Path $PSHOME $executable) `
                    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) `
                    -RedirectStandardOutput (Join-Path $directory 'child-stdout.txt') `
                    -RedirectStandardError (Join-Path $directory 'child-stderr.txt') -PassThru
                $deadline = [DateTime]::UtcNow.AddSeconds(90)
                $reachedBoundary = $false
                do {
                    $reachedBoundary = $ready.WaitOne(100)
                } while (-not $reachedBoundary -and -not $process.HasExited -and [DateTime]::UtcNow -lt $deadline)
                if (-not $reachedBoundary) {
                    throw "Child did not reach $stage; inspect child output in $directory."
                }
                if ($process.HasExited) { throw 'Child exited before the synchronized termination.' }
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                if (-not $process.WaitForExit(10000)) { throw 'Owned candidate child did not terminate.' }
                [ordered]@{
                    ProcessId = $process.Id
                    Executable = Join-Path $PSHOME $executable
                    Mode = $journal.Mode
                    Stage = $stage
                    BeforeEvent = [bool]$beforeEvent
                    PlanSHA256 = $journal.PlanHash
                    WriterQualification = 'NotQualified'
                } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'interruption.json') -Encoding UTF8
            } finally {
                if ($null -ne $process) {
                    try {
                        if (-not $process.HasExited) {
                            Stop-Process -Id $process.Id -Force -ErrorAction Stop
                            if (-not $process.WaitForExit(10000)) { throw 'Owned candidate child cleanup failed.' }
                        }
                    } finally { $process.Dispose() }
                }
                $ready.Dispose()
            }
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

    Context 'Explicit public disposable lab option' {
        BeforeEach {
            if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)) {
                function Get-ADGroup { throw 'Test stub' }
            }
            Mock Get-ADGroup {
                param($Identity)
                [pscustomobject]@{ GroupCategory='Security'; SID=$Identity }
            }
            $script:labScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Add-FileSharePermissions.ps1'
            $script:labTarget = New-LocalFixture
            $script:labArgs = @{
                Mode='Apply'; DisposableLocalLab=$true; DisposableAcknowledgement=$true
                TargetPath=$script:labTarget; GroupName='S-1-5-21-100-200-300-400'
                Permissions='ReadAndExecute'; OutputDirectory=(Join-Path $script:localWork 'evidence')
                ChangeTicket='DISPOSABLE-TEST'; Confirm=$false
            }
            $script:labBefore = Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)
        }

        It 'automatically saves recovery data and exactly applies and reverts with fresh audits' {
            $apply = & $script:labScript @script:labArgs
            $apply.Status | Should -Be 'Verified' -Because $apply.Reason
            $apply.ReceiptSHA256 | Should -Match '^[a-f0-9]{64}$'
            Test-Path -LiteralPath (Join-Path $apply.RunDirectory 'preparation.json') | Should -BeTrue
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -Not -BeExactly $script:labBefore
            $after = Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)
            $preview = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $apply.ReceiptPath -ReceiptSHA256 $apply.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $apply.ApplyJournalSHA256 `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -WhatIf
            $preview.Status | Should -Be 'WhatIfOrDeclined' -Because $preview.Reason
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $after
            $revert = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $apply.ReceiptPath -ReceiptSHA256 $apply.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $apply.ApplyJournalSHA256 `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -Confirm:$false
            $revert.Status | Should -Be 'Verified' -Because $revert.Reason
            $revert.RunDirectory | Should -Not -Be $apply.RunDirectory
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore
        }

        It 'reverts with a source-bound recovery record older than 24 hours' {
            $apply = & $script:labScript @script:labArgs
            $apply.Status | Should -Be 'Verified' -Because $apply.Reason
            $plan = [IO.File]::ReadAllText($apply.RecoveryRecordPath) | ConvertFrom-NpJson
            $plan.CreatedUtc = [DateTime]::UtcNow.AddHours(-25).ToString('o')
            $source = Read-NpJournal -Path $apply.ApplyJournalPath
            $source.Status | Should -Be 'Verified'

            # Simulate aged evidence without changing the system clock or the original Apply evidence.
            $run = New-NpRun -OutputDirectory $script:labArgs.OutputDirectory -Target $script:labTarget
            $planPath = Join-Path $run 'candidate-plan.json'
            $planHash = Write-NpLocalEvidenceFile $planPath $plan
            $journal = New-NpJournal $run Apply 'DISPOSABLE-TEST' $planHash $script:labTarget
            foreach ($sourceEvent in $source.Events) {
                Write-NpEvent $journal $sourceEvent.Stage $sourceEvent.Result @($sourceEvent.Changes)
            }
            $receiptPath = Join-Path $run 'receipt.json'
            $receiptHash = Write-NpLocalEvidenceFile $receiptPath ([ordered]@{
                Schema='NtfsDisposableReceipt/2'; SourceHash=$plan.SourceHash; Target=$script:labTarget
                PlanPath=$planPath; PlanSHA256=$planHash; JournalPath=$journal.Path
            })
            $journalHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))

            $revert = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $receiptPath -ReceiptSHA256 $receiptHash `
                -ReviewedApplyJournalSHA256 $journalHash `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -Confirm:$false
            $revert.Status | Should -Be 'Verified' -Because $revert.Reason
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore
        }

        It 'does not mutate for WhatIf and supports already satisfied no-op' {
            $previewArgs = $script:labArgs.Clone()
            $previewArgs.Confirm = $true
            $preview = & $script:labScript @previewArgs -WhatIf
            $preview.Status | Should -Be 'WhatIfOrDeclined' -Because $preview.Reason
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore
            $previewRevert = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $preview.ReceiptPath -ReceiptSHA256 $preview.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $preview.ApplyJournalSHA256 -ReviewedPartialApplyRecovery `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -Confirm:$false
            $previewRevert.Status | Should -Be 'Blocked'
            $script:labArgs.GroupName = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $script:labArgs.Permissions = 'Read'
            $noOp = & $script:labScript @script:labArgs
            $noOp.Status | Should -Be 'NoOp' -Because $noOp.Reason
            $wrongRecovery = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $noOp.ReceiptPath -ReceiptSHA256 $noOp.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $noOp.ApplyJournalSHA256 -ReviewedPartialApplyRecovery `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -Confirm:$false
            $wrongRecovery.Status | Should -Be 'Blocked'
            $revert = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $noOp.ReceiptPath -ReceiptSHA256 $noOp.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $noOp.ApplyJournalSHA256 `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -Confirm:$false
            $revert.Status | Should -Be 'NoOp' -Because $revert.Reason
        }

        It 'rejects a prepared Apply plan at both the public and internal entry points' {
            $preview = & $script:labScript @script:labArgs -WhatIf
            $preview.Status | Should -Be 'WhatIfOrDeclined' -Because $preview.Reason
            $withPlan = $script:labArgs.Clone()
            $withPlan.PlanPath = $preview.RecoveryRecordPath
            $withPlan.PlanSHA256 = $preview.RecoveryRecordSHA256
            $blocked = & $script:labScript @withPlan
            $blocked.Status | Should -Be 'Blocked'
            $blocked.Reason | Should -Match 'does not accept PlanPath'

            $plan = [IO.File]::ReadAllText($preview.RecoveryRecordPath) | ConvertFrom-NpJson
            $journal = New-LocalJournal -plan $plan
            $direct = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash `
                -journal $journal -DisposableAcknowledgement -Confirm:$false
            $direct.Status | Should -Be 'Blocked'
            $direct.Error | Should -Match 'cannot accept a prepared plan'
            Test-Path -LiteralPath $journal.Path | Should -BeFalse
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore
        }

        It 'replans from current permissions after a preview and reverts to that current baseline' {
            $preview = & $script:labScript @script:labArgs -WhatIf
            $preview.Status | Should -Be 'WhatIfOrDeclined' -Because $preview.Reason
            $previewPlan = [IO.File]::ReadAllText($preview.RecoveryRecordPath) | ConvertFrom-NpJson
            $previewBefore = Get-NpCanonicalJson @($previewPlan.Entries | ForEach-Object Before)

            $acl = Get-Acl -LiteralPath $script:labTarget
            $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-999')
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'Read', 'Allow'))
            Set-Acl -LiteralPath $script:labTarget -AclObject $acl -ErrorAction Stop
            $currentBefore = Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)
            $currentBefore | Should -Not -BeExactly $previewBefore

            $apply = & $script:labScript @script:labArgs
            $apply.Status | Should -Be 'Verified' -Because $apply.Reason
            $apply.RecoveryRecordPath | Should -Not -BeExactly $preview.RecoveryRecordPath
            $apply.RecoveryRecordSHA256 | Should -Not -BeExactly $preview.RecoveryRecordSHA256
            $plan = [IO.File]::ReadAllText($apply.RecoveryRecordPath) | ConvertFrom-NpJson
            (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before)) | Should -BeExactly $currentBefore
            $revert = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $apply.ReceiptPath -ReceiptSHA256 $apply.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $apply.ApplyJournalSHA256 `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -Confirm:$false
            $revert.Status | Should -Be 'Verified' -Because $revert.Reason
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $currentBefore
        }

        It 'replans a retry after a transient prewrite failure' {
            $script:failFirstLabIntent = $true
            $script:retryLabEventWriter = ${function:Write-NpEvent}
            Mock Write-NpEvent {
                param($Journal, $Stage, $Result, $Changes)
                if ($Stage -ceq 'CandidateWriteIntent' -and $script:failFirstLabIntent) {
                    throw 'Injected transient intent failure'
                }
                & $script:retryLabEventWriter $Journal $Stage $Result $Changes
            }
            $parameters = @{
                Mode='Apply'; TargetPath=$script:labTarget; TargetPlatform='Auto'
                GroupName=$script:labArgs.GroupName; Permissions='ReadAndExecute'
                Scope='ThisFolderSubfoldersAndFiles'; OutputDirectory=$script:labArgs.OutputDirectory
                ChangeTicket='DISPOSABLE-TEST'; MaxPaths=10000; DisposableAcknowledgement=$true
                Preview=$false; BoundParameters=@{ Confirm=$false }
            }
            $first = Invoke-NpDisposableLab @parameters
            $first.Status | Should -Be 'Blocked'
            Test-Path -LiteralPath $first.RecoveryRecordPath | Should -BeTrue
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore

            $acl = Get-Acl -LiteralPath $script:labTarget
            $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-999')
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'Read', 'Allow'))
            Set-Acl -LiteralPath $script:labTarget -AclObject $acl -ErrorAction Stop
            $retryBefore = Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)
            $script:failFirstLabIntent = $false
            $retry = Invoke-NpDisposableLab @parameters
            $retry.Status | Should -Be 'Verified' -Because $retry.Reason
            $retry.RecoveryRecordPath | Should -Not -BeExactly $first.RecoveryRecordPath
            $retryPlan = [IO.File]::ReadAllText($retry.RecoveryRecordPath) | ConvertFrom-NpJson
            (Get-NpCanonicalJson @($retryPlan.Entries | ForEach-Object Before)) | Should -BeExactly $retryBefore
            $revert = Invoke-NpDisposableLab -Mode Revert -DisposableAcknowledgement $true `
                -ReceiptPath $retry.ReceiptPath -ReceiptSHA256 $retry.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $retry.ApplyJournalSHA256 `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' `
                -Preview $false -BoundParameters @{ Confirm=$false }
            $revert.Status | Should -Be 'Verified' -Because $revert.Reason
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $retryBefore
        }

        It 'rejects tampered receipt and journal without changing the target' {
            $apply = & $script:labScript @script:labArgs
            $apply.Status | Should -Be 'Verified' -Because $apply.Reason
            $state = Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)
            $parameters = @{
                Mode='Revert'; DisposableLocalLab=$true; DisposableAcknowledgement=$true
                ReceiptPath=$apply.ReceiptPath; ReceiptSHA256=('0'*64)
                ReviewedApplyJournalSHA256=$apply.ApplyJournalSHA256
                OutputDirectory=$script:labArgs.OutputDirectory; ChangeTicket='RECOVERY-TEST'; Confirm=$false
            }
            $badReceipt = & $script:labScript @parameters
            $badReceipt.Status | Should -Be 'Blocked'
            $parameters.ReceiptSHA256 = $apply.ReceiptSHA256
            $parameters.ReviewedApplyJournalSHA256 = '0'*64
            (& $script:labScript @parameters).Status | Should -Be 'Blocked'
            $parameters.ReviewedApplyJournalSHA256 = $apply.ApplyJournalSHA256
            [IO.File]::AppendAllText($apply.ApplyJournalPath, 'tamper')
            $badJournal = & $script:labScript @parameters
            $badJournal.Status | Should -Be 'Blocked'
            $parameters.ReviewedApplyJournalSHA256 = Get-NpBytesHash ([IO.File]::ReadAllBytes($apply.ApplyJournalPath))
            (& $script:labScript @parameters -ReviewedPartialApplyRecovery).Status | Should -Be 'Blocked'
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $state
        }

        It 'rejects altered recovery snapshots and nonlocal platform declarations' {
            $unsupported = $script:labArgs.Clone()
            $unsupported.TargetPlatform = 'NetApp'
            (& $script:labScript @unsupported).Status | Should -Be 'Blocked'
            $apply = & $script:labScript @script:labArgs
            $apply.Status | Should -Be 'Verified' -Because $apply.Reason
            $state = Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)
            [IO.File]::AppendAllText($apply.RecoveryRecordPath, 'tamper')
            $revert = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $apply.ReceiptPath -ReceiptSHA256 $apply.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $apply.ApplyJournalSHA256 `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -Confirm:$false
            $revert.Status | Should -Be 'Blocked'
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $state
        }

        It 'rejects descriptor drift and requires acknowledgement' {
            $unacknowledged = $script:labArgs.Clone()
            $unacknowledged.DisposableAcknowledgement = $false
            (& $script:labScript @unacknowledged).Status | Should -Be 'Blocked'
            $apply = & $script:labScript @script:labArgs
            $apply.Status | Should -Be 'Verified' -Because $apply.Reason
            $acl = Get-Acl -LiteralPath $script:labTarget
            $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-999')
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'Read', 'Allow'))
            Set-Acl -LiteralPath $script:labTarget -AclObject $acl
            $state = Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)
            $revert = & $script:labScript -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $apply.ReceiptPath -ReceiptSHA256 $apply.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $apply.ApplyJournalSHA256 `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' -Confirm:$false
            $revert.Status | Should -Be 'Blocked'
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $state
        }

        It 'persists a failure receipt and requires reviewed partial recovery after a post-write audit fault' {
            $script:failLabProof = $true
            $script:labEventWriter = ${function:Write-NpEvent}
            Mock Write-NpEvent {
                param($Journal, $Stage, $Result, $Changes)
                if ($Stage -ceq 'CandidatePathVerified' -and $script:failLabProof) { throw 'Injected lab proof failure' }
                & $script:labEventWriter $Journal $Stage $Result $Changes
            }
            $failed = Invoke-NpDisposableLab -Mode Apply -TargetPath $script:labTarget -TargetPlatform Auto `
                -GroupName $script:labArgs.GroupName -Permissions ReadAndExecute `
                -Scope ThisFolderSubfoldersAndFiles -OutputDirectory $script:labArgs.OutputDirectory `
                -ChangeTicket 'DISPOSABLE-TEST' -MaxPaths 10000 -DisposableAcknowledgement $true `
                -Preview $false -BoundParameters @{ Confirm=$false }
            $failed.Status | Should -Be 'Indeterminate' -Because $failed.Reason
            $failed.ReceiptSHA256 | Should -Match '^[a-f0-9]{64}$'
            $parameters = @{
                Mode='Revert'; DisposableAcknowledgement=$true
                ReceiptPath=$failed.ReceiptPath; ReceiptSHA256=$failed.ReceiptSHA256
                ReviewedApplyJournalSHA256=$failed.ApplyJournalSHA256
                OutputDirectory=$script:labArgs.OutputDirectory; ChangeTicket='RECOVERY-TEST'
                Preview=$false; BoundParameters=@{ Confirm=$false }
            }
            $script:failLabProof = $false
            (Invoke-NpDisposableLab @parameters).Status | Should -Be 'Blocked'
            $recovery = Invoke-NpDisposableLab @parameters -ReviewedPartialApplyRecovery $true
            $recovery.Status | Should -Be 'Verified' -Because $recovery.Reason
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore
        }

        It 'blocks before mutation if prewrite receipt creation fails' {
            $script:failReceiptOnce = $true
            $script:evidenceWriter = ${function:Write-NpLocalEvidenceFile}
            Mock Write-NpLocalEvidenceFile {
                param($Path, $Value)
                if ($Path -like '*\receipt.json' -and $script:failReceiptOnce) {
                    $script:failReceiptOnce = $false
                    throw 'Injected receipt failure'
                }
                & $script:evidenceWriter $Path $Value
            }
            $failed = Invoke-NpDisposableLab -Mode Apply -TargetPath $script:labTarget -TargetPlatform Auto `
                -GroupName $script:labArgs.GroupName -Permissions ReadAndExecute `
                -Scope ThisFolderSubfoldersAndFiles -OutputDirectory $script:labArgs.OutputDirectory `
                -ChangeTicket 'DISPOSABLE-TEST' -MaxPaths 10000 -DisposableAcknowledgement $true `
                -Preview $false -BoundParameters @{ Confirm=$false }
            $failed.Status | Should -Be 'Blocked'
            $failed.Reason | Should -Match 'Injected receipt failure'
            Test-Path -LiteralPath $failed.ApplyJournalPath | Should -BeFalse
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore
        }

        It 'retains recovery details if final lock cleanup fails after Apply' {
            $script:failLockCleanup = $true
            Mock Remove-Item {
                param($LiteralPath)
                if ($LiteralPath -like '*\candidate.lock' -and $script:failLockCleanup) {
                    throw 'Injected final lock cleanup failure'
                }
                if ($LiteralPath -notlike '*\candidate.lock' -or -not [IO.File]::Exists($LiteralPath)) {
                    throw 'Unexpected lock cleanup request.'
                }
                [IO.File]::Delete($LiteralPath)
            }
            $apply = Invoke-NpDisposableLab -Mode Apply -TargetPath $script:labTarget -TargetPlatform Auto `
                -GroupName $script:labArgs.GroupName -Permissions ReadAndExecute `
                -Scope ThisFolderSubfoldersAndFiles -OutputDirectory $script:labArgs.OutputDirectory `
                -ChangeTicket 'DISPOSABLE-TEST' -MaxPaths 10000 -DisposableAcknowledgement $true `
                -Preview $false -BoundParameters @{ Confirm=$false }
            $apply.Status | Should -Be 'Indeterminate'
            $apply.Reason | Should -Match 'Injected final lock cleanup failure'
            Test-Path -LiteralPath $apply.ReceiptPath | Should -BeTrue
            $apply.ReceiptSHA256 | Should -BeExactly (Get-NpBytesHash ([IO.File]::ReadAllBytes($apply.ReceiptPath)))
            $apply.RecoveryRecordSHA256 | Should -BeExactly (Get-NpBytesHash ([IO.File]::ReadAllBytes($apply.RecoveryRecordPath)))
            $apply.ApplyJournalSHA256 | Should -BeExactly (Get-NpBytesHash ([IO.File]::ReadAllBytes($apply.ApplyJournalPath)))

            $script:failLockCleanup = $false
            $revert = Invoke-NpDisposableLab -Mode Revert -DisposableAcknowledgement $true `
                -ReceiptPath $apply.ReceiptPath -ReceiptSHA256 $apply.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $apply.ApplyJournalSHA256 `
                -OutputDirectory $script:labArgs.OutputDirectory -ChangeTicket 'RECOVERY-TEST' `
                -Preview $false -BoundParameters @{ Confirm=$false }
            $revert.Status | Should -Be 'Verified' -Because $revert.Reason
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore
        }

        It 'recovers an owned ad-hoc Apply interrupted after its first native write using its original prewrite receipt' {
            $scratch = Join-Path $script:localWork ('interruption_' + [guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($scratch)
            $outputDirectory = Join-Path $scratch 'evidence'
            $eventName = 'Local\NtfsAdHocInterruption_' + [guid]::NewGuid().ToString('N')
            $localScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'NtfsPermissions.Local.ps1'
            $lines = [IO.File]::ReadAllLines($localScript)
            $lineNumber = 0
            for ($i = 0; $i -lt $lines.Length; $i++) {
                if ($lines[$i] -match "^\s*Write-NpEvent \`$journal 'CandidatePathVerified'") {
                    if ($lineNumber) { throw 'Ambiguous interruption breakpoint.' }
                    $lineNumber = $i + 1
                }
            }
            if (-not $lineNumber) { throw 'Interruption breakpoint not found.' }
            $requestPath = Join-Path $scratch 'request.clixml'
            @{
                Entry=$script:labScript; LocalScript=$localScript; Line=$lineNumber
                Target=$script:labTarget; Output=$outputDirectory; EventName=$eventName
            } | Export-Clixml -LiteralPath $requestPath
            $command = @'
$ErrorActionPreference = 'Stop'
$request = Import-Clixml -LiteralPath '__REQUEST_PATH__'
function global:Get-ADGroup {
    param($Identity, $Properties)
    [pscustomobject]@{ GroupCategory='Security'; SID=$Identity }
}
$global:signal = [Threading.EventWaitHandle]::OpenExisting($request.EventName)
Set-PSBreakpoint -Script $request.LocalScript -Line $request.Line -Action {
    $null = $global:signal.Set()
    [Threading.Thread]::Sleep([Threading.Timeout]::Infinite)
} | Out-Null
& $request.Entry -Mode Apply -DisposableLocalLab -DisposableAcknowledgement `
    -TargetPath $request.Target -GroupName 'S-1-5-21-100-200-300-400' -Permissions ReadAndExecute `
    -OutputDirectory $request.Output -ChangeTicket 'INTERRUPTION-TEST' -Confirm:$false
throw 'Apply returned before the interruption boundary.'
'@
            $command = $command.Replace('__REQUEST_PATH__', $requestPath.Replace("'", "''"))
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            $executable = if ($PSVersionTable.PSEdition -ceq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
            $signal = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $eventName)
            $process = $null
            try {
                $process = Start-Process -FilePath (Join-Path $PSHOME $executable) `
                    -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded) `
                    -RedirectStandardOutput (Join-Path $scratch 'stdout.txt') `
                    -RedirectStandardError (Join-Path $scratch 'stderr.txt') -PassThru
                $deadline = [DateTime]::UtcNow.AddSeconds(90)
                $ready = $false
                do { $ready = $signal.WaitOne(100) } while (-not $ready -and -not $process.HasExited -and [DateTime]::UtcNow -lt $deadline)
                if (-not $ready -or $process.HasExited) { throw "Child did not reach the post-write breakpoint; inspect $scratch." }
                $runs = @(Get-ChildItem -LiteralPath $outputDirectory -Directory)
                $runs.Count | Should -Be 1
                $sourceRun = $runs[0].FullName
                $receiptPath = Join-Path $sourceRun 'receipt.json'
                $receiptBytes = [IO.File]::ReadAllBytes($receiptPath)
                $receiptHash = Get-NpBytesHash $receiptBytes
                $prewrite = Read-NpJournal -Path (Join-Path $sourceRun 'orchestration.jsonl')
                $prepared = @($prewrite.Events | Where-Object Stage -ceq 'RecoveryPrepared')
                $prepared.Count | Should -Be 1
                $prepared[0].Changes[0].ReceiptSHA256 | Should -BeExactly $receiptHash
                $prepared[0].Changes[0].ReceiptPath | Should -BeExactly $receiptPath
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                if (-not $process.WaitForExit(10000)) { throw 'Owned ad-hoc child did not terminate.' }
            } finally {
                if ($null -ne $process) {
                    try {
                        if (-not $process.HasExited) {
                            Stop-Process -Id $process.Id -Force -ErrorAction Stop
                            if (-not $process.WaitForExit(10000)) { throw 'Owned ad-hoc child cleanup failed.' }
                        }
                    } finally { $process.Dispose() }
                }
                $signal.Dispose()
            }
            $receipt = [Text.UTF8Encoding]::new($false,$true).GetString($receiptBytes) | ConvertFrom-NpJson
            $receipt.PSObject.Properties.Name | Should -Not -Contain 'Status'
            $receipt.PSObject.Properties.Name | Should -Not -Contain 'JournalSHA256'
            $source = Read-NpJournal -Path $receipt.JournalPath
            $source.Status | Should -Be 'Verified'
            @($source.Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 1
            @($source.Events | Where-Object Stage -ceq 'CandidatePathVerified').Count | Should -Be 0
            @($source.Events | Where-Object Stage -ceq 'CandidateComplete').Count | Should -Be 0
            $plan = [IO.File]::ReadAllText($receipt.PlanPath) | ConvertFrom-NpJson
            $states = @(Get-NpLocalInventory -targetPath $script:labTarget)
            $states[0].Descriptor | Should -BeExactly $plan.Entries[0].Desired.Descriptor
            for ($i = 1; $i -lt $states.Count; $i++) {
                (Get-NpCanonicalJson $states[$i]) | Should -BeExactly (Get-NpCanonicalJson $plan.Entries[$i].Before)
            }
            $parameters = @{
                Mode='Revert'; DisposableLocalLab=$true; DisposableAcknowledgement=$true
                ReceiptPath=$receiptPath; ReceiptSHA256=$receiptHash; ReviewedApplyJournalSHA256=$source.SHA256
                OutputDirectory=$outputDirectory; ChangeTicket='RECOVERY-TEST'; Confirm=$false
            }
            (& $script:labScript @parameters).Status | Should -Be 'Blocked'
            $recovery = & $script:labScript @parameters -ReviewedPartialApplyRecovery
            $recovery.Status | Should -Be 'Verified' -Because $recovery.Reason
            $recovery.RunDirectory | Should -Not -Be $sourceRun
            (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $script:labTarget)) | Should -BeExactly $script:labBefore
            (Get-NpBytesHash ([IO.File]::ReadAllBytes($receiptPath))) | Should -BeExactly $receiptHash
            (Get-NpBytesHash ([IO.File]::ReadAllBytes($receipt.JournalPath))) | Should -BeExactly $source.SHA256
        }
    }

    It 'refuses a descriptor that loses <Detail> when serialized for a change' -ForEach @(
        @{ Detail = 'ACE flags'; AceFlags = 64; Revision = 2; Control = 4 }
        @{ Detail = 'ACL revision'; AceFlags = 0; Revision = 4; Control = 4 }
        @{ Detail = 'control flags'; AceFlags = 0; Revision = 2; Control = 12 }
    ) {
        $sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $acl = [Security.AccessControl.RawAcl]::new([byte]$Revision, 1)
        $acl.InsertAce(0, [Security.AccessControl.CommonAce]::new(
            [Security.AccessControl.AceFlags]$AceFlags, [Security.AccessControl.AceQualifier]::AccessAllowed,
            1, $sid, $false, $null))
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Security.AccessControl.ControlFlags]$Control, $sid, $sid, $null, $acl)
        $validator = ([NtfsPermissions.LocalCandidate.Lease]).GetMethod(
            'ValidateDescriptor', [Reflection.BindingFlags]'NonPublic,Static')
        { $validator.Invoke($null, @($raw)) } | Should -Throw '*cannot be represented losslessly*'
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
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $hash -journal $journal -DisposableAcknowledgement -Confirm:$false
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

    It 'matches Windows allow rights for an initially absent <Permission> grant' -ForEach @(
        @{ Permission = 'Read' }
        @{ Permission = 'ReadAndExecute' }
        @{ Permission = 'Modify' }
        @{ Permission = 'FullControl' }
    ) {
        $target = New-LocalFixture
        $grants = @(Get-NpGrants -GroupName 'FixtureReaders' -Permissions $Permission `
            -Resolve { 'S-1-5-21-100-200-300-400' })
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $grants -scope ThisFolderOnly
        $journal = New-LocalJournal -plan $plan
        $apply = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal `
            -DisposableAcknowledgement -Confirm:$false
        $apply.Status | Should -Be 'Verified' -Because $apply.Error
        $sid = [Security.Principal.SecurityIdentifier]::new($grants[0].SID)
        $expected = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]$Permission, 'Allow')
        $actual = @((Get-Acl -LiteralPath $target).GetAccessRules(
            $true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -ceq $sid.Value })
        $actual.Count | Should -Be 1
        [int]$actual[0].FileSystemRights | Should -Be ([int]$expected.FileSystemRights)
        $revertJournal = New-LocalJournal -plan $plan -mode Revert
        $revert = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $revertJournal `
            -mode Revert -applyJournalPath $journal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) `
            -DisposableAcknowledgement -Confirm:$false
        $revert.Status | Should -Be 'Verified' -Because $revert.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
    }

    It 'performs no target changes for WhatIf or an already satisfied request' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -WhatIf
        $result.Status | Should -Be 'WhatIfOrDeclined'
        (Test-Path -LiteralPath (Join-Path (Split-Path $journal.Path -Parent) 'candidate.lock')) | Should -BeFalse
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        $ownerGrants = @(Get-NpGrants -GroupName 'FixtureOwner' -Permissions Read `
            -Resolve { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value })
        $noOpPlan = New-NpLocalCandidatePlan -targetPath $target -grants $ownerGrants
        $noOpJournal = New-LocalJournal -plan $noOpPlan
        $noOp = Invoke-LocalCandidateWithInjectedPlan -plan $noOpPlan -planSHA256 $noOpJournal.PlanHash -journal $noOpJournal -DisposableAcknowledgement -Confirm:$false
        $noOp.Status | Should -Be 'NoOp' -Because $noOp.Error
        @((Read-NpJournal -Path $noOpJournal.Path).Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 0
    }

    It 'keeps the 24-hour limit for Apply plans but allows an expired plan only for evidence-bound recovery' {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $plan.CreatedUtc = [DateTime]::UtcNow.AddHours(-25).ToString('o')
        $planHash = Get-NtfsHash (Get-NpCanonicalJson $plan)

        { Assert-NpLocalCandidatePlan -plan $plan -planSHA256 $planHash } |
            Should -Throw '*Candidate plan expired*'
        { Assert-NpLocalCandidatePlan -plan $plan -planSHA256 $planHash -allowExpiredForRecovery } |
            Should -Not -Throw
        $journal = New-LocalJournal -plan $plan
        $apply = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal `
            -DisposableAcknowledgement -Confirm:$false
        $apply.Status | Should -Be 'Blocked'
        $apply.Error | Should -Match 'Candidate plan expired'

        $plan.CreatedUtc = [DateTime]::UtcNow.AddMinutes(6).ToString('o')
        $futureHash = Get-NtfsHash (Get-NpCanonicalJson $plan)
        { Assert-NpLocalCandidatePlan -plan $plan -planSHA256 $futureHash -allowExpiredForRecovery } |
            Should -Throw '*Candidate plan expired or future dated*'
    }

    It 'refuses a descendant deny overlap recursively and preserves it for folder-only Apply and Revert' {
        $target = New-LocalFixture
        $child = Join-Path $target 'child'
        $acl = Get-Acl -LiteralPath $child
        $denySid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-999')
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $denySid, 'ReadAndExecute', 'None', 'None', 'Deny'))
        Set-Acl -LiteralPath $child -AclObject $acl -ErrorAction Stop
        $before = @(Get-NpLocalInventory -targetPath $target)

        { New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants `
            -scope ThisFolderSubfoldersAndFiles } | Should -Throw '*Applicable deny overlap*'
        (Get-NpCanonicalJson @(Get-NpLocalInventory -targetPath $target)) |
            Should -BeExactly (Get-NpCanonicalJson $before)

        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants -scope ThisFolderOnly
        $journal = New-LocalJournal -plan $plan
        $apply = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal `
            -DisposableAcknowledgement -Confirm:$false
        $apply.Status | Should -Be 'Verified' -Because $apply.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Desired))
        $revertJournal = New-LocalJournal -plan $plan -mode Revert
        $revert = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $revertJournal `
            -mode Revert -applyJournalPath $journal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) `
            -DisposableAcknowledgement -Confirm:$false
        $revert.Status | Should -Be 'Verified' -Because $revert.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) | Should -BeExactly (Get-NpCanonicalJson $before)
    }

    It 'propagates through a child with an existing non-inheritable grant and restores the baseline' {
        $target = New-LocalFixture
        $child = Join-Path $target 'child'
        $acl = Get-Acl -LiteralPath $child
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($script:localGrants[0].SID),
            'ReadAndExecute', 'None', 'None', 'Allow'))
        Set-Acl -LiteralPath $child -AclObject $acl -ErrorAction Stop
        $before = @(Get-NpLocalInventory -targetPath $target)
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants `
            -scope ThisFolderSubfoldersAndFiles
        $journal = New-LocalJournal -plan $plan
        $apply = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal `
            -DisposableAcknowledgement -Confirm:$false
        $apply.Status | Should -Be 'Verified' -Because $apply.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Desired))
        $revertJournal = New-LocalJournal -plan $plan -mode Revert
        $revert = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $revertJournal `
            -mode Revert -applyJournalPath $journal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) `
            -DisposableAcknowledgement -Confirm:$false
        $revert.Status | Should -Be 'Verified' -Because $revert.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) | Should -BeExactly (Get-NpCanonicalJson $before)
    }

    It 'rejects tampered desired descriptors even with a newly reviewed hash' {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $plan.Entries[0].Desired.Descriptor = $plan.Entries[0].Before.Descriptor
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
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
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
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
            $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
            $result.Status | Should -Be 'Blocked'
            $result.Error | Should -Match 'Cannot pin'
        } finally { $stream.Dispose() }
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
    }

    It 'retries a transient <Fault> refusal in a fresh audit and makes repeated Revert a NoOp' -ForEach @(
        @{ Fault = 'held handle' }
        @{ Fault = 'durable intent' }
    ) {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $firstJournal = New-LocalJournal -plan $plan
        $stream = $null
        $script:failRetryIntent = $true
        if ($Fault -ceq 'held handle') {
            $stream = [IO.FileStream]::new((Join-Path $plan.TargetDescriptor.CanonicalPath 'root-file.txt'),
                [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        } else {
            $script:retryEventWriter = ${function:Write-NpEvent}
            Mock Write-NpEvent {
                param($Journal, $Stage, $Result, $Changes)
                if ($Stage -ceq 'CandidateWriteIntent' -and $script:failRetryIntent) {
                    throw 'Injected transient durable intent failure'
                }
                & $script:retryEventWriter $Journal $Stage $Result $Changes
            }
        }
        try {
            $first = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $firstJournal.PlanHash -journal $firstJournal `
                -DisposableAcknowledgement -Confirm:$false
            $first.Status | Should -Be 'Blocked'
        } finally {
            if ($null -ne $stream) { $stream.Dispose() }
            $script:failRetryIntent = $false
        }
        $firstHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($firstJournal.Path))
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        $retryJournal = New-LocalJournal -plan $plan
        $retry = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $retryJournal.PlanHash -journal $retryJournal `
            -DisposableAcknowledgement -Confirm:$false
        $retry.Status | Should -Be 'Verified' -Because $retry.Error
        $retryHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($retryJournal.Path))
        Assert-NpLocalApplyEvidence -plan $plan -planSHA256 $retryJournal.PlanHash `
            -applyJournalPath $retryJournal.Path -applyJournalSHA256 $retryHash
        foreach ($expected in 'Verified', 'NoOp') {
            $revertJournal = New-LocalJournal -plan $plan -mode Revert
            $revert = Invoke-NpLocalCandidate -plan $plan -planSHA256 $retryJournal.PlanHash -journal $revertJournal `
                -mode Revert -applyJournalPath $retryJournal.Path -applyJournalSHA256 $retryHash `
                -DisposableAcknowledgement -Confirm:$false
            $revert.Status | Should -Be $expected -Because $revert.Error
        }
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        (Get-NpBytesHash ([IO.File]::ReadAllBytes($firstJournal.Path))) | Should -BeExactly $firstHash
        (Test-Path -LiteralPath (Join-Path (Split-Path $firstJournal.Path -Parent) 'candidate.lock')) | Should -BeTrue
    }

    It 'detects namespace additions before any writer call' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        [IO.File]::WriteAllText((Join-Path $target 'unexpected.txt'), 'unapproved')
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'Namespace add/delete/rename drift'
        @((Read-NpJournal -Path $journal.Path).Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 0
    }

    It 'preserves administrator drift and refuses the entire parent recovery with InterruptedRevert=<InterruptedRevert>' -ForEach @(
        @{ InterruptedRevert = $false }
        @{ InterruptedRevert = $true }
    ) {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $apply = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $apply.Status | Should -Be 'Verified' -Because $apply.Error
        if ($InterruptedRevert) {
            $interruptedJournal = New-LocalJournal -plan $plan -mode Revert
            Invoke-LocalProcessInterruption -plan $plan -journal $interruptedJournal `
                -stage CandidatePathVerified -applyJournal $journal
        }
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

    It 'preserves a security-only edit after durable intent and stops without writing or recovering' {
        $script:driftTarget = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $script:driftTarget -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $script:driftDescriptor = ''
        $script:originalEventWriter = ${function:Write-NpEvent}
        Mock Write-NpEvent {
            param($Journal, $Stage, $Result, $Changes)
            & $script:originalEventWriter $Journal $Stage $Result $Changes
            if ($Stage -ceq 'CandidateWriteIntent') {
                $acl = Get-Acl -LiteralPath $script:driftTarget
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-401'), 'Read', 'Allow'))
                Set-Acl -LiteralPath $script:driftTarget -AclObject $acl -ErrorAction Stop
                $script:driftDescriptor = (Get-Acl -LiteralPath $script:driftTarget).Sddl
            }
        }
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal `
            -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Indeterminate'
        $result.Error | Should -Match 'Pre-write descriptor drift'
        $events = Read-NpJournal -Path $journal.Path
        @($events.Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 1
        @($events.Events | Where-Object Stage -ceq 'CandidatePathVerified').Count | Should -Be 0
        $events.Events[-1].Stage | Should -Be 'CandidateStopped'
        $events.Events[-1].Result | Should -Be 'Indeterminate'
        $states = @(Get-LocalState -plan $plan)
        $states[0].Descriptor | Should -BeExactly $script:driftDescriptor
        for ($i = 1; $i -lt $states.Count; $i++) {
            (Get-NpCanonicalJson $states[$i]) | Should -BeExactly (Get-NpCanonicalJson $plan.Entries[$i].Before)
        }
        { Assert-NpLocalApplyEvidence -plan $plan -planSHA256 $journal.PlanHash `
            -applyJournalPath $journal.Path -applyJournalSHA256 $events.SHA256 } |
            Should -Throw '*interrupted recovery requires independent review*'
    }

    It 'stops before writes when durable intent cannot be recorded' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        Mock Write-NpEvent {
            if ($Stage -ceq 'CandidateWriteIntent') { throw 'Injected durable intent failure' }
        }
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'durable intent failure'
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        (Test-Path -LiteralPath (Join-Path (Split-Path $journal.Path -Parent) 'candidate.lock')) | Should -BeTrue
    }

    It 'reports post-write audit failure without automatic retry and supports separately reviewed recovery' {
        $target = New-LocalFixture
        $plan = New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $script:postWriteAuditFailure = $true
        $script:postWriteEventWriter = ${function:Write-NpEvent}
        Mock Write-NpEvent {
            param($Journal, $Stage, $Result, $Changes)
            if ($Stage -ceq 'CandidatePathVerified' -and $script:postWriteAuditFailure) {
                throw 'Injected post-write audit failure'
            }
            & $script:postWriteEventWriter $Journal $Stage $Result $Changes
        }
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Indeterminate'
        $result.Error | Should -Match 'post-write audit failure'
        $states = @(Get-LocalState -plan $plan)
        $states[0].Descriptor | Should -BeExactly $plan.Entries[0].Desired.Descriptor
        $states[1].Descriptor | Should -BeExactly $plan.Entries[1].Before.Descriptor
        (Test-Path -LiteralPath (Join-Path (Split-Path $journal.Path -Parent) 'candidate.lock')) | Should -BeTrue
        $sourceHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))
        $script:postWriteAuditFailure = $false
        $recoveryJournal = New-LocalJournal -plan $plan -mode Revert
        $recovery = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $recoveryJournal `
            -mode Revert -applyJournalPath $journal.Path -applyJournalSHA256 $sourceHash `
            -reviewedPartialApplyRecovery -DisposableAcknowledgement -Confirm:$false
        $recovery.Status | Should -Be 'Verified' -Because $recovery.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        $freshJournal = New-LocalJournal -plan $plan
        $fresh = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $freshJournal.PlanHash -journal $freshJournal `
            -DisposableAcknowledgement -Confirm:$false
        $fresh.Status | Should -Be 'Verified' -Because $fresh.Error
        $finalJournal = New-LocalJournal -plan $plan -mode Revert
        $final = Invoke-NpLocalCandidate -plan $plan -planSHA256 $freshJournal.PlanHash -journal $finalJournal `
            -mode Revert -applyJournalPath $freshJournal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($freshJournal.Path))) `
            -DisposableAcknowledgement -Confirm:$false
        $final.Status | Should -Be 'Verified' -Because $final.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) | Should -BeExactly $sourceHash
    }

    It 'preserves exact state and evidence after terminating <Mode> at <Boundary>' -ForEach @(
        @{ Mode = 'Apply'; Boundary = 'durable intent'; Stage = 'CandidateWriteIntent'; BeforeEvent = $false; Written = $false }
        @{ Mode = 'Apply'; Boundary = 'write before proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $true; Written = $true }
        @{ Mode = 'Apply'; Boundary = 'durable proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $false; Written = $true }
        @{ Mode = 'Revert'; Boundary = 'durable intent'; Stage = 'CandidateWriteIntent'; BeforeEvent = $false; Written = $false }
        @{ Mode = 'Revert'; Boundary = 'write before proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $true; Written = $true }
        @{ Mode = 'Revert'; Boundary = 'durable proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $false; Written = $true }
    ) {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $applyJournal = $null
        if ($Mode -ceq 'Revert') {
            $applyJournal = New-LocalJournal -plan $plan
            $apply = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $applyJournal.PlanHash -journal $applyJournal `
                -DisposableAcknowledgement -Confirm:$false
            $apply.Status | Should -Be 'Verified' -Because $apply.Error
        }
        $journal = New-LocalJournal -plan $plan -mode $Mode
        Invoke-LocalProcessInterruption -plan $plan -journal $journal -stage $Stage `
            -beforeEvent:$BeforeEvent -applyJournal $applyJournal

        $evidence = Read-NpJournal -Path $journal.Path
        $evidence.Status | Should -Be 'Verified' -Because 'hash-chain consistency does not mean the operation completed'
        @($evidence.Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 1
        $proofCount = if ($Stage -ceq 'CandidatePathVerified' -and -not $BeforeEvent) { 1 } else { 0 }
        @($evidence.Events | Where-Object Stage -ceq 'CandidatePathVerified').Count | Should -Be $proofCount
        @($evidence.Events | Where-Object { $_.Stage -in @('CandidateComplete', 'CandidateStopped') }).Count | Should -Be 0
        $lockPath = Join-Path (Split-Path $journal.Path -Parent) 'candidate.lock'
        (Test-Path -LiteralPath $lockPath) | Should -BeTrue
        $observed = @(Get-LocalState -plan $plan)
        $observed.Count | Should -Be $plan.Entries.Count
        for ($index = 0; $index -lt $observed.Count; $index++) {
            $afterWrite = $Written -and $index -eq 0
            $expected = if (($Mode -ceq 'Apply') -eq $afterWrite) {
                $plan.Entries[$index].Desired
            } else { $plan.Entries[$index].Before }
            (Get-NpCanonicalJson $observed[$index]) | Should -BeExactly (Get-NpCanonicalJson $expected)
        }
        $interruptedState = Get-NpCanonicalJson $observed
        $reuse = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal `
            -mode $Mode -DisposableAcknowledgement -Confirm:$false
        $reuse.Status | Should -Be 'Blocked'
        $reuse.Error | Should -Match 'audit binding mismatch'
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) | Should -BeExactly $interruptedState

        $recoveryJournal = New-LocalJournal -plan $plan -mode Revert
        $sourceJournal = if ($Mode -ceq 'Apply') { $journal } else { $applyJournal }
        $recovery = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $recoveryJournal `
            -mode Revert -applyJournalPath $sourceJournal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($sourceJournal.Path))) `
            -DisposableAcknowledgement -Confirm:$false
        if ($Mode -ceq 'Apply') {
            $recovery.Status | Should -Be 'Blocked'
            $recovery.Error | Should -Match 'interrupted recovery requires independent review'
            @((Read-NpJournal -Path $recoveryJournal.Path).Events |
                Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 0
            (Get-NpCanonicalJson (Get-LocalState -plan $plan)) | Should -BeExactly $interruptedState
            $reviewedJournal = New-LocalJournal -plan $plan -mode Revert
            $restored = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $reviewedJournal `
                -mode Revert -applyJournalPath $journal.Path -applyJournalSHA256 $evidence.SHA256 `
                -reviewedPartialApplyRecovery -DisposableAcknowledgement -Confirm:$false
            $expectedRecovery = if ($Written) { 'Verified' } else { 'NoOp' }
            $restored.Status | Should -Be $expectedRecovery -Because $restored.Error
            @((Read-NpJournal -Path $reviewedJournal.Path).Events |
                Where-Object Stage -ceq 'CandidatePartialApplyRecovery').Count | Should -Be 1
            (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
                Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
            $freshJournal = New-LocalJournal -plan $plan
            $fresh = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $freshJournal.PlanHash -journal $freshJournal `
                -DisposableAcknowledgement -Confirm:$false
            $fresh.Status | Should -Be 'Verified' -Because $fresh.Error
            $freshHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($freshJournal.Path))
            Assert-NpLocalApplyEvidence -plan $plan -planSHA256 $freshJournal.PlanHash `
                -applyJournalPath $freshJournal.Path -applyJournalSHA256 $freshHash
            $finalJournal = New-LocalJournal -plan $plan -mode Revert
            $final = Invoke-NpLocalCandidate -plan $plan -planSHA256 $freshJournal.PlanHash -journal $finalJournal `
                -mode Revert -applyJournalPath $freshJournal.Path -applyJournalSHA256 $freshHash `
                -DisposableAcknowledgement -Confirm:$false
            $final.Status | Should -Be 'Verified' -Because $final.Error
        } else {
            $recovery.Status | Should -Be 'Verified' -Because $recovery.Error
            (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
                Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
            $againJournal = New-LocalJournal -plan $plan -mode Revert
            $again = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $againJournal `
                -mode Revert -applyJournalPath $sourceJournal.Path `
                -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($sourceJournal.Path))) `
                -DisposableAcknowledgement -Confirm:$false
            $again.Status | Should -Be 'NoOp' -Because $again.Error
        }
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) | Should -BeExactly $evidence.SHA256
        (Test-Path -LiteralPath $lockPath) | Should -BeTrue
        foreach ($file in 'root-file.txt', 'child\file.txt', 'protected\sentinel.txt') {
            $content = if ($file -ceq 'protected\sentinel.txt') { 'unchanged' } else { 'disposable' }
            [IO.File]::ReadAllText((Join-Path $plan.TargetDescriptor.CanonicalPath $file)) |
                Should -BeExactly $content
        }
    }

    It 'recovers <Operation> Apply interrupted at <Boundary> before a fresh retry' -ForEach @(
        @{ Operation = 'Remove'; Boundary = 'durable intent'; Stage = 'CandidateWriteIntent'; BeforeEvent = $false; Written = $false }
        @{ Operation = 'Remove'; Boundary = 'write before proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $true; Written = $true }
        @{ Operation = 'Remove'; Boundary = 'durable proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $false; Written = $true }
        @{ Operation = 'Replace'; Boundary = 'durable intent'; Stage = 'CandidateWriteIntent'; BeforeEvent = $false; Written = $false }
        @{ Operation = 'Replace'; Boundary = 'write before proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $true; Written = $true }
        @{ Operation = 'Replace'; Boundary = 'durable proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $false; Written = $true }
    ) {
        $target = New-LocalFixture
        $sourceSid = 'S-1-5-21-100-200-300-401'
        $acl = Get-Acl -LiteralPath $target -ErrorAction Stop
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sourceSid),
            'ReadPermissions', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
        Set-Acl -LiteralPath $target -AclObject $acl -ErrorAction Stop
        $grants = if ($Operation -ceq 'Replace') { @($script:localGrants) } else { @() }
        $plan = New-NpLocalCandidatePlan -targetPath $target -operation $Operation `
            -removal (Resolve-NpLocalRemoval $sourceSid) -grants $grants
        $journal = New-LocalJournal -plan $plan
        Invoke-LocalProcessInterruption -plan $plan -journal $journal -stage $Stage -beforeEvent:$BeforeEvent
        $evidence = Read-NpJournal -Path $journal.Path
        $evidence.Status | Should -Be 'Verified'
        @($evidence.Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 1
        @($evidence.Events | Where-Object { $_.Stage -in @('CandidateComplete', 'CandidateStopped') }).Count |
            Should -Be 0
        $observed = @(Get-LocalState -plan $plan)
        for ($index = 0; $index -lt $observed.Count; $index++) {
            $expected = if ($Written -and $index -eq 0) { $plan.Entries[$index].Desired } else { $plan.Entries[$index].Before }
            (Get-NpCanonicalJson $observed[$index]) | Should -BeExactly (Get-NpCanonicalJson $expected)
        }
        $blockedJournal = New-LocalJournal -plan $plan -mode Revert
        $blocked = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $blockedJournal `
            -mode Revert -applyJournalPath $journal.Path -applyJournalSHA256 $evidence.SHA256 `
            -DisposableAcknowledgement -Confirm:$false
        $blocked.Status | Should -Be 'Blocked'
        $blocked.Error | Should -Match 'interrupted recovery requires independent review'
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) | Should -BeExactly (Get-NpCanonicalJson $observed)

        $recoveryJournal = New-LocalJournal -plan $plan -mode Revert
        $recovery = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $recoveryJournal `
            -mode Revert -applyJournalPath $journal.Path -applyJournalSHA256 $evidence.SHA256 `
            -reviewedPartialApplyRecovery -DisposableAcknowledgement -Confirm:$false
        $expectedStatus = if ($Written) { 'Verified' } else { 'NoOp' }
        $recovery.Status | Should -Be $expectedStatus -Because $recovery.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        $freshJournal = New-LocalJournal -plan $plan
        $fresh = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $freshJournal.PlanHash -journal $freshJournal `
            -DisposableAcknowledgement -Confirm:$false
        $fresh.Status | Should -Be 'Verified' -Because $fresh.Error
        $revertJournal = New-LocalJournal -plan $plan -mode Revert
        $revert = Invoke-NpLocalCandidate -plan $plan -planSHA256 $freshJournal.PlanHash -journal $revertJournal `
            -mode Revert -applyJournalPath $freshJournal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($freshJournal.Path))) `
            -DisposableAcknowledgement -Confirm:$false
        $revert.Status | Should -Be 'Verified' -Because $revert.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) | Should -BeExactly $evidence.SHA256
    }

    It 'refuses reviewed partial Apply recovery for <Fault> without changing any path' -ForEach @(
        @{ Fault = 'active source lock' }
        @{ Fault = 'administrator drift' }
        @{ Fault = 'missing path intent' }
        @{ Fault = 'wrong source hash' }
    ) {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $source = New-LocalJournal -plan $plan
        Invoke-LocalProcessInterruption -plan $plan -journal $source -stage CandidatePathVerified
        $sourceHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($source.Path))
        $lockPath = Join-Path (Split-Path $source.Path -Parent) 'candidate.lock'
        $heldLock = $null
        if ($Fault -ceq 'active source lock') {
            $heldLock = [IO.FileStream]::new($lockPath, [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        } elseif ($Fault -ceq 'administrator drift') {
            $path = Join-Path $plan.TargetDescriptor.CanonicalPath 'root-file.txt'
            $acl = Get-Acl -LiteralPath $path
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-401'), 'Read', 'Allow'))
            Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
        } elseif ($Fault -ceq 'missing path intent') {
            $entry = @($plan.Entries | Where-Object { $_.Before.Path -ceq (Join-Path $plan.TargetDescriptor.CanonicalPath 'child') })[0]
            $lease = [NtfsPermissions.LocalCandidate.Lease]::Open($entry.Before.Path, $true)
            try { $null = $lease.WriteDacl($entry.Before.Descriptor, $entry.Desired.Descriptor) }
            finally { $lease.Dispose() }
        }
        $before = Get-NpCanonicalJson (Get-LocalState -plan $plan)
        $hash = if ($Fault -ceq 'wrong source hash') { '0' * 64 } else { $sourceHash }
        $journal = New-LocalJournal -plan $plan -mode Revert
        try {
            $result = Invoke-NpLocalCandidate -plan $plan -planSHA256 $journal.PlanHash -journal $journal `
                -mode Revert -applyJournalPath $source.Path -applyJournalSHA256 $hash `
                -reviewedPartialApplyRecovery -DisposableAcknowledgement -Confirm:$false
            $result.Status | Should -Be 'Blocked'
            $expectedError = switch ($Fault) {
                'active source lock' { 'Cannot exclusively pin' }
                'administrator drift' { 'identity/descriptor drift' }
                'missing path intent' { 'no durable write intent' }
                'wrong source hash' { 'evidence hash mismatch' }
            }
            $result.Error | Should -Match $expectedError
            @((Read-NpJournal -Path $journal.Path).Events |
                Where-Object Stage -ceq 'CandidateWriteIntent').Count | Should -Be 0
        } finally {
            if ($null -ne $heldLock) { $heldLock.Dispose() }
        }
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) | Should -BeExactly $before
        (Get-NpBytesHash ([IO.File]::ReadAllBytes($source.Path))) | Should -BeExactly $sourceHash
        (Test-Path -LiteralPath $lockPath) | Should -BeTrue
    }

    It 'retries partial-Apply recovery after interruption at <Boundary> and then completes a fresh Apply' -ForEach @(
        @{ Boundary = 'durable intent'; Stage = 'CandidateWriteIntent'; BeforeEvent = $false }
        @{ Boundary = 'write before proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $true }
        @{ Boundary = 'durable proof'; Stage = 'CandidatePathVerified'; BeforeEvent = $false }
    ) {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $source = New-LocalJournal -plan $plan
        Invoke-LocalProcessInterruption -plan $plan -journal $source -stage CandidatePathVerified
        $sourceHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($source.Path))
        $interrupted = New-LocalJournal -plan $plan -mode Revert
        Invoke-LocalProcessInterruption -plan $plan -journal $interrupted -stage $Stage `
            -beforeEvent:$BeforeEvent -applyJournal $source -reviewedPartialApplyRecovery
        $interruptedHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($interrupted.Path))
        $retryJournal = New-LocalJournal -plan $plan -mode Revert
        $retry = Invoke-NpLocalCandidate -plan $plan -planSHA256 $retryJournal.PlanHash -journal $retryJournal `
            -mode Revert -applyJournalPath $source.Path -applyJournalSHA256 $sourceHash `
            -reviewedPartialApplyRecovery -DisposableAcknowledgement -Confirm:$false
        $retry.Status | Should -BeIn @('Verified', 'NoOp') -Because $retry.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        $freshJournal = New-LocalJournal -plan $plan
        $fresh = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $freshJournal.PlanHash -journal $freshJournal `
            -DisposableAcknowledgement -Confirm:$false
        $fresh.Status | Should -Be 'Verified' -Because $fresh.Error
        $finalJournal = New-LocalJournal -plan $plan -mode Revert
        $final = Invoke-NpLocalCandidate -plan $plan -planSHA256 $freshJournal.PlanHash -journal $finalJournal `
            -mode Revert -applyJournalPath $freshJournal.Path `
            -applyJournalSHA256 (Get-NpBytesHash ([IO.File]::ReadAllBytes($freshJournal.Path))) `
            -DisposableAcknowledgement -Confirm:$false
        $final.Status | Should -Be 'Verified' -Because $final.Error
        (Get-NpCanonicalJson (Get-LocalState -plan $plan)) |
            Should -BeExactly (Get-NpCanonicalJson @($plan.Entries | ForEach-Object Before))
        foreach ($attempt in @(
            @{ Journal = $source; Hash = $sourceHash }
            @{ Journal = $interrupted; Hash = $interruptedHash }
        )) {
            (Get-NpBytesHash ([IO.File]::ReadAllBytes($attempt.Journal.Path))) | Should -BeExactly $attempt.Hash
            (Test-Path -LiteralPath (Join-Path (Split-Path $attempt.Journal.Path -Parent) 'candidate.lock')) |
                Should -BeTrue
        }
        foreach ($file in 'root-file.txt', 'child\file.txt', 'protected\sentinel.txt') {
            $content = if ($file -ceq 'protected\sentinel.txt') { 'unchanged' } else { 'disposable' }
            [IO.File]::ReadAllText((Join-Path $plan.TargetDescriptor.CanonicalPath $file)) |
                Should -BeExactly $content
        }
    }

    It 'rejects the partial-recovery acknowledgement in Apply mode before writes' {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal `
            -reviewedPartialApplyRecovery -DisposableAcknowledgement -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'requires Revert mode'
        Test-Path -LiteralPath $journal.Path | Should -BeFalse
    }

    It 'rejects incomplete path bounds, remote audit directories, and device-prefixed UNC handles' {
        $target = New-LocalFixture
        { New-NpLocalCandidatePlan -targetPath $target -grants $script:localGrants -maxPaths 1 } |
            Should -Throw '*path limit*'
        { [NtfsPermissions.LocalCandidate.Lease]::OpenAuditDirectory('\\SERVER\Share\Folder') } |
            Should -Throw '*direct local*'
        { [NtfsPermissions.LocalCandidate.Lease]::Open('\\?\UNC\SERVER\Share\Folder', $true) } |
            Should -Throw '*static direct UNC*'
    }

    It 'preserves non-auto-inherited DACL control flags during NtSetSecurityObject writes' {
        $target = New-LocalFixture
        $rawRoot = Join-Path $target 'non-ai-root'
        $ownerObject = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $rawAcl = [Security.AccessControl.DirectorySecurity]::new()
        $rawAcl.SetAccessRuleProtection($true, $false)
        $rawAcl.SetOwner($ownerObject)
        $rawAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $ownerObject, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
        if ($PSVersionTable.PSEdition -ceq 'Desktop') {
            [void][IO.Directory]::CreateDirectory($rawRoot, $rawAcl)
        } else {
            [void][IO.FileSystemAclExtensions]::CreateDirectory($rawAcl, $rawRoot)
        }
        $leaf = Join-Path $rawRoot 'non-ai-leaf'
        [void][IO.Directory]::CreateDirectory($leaf)
        $setProbe = [NtfsPermissions.LocalCandidate.Lease]::Open($leaf, $true)
        try {
            $initial = $setProbe.Read()
            $initialSnapshot = ConvertTo-NpLocalSnapshot -nativeSnapshot $initial
            $initialRaw = [Security.AccessControl.RawSecurityDescriptor]::new($initial.Descriptor)
            ([int]($initialRaw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)) |
                Should -Be 0
            $desiredSnapshot = New-NpLocalDesiredSnapshot -before $initialSnapshot -grants @(
                [pscustomobject]@{ GroupName = 'TestGroup'; SID = 'S-1-5-21-100-200-300-400'; Permissions = 'ReadAndExecute'; Mask = 1179817 }
            ) -scope ThisFolderSubfoldersAndFiles -isRoot $true
            $updated = $setProbe.WriteDacl($initial.Descriptor, $desiredSnapshot.Descriptor)
            $updated.Descriptor | Should -BeExactly $desiredSnapshot.Descriptor
            $updatedRaw = [Security.AccessControl.RawSecurityDescriptor]::new($updated.Descriptor)
            ([int]($updatedRaw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)) |
                Should -Be 0
            $reverted = $setProbe.WriteDacl($updated.Descriptor, $initial.Descriptor)
            $reverted.Descriptor | Should -BeExactly $initial.Descriptor
        } finally {
            $setProbe.Dispose()
        }
    }

    It 'resolves UNC share-root parents cleanly and scopes auto-inherited safety by platform' {
        (Get-NpParentPath '\\filer\assessment\Dept') | Should -BeExactly '\\filer\assessment'
        (Get-NpParentPath '\\filer\assessment\Dept\Child') | Should -BeExactly '\\filer\assessment\Dept'
        (Get-NpParentPath 'C:\Dept') | Should -BeExactly 'C:\'
        (Get-NpParentPath 'C:\Dept\Child') | Should -BeExactly 'C:\Dept'
        $nonAiEntry = [pscustomobject]@{
            Boundary = $false
            Before = [pscustomobject]@{ Path = '\\filer\assessment\Dept'; Control = 32772; Descriptor = 'O:BAG:SYD:(A;OICI;FA;;;BA)' }
            Desired = [pscustomobject]@{ Path = '\\filer\assessment\Dept'; Control = 32772; Descriptor = 'O:BAG:SYD:(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;WD)' }
        }
        { Assert-NpLocalInheritanceSafety -entries @($nonAiEntry) -platform LocalWindows } | Should -Throw '*auto-inherited*'
        { Assert-NpLocalInheritanceSafety -entries @($nonAiEntry) -platform WindowsSMB } | Should -Throw '*auto-inherited*'
        { Assert-NpLocalInheritanceSafety -entries @($nonAiEntry) -platform NetAppSMB } | Should -Not -Throw
        { Assert-NpLocalInheritanceSafety -entries @($nonAiEntry) -platform GenericSMB } | Should -Not -Throw
    }

    It 'pins parent, nested directory, and child file simultaneously with zero-share handles and blocks external open handles' {
        $target = New-LocalFixture
        $nested = Join-Path $target 'child'
        $childFile = Join-Path $nested 'file.txt'
        $rootLease = [NtfsPermissions.LocalCandidate.Lease]::Open($target, $true)
        try {
            $nestedLease = [NtfsPermissions.LocalCandidate.Lease]::Open($nested, $true)
            try {
                $fileLease = [NtfsPermissions.LocalCandidate.Lease]::Open($childFile, $true)
                try {
                    $rootLease.Read().Identity | Should -Match '^LocalNTFS:'
                    $nestedLease.Read().Identity | Should -Match '^LocalNTFS:'
                    $fileLease.Read().Identity | Should -Match '^LocalNTFS:'
                } finally {
                    $fileLease.Dispose()
                }
            } finally {
                $nestedLease.Dispose()
            }
        } finally {
            $rootLease.Dispose()
        }
        $externalStream = [IO.File]::Open($childFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            { [NtfsPermissions.LocalCandidate.Lease]::Open($childFile, $true) } | Should -Throw '*Cannot pin*'
        } finally {
            $externalStream.Dispose()
        }
    }

    It 'rejects missing disposable acknowledgement without creating audit or target writes' {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $result = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Error | Should -Match 'DisposableAcknowledgement'
        (Test-Path -LiteralPath $journal.Path) | Should -BeFalse
    }

    It 'refuses torn recovery evidence and preserves the verified after-state' {
        $plan = New-NpLocalCandidatePlan -targetPath (New-LocalFixture) -grants $script:localGrants
        $journal = New-LocalJournal -plan $plan
        $apply = Invoke-LocalCandidateWithInjectedPlan -plan $plan -planSHA256 $journal.PlanHash -journal $journal -DisposableAcknowledgement -Confirm:$false
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
