#requires -Version 5.1
<#
.SYNOPSIS
Internal, unqualified local-NTFS writer candidate and safety helpers.
.DESCRIPTION
Not loaded by Add-FileSharePermissions.ps1. Use only in independently approved
disposable experiments. Public Apply/Revert remain blocked. Requires Windows,
fixed local NTFS, and explicit READ_CONTROL/WRITE_DAC access; no elevation or
privilege changes are attempted. Native source is compiled with Add-Type.
Zero-share handles pin the observed objects and suppress implicit propagation,
but cannot prove atomic namespace coverage or exclude other administrator ACL
edits. Success here is verification, not platform or production qualification.
.NOTES
Release version: NtfsAssessment.Common.ps1, Permissions entry in NtfsVersions.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'NtfsPermissions.Common.ps1')

function Initialize-NpLocalNative {
    <#
    .SYNOPSIS
    Loads the exact native source or rejects a stale assembly in this process.
    #>
    [CmdletBinding()]
    param()
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'The local NTFS candidate requires Windows.'
    }
    $nativePath = Join-Path $PSScriptRoot 'NtfsPermissions.Local.cs'
    $bytes = [IO.File]::ReadAllBytes($nativePath)
    $hash = Get-NpBytesHash $bytes
    $type = 'NtfsPermissions.LocalCandidate.Lease' -as [type]
    if ($null -eq $type) {
        $source = [Text.UTF8Encoding]::new($false, $true).GetString($bytes).Replace('__SOURCE_SHA256__', $hash)
        Add-Type -TypeDefinition $source -ErrorAction Stop
    } elseif ($type::SourceSHA256 -cne $hash) {
        throw 'Native source changed after assembly load; start a new PowerShell process.'
    }
}

function ConvertTo-NpLocalSnapshot {
    <#
    .SYNOPSIS
    Converts a handle-bound descriptor into the existing strict snapshot model.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $nativeSnapshot
    )
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($nativeSnapshot.Descriptor)
    $aces = @(
        foreach ($ace in $raw.DiscretionaryAcl) {
            $flags = [int]$ace.AceFlags
            [pscustomobject][ordered]@{
                SID = $ace.SecurityIdentifier.Value
                Type = $(if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed) { 'Allow' } else { 'Deny' })
                Mask = [long]$ace.AccessMask
                Inherited = [bool]($flags -band 16)
                ContainerInherit = [bool]($flags -band 2)
                ObjectInherit = [bool]($flags -band 1)
                InheritOnly = [bool]($flags -band 8)
                NoPropagate = [bool]($flags -band 4)
            }
        }
    )
    $snapshot = [pscustomobject][ordered]@{
        Path = $nativeSnapshot.Path
        Kind = $nativeSnapshot.Kind
        Identity = $nativeSnapshot.Identity
        Owner = $raw.Owner.Value
        Group = $raw.Group.Value
        Control = [int]$raw.ControlFlags
        Protected = [bool]($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
        DaclPresent = $true
        Canonical = $true
        Aces = $aces
        Descriptor = $nativeSnapshot.Descriptor
    }
    Assert-NpSnapshot $snapshot
    return $snapshot
}

function Get-NpLocalInventory {
    <#
    .SYNOPSIS
    Inventories the complete local tree, including protected branch contents.
    .DESCRIPTION
    Descendants are observed for both scopes. Protected branches are retained
    as unchanged sentinels, not writable traversal targets. Reparse/hard links,
    access failures and limits throw instead of returning complete-looking data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $targetPath,
        [ValidateRange(1, 100000)][int] $maxPaths = 10000
    )
    Initialize-NpLocalNative
    $targetPath = ConvertTo-NpPath $targetPath
    if ($targetPath.StartsWith('\\')) { throw 'The local candidate rejects SMB and mapped targets.' }
    $queue = [Collections.Generic.Queue[string]]::new()
    $snapshots = [Collections.Generic.List[object]]::new()
    $identities = @{}
    $queue.Enqueue($targetPath)
    while ($queue.Count -gt 0) {
        $path = $queue.Dequeue()
        if ($snapshots.Count -ge $maxPaths) { throw 'Local inventory path limit reached; no writable coverage.' }
        $lease = [NtfsPermissions.LocalCandidate.Lease]::Open($path, $false)
        try {
            $snapshot = ConvertTo-NpLocalSnapshot -nativeSnapshot $lease.Read()
            if ($snapshots.Count -eq 0 -and $snapshot.Kind -cne 'Folder') { throw 'Local target must be a directory.' }
            if ($identities.ContainsKey($snapshot.Identity)) { throw 'Duplicate physical object identity in local inventory.' }
            $identities[$snapshot.Identity] = $true
            $snapshots.Add($snapshot)
            if ($snapshot.Kind -ceq 'Folder') {
                foreach ($childPath in $lease.GetChildPaths($maxPaths)) { $queue.Enqueue($childPath) }
            }
        } finally { $lease.Dispose() }
    }
    return $snapshots.ToArray()
}

function New-NpLocalDesiredSnapshot {
    <#
    .SYNOPSIS
    Materializes a narrow simple-grant intent as an exact ordered DACL descriptor.
    .DESCRIPTION
    Existing ACE bytes, owner/group/control are preserved. Unsupported or
    ambiguous descriptors and applicable deny overlaps are rejected.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Constructs descriptor data only; no writes.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $before,
        [Parameter(Mandatory = $true)] $grants,
        [Parameter(Mandatory = $true)][ValidateSet('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles')][string] $scope,
        [Parameter(Mandatory = $true)][bool] $isRoot
    )
    $proposal = New-NpProposal $before $grants $scope $isRoot
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($before.Descriptor)
    $acl = [Security.AccessControl.RawAcl]::new($raw.DiscretionaryAcl.Revision, $proposal.Intent.Aces.Count)
    foreach ($entry in $proposal.Intent.Aces) {
        $flags = 0
        if ($entry.Inherited) { $flags = $flags -bor 16 }
        if ($entry.ContainerInherit) { $flags = $flags -bor 2 }
        if ($entry.ObjectInherit) { $flags = $flags -bor 1 }
        if ($entry.InheritOnly) { $flags = $flags -bor 8 }
        if ($entry.NoPropagate) { $flags = $flags -bor 4 }
        $qualifier = if ($entry.Type -ceq 'Allow') {
            [Security.AccessControl.AceQualifier]::AccessAllowed
        } else { [Security.AccessControl.AceQualifier]::AccessDenied }
        $ace = [Security.AccessControl.CommonAce]::new(
            [Security.AccessControl.AceFlags]$flags, $qualifier, [int]$entry.Mask,
            [Security.Principal.SecurityIdentifier]::new($entry.SID), $false, $null)
        $acl.InsertAce($acl.Count, $ace)
    }
    $raw.DiscretionaryAcl = $acl
    $desired = [pscustomobject]@{
        Path = $before.Path
        Kind = $before.Kind
        Identity = $before.Identity
        Descriptor = $raw.GetSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
    }
    return ConvertTo-NpLocalSnapshot -nativeSnapshot $desired
}

function New-NpLocalCandidatePlan {
    <#
    .SYNOPSIS
    Creates a non-public local candidate plan with exact preimages and desired states.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a read-only in-memory plan; no target writes.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $targetPath,
        [Parameter(Mandatory = $true)] $grants,
        [ValidateSet('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles')][string] $scope = 'ThisFolderSubfoldersAndFiles',
        [ValidateRange(1, 100000)][int] $maxPaths = 10000
    )
    $descriptor = Resolve-NpTarget -Path $targetPath -TargetPlatform Windows
    if ($descriptor.Addressing -cne 'LocalFixed' -or $descriptor.Platform -cne 'LocalWindows') {
        throw 'Candidate plans require direct local fixed NTFS, never SMB or mapped drives.'
    }
    Assert-NpNormalizedGrants $grants
    $inventory = @(Get-NpLocalInventory -targetPath $descriptor.CanonicalPath -maxPaths $maxPaths)
    $boundaries = @{}
    $entries = @(
        foreach ($before in $inventory) {
            $isRoot = $before.Path -ceq $descriptor.CanonicalPath
            $boundary = -not $isRoot -and ($before.Protected -or (Test-NpProtectedAncestor $before.Path $boundaries))
            if ($boundary) { $boundaries[$before.Path] = $true }
            $desired = if ($boundary -or (-not $isRoot -and $scope -ceq 'ThisFolderOnly')) {
                $before
            } else {
                New-NpLocalDesiredSnapshot -before $before -grants $grants -scope $scope -isRoot $isRoot
            }
            [pscustomobject][ordered]@{ Before = $before; Desired = $desired; Boundary = $boundary }
        }
    )
    return [pscustomobject][ordered]@{
        Schema = 'NtfsLocalCandidatePlan/1'
        SourceHash = Get-NpSourceHash
        CreatedUtc = [DateTime]::UtcNow.ToString('o')
        TargetDescriptor = $descriptor
        Scope = $scope
        MaxPaths = $maxPaths
        Grants = @($grants)
        Entries = $entries
        WriterQualification = 'NotQualified'
    }
}

function Assert-NpLocalCandidatePlan {
    <#
    .SYNOPSIS
    Rejects tampered, stale or nonlocal candidate plans before acquiring write handles.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $plan,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string] $planSHA256
    )
    Assert-NpProperties $plan @('Schema', 'SourceHash', 'CreatedUtc', 'TargetDescriptor', 'Scope', 'MaxPaths', 'Grants', 'Entries', 'WriterQualification')
    if ((Get-NtfsHash (Get-NpCanonicalJson $plan)) -ine $planSHA256 -or
        $plan.Schema -cne 'NtfsLocalCandidatePlan/1' -or $plan.SourceHash -cne (Get-NpSourceHash) -or
        $plan.WriterQualification -cne 'NotQualified') { throw 'Candidate plan hash/source/schema/qualification mismatch.' }
    $descriptor = $plan.TargetDescriptor
    Assert-NpTargetDescriptor $descriptor $descriptor.CanonicalPath
    Assert-NpExecutionHost $descriptor
    if ($descriptor.Addressing -cne 'LocalFixed' -or $descriptor.Platform -cne 'LocalWindows') {
        throw 'The candidate rejects nonlocal plans.'
    }
    $currentDescriptor = Resolve-NpTarget -Path $descriptor.CanonicalPath -TargetPlatform Windows
    if ((Get-NpCanonicalJson $currentDescriptor) -cne (Get-NpCanonicalJson $descriptor)) {
        throw 'Local volume/namespace binding changed.'
    }
    $created = [DateTimeOffset]::Parse($plan.CreatedUtc, [Globalization.CultureInfo]::InvariantCulture)
    if ($created -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or $created -lt [DateTimeOffset]::UtcNow.AddHours(-24)) {
        throw 'Candidate plan expired or future dated.'
    }
    if ($plan.Scope -cnotin @('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles') -or
        $plan.MaxPaths -lt 1 -or $plan.MaxPaths -gt 100000 -or
        @($plan.Entries).Count -eq 0 -or @($plan.Entries).Count -gt $plan.MaxPaths) {
        throw 'Invalid candidate scope or inventory bounds.'
    }
    Assert-NpNormalizedGrants $plan.Grants
    $paths = @{}
    $identities = @{}
    $boundaries = @{}
    foreach ($entry in $plan.Entries) {
        Assert-NpProperties $entry @('Before', 'Desired', 'Boundary')
        Assert-NpSnapshot $entry.Before
        Assert-NpSnapshot $entry.Desired
        $path = $entry.Before.Path
        $root = $path -ceq $descriptor.CanonicalPath
        if ((ConvertTo-NpPath $path) -cne $path -or $paths.ContainsKey($path) -or
            $identities.ContainsKey($entry.Before.Identity) -or
            (-not $root -and -not $path.StartsWith($descriptor.CanonicalPath + '\', [StringComparison]::OrdinalIgnoreCase)) -or
            $entry.Before.Identity -notmatch '^LocalNTFS:' -or $entry.Boundary -isnot [bool]) {
            throw 'Invalid candidate path or physical identity.'
        }
        if ($paths.Count -eq 0 -and (-not $root -or $entry.Before.Kind -cne 'Folder')) {
            throw 'Candidate root must be first and must be a directory.'
        }
        if (-not $root) {
            $parent = Split-Path -Parent $path
            if (-not $paths.ContainsKey($parent)) { throw 'Candidate namespace lacks a preceding parent.' }
        }
        $boundary = -not $root -and ($entry.Before.Protected -or (Test-NpProtectedAncestor $path $boundaries))
        if ($entry.Boundary -ne $boundary) { throw 'Candidate protected boundary mismatch.' }
        if ($boundary) { $boundaries[$path] = $true }
        $expected = if ($boundary -or (-not $root -and $plan.Scope -ceq 'ThisFolderOnly')) {
            $entry.Before
        } else {
            New-NpLocalDesiredSnapshot -before $entry.Before -grants $plan.Grants -scope $plan.Scope -isRoot $root
        }
        if ((Get-NpCanonicalJson $expected) -cne (Get-NpCanonicalJson $entry.Desired)) {
            throw 'Candidate desired descriptor reconstruction mismatch.'
        }
        $paths[$path] = $true
        $identities[$entry.Before.Identity] = $true
    }
}

function Assert-NpLocalNamespace {
    <#
    .SYNOPSIS
    Checks the complete observed namespace while approved handles remain pinned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $plan,
        [Parameter(Mandatory = $true)] $leases
    )
    $expected = @($plan.Entries | ForEach-Object { $_.Before.Path } | Sort-Object)
    $found = [Collections.Generic.List[string]]::new()
    $leaseMap = @{}
    foreach ($lease in $leases) { $leaseMap[$lease.Path] = $lease }
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($plan.TargetDescriptor.CanonicalPath)
    while ($queue.Count -gt 0) {
        $path = $queue.Dequeue()
        if ($found.Count -ge $plan.MaxPaths) { throw 'Namespace exceeded approved path limit.' }
        if (-not $leaseMap.ContainsKey($path)) { throw 'Namespace add/delete/rename drift.' }
        $lease = $leaseMap[$path]
        $found.Add($path)
        if ($lease.Read().Kind -ceq 'Folder') {
            foreach ($childPath in $lease.GetChildPaths($plan.MaxPaths)) {
                $queue.Enqueue($childPath)
            }
        }
    }
    if ((Get-NpCanonicalJson @($found.ToArray() | Sort-Object)) -cne (Get-NpCanonicalJson $expected)) {
        throw 'Namespace add/delete/rename drift.'
    }
}

function Invoke-NpLocalCandidate {
    <#
    .SYNOPSIS
    Runs the internal unqualified candidate with durable intent and exact guards.
    .DESCRIPTION
    Caller must independently authorize a disposable experiment and retain the
    reviewed plan. Revert requires a reviewed, complete successful Apply journal.
    Interrupted/failed writes are indeterminate: no retries or automatic rollback.
    This function is not called by public Apply/Revert and is not qualification.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)] $plan,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string] $planSHA256,
        [Parameter(Mandatory = $true)] $journal,
        [switch] $disposableAcknowledgement,
        [ValidateSet('Apply', 'Revert')][string] $mode = 'Apply',
        [string] $applyJournalPath,
        [string] $applyJournalSHA256
    )
    $leases = [Collections.Generic.List[object]]::new()
    $attempted = $false
    $targetLock = $null
    $runLock = $null
    $lockPath = ''
    $auditLease = $null
    $completed = $false
    try {
        if (-not $disposableAcknowledgement) { throw 'DisposableAcknowledgement is required for an independently approved local candidate experiment.' }
        Initialize-NpLocalNative
        $plan = (Get-NpCanonicalJson $plan) | ConvertFrom-NpJson
        Assert-NpLocalCandidatePlan -plan $plan -planSHA256 $planSHA256
        if ($journal.Mode -cne $mode -or $journal.PlanHash -ine $planSHA256 -or
            $journal.Target -cne $plan.TargetDescriptor.CanonicalPath -or
            $journal.SourceHash -cne $plan.SourceHash -or [string]::IsNullOrWhiteSpace($journal.Ticket) -or
            $journal.Ticket -match '[\x00-\x1f]' -or $journal.Sequence -ne 0 -or
            (Test-Path -LiteralPath $journal.Path)) {
            throw 'Candidate audit binding mismatch or missing ticket.'
        }
        $journalPath = ConvertTo-NpPath ([IO.Path]::GetFullPath($journal.Path))
        if ($journalPath.StartsWith('\\') -or $journalPath.StartsWith($journal.Target + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Candidate audit must be local and outside the target.'
        }
        $journalDirectory = Split-Path -Parent $journalPath
        # Require the same restrictive evidence ACL as New-NpRun and pin its namespace.
        $auditLease = [NtfsPermissions.LocalCandidate.Lease]::Open($journalDirectory, $false)
        $null = $auditLease.Read()
        $targetProbe = [NtfsPermissions.LocalCandidate.Lease]::Open($journal.Target, $false)
        try {
            if ($auditLease.PhysicalPath -ieq $targetProbe.PhysicalPath -or
                $auditLease.PhysicalPath.StartsWith($targetProbe.PhysicalPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Candidate audit storage overlaps the physical target namespace.'
            }
        } finally { $targetProbe.Dispose() }
        $acl = Get-Acl -LiteralPath $journalDirectory -ErrorAction Stop
        $actorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $actorSid -or
            $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -cne $actorSid -or
            $rules[0].IsInherited -or [int]$rules[0].FileSystemRights -ne 2032127 -or
            $rules[0].AccessControlType -ne 'Allow' -or [int]$rules[0].InheritanceFlags -ne 3 -or
            [int]$rules[0].PropagationFlags -ne 0) { throw 'Candidate requires a restrictive New-NpRun audit directory.' }
        $lockPath = Join-Path $journalDirectory 'candidate.lock'
        $runLock = [IO.FileStream]::new($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        Write-NpEvent $journal 'CandidatePreflight' 'NotQualified'
        if ($mode -ceq 'Apply' -and ($applyJournalPath -or $applyJournalSHA256)) {
            throw 'Apply cannot include recovery evidence.'
        }
        if ($mode -ceq 'Revert') {
            Assert-NpLocalApplyEvidence -plan $plan -planSHA256 $planSHA256 `
                -applyJournalPath $applyJournalPath -applyJournalSHA256 $applyJournalSHA256
        }
        if (-not $PSCmdlet.ShouldProcess($journal.Target, "$($mode) unqualified LOCAL disposable candidate")) {
            Write-NpEvent $journal 'CandidateComplete' 'WhatIfOrDeclined'
            $completed = $true
            return [pscustomobject]@{ Status = 'WhatIfOrDeclined'; WriterQualification = 'NotQualified'; Error = '' }
        }
        $targetLock = Enter-NpTargetLock $journal.Target
        $work = @(
            foreach ($entry in $plan.Entries) {
                $expected = if ($mode -ceq 'Apply') { $entry.Before } else { $entry.Desired }
                $desired = if ($mode -ceq 'Apply') { $entry.Desired } else { $entry.Before }
                $write = $expected.Descriptor -cne $desired.Descriptor
                $lease = [NtfsPermissions.LocalCandidate.Lease]::Open($entry.Before.Path, $write)
                $leases.Add($lease)
                $current = ConvertTo-NpLocalSnapshot -nativeSnapshot $lease.Read()
                $decision = if ($mode -ceq 'Revert') {
                    Get-NpRevertDecision $current $entry.Before $entry.Desired
                } elseif ((Get-NpCanonicalJson $current) -ceq (Get-NpCanonicalJson $expected)) {
                    $(if ($write) { 'Write' } else { 'NoOp' })
                } else { 'Conflict' }
                if ($decision -in @('Conflict', 'RevertConflict')) {
                    throw "Candidate pre-write identity/descriptor drift: $($entry.Before.Path)"
                }
                [pscustomobject]@{ Lease = $lease; Current = $current; Desired = $desired; Decision = $decision }
            }
        )
        Assert-NpLocalNamespace -plan $plan -leases $leases
        foreach ($step in $work) {
            if ((Get-NpCanonicalJson (ConvertTo-NpLocalSnapshot -nativeSnapshot $step.Lease.Read())) -cne
                (Get-NpCanonicalJson $step.Current)) { throw 'Concurrent descriptor drift before candidate write.' }
        }
        # Each directory lease uses zero sharing. Parent recovery cannot implicitly
        # propagate into descendants; any conflict above refuses the whole recovery.
        foreach ($step in $work) {
            if ($step.Decision -ceq 'NoOp') { continue }
            Assert-NpLocalNamespace -plan $plan -leases $leases
            Write-NpEvent $journal 'CandidateWriteIntent' 'Pending' @([ordered]@{
                Path = $step.Current.Path
                Identity = $step.Current.Identity
                BeforeDescriptor = $step.Current.Descriptor
                DesiredDescriptor = $step.Desired.Descriptor
            })
            $attempted = $true
            $after = $step.Lease.WriteDacl($step.Current.Descriptor, $step.Desired.Descriptor)
            $actual = ConvertTo-NpLocalSnapshot -nativeSnapshot $after
            if ((Get-NpCanonicalJson $actual) -cne (Get-NpCanonicalJson $step.Desired)) {
                throw 'Candidate full post-write verification mismatch.'
            }
            Write-NpEvent $journal 'CandidatePathVerified' 'Verified' @([ordered]@{
                Path = $actual.Path
                Identity = $actual.Identity
                Descriptor = $actual.Descriptor
            })
        }
        Assert-NpLocalNamespace -plan $plan -leases $leases
        foreach ($step in $work) {
            if ((Get-NpCanonicalJson (ConvertTo-NpLocalSnapshot -nativeSnapshot $step.Lease.Read())) -cne
                (Get-NpCanonicalJson $step.Desired)) { throw 'Candidate final per-path verification mismatch.' }
        }
        $status = if (@($work | Where-Object Decision -cne 'NoOp').Count -eq 0) { 'NoOp' } else { 'Verified' }
        Write-NpEvent $journal 'CandidateComplete' $status
        $completed = $true
        return [pscustomobject]@{ Status = $status; WriterQualification = 'NotQualified'; Error = '' }
    } catch {
        $failure = $_.Exception.Message
        $status = if ($attempted) { 'Indeterminate' } else { 'Blocked' }
        if ($null -ne $runLock) {
            try { Write-NpEvent $journal 'CandidateStopped' $status @($failure) }
            catch { $failure += '; AUDIT FAILURE: ' + $_.Exception.Message }
        }
        Write-Warning "Local candidate $($status): $($failure)"
        return [pscustomobject]@{ Status = $status; WriterQualification = 'NotQualified'; Error = $failure }
    } finally {
        for ($index = $leases.Count - 1; $index -ge 0; $index--) { $leases[$index].Dispose() }
        if ($null -ne $targetLock) { $targetLock.ReleaseMutex(); $targetLock.Dispose() }
        if ($null -ne $auditLease) { $auditLease.Dispose() }
        if ($null -ne $runLock) {
            $runLock.Dispose()
            if ($completed) { Remove-Item -LiteralPath $lockPath -WhatIf:$false -Confirm:$false -ErrorAction Stop }
        }
    }
}

function Assert-NpLocalApplyEvidence {
    <#
    .SYNOPSIS
    Requires exact reviewed successful candidate Apply evidence before recovery.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $plan,
        [Parameter(Mandatory = $true)][string] $planSHA256,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $applyJournalPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string] $applyJournalSHA256
    )
    $evidence = Read-NpJournal -Path $applyJournalPath
    if ($evidence.Status -cne 'Verified' -or $evidence.SHA256 -ine $applyJournalSHA256) {
        throw 'Candidate Apply evidence hash mismatch or indeterminate journal.'
    }
    foreach ($record in $evidence.Events) {
        if ($record.Mode -cne 'Apply' -or $record.PlanHash -ine $planSHA256 -or
            $record.SourceHash -cne $plan.SourceHash -or $record.Target -cne $plan.TargetDescriptor.CanonicalPath -or
            $record.Host -cne [Environment]::MachineName) { throw 'Candidate Apply evidence binding mismatch.' }
    }
    $last = $evidence.Events[-1]
    if ($last.Stage -cne 'CandidateComplete' -or $last.Result -cnotin @('Verified', 'NoOp') -or
        @($evidence.Events | Where-Object Stage -ceq 'CandidateStopped').Count -gt 0) {
        throw 'Candidate Apply did not complete; interrupted recovery requires independent review.'
    }
    $verified = @{}
    $intents = @{}
    foreach ($record in $evidence.Events) {
        if ($record.Stage -ceq 'CandidateWriteIntent') {
            if ($record.Changes.Count -ne 1) { throw 'Invalid candidate write intent evidence.' }
            $intent = $record.Changes[0]
            Assert-NpProperties $intent @('Path', 'Identity', 'BeforeDescriptor', 'DesiredDescriptor')
            $entry = @($plan.Entries | Where-Object { $_.Before.Path -ceq $intent.Path })
            if ($entry.Count -ne 1 -or $intents.ContainsKey($intent.Path) -or
                $intent.Identity -cne $entry[0].Before.Identity -or
                $intent.BeforeDescriptor -cne $entry[0].Before.Descriptor -or
                $intent.DesiredDescriptor -cne $entry[0].Desired.Descriptor) {
                throw 'Candidate write intent differs from approved exact states.'
            }
            $intents[$intent.Path] = $true
        } elseif ($record.Stage -ceq 'CandidatePathVerified') {
            if ($record.Changes.Count -ne 1) { throw 'Invalid candidate path verification evidence.' }
            $proof = $record.Changes[0]
            Assert-NpProperties $proof @('Path', 'Identity', 'Descriptor')
            $entry = @($plan.Entries | Where-Object { $_.Before.Path -ceq $proof.Path })
            if ($entry.Count -ne 1 -or -not $intents.ContainsKey($proof.Path) -or $verified.ContainsKey($proof.Path) -or
                $proof.Identity -cne $entry[0].Desired.Identity -or $proof.Descriptor -cne $entry[0].Desired.Descriptor) {
                throw 'Candidate path proof mismatch or missing preceding intent.'
            }
            $verified[$proof.Path] = $true
        }
    }
    foreach ($entry in $plan.Entries) {
        if ($entry.Before.Descriptor -cne $entry.Desired.Descriptor -and -not $verified.ContainsKey($entry.Before.Path)) {
            throw 'Missing candidate Apply per-path verification proof.'
        }
    }
}
