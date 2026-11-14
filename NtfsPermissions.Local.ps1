#requires -Version 5.1
<#
.SYNOPSIS
Internal, unqualified local-NTFS writer candidate and safety helpers.
.DESCRIPTION
Loaded publicly only by an explicit disposable-lab opt-in. Default public
Apply/Revert remain blocked. Requires Windows,
fixed local NTFS, and explicit READ_CONTROL/WRITE_DAC access; no elevation or
privilege changes are attempted. Native source is compiled with Add-Type.
Zero-share handles pin the observed objects but do not guarantee suppression of
implicit propagation, atomic namespace coverage, or exclusion of other administrator
ACL edits. Success here is verification, not platform or production qualification.
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

function Resolve-NpLocalRemoval {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $principal)

    if ([string]::IsNullOrWhiteSpace($principal) -or $principal -match '[\x00-\x1f]') {
        throw 'A removal principal without control characters is required.'
    }
    $sid = if ($principal -ieq 'Everyone') {
        'S-1-1-0'
    } elseif ($principal -match '^S-1-') {
        [Security.Principal.SecurityIdentifier]::new($principal).Value
    } else {
        Resolve-NpWindowsGroup $principal
    }
    return [pscustomobject][ordered]@{ Principal = $principal; SID = $sid.ToUpperInvariant() }
}

function Assert-NpLocalChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Add', 'Remove', 'Replace')][string] $operation,
        $removal,
        [AllowEmptyCollection()][object[]] $grants = @()
    )
    $grantCount = if ($null -eq $grants) { 0 } else { $grants.Count }
    if ($operation -eq 'Add') {
        if ($null -ne $removal) { throw 'Add cannot include a removal principal.' }
        Assert-NpNormalizedGrants $grants
        return
    }
    Assert-NpProperties $removal @('Principal', 'SID')
    if ($removal.Principal -isnot [string] -or [string]::IsNullOrWhiteSpace($removal.Principal) -or
        $removal.Principal -match '[\x00-\x1f]' -or $removal.SID -isnot [string] -or
        $removal.SID -cne ([Security.Principal.SecurityIdentifier]::new($removal.SID)).Value) {
        throw 'Invalid removal principal or SID.'
    }
    if ($operation -eq 'Remove') {
        if ($grantCount) { throw 'Remove cannot include replacement grants.' }
        return
    }
    Assert-NpNormalizedGrants $grants
    if (@($grants | Where-Object SID -ieq $removal.SID).Count) {
        throw 'The removal principal and replacement group must have different SIDs.'
    }
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
        [AllowEmptyCollection()][object[]] $grants = @(),
        [Parameter(Mandatory = $true)][ValidateSet('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles')][string] $scope,
        [Parameter(Mandatory = $true)][bool] $isRoot,
        [ValidateSet('Add', 'Remove', 'Replace')][string] $operation = 'Add',
        $removal
    )
    $working = $before
    $matching = @()
    if ($operation -ne 'Add') {
        $matching = @($before.Aces | Where-Object SID -ieq $removal.SID)
        if ($isRoot -and @($matching | Where-Object Inherited).Count) {
            $parent = Split-Path -Parent $before.Path
            throw "Removal principal has an inherited ACE at the target. Inspect parent $parent or its ancestors; inheritance is not changed."
        }
        if (@($matching | Where-Object Type -ceq 'Deny').Count) {
            throw "Removal principal has a deny ACE at $($before.Path); deny removal is not supported."
        }
        if ($isRoot -and $scope -ceq 'ThisFolderOnly' -and @($matching | Where-Object {
                $_.Type -ceq 'Allow' -and ($_.ContainerInherit -or $_.ObjectInherit)
            }).Count) {
            throw 'Folder-only removal cannot remove an inheritable ACE; use the recursive scope or review the ACE manually.'
        }
        $working = (Get-NpCanonicalJson $before) | ConvertFrom-NpJson
        $working.Aces = @($working.Aces | Where-Object {
            -not ($_.SID -ieq $removal.SID -and $_.Type -ceq 'Allow')
        })
    }
    $aces = @(
        if ($operation -ceq 'Remove') {
            $working.Aces
        } elseif ($operation -ceq 'Replace') {
            if ($matching.Count -gt 0) {
                $null = New-NpProposal $working $grants $scope $isRoot
                $existing = @{}
                foreach ($entry in $working.Aces) { $existing[(Get-NpCanonicalJson $entry)] = $true }
                foreach ($entry in $before.Aces) {
                    if ($entry.SID -ieq $removal.SID -and $entry.Type -ceq 'Allow') {
                        foreach ($grant in $grants) {
                            $replacement = [pscustomobject][ordered]@{
                                SID = $grant.SID; Type = 'Allow'; Mask = [long]$grant.Mask
                                Inherited = $entry.Inherited; ContainerInherit = $entry.ContainerInherit
                                ObjectInherit = $entry.ObjectInherit; InheritOnly = $entry.InheritOnly
                                NoPropagate = $entry.NoPropagate
                            }
                            $key = Get-NpCanonicalJson $replacement
                            if (-not $existing.ContainsKey($key)) {
                                $existing[$key] = $true
                                $replacement
                            }
                        }
                    } else { $entry }
                }
            } else { $working.Aces }
        } else {
            $proposal = New-NpProposal $working $grants $scope $isRoot
            $proposal.Intent.Aces
        }
    )
    if ($aces.Count -gt 1500) { throw 'Aggregate ACL size guard exceeded.' }
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($before.Descriptor)
    $acl = [Security.AccessControl.RawAcl]::new($raw.DiscretionaryAcl.Revision, $aces.Count)
    foreach ($entry in $aces) {
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
    if ($acl.BinaryLength -gt 60000) { throw 'Aggregate ACL size guard exceeded.' }
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

function Assert-NpLocalReplacementSource {
    [CmdletBinding()]
    param($entries, [string] $scope, $removal, $grants)

    $root = $entries[0].Before
    if (@($root.Aces | Where-Object { $_.SID -ieq $removal.SID -and $_.Type -ceq 'Allow' }).Count) {
        return
    }
    foreach ($entry in $entries) {
        $isRoot = $entry.Before.Path -ceq $root.Path
        if ($entry.Boundary -or (-not $isRoot -and $scope -ceq 'ThisFolderOnly')) { continue }
        if ($entry.Before.Descriptor -cne $entry.Desired.Descriptor -or
            -not (New-NpProposal $entry.Before $grants $scope $isRoot).NoOp) {
            throw 'Replacement source is absent at the target; no new grant or descendant change will be made.'
        }
    }
}

function Assert-NpLocalInheritanceSafety {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]] $entries)

    if (@($entries | Where-Object { $_.Before.Descriptor -cne $_.Desired.Descriptor }).Count -eq 0) { return }
    $autoInherited = [int][Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited
    foreach ($entry in $entries) {
        if (-not $entry.Boundary -and -not ([int]$entry.Before.Control -band $autoInherited)) {
            throw "DACL auto-inherited control is absent at $($entry.Before.Path); a write could change inheritance unexpectedly."
        }
    }
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
        [AllowEmptyCollection()][object[]] $grants = @(),
        [ValidateSet('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles')][string] $scope = 'ThisFolderSubfoldersAndFiles',
        [ValidateRange(1, 100000)][int] $maxPaths = 10000,
        [ValidateSet('Add', 'Remove', 'Replace')][string] $operation = 'Add',
        $removal
    )
    $operation = switch ($operation) { 'Add' { 'Add' } 'Remove' { 'Remove' } 'Replace' { 'Replace' } }
    if ($null -eq $grants) { $grants = @() }
    $descriptor = Resolve-NpTarget -Path $targetPath -TargetPlatform Windows
    if ($descriptor.Addressing -cne 'LocalFixed' -or $descriptor.Platform -cne 'LocalWindows') {
        throw 'Candidate plans require direct local fixed NTFS, never SMB or mapped drives.'
    }
    Assert-NpLocalChange -operation $operation -removal $removal -grants $grants
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
                New-NpLocalDesiredSnapshot -before $before -grants $grants -scope $scope -isRoot $isRoot `
                    -operation $operation -removal $removal
            }
            [pscustomobject][ordered]@{ Before = $before; Desired = $desired; Boundary = $boundary }
        }
    )
    if ($operation -ceq 'Replace') {
        Assert-NpLocalReplacementSource -entries $entries -scope $scope -removal $removal -grants $grants
    }
    Assert-NpLocalInheritanceSafety -entries $entries
    $plan = [ordered]@{
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
    if ($operation -cne 'Add') {
        $plan['Schema'] = 'NtfsLocalCandidatePlan/2'
        $plan['Operation'] = $operation
        $plan['Removal'] = $removal
    }
    return [pscustomobject]$plan
}

function Assert-NpLocalCandidatePlan {
    <#
    .SYNOPSIS
    Rejects tampered, stale or nonlocal candidate plans before acquiring write handles.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $plan,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string] $planSHA256,
        [switch] $allowExpiredForRecovery
    )
    $removal = $null
    if ($plan.Schema -ceq 'NtfsLocalCandidatePlan/1') {
        Assert-NpProperties $plan @('Schema', 'SourceHash', 'CreatedUtc', 'TargetDescriptor', 'Scope', 'MaxPaths', 'Grants', 'Entries', 'WriterQualification')
        $operation = 'Add'
    } elseif ($plan.Schema -ceq 'NtfsLocalCandidatePlan/2') {
        Assert-NpProperties $plan @('Schema', 'SourceHash', 'CreatedUtc', 'TargetDescriptor', 'Scope', 'MaxPaths', 'Grants', 'Entries', 'WriterQualification', 'Operation', 'Removal')
        if ($plan.Operation -cnotin @('Remove', 'Replace')) { throw 'Invalid candidate removal operation.' }
        $operation = $plan.Operation
        $removal = $plan.Removal
    } else { throw 'Candidate plan schema mismatch.' }
    if ((Get-NtfsHash (Get-NpCanonicalJson $plan)) -ine $planSHA256 -or
        $plan.SourceHash -cne (Get-NpSourceHash) -or
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
    if ($created -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or
        (-not $allowExpiredForRecovery -and $created -lt [DateTimeOffset]::UtcNow.AddHours(-24))) {
        throw 'Candidate plan expired or future dated.'
    }
    if ($plan.Scope -cnotin @('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles') -or
        $plan.MaxPaths -lt 1 -or $plan.MaxPaths -gt 100000 -or
        @($plan.Entries).Count -eq 0 -or @($plan.Entries).Count -gt $plan.MaxPaths) {
        throw 'Invalid candidate scope or inventory bounds.'
    }
    Assert-NpLocalChange -operation $operation -removal $removal -grants $plan.Grants
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
            New-NpLocalDesiredSnapshot -before $entry.Before -grants $plan.Grants -scope $plan.Scope -isRoot $root `
                -operation $operation -removal $removal
        }
        if ((Get-NpCanonicalJson $expected) -cne (Get-NpCanonicalJson $entry.Desired)) {
            throw 'Candidate desired descriptor reconstruction mismatch.'
        }
        $paths[$path] = $true
        $identities[$entry.Before.Identity] = $true
    }
    if ($operation -ceq 'Replace') {
        Assert-NpLocalReplacementSource -entries $plan.Entries -scope $plan.Scope -removal $removal -grants $plan.Grants
    }
    Assert-NpLocalInheritanceSafety -entries $plan.Entries
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
    Apply creates and persists its own plan in this invocation; it never accepts
    a previously prepared plan. Revert uses the saved plan and a reviewed Apply
    journal. Caller must independently authorize a disposable experiment.
    Interrupted/failed writes are indeterminate: no automatic retry or rollback.
    Explicit reviewed partial-Apply recovery can restore the original baseline
    before a fresh Apply attempt; it never resumes an incomplete Apply in place.
    The explicit disposable-lab entry point uses this candidate; it is not qualification.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        $plan,
        [string] $planSHA256,
        [Parameter(Mandatory = $true)] $journal,
        [switch] $disposableAcknowledgement,
        [ValidateSet('Apply', 'Revert')][string] $mode = 'Apply',
        [string] $applyJournalPath,
        [string] $applyJournalSHA256,
        [switch] $reviewedPartialApplyRecovery,
        [string] $applyTargetPath,
        [object[]] $applyGrants,
        [ValidateSet('Add', 'Remove', 'Replace')][string] $applyOperation = 'Add',
        $applyRemoval,
        [ValidateSet('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles')]
        [string] $applyScope = 'ThisFolderSubfoldersAndFiles',
        [ValidateRange(1, 100000)][int] $applyMaxPaths = 10000,
        $orchestration,
        [ref] $resultReference
    )
    $leases = [Collections.Generic.List[object]]::new()
    $attempted = $false
    $targetLock = $null
    $runLock = $null
    $lockPath = ''
    $auditLease = $null
    $partialApplyLock = $null
    $completed = $false
    $result = [pscustomobject]@{
        Status = 'Blocked'; WriterQualification = 'NotQualified'; Error = ''
        RecoveryRecordPath = ''; RecoveryRecordSHA256 = ''; ReceiptPath = ''; ReceiptSHA256 = ''
        AuditReportPath = ''; AuditReportSHA256 = ''; ExcludedPathCount = 0
    }
    if ($null -ne $resultReference) { $resultReference.Value = $result }
    try {
        if (-not $disposableAcknowledgement) { throw 'DisposableAcknowledgement is required for an independently approved local candidate experiment.' }
        if ($mode -ceq 'Apply') {
            if ($PSBoundParameters.ContainsKey('plan') -or $PSBoundParameters.ContainsKey('planSHA256')) {
                throw 'Apply cannot accept a prepared plan; it creates a fresh plan in this invocation.'
            }
            if ([string]::IsNullOrWhiteSpace($applyTargetPath) -or $null -eq $orchestration -or
                $journal.PlanHash -or $journal.Target -cne $applyTargetPath) {
                throw 'Apply requires a fresh target and unbound audit.'
            }
            Assert-NpLocalChange -operation $applyOperation -removal $applyRemoval -grants $applyGrants
            if ($applyJournalPath -or $applyJournalSHA256) { throw 'Apply cannot include recovery evidence.' }
            if ($reviewedPartialApplyRecovery) { throw 'ReviewedPartialApplyRecovery requires Revert mode.' }
        } else {
            foreach ($name in @('applyTargetPath', 'applyGrants', 'applyOperation', 'applyRemoval', 'applyScope', 'applyMaxPaths', 'orchestration')) {
                if ($PSBoundParameters.ContainsKey($name)) { throw "Revert cannot accept $name." }
            }
            if ($null -eq $plan -or $planSHA256 -notmatch '^[a-fA-F0-9]{64}$') {
                throw 'Revert requires its saved recovery plan and hash.'
            }
        }
        Initialize-NpLocalNative
        if ($mode -ceq 'Revert') {
            $plan = (Get-NpCanonicalJson $plan) | ConvertFrom-NpJson
            Assert-NpLocalCandidatePlan -plan $plan -planSHA256 $planSHA256 -allowExpiredForRecovery
        }
        if ($journal.Mode -cne $mode -or $journal.SourceHash -cne (Get-NpSourceHash) -or
            ($mode -ceq 'Revert' -and ($journal.PlanHash -ine $planSHA256 -or
                $journal.Target -cne $plan.TargetDescriptor.CanonicalPath -or $journal.SourceHash -cne $plan.SourceHash)) -or
            [string]::IsNullOrWhiteSpace($journal.Ticket) -or
            $journal.Ticket -match '[\x00-\x1f]' -or $journal.Sequence -ne 0 -or
            (Test-Path -LiteralPath $journal.Path)) {
            throw 'Candidate audit binding mismatch or missing ticket.'
        }
        $journalPath = ConvertTo-NpPath ([IO.Path]::GetFullPath($journal.Path))
        if ($journalPath.StartsWith('\\') -or $journalPath.StartsWith($journal.Target + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Candidate audit must be local and outside the target.'
        }
        $journalDirectory = Split-Path -Parent $journalPath
        if (([IO.DriveInfo]::new([IO.Path]::GetPathRoot($journalDirectory))).DriveType -ne [IO.DriveType]::Fixed) {
            throw 'Candidate audit must be on a fixed local volume.'
        }
        if ($mode -ceq 'Apply' -and
            ($journalPath -cne (Join-Path $journalDirectory 'events.jsonl') -or
                (ConvertTo-NpPath ([IO.Path]::GetFullPath($orchestration.Path))) -cne (Join-Path $journalDirectory 'orchestration.jsonl') -or
                $orchestration.Mode -cne 'Apply' -or $orchestration.Target -cne $journal.Target -or
                $orchestration.SourceHash -cne $journal.SourceHash -or
                $orchestration.Ticket -cne $journal.Ticket -or $orchestration.PlanHash)) {
            throw 'Apply orchestration audit binding mismatch.'
        }
        # Require the same restrictive evidence ACL as New-NpRun and pin its namespace.
        $auditLease = [NtfsPermissions.LocalCandidate.Lease]::OpenAuditDirectory($journalDirectory)
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
        if ($mode -ceq 'Apply') {
            $planParameters = @{
                targetPath = $applyTargetPath; grants = $applyGrants
                scope = $applyScope; maxPaths = $applyMaxPaths
            }
            if ($applyOperation -ne 'Add') {
                $planParameters.operation = $applyOperation
                $planParameters.removal = $applyRemoval
            }
            $plan = New-NpLocalCandidatePlan @planParameters
            $result.RecoveryRecordPath = Join-Path $journalDirectory 'candidate-plan.json'
            $planSHA256 = Write-NpLocalEvidenceFile $result.RecoveryRecordPath $plan
            $result.RecoveryRecordSHA256 = $planSHA256
            $plan = (Get-NpCanonicalJson $plan) | ConvertFrom-NpJson
            Assert-NpLocalCandidatePlan -plan $plan -planSHA256 $planSHA256
            $journal.PlanHash = $planSHA256
            $prepared = [ordered]@{
                Schema='NtfsDisposablePreparation/1'; SourceHash=$plan.SourceHash; Target=$journal.Target
                PlanPath=$result.RecoveryRecordPath; PlanSHA256=$planSHA256; JournalPath=$journalPath
            }
            $null = Write-NpLocalEvidenceFile (Join-Path $journalDirectory 'preparation.json') $prepared
            $result.ReceiptPath = Join-Path $journalDirectory 'receipt.json'
            $receiptData = [ordered]@{
                Schema='NtfsDisposableReceipt/2'; SourceHash=$plan.SourceHash; Target=$journal.Target
                PlanPath=$result.RecoveryRecordPath; PlanSHA256=$planSHA256; JournalPath=$journalPath
            }
            $result.ReceiptSHA256 = Write-NpLocalEvidenceFile $result.ReceiptPath $receiptData
            Write-NpEvent $orchestration 'RecoveryPrepared' 'Persisted' @([ordered]@{
                ReceiptPath=$result.ReceiptPath; ReceiptSHA256=$result.ReceiptSHA256; PlanSHA256=$planSHA256
            })
            Write-Information "Prewrite receipt: $($result.ReceiptPath); SHA256: $($result.ReceiptSHA256)" -InformationAction Continue
        }
        $result.ExcludedPathCount = @($plan.Entries | Where-Object Boundary).Count
        if ($mode -ceq 'Apply' -and $applyOperation -ne 'Add' -and $result.ExcludedPathCount) {
            Write-Warning "$($result.ExcludedPathCount) protected descendant paths are excluded and remain unchanged."
        }
        $lockPath = Join-Path $journalDirectory 'candidate.lock'
        $runLock = [IO.FileStream]::new($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        Write-NpEvent $journal 'CandidatePreflight' 'NotQualified'
        $partialIntents = $null
        if ($mode -ceq 'Revert') {
            if ($reviewedPartialApplyRecovery) {
                if ([string]::IsNullOrWhiteSpace($applyJournalPath)) { throw 'Partial Apply recovery requires the reviewed Apply journal.' }
                $sourceLockPath = Join-Path (Split-Path -Parent ([IO.Path]::GetFullPath($applyJournalPath))) 'candidate.lock'
                try {
                    $partialApplyLock = [IO.FileStream]::new($sourceLockPath, [IO.FileMode]::Open,
                        [IO.FileAccess]::Read, [IO.FileShare]::None)
                } catch [IO.IOException] {
                    throw "Cannot exclusively pin the preserved partial Apply lock; the source may still be active or unavailable: $($_.Exception.Message)"
                }
                $evidence = Get-NpLocalApplyEvidence -plan $plan -planSHA256 $planSHA256 `
                    -applyJournalPath $applyJournalPath -applyJournalSHA256 $applyJournalSHA256 -allowIncomplete
                if ($evidence.IsComplete) { throw 'Use ordinary Revert for complete Apply evidence.' }
                $partialIntents = $evidence.Intents
                Write-NpEvent $journal 'CandidatePartialApplyRecovery' 'Reviewed' @([ordered]@{
                    ApplyJournalPath = [IO.Path]::GetFullPath($applyJournalPath)
                    ApplyJournalSHA256 = $evidence.SHA256
                })
            } else {
                Assert-NpLocalApplyEvidence -plan $plan -planSHA256 $planSHA256 `
                    -applyJournalPath $applyJournalPath -applyJournalSHA256 $applyJournalSHA256
            }
        }
        if (-not $PSCmdlet.ShouldProcess($journal.Target, "$($mode) unqualified LOCAL disposable candidate")) {
            Write-NpEvent $journal 'CandidateComplete' 'WhatIfOrDeclined'
            $completed = $true
            $result.Status = 'WhatIfOrDeclined'
            return $result
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
                if ($reviewedPartialApplyRecovery -and $decision -ceq 'RestoreBefore' -and
                    -not $partialIntents.ContainsKey($entry.Before.Path)) {
                    throw "Partial Apply has no durable write intent for path: $($entry.Before.Path)"
                }
                [pscustomobject]@{
                    Lease = $lease; Current = $current; Desired = $desired; Decision = $decision
                    Boundary = $entry.Boundary; Verified = $null
                }
            }
        )
        Assert-NpLocalNamespace -plan $plan -leases $leases
        foreach ($step in $work) {
            if ((Get-NpCanonicalJson (ConvertTo-NpLocalSnapshot -nativeSnapshot $step.Lease.Read())) -cne
                (Get-NpCanonicalJson $step.Current)) { throw 'Concurrent descriptor drift before candidate write.' }
        }
        # Zero sharing is not a general guarantee against inherited ACL changes.
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
            $step.Verified = ConvertTo-NpLocalSnapshot -nativeSnapshot $step.Lease.Read()
            if ((Get-NpCanonicalJson $step.Verified) -cne (Get-NpCanonicalJson $step.Desired)) {
                throw 'Candidate final per-path verification mismatch.'
            }
        }
        $status = if (@($work | Where-Object Decision -cne 'NoOp').Count -eq 0) { 'NoOp' } else { 'Verified' }
        $auditReportPath = Join-Path $journalDirectory 'permissions-before-after.csv'
        $auditReportSHA256 = Write-NpLocalAuditReport -path $auditReportPath -work $work -plan $plan -journal $journal
        $result.AuditReportPath = $auditReportPath
        $result.AuditReportSHA256 = $auditReportSHA256
        Write-NpEvent $journal 'CandidateComplete' $status @([ordered]@{
            AuditReportPath = $result.AuditReportPath; AuditReportSHA256 = $result.AuditReportSHA256
        })
        $completed = $true
        $result.Status = $status
        return $result
    } catch {
        $failure = $_.Exception.Message
        $status = if ($attempted) { 'Indeterminate' } else { 'Blocked' }
        if ($null -ne $runLock) {
            try { Write-NpEvent $journal 'CandidateStopped' $status @($failure) }
            catch { $failure += '; AUDIT FAILURE: ' + $_.Exception.Message }
        }
        Write-Warning "Local candidate $($status): $($failure)"
        $result.Status = $status
        $result.Error = $failure
        return $result
    } finally {
        for ($index = $leases.Count - 1; $index -ge 0; $index--) { $leases[$index].Dispose() }
        if ($null -ne $targetLock) { $targetLock.ReleaseMutex(); $targetLock.Dispose() }
        if ($null -ne $auditLease) { $auditLease.Dispose() }
        if ($null -ne $partialApplyLock) { $partialApplyLock.Dispose() }
        if ($null -ne $runLock) {
            $runLock.Dispose()
            if ($completed) { Remove-Item -LiteralPath $lockPath -WhatIf:$false -Confirm:$false -ErrorAction Stop }
        }
    }
}

function Get-NpLocalApplyEvidence {
    <#
    .SYNOPSIS
    Validates exact Apply evidence; incomplete prefixes authorize only reviewed recovery.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $plan,
        [Parameter(Mandatory = $true)][string] $planSHA256,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $applyJournalPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string] $applyJournalSHA256,
        [switch] $allowIncomplete
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
    $complete = $last.Stage -ceq 'CandidateComplete' -and $last.Result -cin @('Verified', 'NoOp') -and
        @($evidence.Events | Where-Object Stage -ceq 'CandidateStopped').Count -eq 0
    if (-not $complete -and -not $allowIncomplete) {
        throw 'Candidate Apply did not complete; interrupted recovery requires independent review.'
    }
    if (-not $complete) {
        $stopped = @($evidence.Events | Where-Object Stage -ceq 'CandidateStopped')
        if (@($evidence.Events | Where-Object Stage -ceq 'CandidateComplete').Count -or
            @($evidence.Events | Where-Object {
                $_.Stage -cnotin @('CandidatePreflight', 'CandidateWriteIntent', 'CandidatePathVerified', 'CandidateStopped')
            }).Count -or $stopped.Count -gt 1 -or
            ($stopped.Count -eq 1 -and ($last.Stage -cne 'CandidateStopped' -or
                $last.Result -cnotin @('Blocked', 'Indeterminate')))) {
            throw 'Invalid incomplete candidate Apply event sequence.'
        }
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
        if ($complete -and $entry.Before.Descriptor -cne $entry.Desired.Descriptor -and
            -not $verified.ContainsKey($entry.Before.Path)) {
            throw 'Missing candidate Apply per-path verification proof.'
        }
    }
    return [pscustomobject]@{ IsComplete = $complete; Intents = $intents; SHA256 = $evidence.SHA256 }
}

function Assert-NpLocalApplyEvidence {
    <#
    .SYNOPSIS
    Requires exact reviewed successful candidate Apply evidence before ordinary recovery.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $plan,
        [Parameter(Mandatory = $true)][string] $planSHA256,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $applyJournalPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string] $applyJournalSHA256
    )
    $null = Get-NpLocalApplyEvidence -plan $plan -planSHA256 $planSHA256 `
        -applyJournalPath $applyJournalPath -applyJournalSHA256 $applyJournalSHA256
}

function Write-NpLocalEvidenceFile {
    param([string]$Path, $Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((Get-NpCanonicalJson $Value))
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    return Get-NpBytesHash $bytes
}

function Write-NpLocalAuditReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $path,
        [Parameter(Mandatory = $true)] $work,
        [Parameter(Mandatory = $true)] $plan,
        [Parameter(Mandatory = $true)] $journal
    )
    $verifiedUtc = [DateTime]::UtcNow.ToString('o')
    $operation = if ($plan.Schema -ceq 'NtfsLocalCandidatePlan/2') { $plan.Operation } else { 'Add' }
    $ticket = if ($journal.Ticket -match '^\s*[=+\-@]') { "'" + $journal.Ticket } else { $journal.Ticket }
    $pendingPath = $path + '.pending'
    $stream = [IO.FileStream]::new($pendingPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    $writer = $null
    try {
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($true), 16384, $true)
        $columns = $null
        foreach ($step in $work) {
            $scopeStatus = if ($step.Boundary) {
                'ProtectedBoundary'
            } elseif ($plan.Scope -ceq 'ThisFolderOnly' -and $step.Current.Path -cne $plan.TargetDescriptor.CanonicalPath) {
                'OutsideSelectedScope'
            } else { 'InScope' }
            $row = [pscustomobject][ordered]@{
                Path = $step.Current.Path; Kind = $step.Current.Kind; Scope = $scopeStatus
                OperationId = $journal.OperationId; Host = $journal.HostName
                Mode = $journal.Mode; Operation = $operation; Actor = $journal.Actor
                ChangeTicket = $ticket; VerifiedUtc = $verifiedUtc
                Result = $(if ($step.Decision -ceq 'NoOp') { 'Unchanged' } else { 'Changed' })
                BeforeDescriptor = $step.Current.Descriptor; AfterDescriptor = $step.Verified.Descriptor
                RemovedAces = Get-NpCanonicalJson @(Get-NpLocalAceDifference $step.Current.Aces $step.Verified.Aces)
                AddedAces = Get-NpCanonicalJson @(Get-NpLocalAceDifference $step.Verified.Aces $step.Current.Aces)
                BeforeAces = Get-NpCanonicalJson @($step.Current.Aces)
                AfterAces = Get-NpCanonicalJson @($step.Verified.Aces)
            }
            if ($null -eq $columns) {
                $columns = @($row.PSObject.Properties.Name)
                $writer.WriteLine((ConvertTo-NtfsCsvRecord $columns))
            }
            $writer.WriteLine((ConvertTo-NtfsCsvRecord @($columns | ForEach-Object { $row.$_ })))
        }
        if ($null -eq $columns) { throw 'Cannot write an audit report without verified paths.' }
        $writer.Flush()
        $stream.Flush($true)
        $stream.Position = 0
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    } finally {
        if ($null -ne $writer) { $writer.Dispose() }
        $stream.Dispose()
    }
    [IO.File]::Move($pendingPath, $path)
    return $hash
}

function Get-NpLocalAceDifference {
    [CmdletBinding()]
    param($left, $right)
    $counts = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::Ordinal)
    foreach ($ace in $right) {
        $key = Get-NpCanonicalJson $ace
        if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
    }
    foreach ($ace in $left) {
        $key = Get-NpCanonicalJson $ace
        if ($counts.ContainsKey($key) -and $counts[$key] -gt 0) {
            $counts[$key]--
        } else { $ace }
    }
}

function Invoke-NpDisposableLab {
    <#
    .SYNOPSIS
    Orchestrates the unqualified local candidate using automatically captured recovery evidence.
    #>
    [CmdletBinding()]
    param(
        [string]$Mode, [string]$TargetPath, [string]$TargetPlatform, [string]$GroupName,
        [string]$Permissions, [string]$GroupPermissionsJson, [string]$GroupPermissionsFile,
        [ValidateSet('Add', 'Remove', 'Replace')][string]$Operation = 'Add', [string]$RemovePrincipal,
        [string]$Scope, [string]$OutputDirectory, [string]$ChangeTicket, [int]$MaxPaths,
        [bool]$DisposableAcknowledgement, [string]$ReceiptPath, [string]$ReceiptSHA256, [string]$ReviewedApplyJournalSHA256,
        [bool]$ReviewedPartialApplyRecovery, [bool]$Preview, [string]$CallerConfirmPreference = 'High', $BoundParameters
    )
    # Evidence is deliberately created even under WhatIf; the candidate alone
    # receives the caller's ShouldProcess preferences for target ACL mutation.
    $WhatIfPreference = $false
    $ConfirmPreference = 'None'
    $run = ''
    $planPath = ''
    $planHash = ''
    $receiptFile = ''
    $receiptHash = ''
    $journalPath = ''
    $journalHash = ''
    $auditReportPath = ''
    $auditReportHash = ''
    $excludedPathCount = 0
    $effectiveOperation = switch ($Operation) { 'Add' { 'Add' } 'Remove' { 'Remove' } 'Replace' { 'Replace' } }
    $status = 'Blocked'
    $reason = ''
    $candidateInvoked = $false
    $candidateResult = $null
    $audit = $null
    try {
        if ($Mode -cnotin @('Apply','Revert')) { throw 'DisposableLocalLab is only available for Apply or Revert.' }
        if (-not $DisposableAcknowledgement -or [string]::IsNullOrWhiteSpace($ChangeTicket) -or $ChangeTicket -match '[\x00-\x1f]') {
            throw 'DisposableLocalLab requires DisposableAcknowledgement and a valid ChangeTicket.'
        }
        foreach ($name in @('PlanPath','PlanSHA256','RecoveryManifestPath','RecoveryJournalPath','RecoveryJournalSHA256','MaxPlanAgeHours')) {
            if ($BoundParameters.ContainsKey($name)) { throw "DisposableLocalLab does not accept $name." }
        }
        if ($Mode -ceq 'Apply') {
            if ($ReceiptPath -or $ReceiptSHA256 -or $ReviewedApplyJournalSHA256 -or $ReviewedPartialApplyRecovery) { throw 'Apply cannot accept recovery evidence.' }
            if ($effectiveOperation -ceq 'Add' -and ($RemovePrincipal -or $BoundParameters.ContainsKey('RemovePrincipal'))) {
                throw 'Add cannot include RemovePrincipal.'
            }
            if ($effectiveOperation -cne 'Add' -and [string]::IsNullOrWhiteSpace($RemovePrincipal)) {
                throw 'Remove and Replace require RemovePrincipal.'
            }
            if ($effectiveOperation -ceq 'Remove') {
                foreach ($name in @('GroupName', 'Permissions', 'GroupPermissionsJson', 'GroupPermissionsFile')) {
                    if ($BoundParameters.ContainsKey($name)) { throw "Remove cannot include $name." }
                }
                if ($GroupName -or $Permissions -or $GroupPermissionsJson -or $GroupPermissionsFile) {
                    throw 'Remove cannot include replacement grants.'
                }
            }
            if ($TargetPlatform -cnotin @('Auto','Windows')) { throw 'DisposableLocalLab rejects SMB and NAS platforms.' }
            $descriptor = Resolve-NpTarget -Path $TargetPath -TargetPlatform Windows
            if ($descriptor.Addressing -cne 'LocalFixed' -or $descriptor.Platform -cne 'LocalWindows') {
                throw 'DisposableLocalLab requires direct local fixed NTFS, not SMB or mapped drives.'
            }
            $target = $descriptor.CanonicalPath
        } else {
            foreach ($name in @('TargetPath','TargetPlatform','GroupName','Permissions','GroupPermissionsJson','GroupPermissionsFile','Operation','RemovePrincipal','Scope','MaxPaths')) {
                if ($BoundParameters.ContainsKey($name)) { throw "Revert takes its target and grants from the receipt, not $name." }
            }
            if (-not $ReceiptPath -or $ReceiptSHA256 -notmatch '^[a-fA-F0-9]{64}$' -or
                $ReviewedApplyJournalSHA256 -notmatch '^[a-fA-F0-9]{64}$') {
                throw 'Revert requires the Apply ReceiptPath, independently retained ReceiptSHA256 and reviewed Apply journal SHA256.'
            }
            $receiptFullPath = [IO.Path]::GetFullPath($ReceiptPath)
            if ($receiptFullPath.StartsWith('\\') -or ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($receiptFullPath))).DriveType -ne [IO.DriveType]::Fixed) {
                throw 'Receipt must be on a fixed local volume.'
            }
            if ((Get-Item -LiteralPath $receiptFullPath -ErrorAction Stop).Length -gt 1MB) { throw 'Receipt is too large.' }
            $receiptBytes = [IO.File]::ReadAllBytes($receiptFullPath)
            if ((Get-NpBytesHash $receiptBytes) -ine $ReceiptSHA256) { throw 'Receipt hash mismatch.' }
            $receipt = [Text.UTF8Encoding]::new($false,$true).GetString($receiptBytes) | ConvertFrom-NpJson
            Assert-NpProperties $receipt @('Schema','SourceHash','Target','PlanPath','PlanSHA256','JournalPath')
            if ($receipt.Schema -cne 'NtfsDisposableReceipt/2' -or $receipt.SourceHash -cne (Get-NpSourceHash) -or
                $receipt.PlanSHA256 -notmatch '^[a-fA-F0-9]{64}$') {
                throw 'Receipt schema, source or evidence hash mismatch.'
            }
            $sourceDirectory = Split-Path -Parent $receiptFullPath
            $planPath = Join-Path $sourceDirectory 'candidate-plan.json'
            $journalPath = Join-Path $sourceDirectory 'events.jsonl'
            if ($receipt.PlanPath -cne $planPath -or $receipt.JournalPath -cne $journalPath) { throw 'Receipt evidence paths do not match its own run directory.' }
            if ((Get-Item -LiteralPath $planPath -ErrorAction Stop).Length -gt 100000000) { throw 'Candidate recovery record is too large.' }
            $planBytes = [IO.File]::ReadAllBytes($planPath)
            $planHash = Get-NpBytesHash $planBytes
            if ($planHash -ine $receipt.PlanSHA256) { throw 'Candidate recovery record hash mismatch.' }
            $plan = [Text.UTF8Encoding]::new($false,$true).GetString($planBytes) | ConvertFrom-NpJson
            Assert-NpLocalCandidatePlan -plan $plan -planSHA256 $planHash -allowExpiredForRecovery
            if ($receipt.Target -cne $plan.TargetDescriptor.CanonicalPath) { throw 'Receipt target mismatch.' }
            $effectiveOperation = if ($plan.Schema -ceq 'NtfsLocalCandidatePlan/2') { $plan.Operation } else { 'Add' }
            $target = $receipt.Target
            $journalHash = $ReviewedApplyJournalSHA256
        }
        $run = New-NpRun -OutputDirectory $OutputDirectory -Target $target
        $audit = New-NpJournal $run $Mode $ChangeTicket $planHash $target
        $audit.Path = Join-Path $run 'orchestration.jsonl'
        Write-NpEvent $audit 'DisposableLabStart' 'NotQualified' @("WhatIf=$Preview; Operation=$effectiveOperation")
        if ($Mode -ceq 'Apply') {
            $removal = if ($effectiveOperation -cne 'Add') { Resolve-NpLocalRemoval $RemovePrincipal } else { $null }
            $grants = @()
            if ($effectiveOperation -cne 'Remove') {
                $grants = @(Get-NpGrants $GroupName $Permissions $GroupPermissionsJson $GroupPermissionsFile ${function:Resolve-NpWindowsGroup})
            }
            Assert-NpLocalChange -operation $effectiveOperation -removal $removal -grants $grants
            $journalPath = Join-Path $run 'events.jsonl'
        } else {
            $proof = Get-NpLocalApplyEvidence -plan $plan -planSHA256 $planHash `
                -applyJournalPath $journalPath -applyJournalSHA256 $journalHash -allowIncomplete
            if ($ReviewedPartialApplyRecovery -eq $proof.IsComplete) {
                throw 'Incomplete Apply requires explicit ReviewedPartialApplyRecovery; complete Apply must use ordinary Revert.'
            }
        }
        $journal = New-NpJournal $run $Mode $ChangeTicket $planHash $target
        $parameters = @{
            journal=$journal; disposableAcknowledgement=$true; mode=$Mode; WhatIf=$Preview
        }
        if ($BoundParameters.ContainsKey('Confirm')) { $parameters.Confirm = [bool]$BoundParameters['Confirm'] }
        $parameters.resultReference = [ref]$candidateResult
        if ($Mode -ceq 'Apply') {
            $parameters.applyTargetPath = $target
            $parameters.applyGrants = $grants
            $parameters.applyScope = $Scope
            $parameters.applyMaxPaths = $MaxPaths
            $parameters.orchestration = $audit
            if ($effectiveOperation -cne 'Add') {
                $parameters.applyOperation = $effectiveOperation
                $parameters.applyRemoval = $removal
            }
        } else {
            $parameters.plan = $plan
            $parameters.planSHA256 = $planHash
            $parameters.applyJournalPath = $journalPath
            $parameters.applyJournalSHA256 = $journalHash
            $parameters.reviewedPartialApplyRecovery = $ReviewedPartialApplyRecovery
        }
        $candidateInvoked = $true
        try {
            $ConfirmPreference = $CallerConfirmPreference
            $candidateResult = Invoke-NpLocalCandidate @parameters
        } finally {
            $ConfirmPreference = 'None'
            if ($null -ne $candidateResult) {
                $auditReportPath = $candidateResult.AuditReportPath
                $auditReportHash = $candidateResult.AuditReportSHA256
                $excludedPathCount = $candidateResult.ExcludedPathCount
                if ($Mode -ceq 'Apply') {
                    $planPath = $candidateResult.RecoveryRecordPath
                    $planHash = $candidateResult.RecoveryRecordSHA256
                    $receiptFile = $candidateResult.ReceiptPath
                    $receiptHash = $candidateResult.ReceiptSHA256
                }
            }
        }
        $status = $candidateResult.Status
        $reason = $candidateResult.Error
        if ($Mode -ceq 'Apply' -and (Test-Path -LiteralPath $journalPath)) {
            $journalHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($journalPath))
        }
        Write-NpEvent $audit 'DisposableLabComplete' $status @("ReceiptSHA256=$receiptHash; JournalSHA256=$journalHash")
    } catch {
        $reason = $_.Exception.Message
        $status = if ($candidateInvoked -and ($null -eq $candidateResult -or $candidateResult.Status -in @('Verified','Indeterminate'))) { 'Indeterminate' } else { 'Blocked' }
        if ($Mode -ceq 'Apply' -and $candidateInvoked -and $journalPath -and (Test-Path -LiteralPath $journalPath)) {
            try {
                $journalHash = Get-NpBytesHash ([IO.File]::ReadAllBytes($journalPath))
            } catch { $reason += '; JOURNAL HASH FAILURE: ' + $_.Exception.Message }
        }
        if ($null -ne $audit) {
            try { Write-NpEvent $audit 'DisposableLabStopped' $status @($reason) } catch { $reason += '; AUDIT FAILURE: ' + $_.Exception.Message }
        }
    }
    [pscustomobject]@{
        Mode=$Mode; Operation=$effectiveOperation; Status=$status; Reason=$reason; WriterQualification='NotQualified'
        RunDirectory=$run; ReceiptPath=$receiptFile; ReceiptSHA256=$receiptHash
        RecoveryRecordPath=$planPath; RecoveryRecordSHA256=$planHash
        ApplyJournalPath=$journalPath; ApplyJournalSHA256=$journalHash
        AuditReportPath=$auditReportPath; AuditReportSHA256=$auditReportHash; ExcludedPathCount=$excludedPathCount
        Limitation='Disposable local fixed NTFS only; not production qualified. Apply creates a fresh plan in the same run. Revert requires unchanged source and valid saved evidence; no automatic rollback.'
    }
}
