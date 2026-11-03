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

# Read-only evidence workflow, version 0.1.0. No native mutation adapter exists.
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'NtfsPermissions.Common.ps1')
$script:NvVersion = '0.1.0'
$script:NvStages = @('Initialize','CaptureBefore','CaptureAfterApply','CaptureAfterRevert','Report')

function Assert-NvWindows {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Windows read-only capture is required. Offline mocks cannot qualify a writer.'
    }
}

function Get-NvSources {
    $files = foreach ($name in @('Invoke-NtfsPermissionValidation.ps1','NtfsPermissions.Validation.ps1',
        'Add-FileSharePermissions.ps1','NtfsPermissions.Common.ps1','NtfsAssessment.Common.ps1')) {
        [pscustomobject][ordered]@{ Name=$name; SHA256=(Get-NpBytesHash ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name)))) }
    }
    return @($files)
}

function New-NvBinding($Descriptor, $Grants, [string]$Scope, [int]$MaxPaths, [string]$Ticket) {
    Assert-NpTargetDescriptor $Descriptor $Descriptor.CanonicalPath
    Assert-NpNormalizedGrants $Grants
    return [pscustomobject][ordered]@{
        Schema='NtfsPermissionValidation/1'; Version=$script:NvVersion
        CaseId=[guid]::NewGuid().ToString('N'); CreatedUtc=[DateTime]::UtcNow.ToString('o')
        ExecutionHost=[Environment]::MachineName; Actor=([Environment]::UserDomainName + '\' + [Environment]::UserName)
        ChangeTicket=$Ticket; DisposableAcknowledged=$true; TargetDescriptor=$Descriptor
        Grants=@($Grants); Scope=$Scope; MaxPaths=$MaxPaths; Sources=@(Get-NvSources)
        CaptureScope='ThisFolderSubfoldersAndFiles'; WriterQualification='NotQualified'
        Metadata=[ordered]@{
            OS=[Environment]::OSVersion.VersionString; PowerShell=$PSVersionTable.PSVersion.ToString()
            BackendConfiguration='NotAssessed'; SessionVolumeNasMetadata='NotAssessed'
            TargetAuthority='Unverified'; StableObjectIdentity='Unqualified'
            OperatorDeclarations=$null
        }
    }
}

function ConvertTo-NvOperatorMetadata([string]$Json) {
    if ([Text.Encoding]::UTF8.GetByteCount($Json) -gt 8192) { throw 'Operator metadata exceeds 8 KiB.' }
    $member='"(?<key>Session|Volume|Nas|Backend|SecurityStyle|Namespace|EvidenceStorage)"\s*:\s*"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[a-fA-F0-9]{4}))*"'
    $match=[regex]::Match($Json,('^\s*\{\s*'+$member+'(?:\s*,\s*'+$member+')*\s*\}\s*$'))
    $keys=@($match.Groups['key'].Captures | ForEach-Object Value)
    if (-not $match.Success -or $keys.Count -ne 7 -or @($keys | Select-Object -Unique).Count -ne 7) {
        throw 'Operator metadata requires exactly seven unique literal string fields.'
    }
    $value = $Json | ConvertFrom-NpJson
    Assert-NpProperties $value @('Session','Volume','Nas','Backend','SecurityStyle','Namespace','EvidenceStorage')
    foreach ($p in $value.PSObject.Properties) {
        if ($p.Value -isnot [string] -or $p.Value -match '[\x00-\x1f]') { throw 'Operator metadata fields must be single-line strings.' }
    }
    return [pscustomobject][ordered]@{ Status='OperatorDeclarationUnverified'; Values=$value }
}

function Write-NvNewJson([string]$Path, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((Get-NpCanonicalJson $Value))
    $pending = $Path + '.pending'
    $stream = [IO.FileStream]::new($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Move($pending,$Path)
}

function Read-NvJson([string]$Path) {
    if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 256MB) { throw 'Evidence JSON too large; preserve for manual review.' }
    return ([IO.File]::ReadAllText($Path) | ConvertFrom-NpJson)
}

function Get-NvFileHash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Assert-NvLocalCase([string]$CasePath) {
    if (-not [IO.Path]::IsPathRooted($CasePath) -or $CasePath.StartsWith('\\') -or $CasePath.StartsWith('//')) {
        throw 'CasePath must be an absolute trusted local directory.'
    }
    $node = Get-Item -LiteralPath $CasePath -Force -ErrorAction Stop
    if (-not $node.PSIsContainer) { throw 'CasePath must be a directory.' }
    while ($null -ne $node) {
        if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint -or
            ($node.PSObject.Properties.Name -contains 'LinkType' -and $node.LinkType)) { throw 'Linked/reparse evidence paths are forbidden.' }
        $node = $node.Parent
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($CasePath))
        if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'Case must remain on a fixed local volume.' }
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = Get-Acl -LiteralPath $CasePath -ErrorAction Stop
        $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or $rules.Count -ne 1 -or
            $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].IsInherited -or
            [int]$rules[0].InheritanceFlags -ne 3 -or [int]$rules[0].PropagationFlags -ne 0 -or
            $rules[0].AccessControlType -ne 'Allow' -or [int]$rules[0].FileSystemRights -ne 2032127) {
            throw 'Restrictive case ACL changed or is not owned by this operator.'
        }
    }
}

function Assert-NvBinding($Binding) {
    if ($Binding.Schema -cne 'NtfsPermissionValidation/1' -or $Binding.Version -cne $script:NvVersion -or
        $Binding.WriterQualification -cne 'NotQualified' -or $Binding.DisposableAcknowledged -ne $true -or
        $Binding.ExecutionHost -cne [Environment]::MachineName -or
        $Binding.Actor -cne ([Environment]::UserDomainName + '\' + [Environment]::UserName) -or
        [string]::IsNullOrWhiteSpace($Binding.ChangeTicket) -or $Binding.ChangeTicket -match '[\x00-\x1f]' -or
        $Binding.Scope -cnotin @('ThisFolderOnly','ThisFolderSubfoldersAndFiles') -or
        $Binding.CaptureScope -cne 'ThisFolderSubfoldersAndFiles' -or $Binding.MaxPaths -lt 1 -or $Binding.MaxPaths -gt 100000) {
        throw 'Invalid case or host/operator binding.'
    }
    Assert-NpTargetDescriptor $Binding.TargetDescriptor $Binding.TargetDescriptor.CanonicalPath
    Assert-NpExecutionHost $Binding.TargetDescriptor
    Assert-NpNormalizedGrants $Binding.Grants
    if ((Get-NpCanonicalJson @(Get-NvSources)) -cne (Get-NpCanonicalJson $Binding.Sources)) { throw 'Source hashes changed; start a new case after independent review.' }
}

function Get-NvKnownBackingPaths([string]$Target) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return @() }
    if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) { throw 'Cannot check known local SMB backing-path aliases.' }
    $parts=(ConvertTo-NpUnc $Target).Substring(2).Split('\')
    foreach ($share in @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -ieq $parts[1] -and $_.Path })) {
        $backing=[string]$share.Path
        for ($i=2; $i -lt $parts.Length; $i++) { $backing=$backing.TrimEnd('\') + '\' + $parts[$i] }
        $backing
    }
}

function Assert-NvEvidenceSeparation([string]$CasePath, $Descriptor) {
    $target=$Descriptor.CanonicalPath
    if (-not $target.StartsWith('\\')) {
        Assert-NtfsOutputOutsideScope $CasePath $target
    } else {
        foreach ($backing in @(Get-NvKnownBackingPaths $target)) {
            Assert-NtfsOutputOutsideScope $CasePath $backing
        }
    }
}

function Read-NvCase([string]$CasePath) {
    Assert-NvLocalCase $CasePath
    $commits = @(Get-ChildItem -LiteralPath $CasePath -Force -File | Where-Object Name -like '*.commit.json' | Sort-Object Name)
    if (-not $commits.Count -or $commits.Count -gt 5) { throw 'Invalid case: missing or excess commit records.' }
    $previous = '0' * 64
    $bindingHash = ''
    $binding = $null
    $allowed = @('.case.lock')
    $stages = @{}
    for ($i=0; $i -lt $commits.Count; $i++) {
        $commitFile = $commits[$i]
        if ($commitFile.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked commit record.' }
        $commit = Read-NvJson $commitFile.FullName
        Assert-NpProperties $commit @('Sequence','Stage','PreviousSHA256','BindingSHA256','ManifestSHA256')
        $stage = $commit.Stage
        if ($stage -cnotin $script:NvStages -or ($stage -cne 'Report' -and $stage -cne $script:NvStages[$i]) -or
            ($stage -ceq 'Report' -and $i -ne $commits.Count-1) -or
            $commitFile.Name -cne ('{0:d3}-{1}.commit.json' -f ($i+1),$stage) -or
            $commit.Sequence -ne $i+1 -or $commit.PreviousSHA256 -cne $previous) { throw 'Invalid stage order or commit chain.' }
        $directory = Join-Path $CasePath $stage
        $dirItem = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
        if ($dirItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked stage directory.' }
        $manifestPath = Join-Path $directory 'manifest.json'
        if ((Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Linked stage manifest.'
        }
        if ((Get-NvFileHash $manifestPath) -cne $commit.ManifestSHA256) { throw 'Stage manifest hash mismatch.' }
        $manifest = Read-NvJson $manifestPath
        Assert-NpProperties $manifest @('Schema','Stage','BindingSHA256','StartedUtc','CompletedUtc','Actor','Host','Files','Status','WhatIf','ManualActionAcknowledged')
        if ($manifest.Schema -cne 'NtfsPermissionValidationStage/1' -or $manifest.Stage -cne $stage -or
            $manifest.BindingSHA256 -cne $commit.BindingSHA256) { throw 'Invalid stage manifest binding.' }
        $names = @('manifest.json')
        foreach ($file in @($manifest.Files)) {
            Assert-NpProperties $file @('Name','SHA256')
            if ($file.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or $file.Name -in $names) { throw 'Invalid evidence filename.' }
            $names += $file.Name
            $path = Join-Path $directory $file.Name
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or $item.PSIsContainer -or
                (Get-NvFileHash $path) -cne $file.SHA256) { throw 'Evidence hash mismatch or linked file.' }
        }
        $required = switch ($stage) {
            Initialize { @('case.json','manual-matrix.json') }
            Report { @('report.json') }
            CaptureBefore { @('inventory.json','comparison.json','environment.json','intent-review.json') }
            default { @('inventory.json','comparison.json','environment.json') }
        }
        foreach ($name in $required) { if ($name -cnotin $names) { throw "Missing required evidence: $name" } }
        $actual = @(Get-ChildItem -LiteralPath $directory -Force)
        if ($actual.Count -ne $names.Count -or @($actual | Where-Object Name -cnotin $names).Count) { throw 'Unexpected/torn stage artifacts; preserve for review.' }
        if ($i -eq 0) {
            $binding = Read-NvJson (Join-Path $directory 'case.json')
            Assert-NvBinding $binding
            Assert-NvEvidenceSeparation $CasePath $binding.TargetDescriptor
            $bindingHash = Get-NvFileHash (Join-Path $directory 'case.json')
        }
        if ($commit.BindingSHA256 -cne $bindingHash -or $manifest.Actor -cne $binding.Actor -or
            $manifest.Host -cne $binding.ExecutionHost) { throw 'Case/target/platform/actor binding mismatch.' }
        $previous = Get-NvFileHash $commitFile.FullName
        $stages[$stage] = $manifest
        $allowed += @($stage,$commitFile.Name)
    }
    $rootItems = @(Get-ChildItem -LiteralPath $CasePath -Force)
    if (@($rootItems | Where-Object Name -cnotin $allowed).Count) { throw 'Uncommitted/torn case artifacts; preserve and review, never retry automatically.' }
    return [pscustomobject]@{ Binding=$binding; BindingHash=$bindingHash; PreviousHash=$previous; Count=$commits.Count; Stages=$stages }
}

function Get-NvManualMatrix($Binding=$null, [string]$BindingHash='') {
    $tests = @(
        'SingleGroup','MultipleGroups','ThisFolderOnly','ThisFolderSubfoldersAndFiles','NoOp',
        'ProtectedBoundaryAndUntraversedBranch','ApplicableDenies','UnreadablePaths','ReparsePoints','MaxPathsLimit',
        'WhatIfZeroTargetWrites','DeclinedConfirmationZeroTargetWrites','ConcurrentAdminDrift',
        'NamespaceAdd','NamespaceDelete','NamespaceRename','AuditFailureStopsBeforeWrite',
        'CrashDisconnectPartialApply','InterruptedRollback',
        'ParentRollbackMustNotModifyDriftRefusedDescendants',
        'TestAccountRead','TestAccountCreate','TestAccountModify','TestAccountDelete',
        'StableIdentityBoundHandles','ControlledInheritanceAndExclusiveHandleAvailability',
        'DirectBackendDfsAliasAndSecurityStyleProof'
    )
    return [ordered]@{
        Schema='NtfsPermissionValidationManualMatrix/1'
        CaseBindingSHA256=$BindingHash
        Instructions='Edit an EXTERNAL COPY only. Record approved actual commands/results, account/token, UTC timestamps, reviewer and exact source hashes/platform. Submit using Report -ManualObservationsFile. Commands/results are sealed text evidence, not proof of execution. EvidenceAttachments must remain empty; archive extra material independently. No destructive tests are run here. Observed is not certification; no writer exists.'
        AllowedStatuses=@('NotRun','Observed','Failed','NotAssessed')
        Cases=@($tests | ForEach-Object {
            [ordered]@{ Test=$_; Status='NotRun'; Command=''; ActualResult=''; Account=''; Utc=''
                SourceHashes=@($(if ($null -ne $Binding) { $Binding.Sources })); EvidenceAttachments=@()
                Platform=$(if ($null -ne $Binding) { $Binding.TargetDescriptor.Platform } else { '' }); Reviewer='' }
        })
    }
}

function Read-NvManualObservations([string]$Path, $State) {
    if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 1MB) { throw 'Manual observations exceed 1 MiB.' }
    $value = Read-NvJson $Path
    Assert-NpProperties $value @('Schema','CaseBindingSHA256','Instructions','AllowedStatuses','Cases')
    if ($value.Schema -cne 'NtfsPermissionValidationManualMatrix/1' -or
        $value.CaseBindingSHA256 -cne $State.BindingHash) { throw 'Manual observations case binding mismatch.' }
    $template=Get-NvManualMatrix $State.Binding $State.BindingHash
    if (@($value.Cases).Count -ne $template.Cases.Count -or
        (Get-NpCanonicalJson $value.AllowedStatuses) -cne (Get-NpCanonicalJson $template.AllowedStatuses)) {
        throw 'Manual observations must retain the full matrix and allowed statuses.'
    }
    $seen=@{}
    foreach ($item in @($value.Cases)) {
        Assert-NpProperties $item @('Test','Status','Command','ActualResult','Account','Utc','SourceHashes','EvidenceAttachments','Platform','Reviewer')
        foreach ($name in @('Test','Status','Command','ActualResult','Account','Utc','Platform','Reviewer')) {
            if ($item.$name -isnot [string] -or $item.$name -match '[\x00-\x08\x0b\x0c\x0e-\x1f]') { throw 'Invalid manual observation text.' }
        }
        if ($item.Test -cnotin @($template.Cases | ForEach-Object { $_.Test }) -or $seen.ContainsKey($item.Test) -or
            $item.Status -cnotin $template.AllowedStatuses -or
            $item.Platform -cne $State.Binding.TargetDescriptor.Platform -or
            (Get-NpCanonicalJson $item.SourceHashes) -cne (Get-NpCanonicalJson $State.Binding.Sources) -or
            @($item.EvidenceAttachments).Count) { throw 'Manual observations test/source/platform binding mismatch; attachments are external, not imported.' }
        $seen[$item.Test]=$true
        if ($item.Status -cin @('Observed','Failed')) {
            foreach ($name in @('Command','ActualResult','Account','Utc','Reviewer')) {
                if ([string]::IsNullOrWhiteSpace($item.$name)) { throw "Actual command/result/account/UTC/reviewer evidence required: $($item.Test)" }
            }
            $utc=[DateTimeOffset]::Parse($item.Utc,[Globalization.CultureInfo]::InvariantCulture)
            if ($item.Utc -notmatch '(?:Z|\+00:00)$' -or $utc -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or
                $utc -lt [DateTimeOffset]::Parse($State.Binding.CreatedUtc,[Globalization.CultureInfo]::InvariantCulture)) {
                throw 'Manual observation UTC must be within this case lifetime.'
            }
        }
    }
    return $value
}

function Get-NvEnvironment($Binding) {
    Assert-NpExecutionHost $Binding.TargetDescriptor
    $volume = $null
    if ($Binding.TargetDescriptor.Addressing -ceq 'LocalFixed') {
        # Verify the canonical local volume, never resolve the original mapped path again.
        $current = Get-NpDriveBinding $Binding.TargetDescriptor.CanonicalPath.Substring(0,2)
        if ($current.Kind -cne 'Fixed' -or $current.HostName -cne $Binding.TargetDescriptor.LocalHost -or
            (Get-NpCanonicalJson $current.Observation) -cne (Get-NpCanonicalJson $Binding.TargetDescriptor.VolumeObservation)) {
            throw 'Local volume namespace drift detected.'
        }
        $volume = $current.Observation
    }
    return [ordered]@{
        Host=[Environment]::MachineName; Actor=([Environment]::UserDomainName + '\' + [Environment]::UserName)
        OS=[Environment]::OSVersion.VersionString; PowerShell=$PSVersionTable.PSVersion.ToString()
        CanonicalTarget=$Binding.TargetDescriptor.CanonicalPath; Platform=$Binding.TargetDescriptor.Platform
        LocalVolume=$volume; BackendProof='Unverified'; SecurityStyleProof='Unverified'
        StableIdentity='Unqualified'; TargetAuthority='Unverified'; SMBSessionConfiguration='NotAssessed'
    }
}

function ConvertTo-NvCapturedSnapshot($Snapshot) {
    # Get-Acl without -Audit does not establish a SACL. Seal only explicitly read sections.
    $copy=Get-NpCanonicalJson $Snapshot | ConvertFrom-NpJson
    $raw=[Security.AccessControl.RawSecurityDescriptor]::new($copy.Descriptor)
    if ($raw.Owner.Value -cne $copy.Owner -or $raw.Group.Value -cne $copy.Group) { throw 'Descriptor owner/group fidelity mismatch.' }
    $sections=[Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access
    $copy.Descriptor=$raw.GetSddlForm($sections)
    return $copy
}

function Get-NvInventoryObservation($Binding) {
    Assert-NvWindows
    $started=[DateTime]::UtcNow.ToString('o')
    $inventory = Get-NpWindowsInventory $Binding.TargetDescriptor.CanonicalPath ThisFolderSubfoldersAndFiles $Binding.MaxPaths
    $completed=[DateTime]::UtcNow.ToString('o')
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($e in @($inventory.Errors)) { $errors.Add([string]$e) }
    $map = @{}
    $target = $Binding.TargetDescriptor.CanonicalPath
    $boundaries = @{}
    foreach ($p in @($inventory.Boundaries)) { $boundaries[[string]$p] = $true }
    $snapshots=[Collections.Generic.List[object]]::new()
    foreach ($original in @($inventory.Snapshots)) {
        $s=$original
        try {
            Assert-NpSnapshot $s
            $s=ConvertTo-NvCapturedSnapshot $s
            if ((ConvertTo-NpPath $s.Path) -cne $s.Path -or $map.ContainsKey($s.Path) -or
                ($s.Path -ine $target -and -not $s.Path.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)) -or
                (Test-NpProtectedAncestor $s.Path $boundaries)) { throw 'Invalid path, duplicate or traversed protected boundary.' }
            $map[$s.Path] = $s
            if ($s.Path -ieq $target -and $s.Kind -cne 'Folder') { throw 'Root must be a folder.' }
            if ($s.Path -ine $target -and $s.Protected -ne $boundaries.ContainsKey($s.Path)) { throw 'Protected boundary inventory mismatch.' }
        } catch { $errors.Add($_.Exception.Message) }
        $snapshots.Add($s)
    }
    if (-not $map.ContainsKey($target)) { $errors.Add('Root preimage missing.') }
    foreach ($p in $boundaries.Keys) { if (-not $map.ContainsKey($p)) { $errors.Add("Boundary preimage missing: $p") } }
    if (@($inventory.Snapshots).Count -gt $Binding.MaxPaths) { $errors.Add('MaxPaths exceeded.') }
    return [pscustomobject][ordered]@{
        Status=$(if ($errors.Count) { 'Incomplete' } else { 'Observed' })
        StartedUtc=$started; CompletedUtc=$completed
        DescriptorSections='OwnerGroupDacl'; Sacl='NotAssessed'
        CaptureScope='ThisFolderSubfoldersAndFiles'; Snapshots=@($snapshots.ToArray())
        Boundaries=@($inventory.Boundaries); Errors=@($errors.ToArray())
        NamespaceCoverage='CapturedPathsExcludingProtectedBranchContents'
        IdentityQualification='Unqualified'; AtomicSnapshot=$false
    }
}

function Get-NvCapture($Binding) {
    $first=Get-NvInventoryObservation $Binding
    $second=Get-NvInventoryObservation $Binding
    $errors=@($first.Errors)+@($second.Errors)
    $churn=$false
    if ($first.Status -ceq 'Observed' -and $second.Status -ceq 'Observed') {
        $a=@($first.Snapshots | Sort-Object Path)
        $b=@($second.Snapshots | Sort-Object Path)
        $churn=(Get-NpCanonicalJson $a) -cne (Get-NpCanonicalJson $b) -or
            (Get-NpCanonicalJson @($first.Boundaries | Sort-Object)) -cne (Get-NpCanonicalJson @($second.Boundaries | Sort-Object))
        if ($churn) { $errors+= 'Churn observed during the capture interval; observations cannot establish convergence.' }
    }
    $first.Status=if ($errors.Count) { 'Incomplete' } else { 'Observed' }
    $first.Errors=@($errors)
    $first | Add-Member -NotePropertyName VerificationObservation -NotePropertyValue $second
    $first | Add-Member -NotePropertyName Stability -NotePropertyValue $(
        if ($churn) { 'ChurnObserved' } elseif ($errors.Count) { 'NotAssessed' } else { 'MatchingTwoObservationsOnlyNotAtomic' })
    return $first
}

function Get-NvUnrelatedAcl($Before, $After, $Grants) {
    try {
        $sids = @($Grants | ForEach-Object SID)
        $filtered = foreach ($s in @($Before,$After)) {
            $raw = [Security.AccessControl.RawSecurityDescriptor]::new($s.Descriptor)
            $parts = @()
            foreach ($ace in $raw.DiscretionaryAcl) {
                if ($ace -is [Security.AccessControl.CommonAce] -and
                    $ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
                    $ace.SecurityIdentifier.Value -in $sids) { continue }
                $bytes = New-Object byte[] $ace.BinaryLength
                $ace.GetBinaryForm($bytes,0)
                $parts += [Convert]::ToBase64String($bytes)
            }
            # Ordered raw ACE bytes, including denies and opaque ACEs; never reorder.
            Get-NpCanonicalJson $parts
        }
        if ($filtered[0] -ceq $filtered[1]) { return 'ObservedUnchanged' }
        return 'Failed'
    } catch { return 'NotAssessed' }
}

function Compare-NvCapture($Before, $Current, $Binding, [string]$Mode) {
    $base = [ordered]@{
        Status='Incomplete'; Mode=$Mode; Namespace='NotAssessed'; DescriptorResult='NotAssessed'
        ExpectedPostPropagationDescriptor='NotAssessed'; EffectiveAccess='NotAssessed'
        DescriptorSections='OwnerGroupDacl'; SaclEquality='NotAssessed'; AtomicConvergence='NotAssessed'
        StableIdentity='Unqualified'; PhysicalReversionProof='NotAssessed'
        ProtectedBranchContents='NotAssessed'; Rows=@(); Added=@(); Missing=@()
    }
    if ($Before.Status -cne 'Observed' -or $Current.Status -cne 'Observed') { return [pscustomobject]$base }
    foreach ($capture in @($Before,$Current)) {
        if ($capture.PSObject.Properties.Name -cnotcontains 'DescriptorSections' -or
            $capture.DescriptorSections -cne 'OwnerGroupDacl') { return [pscustomobject]$base }
    }
    $a = @{}; $b = @{}
    foreach ($s in @($Before.Snapshots)) { $a[$s.Path] = $s }
    foreach ($s in @($Current.Snapshots)) { $b[$s.Path] = $s }
    $base.Added = @($b.Keys | Where-Object { -not $a.ContainsKey($_) } | Sort-Object)
    $base.Missing = @($a.Keys | Where-Object { -not $b.ContainsKey($_) } | Sort-Object)
    $base.Namespace = if ($base.Added.Count -or $base.Missing.Count -or
        (Get-NpCanonicalJson @($Before.Boundaries | Sort-Object)) -cne (Get-NpCanonicalJson @($Current.Boundaries | Sort-Object))) { 'DriftObserved' } else { 'ObservedSameCapturedPaths' }
    $changed = 0; $failed = 0; $notAssessed = 0
    $rows = foreach ($path in @($a.Keys | Sort-Object)) {
        if (-not $b.ContainsKey($path)) { continue }
        $x=$a[$path]; $y=$b[$path]
        $equal = $x.Descriptor -ceq $y.Descriptor
        if (-not $equal) { $changed++ }
        $metadata = $x.Owner -ceq $y.Owner -and $x.Group -ceq $y.Group -and
            $x.Control -eq $y.Control -and $x.Protected -eq $y.Protected -and $x.Kind -ceq $y.Kind
        $identity = $x.Identity -ceq $y.Identity
        $boundary = $path -in @($Before.Boundaries)
        $unaffected = $boundary -or ($Binding.Scope -ceq 'ThisFolderOnly' -and $path -ine $Binding.TargetDescriptor.CanonicalPath)
        $grant = 'NotAssessed'; $unrelated = 'NotAssessed'
        $rowFailed = -not $metadata -or -not $identity
        if ($Mode -ceq 'Revert' -or $unaffected) {
            if (-not $equal) { $rowFailed = $true }
        } else {
            try {
                $proposal = New-NpProposal $y $Binding.Grants $Binding.Scope ($path -ieq $Binding.TargetDescriptor.CanonicalPath)
                $grant = if ($proposal.NoOp) { 'ObservedAllowCoverageOnly' } else { 'Failed' }
            } catch { $grant = 'Failed' }
            $unrelated = if ($equal) { 'ObservedUnchanged' } else { Get-NvUnrelatedAcl $x $y $Binding.Grants }
            if ($grant -ceq 'Failed' -or $unrelated -ceq 'Failed') { $rowFailed = $true }
            if ($unrelated -ceq 'NotAssessed') { $notAssessed++ }
        }
        if ($rowFailed) { $failed++ }
        [pscustomobject][ordered]@{
            Path=$path; DescriptorExactMatch=$equal; MetadataUnchanged=$metadata
            DescriptorSections='OwnerGroupDacl'; SaclEquality='NotAssessed'
            ObservationalIdentityUnchanged=$identity; ProtectedBoundary=$boundary
            UnaffectedPathExpected=$unaffected; ObservedGrant=$grant; UnrelatedRawAcl=$unrelated
            Status=$(if ($rowFailed) { 'Failed' } else { 'Observed' })
        }
    }
    $base.Rows = @($rows)
    if ($base.Namespace -ceq 'DriftObserved' -or $failed) {
        $base.Status='Failed'
        $base.DescriptorResult=if (-not $changed -and $base.Namespace -cne 'DriftObserved') { 'NoChangeObserved' } else { 'DriftObserved' }
    } elseif ($Mode -ceq 'Revert') {
        $base.Status='Observed'; $base.DescriptorResult='ExactCapturedDescriptorsObservedOnly'
    } elseif (-not $changed) {
        $base.Status='Observed'; $base.DescriptorResult='NoChangeObserved'
    } else {
        $base.Status=if ($notAssessed) { 'NotAssessed' } else { 'Observed' }
        $base.DescriptorResult='ChangedDescriptorsObservedNotExpectedDescriptorVerified'
    }
    return [pscustomobject]$base
}

function New-NvReport([string]$CasePath, $State, $Observations=$null) {
    $missing = @(@('CaptureBefore','CaptureAfterApply','CaptureAfterRevert') | Where-Object { -not $State.Stages.ContainsKey($_) })
    $comparisons = [ordered]@{}
    $status = if ($missing.Count) { 'Incomplete' } else { 'Observed' }
    foreach ($stage in @('CaptureBefore','CaptureAfterApply','CaptureAfterRevert')) {
        if ($State.Stages.ContainsKey($stage)) {
            $capture = Read-NvJson (Join-Path (Join-Path $CasePath $stage) 'inventory.json')
            if ($capture.Status -cne 'Observed') { $status='Incomplete' }
        }
    }
    if ($State.Stages.ContainsKey('CaptureBefore')) {
        $intentReview=Read-NvJson (Join-Path $CasePath 'CaptureBefore/intent-review.json')
        if ($status -cne 'Incomplete' -and @($intentReview.Entries | Where-Object Status -ceq 'Failed').Count) { $status='Failed' }
        $before = Read-NvJson (Join-Path $CasePath 'CaptureBefore/inventory.json')
        foreach ($pair in @(@('CaptureAfterApply','Apply'),@('CaptureAfterRevert','Revert'))) {
            if ($State.Stages.ContainsKey($pair[0])) {
                $current = Read-NvJson (Join-Path (Join-Path $CasePath $pair[0]) 'inventory.json')
                $comparison = Compare-NvCapture $before $current $State.Binding $pair[1]
                $comparisons[$pair[1]] = $comparison
                if ($status -cne 'Incomplete' -and $comparison.Status -ceq 'Failed') { $status='Failed' }
                if ($status -ceq 'Observed' -and $comparison.Status -ceq 'NotAssessed') { $status='NotAssessed' }
            }
        }
    }
    $manualStatus='NotRun'; $functional='NotAssessed'
    if ($null -ne $Observations) {
        $submitted=@($Observations.Cases | Where-Object Status -cne 'NotRun')
        $manualStatus=if (@($submitted | Where-Object Status -ceq 'Failed').Count) { 'Failed' } elseif ($submitted.Count) { 'Observed' } else { 'NotRun' }
        $access=@($Observations.Cases | Where-Object { $_.Test -clike 'TestAccount*' })
        if (@($access | Where-Object Status -ceq 'Failed').Count) { $functional='Failed' }
        elseif (@($access | Where-Object Status -ceq 'Observed').Count -eq 4) { $functional='Observed' }
        if ($manualStatus -ceq 'Failed' -and $status -cne 'Incomplete') { $status='Failed' }
    }
    return [ordered]@{
        Schema='NtfsPermissionValidationReport/1'; Status=$status; MissingStages=$missing
        WriterQualification='NotQualified'; NativeWriter='Absent'; TargetWrites=0
        CaseBindingSHA256=$State.BindingHash; TargetDescriptor=$State.Binding.TargetDescriptor
        IndependentComparison=$comparisons; ManualMatrixStatus=$manualStatus; FunctionalAccess=$functional
        ManualEvidenceAuthority='OperatorSubmittedNotIndependentlyVerified'
        ExpectedPostPropagationDescriptors='NotAssessed'; PhysicalIdentityProof='Unqualified'
        Limits=@('Observational non-atomic snapshots only; hash consistency is not authenticity.',
            'Protected branch contents untraversed; SACL and effective access not assessed.',
            'No stable object, backend, DFS, target-authority or infrastructure proof.',
            'No propagation, crash, concurrency, guarded rollback or writer qualification.',
            'Unchanged descriptors are not change success. Missing preimages never imply safe revert.',
            'No Windows results qualify Windows SMB, NetApp SMB or generic SMB independently.')
    }
}

function Invoke-NvStage {
    param([string]$CasePath, [string]$Stage, $Binding=$null, [bool]$ManualAcknowledged=$false, [bool]$WhatIfRecorded=$false,
        [string]$ManualObservationsFile='')
    Assert-NvWindows
    if ($Stage -cnotin $script:NvStages) { throw 'Unknown validation stage.' }
    Assert-NvLocalCase $CasePath
    $lockPath = Join-Path $CasePath '.case.lock'
    $lock = [IO.FileStream]::new($lockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    $clean = $false
    try {
        $started = [DateTime]::UtcNow.ToString('o')
        if ($Stage -ceq 'Initialize') {
            if (@(Get-ChildItem -LiteralPath $CasePath -Force | Where-Object Name -cne '.case.lock').Count) { throw 'Initialize requires an empty NEW case.' }
            Assert-NvBinding $Binding
            Assert-NvEvidenceSeparation $CasePath $Binding.TargetDescriptor
            $state = [pscustomobject]@{ Count=0; PreviousHash=('0'*64); Binding=$Binding; BindingHash=''; Stages=@{} }
        } else {
            if ($null -ne $Binding) { throw 'Binding overrides are forbidden on resume.' }
            $state = Read-NvCase $CasePath
            $Binding = $state.Binding
            if ($state.Stages.ContainsKey('Report') -or $state.Stages.ContainsKey($Stage) -or
                ($Stage -cne 'Report' -and $Stage -cne $script:NvStages[$state.Count])) { throw 'Stage out of order or immutable stage already exists.' }
            if ($Stage -in @('CaptureAfterApply','CaptureAfterRevert') -and -not $ManualAcknowledged) { throw 'External manual-action acknowledgement required.' }
        }
        if ($ManualObservationsFile -and $Stage -cne 'Report') { throw 'Manual observations are Report-only.' }
        $observations=if ($ManualObservationsFile) { Read-NvManualObservations $ManualObservationsFile $state } else { $null }
        $directory = Join-Path $CasePath $Stage
        # Reserving a stage is irreversible: exceptions leave evidence and lock for review.
        if (Test-Path -LiteralPath $directory) { throw 'Immutable stage already exists.' }
        [void][IO.Directory]::CreateDirectory($directory)
        $status = 'Observed'
        if ($Stage -ceq 'Initialize') {
            Write-NvNewJson (Join-Path $directory 'case.json') $Binding
            $state.BindingHash = Get-NvFileHash (Join-Path $directory 'case.json')
            Write-NvNewJson (Join-Path $directory 'manual-matrix.json') (Get-NvManualMatrix $Binding $state.BindingHash)
        } elseif ($Stage -ceq 'Report') {
            if ($null -ne $observations) { Write-NvNewJson (Join-Path $directory 'manual-observations.json') $observations }
            $report = New-NvReport $CasePath $state $observations
            $status = $report.Status
            Write-NvNewJson (Join-Path $directory 'report.json') $report
        } else {
            Write-NvNewJson (Join-Path $directory 'environment.json') (Get-NvEnvironment $Binding)
            $capture = Get-NvCapture $Binding
            $status = $capture.Status
            Write-NvNewJson (Join-Path $directory 'inventory.json') $capture
            $comparison = if ($Stage -ceq 'CaptureBefore') {
                $intents = foreach ($snapshot in @($capture.Snapshots)) {
                    $unaffected = $snapshot.Path -in @($capture.Boundaries) -or
                        ($Binding.Scope -ceq 'ThisFolderOnly' -and $snapshot.Path -ine $Binding.TargetDescriptor.CanonicalPath)
                    try {
                        $proposal = if ($unaffected) { $null } else {
                            New-NpProposal $snapshot $Binding.Grants $Binding.Scope ($snapshot.Path -ieq $Binding.TargetDescriptor.CanonicalPath)
                        }
                        [ordered]@{ Path=$snapshot.Path; Status='Observed'; Unaffected=$unaffected; AbstractIntent=$proposal; Error='' }
                    } catch {
                        [ordered]@{ Path=$snapshot.Path; Status='Failed'; Unaffected=$unaffected; AbstractIntent=$null; Error=$_.Exception.Message }
                    }
                }
                Write-NvNewJson (Join-Path $directory 'intent-review.json') ([ordered]@{
                    Model='AbstractIntentOnly'; ExpectedPostPropagationDescriptor='NotAssessed'
                    Coverage=$capture.Status; Entries=@($intents)
                })
                if ($status -cne 'Incomplete' -and @($intents | Where-Object { $_.Status -ceq 'Failed' }).Count) { $status='Failed' }
                [ordered]@{ Status=$status; Mode='Baseline'; ExpectedDescriptor='NotAssessed'; WriterQualification='NotQualified' }
            } else {
                $before = Read-NvJson (Join-Path $CasePath 'CaptureBefore/inventory.json')
                $mode = if ($Stage -ceq 'CaptureAfterApply') { 'Apply' } else { 'Revert' }
                Compare-NvCapture $before $capture $Binding $mode
            }
            if ($Stage -cne 'CaptureBefore') { $status=$comparison.Status }
            Write-NvNewJson (Join-Path $directory 'comparison.json') $comparison
            if (@($capture.Snapshots).Count) {
                $rows = @($capture.Snapshots | Select-Object Path,Kind,Identity,Owner,Group,Control,Protected,Descriptor)
                Export-NtfsCsvData $rows (Join-Path $directory 'snapshots.csv')
            }
        }
        $manifest = [ordered]@{
            Schema='NtfsPermissionValidationStage/1'; Stage=$Stage; BindingSHA256=$state.BindingHash
            StartedUtc=$started; CompletedUtc=[DateTime]::UtcNow.ToString('o')
            Actor=$Binding.Actor; Host=$Binding.ExecutionHost
            Files=@(Get-ChildItem -LiteralPath $directory -File | Sort-Object Name | ForEach-Object {
                [ordered]@{ Name=$_.Name; SHA256=(Get-NvFileHash $_.FullName) }
            })
            Status=$status; WhatIf=$WhatIfRecorded; ManualActionAcknowledged=$ManualAcknowledged
        }
        Write-NvNewJson (Join-Path $directory 'manifest.json') $manifest
        $commit = [ordered]@{
            Sequence=$state.Count+1; Stage=$Stage; PreviousSHA256=$state.PreviousHash
            BindingSHA256=$state.BindingHash; ManifestSHA256=(Get-NvFileHash (Join-Path $directory 'manifest.json'))
        }
        $commitPath = Join-Path $CasePath ('{0:d3}-{1}.commit.json' -f ($state.Count+1),$Stage)
        Write-NvNewJson $commitPath $commit
        $null = Read-NvCase $CasePath
        $clean = $true
        $next = switch ($Stage) {
            Initialize { "CaptureBefore -CasePath `"$CasePath`" (read-only)" }
            CaptureBefore { 'Review complete baseline and protected boundaries. ONLY separately approved EXTERNAL apply; this toolkit has NO qualified writer. Then CaptureAfterApply -ManualActionAcknowledgement.' }
            CaptureAfterApply { 'Independently review drift and guarded recovery. ONLY separately approved EXTERNAL revert, never propagate parent rollback into drift-refused descendants. Then CaptureAfterRevert -ManualActionAcknowledgement.' }
            CaptureAfterRevert { "Report -CasePath `"$CasePath`"" }
            Report { 'Archive case and commit hashes externally; review JSON manual matrix. Writer qualification remains unavailable.' }
        }
        if ($status -ceq 'Incomplete') { $next='INCOMPLETE: stop external actions, preserve evidence and review. Report may close this case; no safe apply/revert is implied.' }
        elseif ($status -ceq 'Failed') { $next='FAILED evidence checks: stop external actions; preserve this case for independent drift/recovery review. Report may close it; no automatic recovery is available.' }
        return [pscustomobject]@{
            Version=$script:NvVersion; CasePath=$CasePath; Stage=$Stage; Status=$status
            CommitSHA256=(Get-NvFileHash $commitPath); TargetWrites=0; WriterQualification='NotQualified'; NextStep=$next
        }
    } finally {
        $lock.Dispose()
        if ($clean) { [IO.File]::Delete($lockPath) }
    }
}
