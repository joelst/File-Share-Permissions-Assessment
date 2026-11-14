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
Shared permission planning, evidence and guarded recovery helpers.
.NOTES
Release version: NtfsAssessment.Common.ps1, Permissions entry in NtfsVersions.
Live mutation is disabled.
#>
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'NtfsAssessment.Common.ps1')

function ConvertTo-NpUnc([string]$Path) {
    if ($Path -notmatch '^\\\\[^\\]+\\[^\\]+(?:\\[^\\]+)*\\?$' -or
        $Path -match '[/\x00-\x1f:*?"<>|]' -or $Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw 'A static direct UNC server/share path is required; device paths and wildcards are not supported.'
    }
    $parts = $Path.TrimEnd('\').Substring(2).Split('\')
    foreach ($part in $parts) {
        if ($part -in @('.', '..') -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
            $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw 'Ambiguous UNC component.' }
    }
    return '\\' + ($parts -join '\')
}

function ConvertTo-NpPath([string]$Path) {
    if ($Path.StartsWith('\\')) { return ConvertTo-NpUnc $Path }
    if ($Path -notmatch '^[A-Za-z]:\\[^\\]+(?:\\[^\\]+)*\\?$') {
        throw 'Use an absolute Windows directory path below a drive root or a direct UNC path.'
    }
    # Apply the same component restrictions to both namespaces, without OS-dependent normalization.
    $prefix = '\\local\volume\'
    $suffix = (ConvertTo-NpUnc ($prefix + $Path.Substring(3))).Substring($prefix.Length)
    return $Path.Substring(0,1).ToUpperInvariant() + ':\' + $suffix
}

function Get-NpDriveBinding([ValidatePattern('^[A-Za-z]:$')][string]$Drive) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Windows is required to verify local volumes or mapped drives; missing elevated mappings cannot be guessed.'
    }
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Drive'" -ErrorAction Stop)
    if ($disks.Count -ne 1) { throw "Drive $Drive is unavailable in this logon/elevation context; supply a direct UNC path." }
    $disk = $disks[0]
    $provider = Get-PSDrive -Name $Drive.Substring(0,1) -PSProvider FileSystem -ErrorAction Stop
    if ($provider.Root -ine ($Drive + '\')) { throw 'Substituted/provider drives are not supported.' }
    $displayRoot = [string]$provider.DisplayRoot
    if ([int]$disk.DriveType -eq 4) {
        if (-not $disk.ProviderName) { throw 'Mapped drive has no verified UNC mapping in this elevation context; use direct UNC.' }
        $mapping = ConvertTo-NpUnc ([string]$disk.ProviderName)
        if ($displayRoot -and (ConvertTo-NpUnc $displayRoot) -ine $mapping) { throw 'Mapped drive namespace disagreement.' }
        return [pscustomobject]@{ Kind='Mapped'; MappingRoot=$mapping; HostName='' }
    }
    $info = [IO.DriveInfo]::new($Drive + '\')
    if ([int]$disk.DriveType -ne 3 -or $info.DriveType -ne [IO.DriveType]::Fixed -or
        $disk.FileSystem -ine 'NTFS' -or $displayRoot) { throw 'Local target must be an actual fixed Windows NTFS volume, not a mapped/substituted drive.' }
    $volumes = @(Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter='$Drive'" -ErrorAction Stop)
    if ($volumes.Count -ne 1 -or [int]$volumes[0].DriveType -ne 3 -or $volumes[0].FileSystem -ine 'NTFS') {
        throw 'Drive letter is not bound to an actual fixed NTFS volume; substituted drives are unsupported.'
    }
    return [pscustomobject]@{
        Kind='Fixed'; MappingRoot=''; HostName=[Environment]::MachineName
        Observation=[pscustomobject][ordered]@{
            Status='ObservedReadOnly'; ExecutionHost=[Environment]::MachineName
            VolumeDeviceId=[string]$volumes[0].DeviceID
            VolumeSerialNumber=[string]$volumes[0].SerialNumber
            FileSystem=[string]$volumes[0].FileSystem
        }
    }
}

function New-NpTargetDescriptor {
    param([string]$Path, [ValidateSet('Auto','Windows','NetApp','Nas')][string]$TargetPlatform='Auto',
        [string]$MappingRoot='', [string]$LocalHost='', $Observation=$null)
    $inputPath = ConvertTo-NpPath $Path
    $canonical = $inputPath
    if ($inputPath.StartsWith('\\')) {
        if ($MappingRoot -or $LocalHost) { throw 'Direct UNC cannot include local drive bindings.' }
        $addressing = 'DirectUNC'
    } elseif ($MappingRoot) {
        if ($LocalHost) { throw 'Mapped target cannot include local host binding.' }
        $MappingRoot = ConvertTo-NpUnc $MappingRoot
        $canonical = ConvertTo-NpUnc ($MappingRoot + '\' + $inputPath.Substring(3))
        $addressing = 'MappedDrive'
    } else {
        if ([string]::IsNullOrWhiteSpace($LocalHost) -or $LocalHost -match '[\\/\x00-\x20]') { throw 'Local fixed target requires its originating Windows host binding.' }
        if ($TargetPlatform -notin @('Auto','Windows')) { throw 'NetApp/NAS targets require an SMB UNC or verified mapped drive.' }
        $addressing = 'LocalFixed'
    }
    $platform = if ($addressing -eq 'LocalFixed') { 'LocalWindows' } else {
        switch ($TargetPlatform) { Windows { 'WindowsSMB' }; NetApp { 'NetAppSMB' }; default { 'GenericSMB' } }
    }
    if ($null -eq $Observation) {
        $Observation = [pscustomobject][ordered]@{
            Status='Unavailable'; ExecutionHost=''; VolumeDeviceId=''; VolumeSerialNumber=''; FileSystem=''
        }
    }
    Assert-NpProperties $Observation @('Status','ExecutionHost','VolumeDeviceId','VolumeSerialNumber','FileSystem')
    foreach ($name in @('Status','ExecutionHost','VolumeDeviceId','VolumeSerialNumber','FileSystem')) {
        if ($Observation.$name -isnot [string] -or $Observation.$name -match '[\x00-\x1f]') { throw 'Invalid volume observation.' }
    }
    if ($Observation.Status -ceq 'ObservedReadOnly') {
        if ($addressing -cne 'LocalFixed' -or $Observation.ExecutionHost -cne $LocalHost -or
            $Observation.FileSystem -ine 'NTFS' -or -not $Observation.VolumeDeviceId -or -not $Observation.VolumeSerialNumber) {
            throw 'Observed local volume evidence is incomplete or inconsistent; SMB filesystem advertisements are not NTFS proof.'
        }
    } elseif ($Observation.Status -cne 'Unavailable' -or $Observation.ExecutionHost -or $Observation.VolumeDeviceId -or
        $Observation.VolumeSerialNumber -or $Observation.FileSystem) { throw 'Invalid unavailable volume observation.' }
    return [pscustomobject][ordered]@{
        InputPath=$inputPath; CanonicalPath=$canonical; Addressing=$addressing
        RequestedPlatform=$TargetPlatform; Platform=$platform; MappingRoot=$MappingRoot; LocalHost=$LocalHost
        AccessModel='WindowsFileSystemAcl'; NamespaceProof='Unqualified'
        QualificationScope=$platform; PlanningStatus='PlanningSupported'; MutationStatus='MutationNotQualified'
        AdapterProfile='WindowsFileSystemAcl.ReadOnly/1'; VolumeObservation=$Observation
        BackendProof='Unverified'; SecurityStyleProof='Unverified'; ObjectIdentityProof='Unqualified'
        TrustStatus='ReviewOnlyUnproven'; GroupResolution='ClientActiveDirectoryOnly'
        TargetIdentityAuthority='Unverified;SvmLocalGroupsUnsupported'
    }
}

function Resolve-NpTarget {
    param([string]$Path, [ValidateSet('Auto','Windows','NetApp','Nas')][string]$TargetPlatform='Auto')
    $path = ConvertTo-NpPath $Path
    if ($path.StartsWith('\\')) { return New-NpTargetDescriptor $path $TargetPlatform }
    $binding = Get-NpDriveBinding $path.Substring(0,2)
    if ($binding.Kind -eq 'Mapped') { return New-NpTargetDescriptor $path $TargetPlatform $binding.MappingRoot }
    if ($binding.Kind -ne 'Fixed') { throw 'Unverified drive binding.' }
    $observation = if ($binding.PSObject.Properties.Name -contains 'Observation') { $binding.Observation } else { $null }
    return New-NpTargetDescriptor $path $TargetPlatform -LocalHost $binding.HostName -Observation $observation
}

function Assert-NpTargetDescriptor($Descriptor, [string]$Target) {
    Assert-NpProperties $Descriptor @('InputPath','CanonicalPath','Addressing','RequestedPlatform','Platform','MappingRoot','LocalHost',
        'AccessModel','NamespaceProof','QualificationScope','PlanningStatus','MutationStatus','AdapterProfile','VolumeObservation',
        'BackendProof','SecurityStyleProof','ObjectIdentityProof','TrustStatus','GroupResolution','TargetIdentityAuthority')
    $expected = New-NpTargetDescriptor $Descriptor.InputPath $Descriptor.RequestedPlatform $Descriptor.MappingRoot $Descriptor.LocalHost $Descriptor.VolumeObservation
    if ((Get-NpCanonicalJson $expected) -cne (Get-NpCanonicalJson $Descriptor) -or $Descriptor.CanonicalPath -cne $Target) {
        throw 'Target addressing/platform/qualification binding mismatch.'
    }
}

function Assert-NpExecutionHost($Descriptor) {
    if ($Descriptor.Addressing -ceq 'LocalFixed' -and $Descriptor.LocalHost -ine [Environment]::MachineName) {
        throw 'Local plan execution host mismatch; a local drive path must never be reinterpreted on another machine.'
    }
}

function New-NpRecoveryModel($Descriptor, $Entries) {
    return [pscustomobject][ordered]@{
        Schema='NtfsPermissionsRecovery/1'; NamespaceSHA256=(Get-NtfsHash (Get-NpCanonicalJson $Descriptor))
        StateModel='AbstractIntentOnly'; Executable=$false
        Paths=@($Entries | ForEach-Object {
            [pscustomobject][ordered]@{
                Path=$_.Before.Path; Identity=$_.Before.Identity; Boundary=$_.Boundary
                BeforeSHA256=(Get-NtfsHash (Get-NpCanonicalJson $_.Before))
                ExpectedIntentSHA256=(Get-NtfsHash (Get-NpCanonicalJson $_.Proposal.Intent))
            }
        })
    }
}

function Get-NpGuardedRecoveryDecision($Plan, $CurrentTargetDescriptor, $Current) {
    Assert-NpTargetDescriptor $Plan.TargetDescriptor $Plan.Target
    Assert-NpTargetDescriptor $CurrentTargetDescriptor $CurrentTargetDescriptor.CanonicalPath
    $model = New-NpRecoveryModel $Plan.TargetDescriptor $Plan.Entries
    if ((Get-NpCanonicalJson $model) -cne (Get-NpCanonicalJson $Plan.Recovery)) { throw 'Recovery model binding mismatch.' }
    if ((Get-NtfsHash (Get-NpCanonicalJson $CurrentTargetDescriptor)) -cne $model.NamespaceSHA256) { return 'NamespaceConflict' }
    $entry = @($Plan.Entries | Where-Object { $_.Before.Path -ceq $Current.Path })
    if ($entry.Count -ne 1) { return 'RevertConflict' }
    Assert-NpSnapshot $Current
    $decision = Get-NpRevertDecision $Current $entry[0].Before $entry[0].Proposal.Intent
    if ($decision -eq 'RestoreBefore') { return 'RestoreBeforeIntentReviewOnly' }
    return $decision
}

function Assert-NpProperties($Object, [string[]]$Names) {
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [array]) { throw 'Expected an object.' }
    $actual = @($Object.PSObject.Properties.Name)
    if (@($actual | Where-Object { $_ -cnotin $Names }).Count -or
        @($Names | Where-Object { $_ -cnotin $actual }).Count) { throw "Strict schema requires: $($Names -join ', ')" }
}

function Get-NpGrants {
    param([string]$GroupName, [string]$Permissions, [string]$Json, [string]$JsonFile, [scriptblock]$Resolve)
    $single = -not [string]::IsNullOrWhiteSpace($GroupName) -or -not [string]::IsNullOrWhiteSpace($Permissions)
    $forms = [int]$single + [int](-not [string]::IsNullOrWhiteSpace($Json)) + [int](-not [string]::IsNullOrWhiteSpace($JsonFile))
    if ($forms -ne 1) { throw 'Specify exactly one input form: group/permissions, JSON array, or JSON file.' }
    if ($single) {
        if (-not $GroupName -or -not $Permissions) { throw 'GroupName and Permissions are both required.' }
        $items = @([pscustomobject]@{ GroupName = $GroupName; Permissions = $Permissions })
    } else {
        if ($JsonFile) {
            $file = Get-Item -LiteralPath $JsonFile -ErrorAction Stop
            if ($file.Length -gt 1MB) { throw 'Grant JSON exceeds 1 MiB.' }
            $Json = [IO.File]::ReadAllText($file.FullName)
        }
        if ([Text.Encoding]::UTF8.GetByteCount($Json) -gt 1MB -or $Json.Trim() -notmatch '^\[[\s\S]*\]$') { throw 'Expected a JSON array, at most 1 MiB.' }
        # Reject duplicate property names before ConvertFrom-Json can silently overwrite them.
        if ($Json -notmatch '^\s*\[\s*(?:\{\s*"(?:GroupName|Permissions)"\s*:\s*"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt])*"\s*,\s*"(?:GroupName|Permissions)"\s*:\s*"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt])*"\s*\}\s*(?:,\s*\{\s*"(?:GroupName|Permissions)"\s*:\s*"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt])*"\s*,\s*"(?:GroupName|Permissions)"\s*:\s*"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt])*"\s*\}\s*)*)?\]\s*$') {
            throw 'Grant JSON must contain objects with exactly GroupName and Permissions string properties (literal property names).'
        }
        $parsed = $Json | ConvertFrom-NpJson
        $items = @($parsed)
    }
    if ($items.Count -lt 1 -or $items.Count -gt 128) { throw 'Supply 1 to 128 grants.' }
    # Windows allow rules include SYNCHRONIZE, which common file opens require.
    $rights = @{ Read = 1179785; ReadAndExecute = 1179817; Modify = 1245631; FullControl = 2032127 }
    $seen = @{}
    $result = @()
    foreach ($item in $items) {
        Assert-NpProperties $item @('GroupName','Permissions')
        if ($item.GroupName -isnot [string] -or [string]::IsNullOrWhiteSpace($item.GroupName) -or
            $item.GroupName -match '[\x00-\x1f]' -or $item.Permissions -isnot [string] -or
            $item.Permissions -cnotin @('Read','ReadAndExecute','Modify','FullControl')) { throw 'Invalid group or permission. Use Read, ReadAndExecute, Modify, or FullControl.' }
        $sid = ([string](& $Resolve $item.GroupName)).ToUpperInvariant()
        $null = Get-NpSidSize $sid
        if ($seen.ContainsKey($sid)) { throw "Duplicate SID alias: $($item.GroupName)" }
        $seen[$sid] = $true
        $result += [pscustomobject][ordered]@{ GroupName = $item.GroupName; SID = $sid; Permissions = $item.Permissions; Mask = $rights[$item.Permissions] }
    }
    return $result
}

function Get-NpSidSize([string]$SID) {
    if ($SID -notmatch '^S-1-\d+(?:-\d+)+$') { throw 'Invalid SID.' }
    $parts = $SID.Split('-')
    if ($parts.Count -gt 18 -or [uint64]::Parse($parts[2]) -gt 281474976710655) { throw 'SID authority/count out of range.' }
    foreach ($part in $parts[3..($parts.Count - 1)]) {
        if ([uint64]::Parse($part) -gt [uint32]::MaxValue) { throw 'SID subauthority out of range.' }
    }
    return 8 + 4 * ($parts.Count - 3)
}

function Assert-NpNormalizedGrants($Grants) {
    $seen = @{}
    $masks = @{ Read = 1179785; ReadAndExecute = 1179817; Modify = 1245631; FullControl = 2032127 }
    if (@($Grants).Count -lt 1 -or @($Grants).Count -gt 128) { throw 'Invalid grants.' }
    foreach ($grant in $Grants) {
        Assert-NpProperties $grant @('GroupName','SID','Permissions','Mask')
        if ($grant.GroupName -isnot [string] -or [string]::IsNullOrWhiteSpace($grant.GroupName) -or $grant.GroupName -match '[\x00-\x1f]' -or
            $grant.Permissions -cnotin @('Read','ReadAndExecute','Modify','FullControl') -or
            $grant.Mask -isnot [ValueType] -or $grant.Mask -ne $masks[$grant.Permissions] -or
            $grant.SID -isnot [string] -or $grant.SID -notmatch '^S-1-\d+(?:-\d+)+$' -or $seen.ContainsKey($grant.SID)) { throw 'Invalid normalized grant or duplicate SID alias.' }
        $seen[$grant.SID] = $true
        $null = Get-NpSidSize $grant.SID
    }
}

function Resolve-NpWindowsGroup([string]$Name) {
    # Translation alone also accepts users. Require AD group discovery, never guess identity type.
    if ($Name -match '^(?:\.|localhost|BUILTIN)\\' -or $Name.StartsWith([Environment]::MachineName + '\',[StringComparison]::OrdinalIgnoreCase) -or
        $Name -match '^S-1-5-32-') { throw 'Client AD security groups only; machine-local and SVM-local groups are unsupported/unvalidated.' }
    if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)) { throw 'Client AD security group resolution requires the ActiveDirectory module (Get-ADGroup); SVM-local groups remain unsupported/unvalidated.' }
    $identity = $Name
    try {
        if ($Name.Contains('\')) {
            $identity = ([Security.Principal.NTAccount]::new($Name)).Translate([Security.Principal.SecurityIdentifier]).Value
        }
        $group = Get-ADGroup -Identity $identity -Properties GroupCategory -ErrorAction Stop
    } catch { throw "Client AD group resolution failed; target/SVM-local authority is not validated or supported: $Name. $($_.Exception.Message)" }
    if ([string]$group.GroupCategory -ne 'Security') { throw "Not a security group: $Name" }
    if ($identity -match '^S-1-' -and [string]$group.SID -ine $identity) { throw 'Resolved group SID mismatch.' }
    return [string]$group.SID
}

function Get-NpCanonicalJson($Value) { return ConvertTo-Json -InputObject $Value -Depth 64 -Compress }

function ConvertFrom-NpJson {
    param([Parameter(ValueFromPipeline=$true)][string]$Json)
    process {
        if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
            ConvertFrom-Json -InputObject $Json -DateKind String -ErrorAction Stop
        } else { ConvertFrom-Json -InputObject $Json -ErrorAction Stop }
    }
}

function Get-NpBytesHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-NpSourceHash {
    $parts = foreach ($name in @('Add-FileSharePermissions.ps1','NtfsPermissions.Common.ps1','NtfsAssessment.Common.ps1',
        'NtfsPermissions.Local.ps1','NtfsPermissions.Local.cs')) {
        $name + ':' + (Get-NpBytesHash ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name))))
    }
    return Get-NtfsHash ($parts -join "`n")
}

function Assert-NpSnapshot($Snapshot) {
    Assert-NpProperties $Snapshot @('Path','Kind','Identity','Owner','Group','Control','Protected','DaclPresent','Canonical','Aces','Descriptor')
    if ($Snapshot.Kind -notin @('Folder','File') -or -not $Snapshot.Identity -or -not $Snapshot.Owner -or -not $Snapshot.Group -or
        -not $Snapshot.Descriptor -or $Snapshot.DaclPresent -ne $true -or $Snapshot.Canonical -ne $true) {
        throw "Absent/null DACL, noncanonical ACL, or incomplete identity/evidence: $($Snapshot.Path)"
    }
    foreach ($flag in @('Protected','DaclPresent','Canonical')) {
        if ($Snapshot.$flag -isnot [bool]) { throw "Invalid snapshot flag: $flag" }
    }
    if ($Snapshot.Control -isnot [ValueType] -or [long]$Snapshot.Control -lt 0 -or [long]$Snapshot.Control -gt 65535) { throw 'Invalid security descriptor control flags.' }
    foreach ($ace in @($Snapshot.Aces)) {
        Assert-NpProperties $ace @('SID','Type','Mask','Inherited','ContainerInherit','ObjectInherit','InheritOnly','NoPropagate')
        if ($ace.Type -notin @('Allow','Deny') -or $ace.SID -notmatch '^S-1-\d+(?:-\d+)+$' -or
            $ace.Mask -isnot [ValueType] -or [long]$ace.Mask -lt 0 -or [long]$ace.Mask -gt 2147483647) {
            throw 'Unsupported conditional, object, or opaque ACE.'
        }
        foreach ($flag in @('Inherited','ContainerInherit','ObjectInherit','InheritOnly','NoPropagate')) {
            if ($ace.$flag -isnot [bool]) { throw "Invalid ACE flag: $flag" }
        }
        $null = Get-NpSidSize $ace.SID
    }
    if (@($Snapshot.Aces).Count -gt 1500) { throw 'Aggregate ACL size guard exceeded.' }
}

function New-NpProposal($Before, $Grants, [string]$Scope, [bool]$Root = $true) {
    Assert-NpSnapshot $Before
    Assert-NpNormalizedGrants $Grants
    if ($Scope -notin @('ThisFolderOnly','ThisFolderSubfoldersAndFiles')) { throw 'Invalid scope.' }
    $inherit = $Scope -eq 'ThisFolderSubfoldersAndFiles'
    # This is an intent model, NOT Windows inheritance calculation or effective-access proof.
    $after = (Get-NpCanonicalJson $Before) | ConvertFrom-NpJson
    $aces = @($after.Aces)
    foreach ($grant in $Grants) {
        foreach ($ace in $aces) {
            # Group membership/token evaluation is deliberately not attempted; any applicable
            # deny overlap is ambiguous, including denies for other SIDs.
            if ($ace.Type -eq 'Deny' -and (-not $ace.InheritOnly -or ($inherit -and ($ace.ContainerInherit -or $ace.ObjectInherit))) -and ([long]$ace.Mask -band [long]$grant.Mask)) {
                throw "Applicable deny overlap at $($Before.Path); no effective-access claims."
            }
        }
        $covered = 0L
        foreach ($ace in $aces) {
            if ($ace.Type -eq 'Allow' -and $ace.SID -eq $grant.SID -and -not $ace.InheritOnly -and
                (-not ($inherit -and $Before.Kind -eq 'Folder') -or
                    ($ace.ContainerInherit -and $ace.ObjectInherit -and -not $ace.NoPropagate))) {
                $covered = $covered -bor [long]$ace.Mask
            }
        }
        if (($covered -band [long]$grant.Mask) -eq [long]$grant.Mask) { continue }
        $aces += [pscustomobject][ordered]@{
            SID = $grant.SID; Type = 'Allow'; Mask = [long]$grant.Mask
            Inherited = -not $Root; ContainerInherit = ($inherit -and $Before.Kind -eq 'Folder')
            ObjectInherit = ($inherit -and $Before.Kind -eq 'Folder'); InheritOnly = $false; NoPropagate = $false
        }
    }
    $aclBytes = 8L
    foreach ($ace in $aces) { $aclBytes += 8 + (Get-NpSidSize $ace.SID) }
    if ($aces.Count -gt 1500 -or $aclBytes -gt 60000) { throw 'Aggregate ACL size guard exceeded.' }
    $after.Aces = @($aces | Where-Object { -not $_.Inherited }) + @($aces | Where-Object { $_.Inherited })
    # Descriptor is immutable BEFORE evidence, never represented as a synthesized Windows SDDL.
    return [pscustomobject][ordered]@{
        Intent = $after
        NoOp = (Get-NpCanonicalJson $Before.Aces) -ceq (Get-NpCanonicalJson $after.Aces)
    }
}

function Get-NpWindowsSnapshot([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point is not supported: $Path" }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.Sddl)
    $aces = @()
    if ($null -ne $raw.DiscretionaryAcl) {
        foreach ($ace in $raw.DiscretionaryAcl) {
            if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.OpaqueLength -ne 0 -or
                $ace.AceQualifier -notin @([Security.AccessControl.AceQualifier]::AccessAllowed,[Security.AccessControl.AceQualifier]::AccessDenied)) {
                $aces += [pscustomobject][ordered]@{
                    SID=''; Type='Unsupported'; Mask=0L; Inherited=$false
                    ContainerInherit=$false; ObjectInherit=$false; InheritOnly=$false; NoPropagate=$false
                }
                continue
            }
            $flags = [int]$ace.AceFlags
            $aces += [pscustomobject][ordered]@{
                SID = $ace.SecurityIdentifier.Value; Type = $(if ([int]$ace.AceQualifier -eq 0) { 'Allow' } else { 'Deny' })
                Mask = [long]$ace.AccessMask; Inherited = [bool]($flags -band 16)
                ContainerInherit = [bool]($flags -band 2); ObjectInherit = [bool]($flags -band 1)
                InheritOnly = [bool]($flags -band 8); NoPropagate = [bool]($flags -band 4)
            }
        }
    }
    # Path/creation-time is only observational, NOT a stable file identity. This blocks execution.
    $identity = 'UNQUALIFIED:' + $item.CreationTimeUtc.Ticks + ':' + $item.FullName
    return [pscustomobject][ordered]@{
        Path = $Path; Kind = $(if ($item.PSIsContainer) { 'Folder' } else { 'File' }); Identity = $identity
        Owner = $raw.Owner.Value; Group = $raw.Group.Value; Control = [int]$raw.ControlFlags
        Protected = [bool]$acl.AreAccessRulesProtected
        DaclPresent = [bool](([int]$raw.ControlFlags -band 4) -and $null -ne $raw.DiscretionaryAcl)
        Canonical = [bool]$acl.AreAccessRulesCanonical; Aces = @($aces); Descriptor = $acl.Sddl
    }
}

function Get-NpWindowsInventory([string]$Target, [string]$Scope, [int]$Limit) {
    $snapshots = [Collections.Generic.List[object]]::new()
    $boundaries = [Collections.Generic.List[string]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    try {
        $Target = ConvertTo-NpPath $Target
        if ($Target.StartsWith('\\')) {
            $parts = $Target.Substring(2).Split('\')
            $ancestor = '\\' + $parts[0] + '\' + $parts[1]
            $remaining = @($parts | Select-Object -Skip 2)
        } else {
            $ancestor = $Target.Substring(0,3)
            $remaining = @($Target.Substring(3).Split('\'))
        }
        foreach ($component in @('') + $remaining) {
            if ($component) { $ancestor = $ancestor.TrimEnd('\') + '\' + $component }
            $node = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Ancestor reparse: $ancestor" }
        }
        $root = Get-NpWindowsSnapshot $Target
        if ($root.Kind -ne 'Folder') { throw 'Target must be a folder.' }
        $snapshots.Add($root)
        $queue = [Collections.Generic.Queue[string]]::new()
        if ($Scope -eq 'ThisFolderSubfoldersAndFiles') { $queue.Enqueue($Target) }
        while ($queue.Count) {
            $folder = $queue.Dequeue()
            $children = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop)
            foreach ($child in $children) {
                if ($snapshots.Count -ge $Limit) { throw 'Inventory path limit reached; coverage incomplete.' }
                $snapshot = Get-NpWindowsSnapshot $child.FullName
                $snapshots.Add($snapshot)
                if ($snapshot.Protected) { $boundaries.Add($snapshot.Path); continue }
                if ($snapshot.Kind -eq 'Folder') { $queue.Enqueue($snapshot.Path) }
            }
            Write-Progress -Activity 'NTFS plan: read-only inventory' -Status "$($snapshots.Count) paths; $($queue.Count) folders pending"
        }
    } catch { $errors.Add($_.Exception.Message) }
    finally { Write-Progress -Activity 'NTFS plan: read-only inventory' -Completed }
    return [pscustomobject]@{ Snapshots = @($snapshots.ToArray()); Boundaries = @($boundaries.ToArray()); Errors = @($errors.ToArray()) }
}

function Test-NpProtectedAncestor([string]$Path, [hashtable]$Boundaries) {
    $ancestor = $Path
    while (($cut = $ancestor.LastIndexOf('\')) -gt 1) {
        $ancestor = $ancestor.Substring(0,$cut)
        if ($Boundaries.ContainsKey($ancestor)) { return $true }
    }
    return $false
}

function New-NpPlan([string]$Target, $Grants, [string]$Scope, $Inventory, [string]$SourceHash, $TargetDescriptor = $null) {
    $Target = ConvertTo-NpPath $Target
    if ($null -eq $TargetDescriptor) {
        # Backwards-compatible UNC planning API; never guess local volume identity.
        if (-not $Target.StartsWith('\\')) { throw 'Local plans require a verified target descriptor.' }
        $TargetDescriptor = New-NpTargetDescriptor $Target
    }
    Assert-NpTargetDescriptor $TargetDescriptor $Target
    Assert-NpNormalizedGrants $Grants
    if ($Scope -notin @('ThisFolderOnly','ThisFolderSubfoldersAndFiles')) { throw 'Invalid scope.' }
    $reasons = @($Inventory.Errors)
    $entries = @()
    $seen = @{}
    $boundaryPaths = @{}
    foreach ($boundaryPath in @($Inventory.Boundaries)) { $boundaryPaths[[string]$boundaryPath] = $true }
    foreach ($snapshot in @($Inventory.Snapshots)) {
        try {
            $path = ConvertTo-NpPath $snapshot.Path
            if ($seen.ContainsKey($path) -or ($path -ine $Target -and -not $path.StartsWith($Target + '\',[StringComparison]::OrdinalIgnoreCase))) { throw 'Invalid or duplicate manifest path.' }
            $seen[$path] = $true
            $isRoot = $path -ieq $Target
            if ($path -cne $snapshot.Path -or ($isRoot -and $snapshot.Kind -ne 'Folder')) { throw 'Non-normalized manifest path or non-folder root.' }
            if ($Scope -eq 'ThisFolderOnly' -and -not $isRoot) { throw 'Folder-only manifest contains descendants.' }
            if (Test-NpProtectedAncestor $path $boundaryPaths) { throw 'Manifest traversed protected branch.' }
            $boundary = -not $isRoot -and [bool]$snapshot.Protected
            Assert-NpSnapshot $snapshot
            $proposal = if ($boundary) { [pscustomobject]@{ Intent = $snapshot; NoOp = $true } } else { New-NpProposal $snapshot $Grants $Scope $isRoot }
            $entries += [pscustomobject][ordered]@{ Before = $snapshot; Boundary = $boundary; Proposal = $proposal }
        } catch { $reasons += $_.Exception.Message }
    }
    if (-not $seen.ContainsKey($Target)) { $reasons += 'Root snapshot missing.' }
    $expectedBoundaries = @($entries | Where-Object Boundary | ForEach-Object { $_.Before.Path })
    if ((Get-NpCanonicalJson $expectedBoundaries) -cne (Get-NpCanonicalJson @($Inventory.Boundaries))) { $reasons += 'Protected boundary manifest mismatch.' }
    $coverageComplete = ($reasons.Count -eq 0 -and $entries.Count -eq @($Inventory.Snapshots).Count -and $seen.ContainsKey($Target))
    $reasons += "ReviewOnlyUnproven: adapter $($TargetDescriptor.AdapterProfile); backend/security-style/target identity authority unverified; SVM-local groups unsupported."
    if ($TargetDescriptor.Addressing -eq 'LocalFixed') {
        $reasons += "Local volume evidence=$($TargetDescriptor.VolumeObservation.Status); host=$($TargetDescriptor.LocalHost). Observations are not stable object identity, freshness or infrastructure trust proof."
    }
    $reasons += "MutationNotQualified/$($TargetDescriptor.QualificationScope): qualified public writer absent; identity, namespace/backend and propagation are unproven in this planning workflow. Windows local, Windows SMB, NetApp SMB and generic SMB require separate qualification."
    return [pscustomobject][ordered]@{
        Schema = 'NtfsPermissionsPlan/2'; Version = $script:NtfsVersions.Permissions
        CreatedUtc = [DateTime]::UtcNow.ToString('o'); SourceHash = $SourceHash
        Target = $Target; TargetDescriptor = $TargetDescriptor; Scope = $Scope; Grants = @($Grants); Entries = @($entries)
        InventoryEvidence = @($Inventory.Snapshots)
        Boundaries = @($Inventory.Boundaries); CoverageComplete = $coverageComplete
        Recovery = (New-NpRecoveryModel $TargetDescriptor $entries)
        Executable = $false; Status = 'Blocked'; Reasons = @($reasons)
    }
}

function Read-NpPlan([string]$Path, [string]$SHA256, [string]$SourceHash, [int]$MaxAgeHours = 24) {
    if ($SHA256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'A reviewed plan SHA256 is required.' }
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -gt 100000000) { throw 'Plan exceeds 100 MB.' }
    # Read once; hash and parse the same immutable byte array (no reopen/hash race).
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ((Get-NpBytesHash $bytes) -ine $SHA256) { throw 'Reviewed plan hash mismatch.' }
    $plan = [Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-NpJson
    if ($plan.Schema -cne 'NtfsPermissionsPlan/2') { throw 'Plan schema changed: legacy plans lack platform/namespace bindings; create and review a new plan.' }
    Assert-NpProperties $plan @('Schema','Version','CreatedUtc','SourceHash','Target','TargetDescriptor','Scope','Grants','Entries','InventoryEvidence','Boundaries','CoverageComplete','Recovery','Executable','Status','Reasons')
    if ($plan.Version -cne $script:NtfsVersions.Permissions -or $plan.SourceHash -cne $SourceHash) { throw 'Plan schema/version/source binding mismatch.' }
    Assert-NpTargetDescriptor $plan.TargetDescriptor $plan.Target
    $created = [DateTimeOffset]::Parse($plan.CreatedUtc,[Globalization.CultureInfo]::InvariantCulture)
    if ($created -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or $created -lt [DateTimeOffset]::UtcNow.AddHours(-$MaxAgeHours)) { throw 'Plan expired or future dated.' }
    if ((ConvertTo-NpPath $plan.Target) -cne $plan.Target -or $plan.Scope -notin @('ThisFolderOnly','ThisFolderSubfoldersAndFiles') -or
        $plan.Executable -isnot [bool] -or $plan.Executable -ne $false -or $plan.CoverageComplete -isnot [bool] -or $plan.Status -cne 'Blocked') { throw 'Invalid target, scope, or qualification claim.' }
    Assert-NpNormalizedGrants $plan.Grants
    $paths = @{}
    $evidenceMap = @{}
    foreach ($evidence in @($plan.InventoryEvidence)) {
        Assert-NpProperties $evidence @('Path','Kind','Identity','Owner','Group','Control','Protected','DaclPresent','Canonical','Aces','Descriptor')
        $path = ConvertTo-NpPath $evidence.Path
        if ($path -cne $evidence.Path -or $evidenceMap.ContainsKey($path) -or
            ($path -ine $plan.Target -and -not $path.StartsWith($plan.Target + '\',[StringComparison]::OrdinalIgnoreCase))) { throw 'Invalid raw inventory evidence path.' }
        $evidenceMap[$path] = $evidence
    }
    $boundaryPaths = @{}
    foreach ($boundary in @($plan.Boundaries)) {
        if ((ConvertTo-NpPath $boundary) -cne $boundary -or $boundaryPaths.ContainsKey($boundary) -or $boundary -ieq $plan.Target) { throw 'Invalid protected boundary manifest.' }
        $boundaryPaths[$boundary] = $true
    }
    foreach ($entry in $plan.Entries) {
        Assert-NpProperties $entry @('Before','Boundary','Proposal')
        Assert-NpSnapshot $entry.Before
        $path = ConvertTo-NpPath $entry.Before.Path
        $root = $path -ieq $plan.Target
        if ($path -cne $entry.Before.Path -or ($root -and $entry.Before.Kind -ne 'Folder') -or
            $paths.ContainsKey($path) -or (-not $root -and -not $path.StartsWith($plan.Target + '\',[StringComparison]::OrdinalIgnoreCase)) -or
            ($plan.Scope -eq 'ThisFolderOnly' -and -not $root)) { throw 'Invalid bound manifest path.' }
        $paths[$path] = $true
        if ($entry.Boundary -isnot [bool] -or $entry.Boundary -ne (-not $root -and [bool]$entry.Before.Protected) -or
            $entry.Boundary -ne $boundaryPaths.ContainsKey($path) -or (Test-NpProtectedAncestor $path $boundaryPaths)) { throw 'Invalid protection boundary.' }
        $expected = if ($entry.Boundary) { [pscustomobject]@{ Intent = $entry.Before; NoOp = $true } } else { New-NpProposal $entry.Before $plan.Grants $plan.Scope $root }
        if ((Get-NpCanonicalJson $expected) -cne (Get-NpCanonicalJson $entry.Proposal)) { throw 'Reconstructed proposal mismatch.' }
        if (-not $evidenceMap.ContainsKey($path) -or (Get-NpCanonicalJson $entry.Before) -cne (Get-NpCanonicalJson $evidenceMap[$path])) { throw 'Before evidence binding mismatch.' }
    }
    if ($plan.CoverageComplete -and -not $paths.ContainsKey($plan.Target)) { throw 'Root absent from complete manifest.' }
    foreach ($boundary in @($plan.Boundaries)) { if (-not $paths.ContainsKey($boundary)) { throw 'Invalid protected branch manifest.' } }
    if ($plan.CoverageComplete -and $paths.Count -ne $evidenceMap.Count) { throw 'Incomplete bound inventory evidence.' }
    if ((Get-NpCanonicalJson (New-NpRecoveryModel $plan.TargetDescriptor $plan.Entries)) -cne (Get-NpCanonicalJson $plan.Recovery)) { throw 'Recovery model binding mismatch.' }
    return $plan
}

function New-NpRun([string]$OutputDirectory, [string]$Target = '') {
    if ($OutputDirectory.StartsWith('\\') -or $OutputDirectory.StartsWith('//')) { throw 'Audit directory must be local, outside the target.' }
    $root = [IO.Path]::GetFullPath($OutputDirectory)
    if ($root.StartsWith('\\') -or $root.StartsWith('//')) { throw 'Audit directory must be local, outside the target.' }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))
        if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'Audit output must use a fixed local volume, not a mapped SMB drive.' }
        if ($Target -and -not $Target.StartsWith('\\')) {
            Assert-NtfsOutputOutsideScope $root (ConvertTo-NpPath $Target)
        } elseif ($Target) {
            # Conservatively check same-named local shares even for a remote server name.
            # This catches common local UNC/backing-directory aliases, not DFS/8.3/subst
            # or all physical mappings; those still require trusted infrastructure review.
            if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) { throw 'Cannot validate local SMB backing-directory output separation (Get-SmbShare required).' }
            $parts = (ConvertTo-NpUnc $Target).Substring(2).Split('\')
            foreach ($share in @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -ieq $parts[1] -and $_.Path })) {
                $backing = [string]$share.Path
                for ($i=2; $i -lt $parts.Length; $i++) { $backing = Join-Path $backing $parts[$i] }
                Assert-NtfsOutputOutsideScope $root $backing
            }
        }
    }
    $probe = $root
    while ($probe) {
        if (Test-Path -LiteralPath $probe) {
            $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
                ($item.PSObject.Properties.Name -contains 'LinkType' -and $item.LinkType)) { throw 'Audit ancestors must not be reparse points or links.' }
        }
        $parent = [IO.Path]::GetDirectoryName($probe)
        if ($parent -eq $probe) { break }
        $probe = $parent
    }
    [void][IO.Directory]::CreateDirectory($root)
    $run = Join-Path $root ('Permissions_' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($run)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner($sid)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $run -AclObject $acl -WhatIf:$false -ErrorAction Stop
        $actual = Get-Acl -LiteralPath $run -ErrorAction Stop
        $rules = @($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if (-not $actual.AreAccessRulesProtected -or -not $actual.AreAccessRulesCanonical -or
            $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or
            $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or
            $rules[0].IsInherited -or [int]$rules[0].InheritanceFlags -ne 3 -or [int]$rules[0].PropagationFlags -ne 0 -or
            $rules[0].AccessControlType -ne 'Allow' -or [int]$rules[0].FileSystemRights -ne 2032127) { throw 'Restrictive audit directory ACL verification failed.' }
    } else {
        & chmod 700 $run
        if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict audit directory.' }
    }
    return $run
}

function New-NpJournal([string]$RunDirectory, [string]$Mode, [string]$Ticket, [string]$PlanHash, [string]$Target) {
    return [pscustomobject]@{
        Path = (Join-Path $RunDirectory 'events.jsonl'); OperationId = [guid]::NewGuid().ToString('N')
        Mode = $Mode; Ticket = $Ticket; PlanHash = $PlanHash; Target = $Target
        Previous = ('0' * 64); Sequence = 0; Actor = [Environment]::UserDomainName + '\' + [Environment]::UserName
        HostName = [Environment]::MachineName; SourceHash = Get-NpSourceHash
    }
}

function Write-NpEvent($Journal, [string]$Stage, [string]$Result, $Changes = @()) {
    $event = [ordered]@{
        Sequence = $Journal.Sequence + 1; Previous = $Journal.Previous; OperationId = $Journal.OperationId
        Utc = [DateTime]::UtcNow.ToString('o'); Actor = $Journal.Actor; Host = $Journal.HostName
        Ticket = $Journal.Ticket; PlanHash = $Journal.PlanHash; SourceHash = $Journal.SourceHash; Version = $script:NtfsVersions.Permissions
        Mode = $Journal.Mode; Stage = $Stage; Target = $Journal.Target; Changes = @($Changes); Result = $Result
    }
    $payload = Get-NpCanonicalJson $event
    $hash = Get-NtfsHash $payload
    $line = Get-NpCanonicalJson ([ordered]@{ Payload = $payload; Hash = $hash })
    $stream = [IO.FileStream]::new($Journal.Path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($line + "`n")
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    $Journal.Sequence++
    $Journal.Previous = $hash
}

function Read-NpJournal([string]$Path, [byte[]]$Bytes) {
    # Verified means hash-chain consistency, never filesystem state or authenticity.
    if ($null -eq $Bytes) {
        if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 100000000) { throw 'Journal exceeds 100 MB; manual evidence review required.' }
        $Bytes = [IO.File]::ReadAllBytes($Path)
    }
    if ($Bytes.Length -gt 100000000) { throw 'Journal exceeds 100 MB; manual evidence review required.' }
    $bytes = $Bytes
    $torn = $bytes.Length -gt 0 -and $bytes[$bytes.Length - 1] -ne 10
    $completeLength = $bytes.Length
    if ($torn) {
        while ($completeLength -gt 0 -and $bytes[$completeLength - 1] -ne 10) { $completeLength-- }
    }
    # A torn final record can include an incomplete UTF-8 code point.
    $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes,0,$completeLength)
    $lines = @($text.Split("`n"))
    $count = $lines.Count - 1
    $previous = '0' * 64
    $events = @()
    for ($i = 0; $i -lt $count; $i++) {
        $record = $lines[$i] | ConvertFrom-NpJson
        Assert-NpProperties $record @('Payload','Hash')
        if ((Get-NtfsHash $record.Payload) -cne $record.Hash) { throw 'Journal hash mismatch.' }
        $event = $record.Payload | ConvertFrom-NpJson
        Assert-NpProperties $event @('Sequence','Previous','OperationId','Utc','Actor','Host','Ticket','PlanHash','SourceHash','Version','Mode','Stage','Target','Changes','Result')
        if ($event.Previous -cne $previous -or $event.Sequence -ne $i + 1) { throw 'Journal chain mismatch.' }
        if ($events.Count) {
            foreach ($binding in @('OperationId','Actor','Host','Ticket','SourceHash','Version','Mode')) {
                if ($event.$binding -cne $events[0].$binding) { throw "Journal operation binding mismatch: $binding" }
            }
        }
        $previous = $record.Hash
        $events += $event
    }
    # Retain ALL bytes; never truncate, repair, resume, or auto-discard a torn record.
    return [pscustomobject]@{ Status = $(if ($torn -or -not $events.Count) { 'Indeterminate' } else { 'Verified' }); Events = @($events); TornFinalRecord = $torn; SHA256 = Get-NpBytesHash $bytes }
}

function Read-NpRecoveryEvidence {
    <#
    .SYNOPSIS
    Validates externally reviewed plan/manifest/journal bindings without mutation.
    .DESCRIPTION
    Torn journals return Indeterminate and permit no automatic restore. SHA hashes
    bind supplied evidence, not identity or enterprise trust. Archive externally.
    #>
    param([string]$ManifestPath, [string]$PlanSHA256, [string]$JournalPath, [string]$JournalSHA256, [string]$SourceHash)
    if ($PlanSHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $JournalSHA256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Reviewed plan and source journal hashes required.' }
    if ((Get-Item -LiteralPath $ManifestPath -ErrorAction Stop).Length -gt 1MB) { throw 'Evidence manifest exceeds 1 MiB.' }
    $manifestBytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($ManifestPath))
    $manifest = [Text.UTF8Encoding]::new($false,$true).GetString($manifestBytes) | ConvertFrom-NpJson
    Assert-NpProperties $manifest @('Schema','PlanSHA256','SourceHash','Files')
    if ($manifest.Schema -cne 'NtfsPermissionsEvidence/1' -or $manifest.PlanSHA256 -ine $PlanSHA256 -or $manifest.SourceHash -cne $SourceHash) { throw 'Recovery manifest/source binding mismatch.' }
    $names = @{}
    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($ManifestPath))
    foreach ($file in @($manifest.Files)) {
        Assert-NpProperties $file @('Name','SHA256')
        if ($file.Name -notmatch '^(plan\.json|before-and-intent(?:_[0-9]+)?\.csv)$' -or $names.ContainsKey($file.Name) -or $file.SHA256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid evidence manifest filename/hash.' }
        $names[$file.Name] = $file.SHA256
        $path = Join-Path $directory $file.Name
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.Length -gt 100000000 -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe evidence file.' }
        if ((Get-NpBytesHash ([IO.File]::ReadAllBytes($item.FullName))) -ine $file.SHA256) { throw 'Evidence file hash mismatch.' }
    }
    if (-not $names.ContainsKey('plan.json') -or $names['plan.json'] -ine $PlanSHA256) { throw 'Manifest must bind the reviewed plan.' }
    $plan = Read-NpPlan (Join-Path $directory 'plan.json') $PlanSHA256 $SourceHash
    if ((Get-Item -LiteralPath $JournalPath -ErrorAction Stop).Length -gt 100000000) { throw 'Source journal exceeds 100 MB.' }
    $journalBytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($JournalPath))
    if ((Get-NpBytesHash $journalBytes) -ine $JournalSHA256) { throw 'Source journal hash mismatch.' }
    $journal = Read-NpJournal -Bytes $journalBytes
    $boundPaths = @{}
    foreach ($entry in $plan.Entries) { $boundPaths[$entry.Before.Path] = $true }
    foreach ($event in $journal.Events) {
        if ($event.SourceHash -cne $SourceHash -or ($event.PlanHash -and $event.PlanHash -ine $PlanSHA256) -or
            ($event.Target -and $event.Target -ine $plan.Target)) { throw 'Recovery journal/source binding mismatch.' }
        if ($event.Stage -in @('WriteIntent','WriteReturned','PathVerified')) {
            if ($event.PlanHash -ine $PlanSHA256 -or $event.Target -ine $plan.Target) { throw 'Recovery path event lacks exact plan/target binding.' }
            foreach ($change in @($event.Changes)) {
                $changedPath = if ($change -is [string]) { $change } else { [string]$change.Path }
                if (-not $boundPaths.ContainsKey($changedPath) -or (ConvertTo-NpPath $changedPath) -cne $changedPath) { throw 'Recovery path outside bound canonical scope.' }
            }
        }
    }
    $hasProof = @($journal.Events | Where-Object { $_.Stage -eq 'PathVerified' -and $_.PlanHash -ieq $PlanSHA256 }).Count -gt 0
    return [pscustomobject]@{
        Status = $(if ($journal.Status -ne 'Verified') { 'Indeterminate' } elseif (-not $hasProof) { 'Blocked' } else { 'ReviewRequired' })
        Plan=$plan; Journal=$journal; ManifestSHA256=(Get-NpBytesHash $manifestBytes)
        RecoveryModel=$plan.Recovery; CurrentState='Unverified'; HasNativeStateProof=$false
        Executable=$false
    }
}

function Enter-NpTargetLock([string]$Target) {
    $name = 'NtfsPermissions_' + (Get-NtfsHash ((ConvertTo-NpPath $Target).ToLowerInvariant()))
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $name = 'Global\' + $name }
    $mutex = [Threading.Mutex]::new($false,$name)
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] {
            $owned = $true
            throw 'Abandoned local target lock; review previous operation evidence before proceeding.'
        }
        if (-not $owned) { throw 'Target is locked by another local operation.' }
        return $mutex
    } catch {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
        throw
    }
}

function Get-NpRevertDecision($Current, $Before, $ExpectedAfter) {
    if ((Get-NpCanonicalJson $Current) -ceq (Get-NpCanonicalJson $Before)) { return 'NoOp' }
    if ((Get-NpCanonicalJson $Current) -ceq (Get-NpCanonicalJson $ExpectedAfter)) { return 'RestoreBefore' }
    return 'RevertConflict'
}

function Invoke-NpOfflineCoordinator {
    <#
    .SYNOPSIS
    Internal synthetic state-machine contract, NOT a native Windows writer.
    .DESCRIPTION
    Accepts only explicitly labeled offline fixtures. No public script parameter
    exposes injection. ExpectedAfter is an abstract intent model, never a native
    descriptor. Mocked success cannot qualify NTFS inheritance or release gates.
    #>
    param($Plan, $Journal, $Adapter, [ValidateSet('Apply','Revert')]$Mode = 'Apply', [switch]$WhatIf, [bool]$Approved = $true)
    if ($Adapter.Kind -cne 'OfflineFixture') { throw 'Only synthetic offline fixtures are supported. Native writer absent/NotQualified.' }
    $attempted = $false
    try {
        Write-NpEvent $Journal 'Preflight' 'Started'
        if ($WhatIf -or -not $Approved) {
            Write-NpEvent $Journal 'Complete' 'WhatIf'
            return 'WhatIf'
        }
        if (-not $Plan.CoverageComplete) { throw 'Incomplete approved coverage.' }
        Assert-NpTargetDescriptor $Plan.TargetDescriptor $Plan.Target
        if ((Get-NpCanonicalJson (New-NpRecoveryModel $Plan.TargetDescriptor $Plan.Entries)) -cne (Get-NpCanonicalJson $Plan.Recovery)) { throw 'Recovery model binding mismatch.' }
        if ($Adapter.PSObject.Properties.Name -contains 'TargetDescriptor' -and
            (Get-NpCanonicalJson $Adapter.TargetDescriptor) -cne (Get-NpCanonicalJson $Plan.TargetDescriptor)) { throw 'Namespace drift.' }
        Assert-NpNormalizedGrants $Plan.Grants
        # Validate all proposals and all drift BEFORE any setter.
        $work = @()
        foreach ($entry in $Plan.Entries) {
            Assert-NpSnapshot $entry.Before
            if ($entry.Before.Identity -notmatch '^fixture-' -or $entry.Before.Descriptor -notmatch '^fixture-before:') { throw 'Offline coordinator requires synthetic fixture identities/descriptors.' }
            $root = $entry.Before.Path -ieq $Plan.Target
            $proposal = if ($entry.Boundary) { [pscustomobject]@{Intent=$entry.Before;NoOp=$true} } else { New-NpProposal $entry.Before $Plan.Grants $Plan.Scope $root }
            if ((Get-NpCanonicalJson $proposal) -cne (Get-NpCanonicalJson $entry.Proposal)) { throw 'Proposal mismatch.' }
            $current = & $Adapter.Read $entry.Before.Path
            if ($Mode -eq 'Apply') {
                if ((Get-NpCanonicalJson $current) -cne (Get-NpCanonicalJson $entry.Before)) { throw 'Pre-write drift (descriptor/control/identity).' }
                $decision = if ($proposal.NoOp) { 'NoOp' } else { 'Write' }
                $desired = $proposal.Intent
            } else {
                $decision = Get-NpRevertDecision $current $entry.Before $proposal.Intent
                if ($decision -eq 'RevertConflict') { Write-NpEvent $Journal 'Preflight' 'RevertConflict'; return 'RevertConflict' }
                $desired = $entry.Before
            }
            $work += [pscustomobject]@{ Path=$entry.Before.Path; Current=$current; Desired=$desired; Decision=$decision }
        }
        foreach ($step in $work) {
            if ($step.Decision -eq 'NoOp') { continue }
            if ((Get-NpCanonicalJson (& $Adapter.Read $step.Path)) -cne (Get-NpCanonicalJson $step.Current)) { throw 'Concurrent drift before intent.' }
            Write-NpEvent $Journal 'WriteIntent' 'Pending' @([ordered]@{
                Path=$step.Path; BeforeSHA256=(Get-NtfsHash (Get-NpCanonicalJson $step.Current))
                DesiredIntentSHA256=(Get-NtfsHash (Get-NpCanonicalJson $step.Desired))
                FixtureOnly=$true
            })
            $attempted = $true
            $null = & $Adapter.Write $step.Path $step.Desired
            Write-NpEvent $Journal 'WriteReturned' 'Unverified' @($step.Path)
            if ((Get-NpCanonicalJson (& $Adapter.Read $step.Path)) -cne (Get-NpCanonicalJson $step.Desired)) { throw 'Verification mismatch.' }
            Write-NpEvent $Journal 'PathVerified' 'Verified' @($step.Path)
        }
        # Propagation/concurrent drift verification is per path, including unchanged boundaries.
        foreach ($step in $work) {
            if ((Get-NpCanonicalJson (& $Adapter.Read $step.Path)) -cne (Get-NpCanonicalJson $step.Desired)) { throw 'Final per-path verification mismatch.' }
        }
        $status = if (@($work | Where-Object Decision -ne 'NoOp').Count -eq 0) { 'NoOp' } elseif ($Mode -eq 'Revert') { 'Reverted' } else { 'Verified' }
        Write-NpEvent $Journal 'Complete' $status
        return $status
    } catch {
        $status = if ($attempted) { 'Indeterminate' } else { 'Failed' }
        try { Write-NpEvent $Journal 'Stopped' $status } catch { }
        return $status
    }
}
