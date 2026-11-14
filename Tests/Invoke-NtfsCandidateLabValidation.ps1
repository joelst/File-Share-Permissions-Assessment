#requires -Version 5.1
# DISCLAIMER:
# This script is provided "AS IS", without warranty or support. Use only in an
# approved disposable lab with independently verified backup and recovery.
<#
.SYNOPSIS
Exercises the unqualified local candidate on a newly generated disposable fixture.
.DESCRIPTION
Creates a new fixture beneath the supplied local fixed NTFS parent. It never
accepts an existing write target or changes AD membership. Two pre-existing,
dedicated nonadministrator domain accounts test allowed and negative-control access. An
optional separate Windows client uses a temporary share created solely for this
fixture; the share is removed before each candidate write.

By default the group starts with ReadAndExecute access. StartWithoutGroupGrant
instead tests a first grant; with a client, a separate held-handle control file
has an explicit read grant to the allowed account.

The candidate applies and reverts one selected grant. Failures stop without automatic
rollback; retain the fixture, plans, journals and locks for independent review.
This is not a production writer, public Apply/Revert bypass, or qualification
of local NTFS, SMB, NAS, or any customer environment.
.EXAMPLE
$allowed = Get-Credential 'LAB\CandidateAllowed'
$control = Get-Credential 'LAB\CandidateControl'
.\Tests\Invoke-NtfsCandidateLabValidation.ps1 -fixtureParent D:\DisposableLab `
    -evidenceRoot D:\LabEvidence -groupName 'LAB\CandidateWriters' `
    -allowedCredential $allowed -controlCredential $control -changeTicket LAB-123 `
    -disposableAcknowledgement
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
    Justification = 'The held stream must persist between commands in a dedicated temporary PSSession.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '',
    Justification = 'Remote values use explicit script-block parameters or the remote environment.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $fixtureParent,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $evidenceRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $groupName,
    [Parameter(Mandatory = $true)][ValidateNotNull()][pscredential] $allowedCredential,
    [Parameter(Mandatory = $true)][ValidateNotNull()][pscredential] $controlCredential,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $changeTicket,
    [ValidateSet('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles')]
    [string] $scope = 'ThisFolderSubfoldersAndFiles',
    [ValidateSet('Read', 'ReadAndExecute', 'Modify', 'FullControl')]
    [string] $permissions = 'Modify',
    [string] $clientComputerName,
    [switch] $startWithoutGroupGrant,
    [switch] $disposableAcknowledgement
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $disposableAcknowledgement) {
    throw 'DisposableAcknowledgement and independent approval for this lab are required.'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The candidate validation runner requires Windows.'
}
if ($changeTicket -match '[\x00-\x1f]' -or [string]::IsNullOrWhiteSpace($changeTicket)) {
    throw 'A nonempty lab change ticket without control characters is required.'
}
$credentials = @{ Allowed = $allowedCredential; Control = $controlCredential }
foreach ($credential in $credentials.Values) {
    if ($credential.UserName -notmatch '^[^\\/\x00-\x20]+\\[^\\/\x00-\x1f]+$' -or
        $credential.UserName -match '^(?:\.|localhost|BUILTIN)\\' -or
        $credential.UserName.StartsWith([Environment]::MachineName + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Use dedicated domain credentials in DOMAIN\account form, not local accounts.'
    }
}
if ($allowedCredential.UserName -ieq $controlCredential.UserName) {
    throw 'Allowed and control credentials must identify different accounts.'
}
if ($clientComputerName -and $clientComputerName -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') {
    throw 'The optional client must be a Windows computer name or DNS name.'
}

$scriptPath = $PSCommandPath
$repository = Split-Path $PSScriptRoot -Parent
. (Join-Path $repository 'NtfsPermissions.Local.ps1')
$probePath = Join-Path $PSScriptRoot 'NtfsCandidateLabProbe.cs'
$probeBytes = [IO.File]::ReadAllBytes($probePath)
$probeHash = Get-NpBytesHash $probeBytes
$probeSource = [Text.UTF8Encoding]::new($false, $true).GetString($probeBytes).Replace('__SOURCE_SHA256__', $probeHash)
$probeType = 'NtfsCandidateLab.Probe' -as [type]
if ($null -eq $probeType) {
    Add-Type -TypeDefinition $probeSource -ErrorAction Stop
} elseif ($probeType::SourceSHA256 -cne $probeHash) {
    throw 'Probe source changed after assembly load; start a new PowerShell process.'
}
Import-Module ActiveDirectory -ErrorAction Stop
$grants = @(Get-NpGrants -GroupName $groupName -Permissions $permissions -Resolve ${function:Resolve-NpWindowsGroup})
$accountSids = @{}
foreach ($role in @('Allowed', 'Control')) {
    $accountSids[$role] = ([Security.Principal.NTAccount]::new($credentials[$role].UserName)).
        Translate([Security.Principal.SecurityIdentifier]).Value
}
if ($accountSids.Allowed -eq $accountSids.Control -or $accountSids.Allowed -eq $grants[0].SID -or
    $accountSids.Control -eq $grants[0].SID) {
    throw 'The allowed account, control account, and security group must have distinct SIDs.'
}
$parent = Resolve-NpTarget -Path $fixtureParent -TargetPlatform Windows
if ($parent.Addressing -cne 'LocalFixed' -or
    -not (Test-Path -LiteralPath $parent.CanonicalPath -PathType Container)) {
    throw 'FixtureParent must be an existing direct local fixed NTFS directory.'
}
Initialize-NpLocalNative
$parentLease = [NtfsPermissions.LocalCandidate.Lease]::Open($parent.CanonicalPath, $false)
try { $null = $parentLease.Read() } finally { $parentLease.Dispose() }
$id = [guid]::NewGuid().ToString('N')
$fixture = Join-Path $parent.CanonicalPath ('CandidateValidation_' + $id)
$shareName = 'NtfsCandidate-' + $id.Substring(0, 12)
$run = New-NpRun -OutputDirectory $evidenceRoot -Target $fixture
$observations = [Collections.Generic.List[object]]::new()
$cleanupErrors = [Collections.Generic.List[string]]::new()
$session = $null
$serverName = ''
$clientName = ''
$shareOpen = $false
$plan = $null
$planHash = ''
$applyPath = ''
$applyHash = ''
$revertPath = ''
$revertHash = ''
$baseline = @()
$after = @()
$stage = 'Starting'
$status = 'Failed'
$failure = ''
$restored = $false
$heldClientStatus = 'NotRun'
$whatIfStatus = 'NotRun'
$applyStatus = 'NotRun'
$revertStatus = 'NotRun'

function Write-LabJson([string]$Name, $Value) {
    $Value | ConvertTo-Json -Depth 40 |
        Set-Content -LiteralPath (Join-Path $run $Name) -Encoding UTF8 -ErrorAction Stop
}

function Write-LabState {
    Write-LabJson 'state.json' ([ordered]@{
        Status = $status; Stage = $stage; Fixture = $fixture; Scope = $scope
        Permissions = $permissions
        StartWithoutGroupGrant = [bool]$startWithoutGroupGrant
        Share = $(if ($clientComputerName) { $shareName } else { '' }); ShareOpen = $shareOpen
        PlanSHA256 = $planHash; ApplyJournal = $applyPath; ApplyJournalSHA256 = $applyHash
        RevertJournal = $revertPath; RevertJournalSHA256 = $revertHash
        BaselineRestored = $restored; Failure = $failure; CleanupErrors = @($cleanupErrors)
        WriterQualification = 'NotQualified'
    })
}

function Invoke-LabCandidateApply {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $auditDirectory, [bool] $preview)
    $journal = New-NpJournal $auditDirectory Apply $changeTicket '' $fixture
    $orchestration = New-NpJournal $auditDirectory Apply $changeTicket '' $fixture
    $orchestration.Path = Join-Path $auditDirectory 'orchestration.jsonl'
    $result = Invoke-NpLocalCandidate -journal $journal -disposableAcknowledgement `
        -applyTargetPath $fixture -applyGrants $grants -applyScope $scope -applyMaxPaths 100 `
        -orchestration $orchestration -WhatIf:$preview -Confirm:$false
    return [pscustomobject]@{ Result = $result; Journal = $journal }
}

function Get-FixtureEvidence {
    @(Get-Item -LiteralPath $fixture -ErrorAction Stop
        Get-ChildItem -LiteralPath $fixture -Recurse -Force -ErrorAction Stop) |
        ForEach-Object {
            [pscustomobject]@{
                Path = $_.FullName; Sddl = (Get-Acl -LiteralPath $_.FullName -ErrorAction Stop).Sddl
                ContentSHA256 = $(if ($_.PSIsContainer) { '' } else {
                    (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                })
            }
        } | Sort-Object Path
}

function Assert-FixtureEvidence($Expected, $Actual, [string]$Label) {
    $left = @($Expected | ForEach-Object { "$($_.Path)|$($_.Sddl)|$($_.ContentSHA256)" } | Sort-Object)
    $right = @($Actual | ForEach-Object { "$($_.Path)|$($_.Sddl)|$($_.ContentSHA256)" } | Sort-Object)
    if (@(Compare-Object $left $right).Count) { throw "$Label differs; stop and review the fixture." }
}

function Assert-PlanImage([string]$State) {
    $current = @(Get-NpLocalInventory -targetPath $fixture -maxPaths 100)
    $expected = @($plan.Entries | ForEach-Object { $_.$State })
    if ((Get-NpCanonicalJson $current) -cne (Get-NpCanonicalJson $expected)) {
        throw "Candidate $State identity/descriptor inventory differs."
    }
}

function Open-LabShare([string]$Phase) {
    if ($shareOpen -or @(Get-SmbShare | Where-Object Name -eq $shareName).Count) {
        throw 'The generated share name already exists.'
    }
    $null = New-SmbShare -Name $shareName -Path $fixture -EncryptData $true `
        -FullAccess @($groupName, $controlCredential.UserName, 'BUILTIN\Administrators') -ErrorAction Stop
    $script:shareOpen = $true
    Write-LabJson "$Phase-share.json" @(Get-SmbShareAccess -Name $shareName |
        Select-Object AccountName, AccessControlType, AccessRight)
}

function Close-LabShare([string]$Phase) {
    if (-not $shareOpen -or (Get-SmbShare -Name $shareName -ErrorAction Stop).Path -ine $fixture) {
        throw 'The generated share is absent or points to a different target.'
    }
    Remove-SmbShare -Name $shareName -Force -Confirm:$false -ErrorAction Stop
    if (@(Get-SmbShare | Where-Object Name -eq $shareName).Count) { throw 'Generated share remains.' }
    $script:shareOpen = $false
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $files = @(Get-SmbOpenFile | Where-Object {
            $_.Path -ieq $fixture -or $_.Path.StartsWith($fixture + '\', [StringComparison]::OrdinalIgnoreCase)
        })
        if (-not $files.Count) { break }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt 10)
    Write-LabJson "$Phase-share-removed.json" ([ordered]@{
        Share = $shareName; Fixture = $fixture; ElapsedMilliseconds = $watch.ElapsedMilliseconds
        RemainingFiles = @($files | Select-Object FileId, SessionId, ClientUserName, Path)
    })
    if ($files.Count) { throw 'Fixture SMB handles remain; no further candidate write is allowed.' }
}

$accessScript = {
    param([pscredential]$Credential, [string]$ExpectedSid, [object[]]$Specs, [string]$Phase, [string]$Role,
        [string]$ProbeSource, [string]$ProbeHash)
    $ErrorActionPreference = 'Stop'
    $probeType = 'NtfsCandidateLab.Probe' -as [type]
    if ($null -eq $probeType) {
        Add-Type -TypeDefinition $ProbeSource -ErrorAction Stop
    } elseif ($probeType::SourceSHA256 -cne $ProbeHash) {
        throw 'Remote probe source changed after assembly load.'
    }
    if (-not ('NtfsCandidateLabLogon' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class NtfsCandidateLabLogon {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LogonUser(string user, string domain, string password,
        int logonType, int provider, out SafeAccessTokenHandle token);
}
'@
    }
    $network = $Credential.GetNetworkCredential()
    $token = $null
    try {
        if (-not [NtfsCandidateLabLogon]::LogonUser($network.UserName, $network.Domain,
                $network.Password, 8, 0, [ref]$token)) {
            throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        $results = [Collections.Generic.List[object]]::new()
        foreach ($spec in $Specs) {
            $bag = @{ Success = $false; Error = ''; Unexpected = $false; Actor = ''; Sid = ''; Administrator = $false }
            $callback = {
                $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
                $bag.Actor = $identity.Name
                $bag.Sid = $identity.User.Value
                $bag.Administrator = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator) -or
                    @($identity.Groups | Where-Object Value -eq 'S-1-5-32-544').Count -gt 0
                try {
                    switch ($spec.Operation) {
                        Read { $null = [IO.File]::ReadAllText($spec.Path) }
                        Modify { [NtfsCandidateLab.Probe]::AppendKnown($spec.Path, $spec.Marker) }
                        Create {
                            $stream = [IO.File]::Open($spec.Path, 'CreateNew', 'Write', 'None')
                            try {
                                $bytes = [Text.Encoding]::UTF8.GetBytes($spec.Marker)
                                $stream.Write($bytes, 0, $bytes.Length)
                            } finally { $stream.Dispose() }
                        }
                        DeleteExisting {
                            $null = [NtfsCandidateLab.Probe]::RemoveKnown($spec.Path, $spec.Marker, $false, $false)
                        }
                        DeleteChild {
                            $null = [NtfsCandidateLab.Probe]::DeleteByName($spec.Path)
                        }
                        default { throw "Unknown access operation: $($spec.Operation)" }
                    }
                    $bag.Success = $true
                } catch {
                    $exception = $_.Exception
                    while ($exception.InnerException) { $exception = $exception.InnerException }
                    $bag.Error = $exception.GetType().FullName + ': ' + $exception.Message
                    $bag.Unexpected = $exception -isnot [UnauthorizedAccessException]
                }
            }.GetNewClosure()
            [Security.Principal.WindowsIdentity]::RunImpersonated($token, [Action]$callback)
            $results.Add([pscustomobject]@{
                Phase = $Phase; Role = $Role; Client = $env:COMPUTERNAME
                Account = $bag.Actor; SID = $bag.Sid; Administrator = $bag.Administrator
                Operation = $spec.Operation; Path = $spec.Path; ExpectedSuccess = $spec.Expected
                ActualSuccess = $bag.Success; Error = $bag.Error
                Passed = ($bag.Success -eq $spec.Expected -and -not $bag.Unexpected -and
                    -not $bag.Administrator -and $bag.Sid -eq $ExpectedSid)
                Utc = [datetime]::UtcNow.ToString('o')
            })
        }
        $results.ToArray()
    } finally {
        if ($null -ne $token) { $token.Dispose() }
        $network = $null
    }
}

function Test-LabAccess([string]$Phase, [bool]$Granted) {
    $image = @(Get-FixtureEvidence)
    $endpoints = @([pscustomobject]@{ Name = $env:COMPUTERNAME; Root = $fixture; Remote = $false })
    if ($session) {
        $endpoints += [pscustomobject]@{ Name = $clientName; Root = "\\$serverName\$shareName"; Remote = $true }
    }
    foreach ($endpoint in $endpoints) {
        foreach ($role in @('Allowed', 'Control')) {
            $specs = [Collections.Generic.List[object]]::new()
            $temporary = [Collections.Generic.List[object]]::new()
            $checks = [Collections.Generic.List[object]]::new()
            $cleanupErrorCount = $cleanupErrors.Count
            try {
                foreach ($relative in @('', 'Child', 'Protected')) {
                    $local = if ($relative) { Join-Path $fixture $relative } else { $fixture }
                    $target = if ($relative) { Join-Path $endpoint.Root $relative } else { $endpoint.Root }
                    $canRead = if ($startWithoutGroupGrant) {
                        $role -ceq 'Allowed' -and $Granted -and
                            $scope -ceq 'ThisFolderSubfoldersAndFiles' -and $relative -cne 'Protected'
                    } else { $role -ceq 'Allowed' }
                    $normal = $role -ceq 'Allowed' -and $Granted -and $relative -cne 'Protected'
                    $canModify = $normal -and $permissions -in @('Modify', 'FullControl') -and
                        $scope -ceq 'ThisFolderSubfoldersAndFiles'
                    $canCreate = $normal -and $permissions -in @('Modify', 'FullControl') -and
                        ($scope -ceq 'ThisFolderSubfoldersAndFiles' -or -not $relative)
                    $canDeleteByName = $canModify -or ($normal -and $permissions -ceq 'FullControl' -and
                        ($scope -ceq 'ThisFolderSubfoldersAndFiles' -or -not $relative))
                    foreach ($operation in @('Read', 'Modify', 'Create', 'DeleteExisting', 'DeleteChild')) {
                        $name = if ($operation -ceq 'Read') { 'data.txt' } else {
                            "$Phase-$($endpoint.Name)-$role-$operation.txt"
                        }
                        $expected = switch ($operation) {
                            Read { $canRead }
                            Create { $canCreate }
                            DeleteExisting { $canRead -and $canDeleteByName }
                            DeleteChild { $canDeleteByName }
                            default { $canModify }
                        }
                        $targetPath = Join-Path $target $name
                        $marker = ''
                        if ($operation -cne 'Read') {
                            $path = Join-Path $local $name
                            if (Test-Path -LiteralPath $path) { throw "Generated probe already exists: $path" }
                            $marker = [guid]::NewGuid().ToString('N')
                            $check = [pscustomobject]@{
                                Operation = $operation; Path = $path; TargetPath = $targetPath
                                Expected = $expected; Marker = $marker; Owned = $false
                            }
                            $temporary.Add($check)
                            $checks.Add($check)
                            if ($operation -in @('Modify', 'DeleteExisting', 'DeleteChild')) {
                                $stream = [IO.File]::Open($path, 'CreateNew', 'Write', 'None')
                                $check.Owned = $true
                                try {
                                    $bytes = [Text.Encoding]::UTF8.GetBytes($marker)
                                    $stream.Write($bytes, 0, $bytes.Length)
                                } finally { $stream.Dispose() }
                            }
                        }
                        $specs.Add([pscustomobject]@{
                            Operation = $operation; Path = $targetPath; Expected = $expected; Marker = $marker
                        })
                    }
                }
                if ($endpoint.Remote) {
                    $results = @(Invoke-Command -Session $session -ScriptBlock $accessScript `
                        -ArgumentList $credentials[$role], $accountSids[$role], $specs.ToArray(), $Phase, $role, $probeSource, $probeHash)
                } else {
                    $results = @(& $accessScript $credentials[$role] $accountSids[$role] $specs.ToArray() $Phase $role $probeSource $probeHash)
                }
                foreach ($result in $results) {
                    $observations.Add($result)
                    if ($result.Operation -ceq 'Create' -and $result.ActualSuccess) {
                        $created = @($checks | Where-Object {
                            $_.Operation -ceq 'Create' -and $_.TargetPath -ieq $result.Path
                        })
                        if ($created.Count -ne 1) { throw 'Created probe did not match exactly one expected path.' }
                        $created[0].Owned = $true
                    }
                }
                Write-LabJson 'access-observations.json' @($observations)
                if ($results.Count -ne 15 -or @($results | Where-Object {
                        -not $_.Passed -or $_.Client -ine $endpoint.Name
                    }).Count) { throw "Access matrix failed: $Phase / $($endpoint.Name) / $role." }
                foreach ($check in $checks) {
                    $exists = [IO.File]::Exists($check.Path)
                    switch ($check.Operation) {
                        Modify {
                            $text = if ($check.Expected) { $check.Marker + '|modified' } else { $check.Marker }
                            if (-not $exists -or [IO.File]::ReadAllText($check.Path) -cne $text) {
                                throw 'Modify result did not match the actual file content.'
                            }
                        }
                        Create {
                            if ($exists -ne $check.Expected -or
                                ($exists -and [IO.File]::ReadAllText($check.Path) -cne $check.Marker)) {
                                throw 'Create result did not match the actual file content.'
                            }
                        }
                        DeleteExisting {
                            if ($exists -eq $check.Expected -or
                                ($exists -and [IO.File]::ReadAllText($check.Path) -cne $check.Marker)) {
                                throw 'Delete result did not match the actual file state.'
                            }
                        }
                        DeleteChild {
                            if ($exists -eq $check.Expected -or
                                ($exists -and [IO.File]::ReadAllText($check.Path) -cne $check.Marker)) {
                                throw 'Parent delete-child result did not match the actual file state.'
                            }
                        }
                    }
                }
            } finally {
                foreach ($check in $temporary) {
                    if (-not $check.Owned) { continue }
                    try {
                        $null = [NtfsCandidateLab.Probe]::RemoveKnown(
                            $check.Path, $check.Marker, ($check.Operation -ceq 'Modify'),
                            ($check.Operation -in @('DeleteExisting', 'DeleteChild') -and $check.Expected))
                    } catch {
                        $exception = $_.Exception
                        while ($exception.InnerException) { $exception = $exception.InnerException }
                        $cleanupErrors.Add('Probe cleanup: ' + $exception.Message)
                    }
                }
            }
            if ($cleanupErrors.Count -gt $cleanupErrorCount) { throw 'Probe cleanup failed; preserve the fixture.' }
        }
    }
    Assert-FixtureEvidence -Expected $image -Actual @(Get-FixtureEvidence) -Label "$Phase functional probes"
}

try {
    Write-LabState
    $sourceFiles = @(
        foreach ($name in @('Add-FileSharePermissions.ps1', 'NtfsAssessment.Common.ps1',
                'NtfsPermissions.Common.ps1', 'NtfsPermissions.Local.ps1', 'NtfsPermissions.Local.cs')) {
            Join-Path $repository $name
        }
        $scriptPath
        $probePath
    )
    $sourceFiles | ForEach-Object { Get-FileHash -LiteralPath $_ -Algorithm SHA256 -ErrorAction Stop } |
        Select-Object Path, Algorithm, Hash |
        Export-Csv -LiteralPath (Join-Path $run 'source-hashes.csv') -NoTypeInformation -Encoding UTF8
    Write-LabJson 'environment.json' ([ordered]@{
        Host = [Environment]::MachineName; PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        OSVersion = [Environment]::OSVersion.VersionString; SourceHash = Get-NpSourceHash
        Group = $groupName; GroupSID = $grants[0].SID; Permissions = $permissions
        AllowedAccount = $allowedCredential.UserName; ControlAccount = $controlCredential.UserName
        WriterQualification = 'NotQualified'
    })
    if ($clientComputerName) {
        $session = New-PSSession -ComputerName $clientComputerName -ErrorAction Stop
        $clientInfo = Invoke-Command -Session $session -ScriptBlock {
            [pscustomobject]@{ Computer = $env:COMPUTERNAME; PowerShellVersion = $PSVersionTable.PSVersion.ToString() }
        }
        if (-not $clientInfo.Computer -or $clientInfo.Computer -ieq [Environment]::MachineName) {
            throw 'The SMB client must be a distinct Windows computer.'
        }
        $clientName = $clientInfo.Computer
        $serverName = [Net.Dns]::GetHostEntry([Environment]::MachineName).HostName
        Write-LabJson 'client.json' $clientInfo
    }
    if (Test-Path -LiteralPath $fixture) { throw 'Generated fixture already exists.' }
    $null = New-Item -Path $fixture -ItemType Directory -ErrorAction Stop
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $actor = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($actor)
    $principals = @('S-1-5-18', 'S-1-5-32-544', $actor.Value)
    if (-not $startWithoutGroupGrant) { $principals += $grants[0].SID }
    foreach ($principal in $principals | Select-Object -Unique) {
        $rights = if ($principal -eq $grants[0].SID) { 'ReadAndExecute' } else { 'FullControl' }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($principal), $rights,
            'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $fixture -AclObject $acl -ErrorAction Stop
    $null = New-Item -Path (Join-Path $fixture 'Child') -ItemType Directory -ErrorAction Stop
    $null = New-Item -Path (Join-Path $fixture 'Protected') -ItemType Directory -ErrorAction Stop
    Set-Acl -LiteralPath (Join-Path $fixture 'Protected') -AclObject $acl -ErrorAction Stop
    foreach ($relative in @('', 'Child', 'Protected')) {
        $directory = if ($relative) { Join-Path $fixture $relative } else { $fixture }
        [IO.File]::WriteAllText((Join-Path $directory 'data.txt'), 'Synthetic candidate validation data')
    }
    $heldRelative = 'Child\data.txt'
    if ($session -and $startWithoutGroupGrant) {
        $heldRelative = 'Child\held.txt'
        $heldPath = Join-Path $fixture $heldRelative
        [IO.File]::WriteAllText($heldPath, 'Synthetic held-handle control')
        $heldAcl = Get-Acl -LiteralPath $heldPath -ErrorAction Stop
        $heldAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($accountSids.Allowed), 'ReadAndExecute', 'Allow'))
        Set-Acl -LiteralPath $heldPath -AclObject $heldAcl -ErrorAction Stop
    }
    $baseline = @(Get-FixtureEvidence)
    Write-LabJson 'fixture-before.json' $baseline
    $restored = $true
    $stage = 'Baseline'
    Write-LabState
    if ($session) { Open-LabShare 'Baseline' }
    Test-LabAccess 'Before' $false

    if ($session) {
        $held = Invoke-Command -Session $session -ArgumentList $allowedCredential, "\\$serverName\$shareName\$heldRelative" -ScriptBlock {
            param([pscredential]$Credential, [string]$Path)
            $network = $Credential.GetNetworkCredential()
            $token = $null
            $bag = @{ Stream = $null; Actor = ''; Sid = '' }
            try {
                if (-not [NtfsCandidateLabLogon]::LogonUser($network.UserName, $network.Domain,
                        $network.Password, 8, 0, [ref]$token)) {
                    throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
                }
                $callback = {
                    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
                    $bag.Actor = $identity.Name; $bag.Sid = $identity.User.Value
                    $bag.Stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
                }.GetNewClosure()
                [Security.Principal.WindowsIdentity]::RunImpersonated($token, [Action]$callback)
                $global:NtfsCandidateHeldStream = $bag.Stream
                [pscustomobject]@{ Client = $env:COMPUTERNAME; Path = $Path; Actor = $bag.Actor; SID = $bag.Sid; Open = $bag.Stream.CanRead }
            } finally {
                if ($null -ne $token) { $token.Dispose() }
                $network = $null
            }
        }
        Write-LabJson 'held-client-handle.json' $held
        try {
            $open = @(Get-SmbOpenFile | Where-Object { $_.Path -ieq (Join-Path $fixture $heldRelative) })
            Write-LabJson 'held-server-open-files.json' @($open | Select-Object FileId, SessionId, ClientUserName, Path)
            if (-not $held.Open -or $held.SID -ne $accountSids.Allowed -or $held.Client -ine $clientName -or -not $open.Count) {
                throw 'The separate-client held file was not observed on the SMB server.'
            }
            $blockedRun = New-NpRun -OutputDirectory (Join-Path $run 'candidate-audits') -Target $fixture
            $stage = 'HeldClientRefusal'
            $restored = $false
            Write-LabState
            $blockedAttempt = Invoke-LabCandidateApply -auditDirectory $blockedRun
            $blockedJournal = $blockedAttempt.Journal
            $blocked = $blockedAttempt.Result
            $heldClientStatus = $blocked.Status
            Write-LabJson 'held-client-result.json' $blocked
            if ($blocked.Status -cne 'Blocked' -or $blocked.Error -notmatch 'Cannot pin') {
                throw 'The candidate did not fail closed on the held SMB file.'
            }
            if (Test-Path -LiteralPath $blockedJournal.Path) {
                $events = Read-NpJournal -Path $blockedJournal.Path
                if ($events.Status -cne 'Verified' -or @($events.Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count) {
                    throw 'Held-client refusal lacks clean zero-write evidence.'
                }
            }
            Assert-FixtureEvidence -Expected $baseline -Actual @(Get-FixtureEvidence) -Label 'Held-client refusal'
            $restored = $true
        } finally {
            Invoke-Command -Session $session -ScriptBlock {
                if ($null -ne $global:NtfsCandidateHeldStream) {
                    $global:NtfsCandidateHeldStream.Dispose()
                    $global:NtfsCandidateHeldStream = $null
                }
            }
        }
        Close-LabShare 'BeforeApply'
    }

    $stage = 'WhatIf'
    Write-LabState
    $dryRun = New-NpRun -OutputDirectory (Join-Path $run 'candidate-audits') -Target $fixture
    $dryAttempt = Invoke-LabCandidateApply -auditDirectory $dryRun -preview $true
    $dryJournal = $dryAttempt.Journal
    $dry = $dryAttempt.Result
    $whatIfStatus = $dry.Status
    Write-LabJson 'whatif-result.json' $dry
    $dryEvents = Read-NpJournal -Path $dryJournal.Path
    if ($dry.Status -cne 'WhatIfOrDeclined' -or $dryEvents.Status -cne 'Verified' -or
        $dryEvents.Events[-1].Stage -cne 'CandidateComplete' -or
        $dryEvents.Events[-1].Result -cne 'WhatIfOrDeclined' -or
        @($dryEvents.Events | Where-Object Stage -ceq 'CandidateWriteIntent').Count) {
        throw 'Candidate WhatIf did not establish zero write intents.'
    }
    $plan = [Text.UTF8Encoding]::new($false, $true).GetString(
        [IO.File]::ReadAllBytes($dry.RecoveryRecordPath)) | ConvertFrom-NpJson
    Assert-PlanImage 'Before'
    Assert-FixtureEvidence -Expected $baseline -Actual @(Get-FixtureEvidence) -Label 'After WhatIf'

    $stage = 'Apply'
    $restored = $false
    $applyStatus = 'Started'
    $plan = $null
    $planHash = ''
    $applyRun = New-NpRun -OutputDirectory (Join-Path $run 'candidate-audits') -Target $fixture
    $applyPath = Join-Path $applyRun 'events.jsonl'
    Write-LabState
    $applyAttempt = Invoke-LabCandidateApply -auditDirectory $applyRun
    $apply = $applyAttempt.Result
    $applyStatus = $apply.Status
    Write-LabJson 'apply-result.json' $apply
    if (-not $apply.RecoveryRecordPath -or -not (Test-Path -LiteralPath $apply.RecoveryRecordPath)) {
        throw "Candidate Apply did not preserve its recovery record: $($apply.Error)"
    }
    $bytes = [IO.File]::ReadAllBytes($apply.RecoveryRecordPath)
    $planHash = Get-NpBytesHash $bytes
    if ($planHash -cne $apply.RecoveryRecordSHA256) { throw 'Candidate Apply recovery record hash mismatch.' }
    $plan = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-NpJson
    $planFile = Join-Path $run 'candidate-plan.json'
    $stream = [IO.FileStream]::new($planFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $expectedCandidateStatus = if (@($plan.Entries | Where-Object {
        $_.Before.Descriptor -cne $_.Desired.Descriptor
    }).Count) { 'Verified' } else { 'NoOp' }
    if ($apply.Status -cne $expectedCandidateStatus) { throw "Candidate Apply did not verify: $($apply.Status) $($apply.Error)" }
    $applyEvents = Read-NpJournal -Path $applyPath
    $applyHash = $applyEvents.SHA256
    Assert-NpLocalApplyEvidence -plan $plan -planSHA256 $planHash -applyJournalPath $applyPath -applyJournalSHA256 $applyHash
    Assert-PlanImage 'Desired'
    $after = @(Get-FixtureEvidence)
    Write-LabJson 'fixture-after-apply.json' $after
    $stage = 'AfterApply'
    Write-LabState
    if ($session) { Open-LabShare 'AfterApply' }
    Test-LabAccess 'AfterApply' $true
    if ($session) { Close-LabShare 'BeforeRevert' }
    Assert-FixtureEvidence -Expected $after -Actual @(Get-FixtureEvidence) -Label 'Before Revert'

    $stage = 'Revert'
    $revertStatus = 'Started'
    $revertRun = New-NpRun -OutputDirectory (Join-Path $run 'candidate-audits') -Target $fixture
    $revertJournal = New-NpJournal $revertRun Revert $changeTicket $planHash $fixture
    $revertPath = $revertJournal.Path
    Write-LabState
    $revert = Invoke-NpLocalCandidate -plan $plan -planSHA256 $planHash -journal $revertJournal `
        -mode Revert -applyJournalPath $applyPath -applyJournalSHA256 $applyHash `
        -disposableAcknowledgement -Confirm:$false
    $revertStatus = $revert.Status
    Write-LabJson 'revert-result.json' $revert
    if ($revert.Status -cne $expectedCandidateStatus) { throw "Candidate Revert did not verify: $($revert.Status) $($revert.Error)" }
    $revertEvents = Read-NpJournal -Path $revertPath
    $revertHash = $revertEvents.SHA256
    if ($revertEvents.Status -cne 'Verified' -or $revertEvents.Events[-1].Stage -cne 'CandidateComplete' -or
        $revertEvents.Events[-1].Result -cne $expectedCandidateStatus) { throw 'Candidate Revert journal is incomplete.' }
    Assert-PlanImage 'Before'
    Assert-FixtureEvidence -Expected $baseline -Actual @(Get-FixtureEvidence) -Label 'After Revert'
    $restored = $true
    $stage = 'AfterRevert'
    Write-LabState
    if ($session) { Open-LabShare 'AfterRevert' }
    Test-LabAccess 'AfterRevert' $false
    if ($session) { Close-LabShare 'AfterRevert' }
    Assert-FixtureEvidence -Expected $baseline -Actual @(Get-FixtureEvidence) -Label 'Final fixture'
    $status = 'Observed'
    $stage = 'Completed'
} catch {
    $restored = $false
    $failure = $_.Exception.Message + ' ' + $_.ScriptStackTrace
    Write-Warning $failure
} finally {
    if ($shareOpen) {
        try { Close-LabShare 'Cleanup' }
        catch { $cleanupErrors.Add('Temporary share cleanup: ' + $_.Exception.Message) }
    }
    if ($null -ne $session) {
        try { Remove-PSSession -Session $session -ErrorAction Stop }
        catch { $cleanupErrors.Add('Remote session cleanup: ' + $_.Exception.Message) }
    }
    if ($cleanupErrors.Count) { $status = 'Failed'; $restored = $false }
    Write-LabState
    Write-LabJson 'summary.json' ([ordered]@{
        Status = $status; Stage = $stage; Failure = $failure; CleanupErrors = @($cleanupErrors)
        EvidencePath = $run; Fixture = $fixture; Scope = $scope; Client = $clientName
        Permissions = $permissions
        StartWithoutGroupGrant = [bool]$startWithoutGroupGrant
        AccessChecks = $observations.Count; FailedChecks = @($observations | Where-Object { -not $_.Passed }).Count
        HeldClientResult = $heldClientStatus; WhatIf = $whatIfStatus
        CandidateApply = $applyStatus; CandidateRevert = $revertStatus; BaselineRestored = $restored
        PlanSHA256 = $planHash; ApplyJournal = $applyPath; ApplyJournalSHA256 = $applyHash
        RevertJournal = $revertPath; RevertJournalSHA256 = $revertHash
        WriterQualification = 'NotQualified'
        Limitations = 'Disposable local candidate only; not public Apply/Revert, SMB writer qualification, or production authorization.'
    })
    Get-ChildItem -LiteralPath $run -Recurse -File | Where-Object Name -ne 'SHA256SUMS.csv' |
        Get-FileHash -Algorithm SHA256 | Select-Object Path, Algorithm, Hash |
        Export-Csv -LiteralPath (Join-Path $run 'SHA256SUMS.csv') -NoTypeInformation -Encoding UTF8
}
if ($status -cne 'Observed') { throw "Candidate lab validation requires review; preserve $run. $failure $($cleanupErrors -join '; ')" }
[pscustomobject]@{
    Status = $status; EvidencePath = $run; Fixture = $fixture; AccessChecks = $observations.Count
    Permissions = $permissions; CandidateApply = $applyStatus; CandidateRevert = $revertStatus; BaselineRestored = $restored
    WriterQualification = 'NotQualified'
}
