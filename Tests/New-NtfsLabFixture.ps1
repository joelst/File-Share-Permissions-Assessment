#requires -Version 5.1
<#
.SYNOPSIS
Creates an isolated AD, NTFS and SMB assessment lab with fictional employees.
.DESCRIPTION
Requires Windows, a local fixed NTFS volume, the ActiveDirectory and SmbShare
modules, an elevated file-server session, and delegated rights to create an OU,
users and security groups beneath the supplied existing AD OU. The execution
host must be a domain-joined member server, not a domain controller.

Creates 100 disabled fictional employees by default, with departments, managers,
Global role groups and Domain Local permission groups (AGDLP). Only dedicated
scenario folders grant Everyone access. Publishes a new share with Everyone
Full access at the SMB layer so the distinct NTFS cases govern access.
No existing directory, AD group, user or share is reused or modified.

Use WhatIf to validate prerequisites and return the proposed inventory without
creating anything. A failed provision is preserved, not rolled back; inspect
the protected manifest and journal before manually cleaning up lab objects.
This provisions test data; it does not enable public permission Apply/Revert.
.PARAMETER rootPath
New lab directory beneath an existing local fixed NTFS parent, outside existing
nonadministrative shares. Must not already exist.
.PARAMETER evidencePath
New protected inventory directory beneath an existing local fixed NTFS parent,
outside the lab, checkout and existing nonadministrative shares.
.PARAMETER parentOu
Distinguished name of an approved existing OU for a new uniquely named lab OU.
.PARAMETER domainController
Writable domain controller used for all AD reads and writes in this run.
.PARAMETER employeeCount
Total fictional employees, including the executive and eight department managers.
.PARAMETER disposableAcknowledgement
Confirms approval to create disposable domain objects, files, ACLs and an SMB share.
.PARAMETER enableAccounts
Explicitly enable generated users after provisioning. Requires initialPassword.
Accounts expire after seven days and must change their password at first sign-in.
.PARAMETER initialPassword
Secure initial lab password, used only with enableAccounts. Never serialized.
.EXAMPLE
$parameters = @{
    rootPath = 'D:\NtfsLab'
    evidencePath = 'C:\NtfsLabInventory'
    parentOu = 'OU=Labs,DC=example,DC=test'
    domainController = 'DC01.example.test'
    disposableAcknowledgement = $true
}
.\Tests\New-NtfsLabFixture.ps1 @parameters -WhatIf
.\Tests\New-NtfsLabFixture.ps1 @parameters
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $rootPath,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $evidencePath,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $parentOu,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $domainController,
    [ValidateRange(17, 1000)][int] $employeeCount = 100,
    [switch] $disposableAcknowledgement,
    [switch] $enableAccounts,
    [Security.SecureString] $initialPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'NtfsAssessment.Common.ps1')

function Test-LabPathWithin {
    <#
    .SYNOPSIS
    Tests equality or a directory-boundary-contained path, ignoring case.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string] $path,
        [Parameter(Mandatory = $true)][string] $parent
    )
    $base = $parent.TrimEnd('\')
    return $path.Equals($base, [StringComparison]::OrdinalIgnoreCase) -or
        $path.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-LabNewPath {
    <#
    .SYNOPSIS
    Validates a new local fixed NTFS path and rejects reparse ancestors.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string] $path
    )
    if ($path -notmatch '^[A-Za-z]:\\' -or $path -match '[\x00-\x1f]' -or
        $path.Substring(2).Contains(':')) {
        throw 'Lab paths must be absolute local drive paths without streams or control characters.'
    }
    $fullPath = [IO.Path]::GetFullPath($path).TrimEnd('\')
    if ($fullPath -match '^[A-Za-z]:$' -or (Test-Path -LiteralPath $fullPath)) {
        throw "Lab paths must be new directories, not an existing path or volume root: $($path)"
    }
    $parentPath = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        throw "The parent directory must already exist: $($parentPath)"
    }
    $ancestor = Get-Item -LiteralPath $parentPath -Force
    while ($null -ne $ancestor) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse-point ancestors are not allowed: $($ancestor.FullName)"
        }
        $ancestor = $ancestor.Parent
    }
    $device = $fullPath.Substring(0, 2)
    $volume = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($device)'"
    if ($null -eq $volume -or $volume.DriveType -ne 3 -or $volume.FileSystem -ne 'NTFS') {
        throw "A local fixed NTFS volume is required: $($device)"
    }
    return $fullPath
}

function Set-LabDirectoryAcl {
    <#
    .SYNOPSIS
    Protects a newly created lab directory and adds only specified lab grants.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Private helper called only after the outer provisioning approval.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier] $operatorSid,
        [object[]] $grants = @()
    )
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($operatorSid)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', $operatorSid.Value) | Select-Object -Unique) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    foreach ($grant in $grants) {
        $identity = [Security.Principal.SecurityIdentifier]::new($grant.Sid)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity, $grant.Rights, $grant.Inheritance, 'None', $grant.Type))
    }
    $aclParameters = @{ LiteralPath = $path; AclObject = $acl; ErrorAction = 'Stop' }
    Set-Acl @aclParameters
    $observed = Get-Acl -LiteralPath $path
    $expectedRules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
        ForEach-Object { $_.IdentityReference.Value + ':' + $_.FileSystemRights + ':' + $_.InheritanceFlags + ':' + $_.PropagationFlags + ':' + $_.AccessControlType } |
        Sort-Object)
    $observedRules = @($observed.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
        ForEach-Object { $_.IdentityReference.Value + ':' + $_.FileSystemRights + ':' + $_.InheritanceFlags + ':' + $_.PropagationFlags + ':' + $_.AccessControlType } |
        Sort-Object)
    if (-not $observed.AreAccessRulesProtected -or
        ($expectedRules -join "`n") -cne ($observedRules -join "`n")) {
        throw "The new directory ACL did not match the intended protected grants: $($path)"
    }
}

function Write-LabJournal {
    <#
    .SYNOPSIS
    Records a completed operation without credentials or passwords.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $path,
        [Parameter(Mandatory = $true)][string] $action,
        [Parameter(Mandatory = $true)][string] $identity
    )
    [pscustomobject]@{ Utc = [datetime]::UtcNow.ToString('o'); Action = $action; Identity = $identity } |
        ConvertTo-Json -Compress |
        Add-Content -LiteralPath $path -Encoding UTF8
}

if (-not $disposableAcknowledgement) { throw 'DisposableAcknowledgement is required for lab provisioning or preview.' }
if ($enableAccounts -and ($null -eq $initialPassword -or $initialPassword.Length -eq 0)) {
    throw 'EnableAccounts requires a nonempty SecureString InitialPassword.'
}
if (-not $enableAccounts -and $null -ne $initialPassword) {
    throw 'InitialPassword is accepted only with EnableAccounts.'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This lab provisioner requires Windows.' }
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if (-not $computer.PartOfDomain -or $computer.DomainRole -ne 3) {
    throw 'Run this provisioner on a domain-joined member file server, not a workstation or domain controller.'
}
$rootPath = Resolve-LabNewPath -path $rootPath
$evidencePath = Resolve-LabNewPath -path $evidencePath
$repositoryPath = Split-Path $PSScriptRoot -Parent
if ((Test-LabPathWithin -path $rootPath -parent $evidencePath) -or
    (Test-LabPathWithin -path $evidencePath -parent $rootPath) -or
    (Test-LabPathWithin -path $rootPath -parent $repositoryPath) -or
    (Test-LabPathWithin -path $evidencePath -parent $repositoryPath)) {
    throw 'Lab, evidence and checkout paths must be separate, nonoverlapping directories.'
}
Import-Module -Name ActiveDirectory -ErrorAction Stop
Import-Module -Name SmbShare -ErrorAction Stop
$controller = Get-ADDomainController -Identity $domainController -Server $domainController
if ($controller.IsReadOnly) { throw 'A writable domain controller is required.' }
$domainController = $controller.HostName
$domain = Get-ADDomain -Server $domainController
if ($domain.DNSRoot -ine $computer.Domain) {
    throw 'The domain controller must belong to the file server domain for Domain Local permission groups.'
}
$null = Get-ADOrganizationalUnit -Identity $parentOu -Server $domainController
foreach ($share in @(Get-SmbShare)) {
    if (-not $share.Special -and $share.Path) {
        $backingPath = [IO.Path]::GetFullPath($share.Path)
        if ((Test-LabPathWithin -path $rootPath -parent $backingPath) -or
            (Test-LabPathWithin -path $evidencePath -parent $backingPath)) {
            throw "Lab and evidence paths must be outside existing shares: $($share.Name)"
        }
    }
}

$labId = [guid]::NewGuid().ToString('N').Substring(0, 8)
$prefix = 'NL' + $labId
$shareName = 'NtfsLab-' + $labId
$labOu = 'OU=' + $shareName + ',' + $parentOu
$usersOu = 'OU=Users,' + $labOu
$groupsOu = 'OU=Groups,' + $labOu
$collisions = @(Get-ADObject -LDAPFilter "(sAMAccountName=$($prefix)*)" -Server $domainController)
$ouCollisions = @(Get-ADObject -LDAPFilter "(ou=$($shareName))" -SearchBase $parentOu `
    -SearchScope OneLevel -Server $domainController)
if ($collisions.Count -or $ouCollisions.Count -or (Get-SmbShare | Where-Object Name -eq $shareName)) {
    throw 'Generated lab names already exist; no existing objects will be reused.'
}

$departments = @(
    @{ Code = 'HR'; Name = 'Human Resources' }
    @{ Code = 'FIN'; Name = 'Finance' }
    @{ Code = 'IT'; Name = 'Information Technology' }
    @{ Code = 'SAL'; Name = 'Sales' }
    @{ Code = 'MKT'; Name = 'Marketing' }
    @{ Code = 'OPS'; Name = 'Operations' }
    @{ Code = 'LEG'; Name = 'Legal' }
    @{ Code = 'ENG'; Name = 'Engineering' }
)
$firstNames = @('Avery', 'Jordan', 'Morgan', 'Taylor', 'Casey', 'Riley', 'Cameron', 'Quinn',
    'Alex', 'Jamie', 'Robin', 'Skyler', 'Drew', 'Reese', 'Rowan', 'Hayden', 'Blair', 'Parker', 'Sage', 'Emerson')
$lastNames = @('Bennett', 'Reed', 'Patel', 'Chen', 'Brooks', 'Rivera', 'Hayes', 'Sullivan',
    'Foster', 'Kim', 'Walsh', 'Shah', 'Clarke', 'Ellis', 'Park', 'Wells', 'Bell', 'Lane', 'Ross', 'Cole')
$users = @(
    for ($index = 0; $index -lt $employeeCount; $index++) {
        $isExecutive = $index -eq 0
        $isManager = $index -ge 1 -and $index -le 8
        $departmentIndex = if ($isExecutive) { 0 } elseif ($isManager) { $index - 1 } else { ($index - 9) % 8 }
        $department = $departments[$departmentIndex]
        $sam = '{0}u{1:D4}' -f $prefix, ($index + 1)
        $givenName = $firstNames[$index % $firstNames.Count]
        $surnameIndex = ($index + [int][math]::Floor($index / $firstNames.Count)) % $lastNames.Count
        $surname = $lastNames[$surnameIndex]
        $role = if ($isExecutive) { 'Executive' } elseif ($isManager) { 'Manager' } elseif (
            [int][math]::Floor(($index - 9) / 8) % 2) { 'Writer' } else { 'Reader' }
        $manager = if ($isExecutive) { '' } elseif ($isManager) { $prefix + 'u0001' } else {
            '{0}u{1:D4}' -f $prefix, ($departmentIndex + 2)
        }
        [pscustomobject][ordered]@{
            SamAccountName = $sam
            DistinguishedName = 'CN=' + $sam + ',' + $usersOu
            UserPrincipalName = $sam + '@' + $domain.DNSRoot
            GivenName = $givenName
            Surname = $surname
            DisplayName = $givenName + ' ' + $surname
            Department = $(if ($isExecutive) { 'Executive Office' } else { $department.Name })
            DepartmentCode = $(if ($isExecutive) { 'EXEC' } else { $department.Code })
            Title = $(if ($isExecutive) { 'Chief Executive Officer (Lab)' } elseif ($isManager) {
                $department.Name + ' Manager (Lab)'
            } else { $department.Name + ' Analyst (Lab)' })
            Role = $role
            ManagerSam = $manager
        }
    }
)
$groups = [Collections.Generic.List[object]]::new()
$memberships = [Collections.Generic.List[object]]::new()
foreach ($item in @(
    @{ Suffix = 'GG-ALL'; Scope = 'Global' }
    @{ Suffix = 'GG-MGR'; Scope = 'Global' }
    @{ Suffix = 'GG-DENY'; Scope = 'Global' }
    @{ Suffix = 'DL-ALL'; Scope = 'DomainLocal' }
    @{ Suffix = 'DL-MGR'; Scope = 'DomainLocal' }
    @{ Suffix = 'DL-DENY'; Scope = 'DomainLocal' }
)) {
    $groups.Add([pscustomobject]@{ Name = $prefix + '-' + $item.Suffix; Scope = $item.Scope })
}
foreach ($user in $users) {
    $memberships.Add([pscustomobject]@{ Group = $prefix + '-GG-ALL'; Member = $user.SamAccountName })
    if ($user.Role -in @('Executive', 'Manager')) {
        $memberships.Add([pscustomobject]@{ Group = $prefix + '-GG-MGR'; Member = $user.SamAccountName })
    }
}
foreach ($suffix in @('ALL', 'MGR', 'DENY')) {
    $memberships.Add([pscustomobject]@{ Group = $prefix + '-DL-' + $suffix; Member = $prefix + '-GG-' + $suffix })
}
$deniedUser = @($users | Where-Object Role -eq 'Reader')[0]
$memberships.Add([pscustomobject]@{ Group = $prefix + '-GG-DENY'; Member = $deniedUser.SamAccountName })
foreach ($department in $departments) {
    foreach ($role in @('R', 'W')) {
        $globalName = $prefix + '-GG-' + $department.Code + '-' + $role
        $localName = $prefix + '-DL-' + $department.Code + '-' + $role
        $groups.Add([pscustomobject]@{ Name = $globalName; Scope = 'Global' })
        $groups.Add([pscustomobject]@{ Name = $localName; Scope = 'DomainLocal' })
        $memberships.Add([pscustomobject]@{ Group = $localName; Member = $globalName })
        foreach ($user in @($users | Where-Object DepartmentCode -eq $department.Code)) {
            if (($role -eq 'W' -and $user.Role -in @('Writer', 'Manager')) -or
                ($role -eq 'R' -and $user.Role -eq 'Reader')) {
                $memberships.Add([pscustomobject]@{ Group = $globalName; Member = $user.SamAccountName })
            }
        }
    }
}

$scenarios = [Collections.Generic.List[object]]::new()
foreach ($department in $departments) {
    $scenarios.Add([pscustomobject]@{
        RelativePath = $department.Name
        Expected = 'Department Readers: read/execute; Writers and manager: modify; other departments: no grant.'
        Grants = @(
            @{ Principal = $prefix + '-DL-' + $department.Code + '-R'; Rights = 'ReadAndExecute'; Inheritance = 'ContainerInherit, ObjectInherit'; Type = 'Allow' }
            @{ Principal = $prefix + '-DL-' + $department.Code + '-W'; Rights = 'Modify'; Inheritance = 'ContainerInherit, ObjectInherit'; Type = 'Allow' }
        )
    })
}
foreach ($case in @(
    @{ Path = 'Everyone-Read'; Principal = 'S-1-1-0'; Rights = 'ReadAndExecute'; Expected = 'Everyone can read, not write.' }
    @{ Path = 'Everyone-Modify'; Principal = 'S-1-1-0'; Rights = 'Modify'; Expected = 'Everyone can create, edit and delete; intentional broad-write finding.' }
    @{ Path = 'Everyone-FullControl'; Principal = 'S-1-1-0'; Rights = 'FullControl'; Expected = 'Everyone has full control; intentional broad-access finding.' }
    @{ Path = 'Inherited'; Principal = $prefix + '-DL-ALL'; Rights = 'ReadAndExecute'; Expected = 'All lab employees read inherited descendants.' }
    @{ Path = 'ExplicitGrant'; Principal = $prefix + '-DL-MGR'; Rights = 'Modify'; Expected = 'Managers receive an explicit inheritable grant.' }
    @{ Path = 'DenyWrite'; Principal = $prefix + '-DL-ALL'; Rights = 'Modify'; Expected = "Lab employees modify except $($deniedUser.SamAccountName), whose Write is denied; delete is not denied." }
)) {
    $grants = @(@{ Principal = $case.Principal; Rights = $case.Rights; Inheritance = 'ContainerInherit, ObjectInherit'; Type = 'Allow' })
    if ($case.Path -eq 'DenyWrite') {
        $grants += @{ Principal = $prefix + '-DL-DENY'; Rights = 'Write'; Inheritance = 'ContainerInherit, ObjectInherit'; Type = 'Deny' }
    }
    $scenarios.Add([pscustomobject]@{ RelativePath = $case.Path; Expected = $case.Expected; Grants = $grants })
}
$scenarios.Add([pscustomobject]@{
    RelativePath = 'Inherited\Protected-Managers'
    Expected = 'Protected inheritance boundary; managers modify, other lab employees have no grant.'
    Grants = @(@{ Principal = $prefix + '-DL-MGR'; Rights = 'Modify'; Inheritance = 'ContainerInherit, ObjectInherit'; Type = 'Allow' })
})
$plan = [ordered]@{
    Version = $script:NtfsVersions.LabFixture
    LabId = $labId
    Notice = 'Fictional lab identities and placeholder data only. Not production write qualification.'
    RootPath = $rootPath
    EvidencePath = $evidencePath
    DomainController = $domainController
    LabOu = $labOu
    ShareName = $shareName
    SharePath = '\\' + [Environment]::MachineName + '\' + $shareName
    EnableAccounts = $enableAccounts.IsPresent
    AccountExpirationUtc = [datetime]::UtcNow.AddDays(7).ToString('o')
    DeniedUser = $deniedUser.SamAccountName
    Users = $users
    Groups = @($groups.ToArray())
    Memberships = @($memberships.ToArray())
    Scenarios = @($scenarios.ToArray())
}
if (-not $PSCmdlet.ShouldProcess(
    "$($rootPath); $($labOu); SMB $($shareName)",
    "Create disposable lab: $($users.Count) users, $($groups.Count) groups, placeholder files and Everyone-access scenarios")) {
    return [pscustomobject]@{ Status = 'PreviewOrDeclined'; Plan = [pscustomobject]$plan }
}

$operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$manifestPath = Join-Path $evidencePath 'manifest.json'
$journalPath = Join-Path $evidencePath 'operations.jsonl'
$logPath = Join-Path $evidencePath 'provisioning.log'
$state = [ordered]@{ Status = 'Provisioning'; StartedUtc = [datetime]::UtcNow.ToString('o'); Plan = $plan; Error = '' }
$evidenceCreated = $false
try {
    $null = New-Item -Path $evidencePath -ItemType Directory -ErrorAction Stop
    Set-LabDirectoryAcl -path $evidencePath -operatorSid $operatorSid
    $evidenceCreated = $true
    $state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Write-NtfsLog -Path $logPath -Component LabFixture -Level INFO -Stage Start -Message $labId
    $users | Export-Csv -LiteralPath (Join-Path $evidencePath 'employees.csv') -NoTypeInformation -Encoding UTF8

    foreach ($ou in @(
        @{ Name = $shareName; Path = $parentOu }
        @{ Name = 'Users'; Path = $labOu }
        @{ Name = 'Groups'; Path = $labOu }
    )) {
        $ouParameters = @{
            Name = $ou.Name; Path = $ou.Path; Server = $domainController
            Description = "Disposable fictional NTFS lab $($labId)"
            ProtectedFromAccidentalDeletion = $true; PassThru = $true; ErrorAction = 'Stop'
        }
        $created = New-ADOrganizationalUnit @ouParameters
        Write-LabJournal -path $journalPath -action 'CreatedOU' -identity $created.DistinguishedName
    }
    foreach ($group in $groups) {
        $groupParameters = @{
            Name = $group.Name; SamAccountName = $group.Name; GroupScope = $group.Scope
            GroupCategory = 'Security'; Path = $groupsOu; Server = $domainController
            Description = "Disposable fictional NTFS lab $($labId) AGDLP"
            PassThru = $true; ErrorAction = 'Stop'
        }
        $created = New-ADGroup @groupParameters
        Write-LabJournal -path $journalPath -action 'CreatedGroup' -identity $created.DistinguishedName
    }
    foreach ($user in $users) {
        $userParameters = @{
            Name = $user.SamAccountName; SamAccountName = $user.SamAccountName
            UserPrincipalName = $user.UserPrincipalName; GivenName = $user.GivenName; Surname = $user.Surname
            DisplayName = $user.DisplayName; Department = $user.Department; Title = $user.Title
            Company = 'Fictional NTFS Lab'; Description = "Synthetic employee for disposable lab $($labId)"
            EmployeeID = $user.SamAccountName; Path = $usersOu; Server = $domainController
            Enabled = $false; AccountExpirationDate = [datetime]::Parse($plan.AccountExpirationUtc)
            PassThru = $true; ErrorAction = 'Stop'
        }
        if ($enableAccounts) {
            $userParameters.AccountPassword = $initialPassword
            $userParameters.ChangePasswordAtLogon = $true
        }
        $created = New-ADUser @userParameters
        Write-LabJournal -path $journalPath -action 'CreatedDisabledUser' -identity $created.DistinguishedName
    }
    foreach ($user in @($users | Where-Object ManagerSam)) {
        $managerParameters = @{
            Identity = $user.DistinguishedName; Manager = 'CN=' + $user.ManagerSam + ',' + $usersOu
            Server = $domainController; ErrorAction = 'Stop'
        }
        Set-ADUser @managerParameters
        Write-LabJournal -path $journalPath -action 'SetManager' -identity $user.DistinguishedName
    }
    foreach ($membership in $memberships) {
        $membershipParameters = @{
            Identity = $membership.Group; Members = @($membership.Member)
            Server = $domainController; ErrorAction = 'Stop'
        }
        Add-ADGroupMember @membershipParameters
        Write-LabJournal -path $journalPath -action 'AddedMembership' -identity ($membership.Group + ' <- ' + $membership.Member)
    }

    $sidMap = @{}
    foreach ($group in $groups) {
        $observed = Get-ADGroup -Identity $group.Name -Properties Members -Server $domainController
        $expectedMembers = @(
            foreach ($membership in @($memberships | Where-Object Group -eq $group.Name)) {
                $memberOu = if ($membership.Member -match '-GG-') { $groupsOu } else { $usersOu }
                'CN=' + $membership.Member + ',' + $memberOu
            }
        )
        if ($observed.GroupScope.ToString() -ne $group.Scope -or $observed.GroupCategory.ToString() -ne 'Security' -or
            (($expectedMembers | Sort-Object) -join "`n") -ine ((@($observed.Members) | Sort-Object) -join "`n")) {
            throw "AD group scope/category/membership did not match the lab plan: $($group.Name)"
        }
        $sidMap[$group.Name] = $observed.SID.Value
    }
    $allSid = $sidMap[$prefix + '-DL-ALL']
    foreach ($scenario in $scenarios) {
        foreach ($grant in $scenario.Grants) {
            $grant.Sid = if ($grant.Principal -eq 'S-1-1-0') { $grant.Principal } else { $sidMap[$grant.Principal] }
        }
    }
    $null = New-Item -Path $rootPath -ItemType Directory -ErrorAction Stop
    Set-LabDirectoryAcl -path $rootPath -operatorSid $operatorSid -grants @(
        @{ Sid = $allSid; Rights = 'ReadAndExecute'; Inheritance = 'None'; Type = 'Allow' }
    )
    Write-LabJournal -path $journalPath -action 'CreatedRoot' -identity $rootPath
    foreach ($scenario in $scenarios) {
        $scenarioPath = Join-Path $rootPath $scenario.RelativePath
        $null = New-Item -Path $scenarioPath -ItemType Directory -ErrorAction Stop
        Set-LabDirectoryAcl -path $scenarioPath -operatorSid $operatorSid -grants $scenario.Grants
        if ($scenario.RelativePath -eq 'Inherited\Protected-Managers') {
            Set-Content -LiteralPath (Join-Path $scenarioPath 'sentinel.txt') -Value 'FICTIONAL: protected branch sentinel.' -Encoding UTF8
            Write-LabJournal -path $journalPath -action 'CreatedScenario' -identity $scenarioPath
            continue
        }
        $levelOne = Join-Path $scenarioPath 'Projects'
        $levelTwo = Join-Path $levelOne 'Current'
        $levelThree = Join-Path $levelTwo 'Drafts'
        foreach ($folder in @($scenarioPath, $levelOne, $levelTwo, $levelThree)) {
            if ($folder -ne $scenarioPath) {
                $null = New-Item -Path $folder -ItemType Directory -ErrorAction Stop
            }
            Set-Content -LiteralPath (Join-Path $folder 'placeholder.txt') -Encoding UTF8 `
                -Value "FICTIONAL LAB DATA ONLY. Lab $($labId). Scenario: $($scenario.RelativePath)."
            Set-Content -LiteralPath (Join-Path $folder 'sample-records.csv') -Encoding UTF8 `
                -Value @('RecordId,Description,Amount', '1,Fictional training record,125', '2,Placeholder only,250')
            @{ LabId = $labId; Fictional = $true; Scenario = $scenario.RelativePath } |
                ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'sample-config.json') -Encoding UTF8
        }
        Write-LabJournal -path $journalPath -action 'CreatedScenario' -identity $scenarioPath
    }
    $scenarios.ToArray() | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $evidencePath 'scenarios.json') -Encoding UTF8
    $aclInventory = @(
        foreach ($item in @(Get-Item -LiteralPath $rootPath) + @(Get-ChildItem -LiteralPath $rootPath -Recurse -Force)) {
            $acl = Get-Acl -LiteralPath $item.FullName
            [pscustomobject]@{
                Path = $item.FullName; IsDirectory = $item.PSIsContainer
                InheritanceProtected = $acl.AreAccessRulesProtected; Sddl = $acl.Sddl
            }
        }
    )
    $aclInventory | Export-Csv -LiteralPath (Join-Path $evidencePath 'acl-inventory.csv') -NoTypeInformation -Encoding UTF8
    if (@($aclInventory | Where-Object { -not $_.IsDirectory }).Count -ne 169 -or
        @($aclInventory | Where-Object IsDirectory).Count -ne 58) {
        throw 'Placeholder file/directory inventory did not match the complete fixture.'
    }
    $everyoneName = [Security.Principal.SecurityIdentifier]::new('S-1-1-0').
        Translate([Security.Principal.NTAccount]).Value
    $shareParameters = @{
        Name = $shareName; Path = $rootPath; FullAccess = @($everyoneName)
        Description = "Disposable fictional NTFS lab $($labId)"
        FolderEnumerationMode = 'AccessBased'; CachingMode = 'None'; EncryptData = $true; ErrorAction = 'Stop'
    }
    $null = New-SmbShare @shareParameters
    Write-LabJournal -path $journalPath -action 'CreatedShare' -identity $shareName
    $observedShare = Get-SmbShare -Name $shareName
    if (-not $observedShare.Path.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not $observedShare.EncryptData -or $observedShare.FolderEnumerationMode.ToString() -ne 'AccessBased') {
        throw 'The new SMB share path/encryption/enumeration settings did not match the lab plan.'
    }
    $shareAccess = @(Get-SmbShareAccess -Name $shareName)
    if ($shareAccess.Count -ne 1 -or $shareAccess[0].AccountName -ne $everyoneName -or
        $shareAccess[0].AccessControlType.ToString() -ne 'Allow' -or $shareAccess[0].AccessRight.ToString() -ne 'Full') {
        throw 'The new SMB share permissions did not match the lab-only Everyone:Full grant.'
    }
    $shareAccess |
        Export-Csv -LiteralPath (Join-Path $evidencePath 'share-permissions.csv') -NoTypeInformation -Encoding UTF8
    if ($enableAccounts) {
        foreach ($user in $users) {
            $enableParameters = @{ Identity = $user.DistinguishedName; Server = $domainController; ErrorAction = 'Stop' }
            Enable-ADAccount @enableParameters
            Write-LabJournal -path $journalPath -action 'EnabledUser' -identity $user.DistinguishedName
        }
    }
    foreach ($user in $users) {
        $observedUser = Get-ADUser -Identity $user.DistinguishedName -Properties Manager, Department, Title -Server $domainController
        $expectedManager = if ($user.ManagerSam) { 'CN=' + $user.ManagerSam + ',' + $usersOu } else { '' }
        if ($observedUser.Enabled -ne $enableAccounts.IsPresent -or $observedUser.Department -ne $user.Department -or
            $observedUser.Title -ne $user.Title -or [string]$observedUser.Manager -ine $expectedManager) {
            throw "AD user state/department/title/manager did not match the lab plan: $($user.SamAccountName)"
        }
    }
    $state.Status = 'Created'
    Write-NtfsLog -Path $logPath -Component LabFixture -Level INFO -Stage Complete -Message $shareName
} catch {
    $state.Status = 'Failed'
    $state.Error = $_.Exception.Message
    Write-Warning "Provisioning failed. Preserve partial lab objects; inspect $($evidencePath). No automatic rollback was attempted."
    throw
} finally {
    if ($evidenceCreated) {
        $state['FinishedUtc'] = [datetime]::UtcNow.ToString('o')
        $state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8 -ErrorAction Stop
    }
}
Write-NtfsCompletion -component 'Lab fixture' -status 'Created' -outputPath $evidencePath `
    -summary "$($users.Count) fictional users, $($groups.Count) AGDLP groups and disposable files created. Accounts enabled: $($enableAccounts.IsPresent)." `
    -reviewPath @($manifestPath, (Join-Path $evidencePath 'employees.csv'), (Join-Path $evidencePath 'scenarios.json')) `
    -requirements 'Wait for AD replication and use a fresh sign-in token for real access tests. Disabled users cannot sign in. Expectations are not effective-access proof.' `
    -nextStep 'Collect only this lab share; save snapshots beneath the protected inventory directory, outside the lab share.' `
    -nextScriptPath '.\Invoke-NtfsAssessment.ps1' `
    -nextParameters ([ordered]@{
        ComputerName = [Environment]::MachineName; IncludeShare = $shareName
        OutputRoot = (Join-Path $evidencePath 'Assessments')
        ResolveActiveDirectory = [Management.Automation.SwitchParameter]$true
        HashOutputs = [Management.Automation.SwitchParameter]$true
    })
[pscustomobject]@{
    Status = $state.Status; RootPath = $rootPath; EvidencePath = $evidencePath; ManifestPath = $manifestPath
    ShareName = $shareName; SharePath = $plan.SharePath; LabOu = $labOu; EmployeeCount = $users.Count
}
