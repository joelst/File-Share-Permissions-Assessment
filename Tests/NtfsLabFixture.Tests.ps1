#requires -Version 5.1
<#
.SYNOPSIS
Tests disposable lab provisioning without contacting AD or creating real shares.
.DESCRIPTION
Requires Windows, Pester 5.2+, and a local NTFS temporary directory. AD and SMB
operations are mocked. Files and ACLs are exercised only in Pester's TestDrive.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'AD command stubs throw unless mocked; they perform no directory mutations.')]
[CmdletBinding()]
param()

Describe 'Disposable AGDLP lab provisioner' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    BeforeAll {
        $script:provisioner = Join-Path $PSScriptRoot 'New-NtfsLabFixture.ps1'
        # Stubs make AD mocks available on development hosts without RSAT.
        function Get-ADDomainController {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($identity, $server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function Get-ADDomain {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function Get-ADOrganizationalUnit {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($identity, $server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function Get-ADObject {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($ldapFilter, $searchBase, $searchScope, $server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function New-ADOrganizationalUnit {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($name, $path, $server, $description, $protectedFromAccidentalDeletion, [switch]$passThru)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function New-ADGroup {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($name, $samAccountName, $groupScope, $groupCategory, $path, $server, $description, [switch]$passThru)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function New-ADUser {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()]
            param($name, $samAccountName, $userPrincipalName, $givenName, $surname, $displayName,
                $department, $title, $company, $description, $employeeId, $path, $server, $enabled,
                $accountExpirationDate, [Security.SecureString]$accountPassword, [bool]$changePasswordAtLogon, [switch]$passThru)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function Set-ADUser {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($identity, $manager, $server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function Add-ADGroupMember {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($identity, $members, $server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function Get-ADGroup {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($identity, $properties, $server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function Enable-ADAccount {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($identity, $server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
        function Get-ADUser {
            <#
            .SYNOPSIS
            Supplies the AD command signature for mocking; unmocked calls fail.
            #>
            [CmdletBinding()] param($identity, $properties, $server)
            throw "Unmocked AD command ($($PSBoundParameters.Count) bound parameters)."
        }
    }

    BeforeEach {
        $caseRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $caseRoot -ItemType Directory
        $script:parameters = @{
            rootPath = Join-Path $caseRoot 'fixture'
            evidencePath = Join-Path $caseRoot 'inventory'
            parentOu = 'OU=Labs,DC=example,DC=test'
            domainController = 'dc.example.test'
            disposableAcknowledgement = $true
            Confirm = $false
        }
        $labState = @{ Groups = @{}; Users = @{}; Share = $null; ExistingBacking = '' }
        $script:password = [Security.SecureString]::new()
        foreach ($character in [guid]::NewGuid().ToString('N').ToCharArray()) { $script:password.AppendChar($character) }
        $script:password.MakeReadOnly()
        Mock Import-Module {} -ParameterFilter { $Name -in @('ActiveDirectory', 'SmbShare') }
        Mock Get-CimInstance {
            if ($ClassName -eq 'Win32_ComputerSystem') {
                [pscustomobject]@{ PartOfDomain = $true; DomainRole = 3; Domain = 'example.test' }
            } else {
                [pscustomobject]@{ DriveType = 3; FileSystem = 'NTFS' }
            }
        }
        Mock Get-ADDomainController { [pscustomobject]@{ IsReadOnly = $false; HostName = 'dc.example.test' } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'example.test' } }
        Mock Get-ADOrganizationalUnit { [pscustomobject]@{ DistinguishedName = $Identity } }
        Mock Get-ADObject {}
        Mock New-ADOrganizationalUnit { [pscustomobject]@{ DistinguishedName = 'OU=' + $Name + ',' + $Path } }
        Mock New-ADGroup {
            $record = [pscustomobject]@{
                DistinguishedName = 'CN=' + $Name + ',' + $Path; GroupScope = $GroupScope
                GroupCategory = $GroupCategory; Members = [Collections.Generic.List[string]]::new()
                SID = [Security.Principal.SecurityIdentifier]::new(('S-1-5-21-100-200-300-' + (1000 + $labState.Groups.Count)))
            }
            $labState.Groups[$Name] = $record
            $record
        }
        Mock New-ADUser {
            $record = [pscustomobject]@{
                DistinguishedName = 'CN=' + $Name + ',' + $Path
                Department = $Department; Title = $Title; Manager = ''; Enabled = $Enabled
            }
            $labState.Users[$SamAccountName] = $record
            $record
        }
        Mock Set-ADUser {
            $sam = ($Identity -split ',')[0].Substring(3)
            $labState.Users[$sam].Manager = $Manager
        }
        Mock Add-ADGroupMember {
            foreach ($member in $Members) {
                $record = if ($labState.Groups.ContainsKey($member)) { $labState.Groups[$member] } else { $labState.Users[$member] }
                $labState.Groups[$Identity].Members.Add($record.DistinguishedName)
            }
        }
        Mock Get-ADGroup { $labState.Groups[$Identity] }
        Mock Enable-ADAccount {
            $sam = ($Identity -split ',')[0].Substring(3)
            $labState.Users[$sam].Enabled = $true
        }
        Mock Get-ADUser {
            $sam = ($Identity -split ',')[0].Substring(3)
            $labState.Users[$sam]
        }
        Mock Get-SmbShare {
            if ($Name -and $null -ne $labState.Share) { $labState.Share }
        }
        Mock New-SmbShare {
            $labState.Share = [pscustomobject]@{
                Name = $Name; Path = $Path; EncryptData = $EncryptData
                FolderEnumerationMode = $FolderEnumerationMode
            }
            $labState.Share
        }
        Mock Get-SmbShareAccess {
            [pscustomobject]@{
                AccountName = [Security.Principal.SecurityIdentifier]::new('S-1-1-0').Translate([Security.Principal.NTAccount]).Value
                AccessControlType = 'Allow'; AccessRight = 'Full'
            }
        }
    }
    AfterEach {
        $script:password.Dispose()
    }

    It 'previews 100 fictional employees with complete manager and AGDLP mappings without writes' {
        $result = & $script:provisioner @parameters -WhatIf
        $result.Status | Should -Be 'PreviewOrDeclined'
        $plan = $result.Plan
        $plan.Users.Count | Should -Be 100
        @($plan.Users.SamAccountName | Select-Object -Unique).Count | Should -Be 100
        @($plan.Users.DisplayName | Select-Object -Unique).Count | Should -Be 100
        foreach ($user in $plan.Users) {
            if ($user.Role -ne 'Executive') {
                $manager = @($plan.Users | Where-Object SamAccountName -eq $user.ManagerSam)
                $manager.Count | Should -Be 1
                $manager[0].Role | Should -BeIn @('Executive', 'Manager')
                if ($user.Role -ne 'Manager') { $manager[0].Department | Should -Be $user.Department }
            }
        }
        foreach ($department in @($plan.Users | Where-Object Role -eq 'Manager')) {
            $staff = @($plan.Users | Where-Object Department -eq $department.Department)
            @($staff | Where-Object Role -eq 'Reader').Count | Should -BeGreaterThan 0
            @($staff | Where-Object Role -eq 'Writer').Count | Should -BeGreaterThan 0
        }
        foreach ($group in $plan.Groups) {
            $edges = @($plan.Memberships | Where-Object Group -eq $group.Name)
            $edges.Count | Should -BeGreaterThan 0
            foreach ($edge in $edges) {
                if ($group.Scope -eq 'DomainLocal') {
                    ($plan.Groups | Where-Object Name -eq $edge.Member).Scope | Should -Be 'Global'
                } else {
                    @($plan.Users | Where-Object SamAccountName -eq $edge.Member).Count | Should -Be 1
                }
            }
        }
        foreach ($scenario in $plan.Scenarios) {
            foreach ($grant in $scenario.Grants) {
                if ($grant.Principal -eq 'S-1-1-0') {
                    $scenario.RelativePath | Should -BeLike 'Everyone-*'
                } else {
                    ($plan.Groups | Where-Object Name -eq $grant.Principal).Scope | Should -Be 'DomainLocal'
                }
            }
        }
        Should -Invoke New-ADOrganizationalUnit -Times 0
        Should -Invoke New-ADUser -Times 0
        Should -Invoke New-SmbShare -Times 0
        Test-Path -LiteralPath $parameters.rootPath | Should -BeFalse
        Test-Path -LiteralPath $parameters.evidencePath | Should -BeFalse
    }

    It 'requires acknowledgement and explicit secure-password opt-in before changes' {
        $parameters.disposableAcknowledgement = $false
        { & $script:provisioner @parameters } | Should -Throw '*DisposableAcknowledgement*'
        $parameters.disposableAcknowledgement = $true
        { & $script:provisioner @parameters -enableAccounts } | Should -Throw '*InitialPassword*'
        { & $script:provisioner @parameters -initialPassword $password } | Should -Throw '*EnableAccounts*'
        Should -Invoke New-ADOrganizationalUnit -Times 0
        Test-Path -LiteralPath $parameters.evidencePath | Should -BeFalse
    }

    It 'refuses existing paths without changing their contents or ACL' {
        $null = New-Item -Path $parameters.rootPath -ItemType Directory
        $sentinel = Join-Path $parameters.rootPath 'keep.txt'
        Set-Content -LiteralPath $sentinel -Value 'unchanged'
        $before = (Get-Acl -LiteralPath $parameters.rootPath).Sddl
        { & $script:provisioner @parameters } | Should -Throw '*new directories*'
        (Get-Content -LiteralPath $sentinel -Raw).Trim() | Should -Be 'unchanged'
        (Get-Acl -LiteralPath $parameters.rootPath).Sddl | Should -BeExactly $before
        Should -Invoke New-ADOrganizationalUnit -Times 0
    }

    It 'rejects overlapping output and fixture directories' {
        $parameters.evidencePath = $parameters.rootPath
        { & $script:provisioner @parameters } | Should -Throw '*nonoverlapping*'
        Should -Invoke New-ADOrganizationalUnit -Times 0
    }

    It 'refuses paths beneath an existing nonadministrative share' {
        $labState.ExistingBacking = Split-Path $parameters.rootPath -Parent
        Mock Get-SmbShare { [pscustomobject]@{ Name = 'Existing'; Path = $labState.ExistingBacking; Special = $false } }
        { & $script:provisioner @parameters } | Should -Throw '*outside existing shares*'
        Should -Invoke New-ADOrganizationalUnit -Times 0
    }

    It 'rejects a junction ancestor before provisioning' {
        $parent = Split-Path $parameters.rootPath -Parent
        $target = Join-Path $parent 'junction-target'
        $junction = Join-Path $parent 'junction'
        $null = New-Item -Path $target -ItemType Directory
        $null = New-Item -Path $junction -ItemType Junction -Target $target
        $parameters.rootPath = Join-Path $junction 'fixture'
        { & $script:provisioner @parameters } | Should -Throw '*Reparse-point ancestors*'
        Should -Invoke New-ADOrganizationalUnit -Times 0
    }

    It 'rejects a domain controller execution host' {
        Mock Get-CimInstance { [pscustomobject]@{ PartOfDomain = $true; DomainRole = 5 } }
        { & $script:provisioner @parameters } | Should -Throw '*member file server*'
        Should -Invoke New-ADOrganizationalUnit -Times 0
    }

    It 'rejects a read-only domain controller or existing lab identity' {
        Mock Get-ADDomainController { [pscustomobject]@{ IsReadOnly = $true; HostName = 'dc.example.test' } }
        { & $script:provisioner @parameters } | Should -Throw '*writable domain controller*'
        Mock Get-ADDomainController { [pscustomobject]@{ IsReadOnly = $false; HostName = 'dc.example.test' } }
        Mock Get-ADObject { [pscustomobject]@{ Name = 'Collision' } }
        { & $script:provisioner @parameters } | Should -Throw '*already exist*'
        Should -Invoke New-ADOrganizationalUnit -Times 0
    }

    It 'rejects a DC in another domain because Domain Local grants must match the file server domain' {
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'other.example.test' } }
        { & $script:provisioner @parameters } | Should -Throw '*file server domain*'
        Should -Invoke New-ADOrganizationalUnit -Times 0
    }

    It 'creates real placeholder files and distinct protected/inherited ACLs with accounts disabled' {
        $result = & $script:provisioner @parameters -InformationVariable completion
        $result.Status | Should -Be 'Created'
        $manifest = Get-Content -LiteralPath $result.ManifestPath -Raw | ConvertFrom-Json
        $manifest.Plan.Users.Count | Should -Be 100
        $labState.Users.Count | Should -Be 100
        @($labState.Users.Values | Where-Object Enabled).Count | Should -Be 0
        @($labState.Users.Values | Where-Object Manager).Count | Should -Be 99
        Should -Invoke New-ADUser -Times 100 -Exactly -ParameterFilter { -not $Enabled -and $null -eq $AccountPassword }
        Should -Invoke Enable-ADAccount -Times 0
        Should -Invoke New-SmbShare -Times 1 -Exactly
        $rootAcl = Get-Acl -LiteralPath $result.RootPath
        $rootAcl.AreAccessRulesProtected | Should -BeTrue
        @($rootAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' }).Count | Should -Be 0
        foreach ($scenario in $manifest.Plan.Scenarios) {
            $scenarioPath = Join-Path $result.RootPath $scenario.RelativePath
            if ($scenario.RelativePath -eq 'Inherited\Protected-Managers') {
                Test-Path -LiteralPath (Join-Path $scenarioPath 'sentinel.txt') | Should -BeTrue
                (Get-Acl -LiteralPath $scenarioPath).AreAccessRulesProtected | Should -BeTrue
                continue
            }
            foreach ($level in @('', 'Projects', 'Projects\Current', 'Projects\Current\Drafts')) {
                $folder = if ($level) { Join-Path $scenarioPath $level } else { $scenarioPath }
                (Get-Content -LiteralPath (Join-Path $folder 'placeholder.txt') -Raw) | Should -Match 'FICTIONAL LAB DATA ONLY'
                @(Import-Csv -LiteralPath (Join-Path $folder 'sample-records.csv')).Count | Should -Be 2
                (Get-Content -LiteralPath (Join-Path $folder 'sample-config.json') -Raw | ConvertFrom-Json).Fictional | Should -BeTrue
                if ($level) { (Get-Acl -LiteralPath $folder).AreAccessRulesProtected | Should -BeFalse }
            }
        }
        $denyAcl = Get-Acl -LiteralPath (Join-Path $result.RootPath 'DenyWrite')
        @($denyAcl.Access | Where-Object AccessControlType -eq 'Deny').Count | Should -Be 1
        $evidenceAcl = Get-Acl -LiteralPath $result.EvidencePath
        $evidenceAcl.AreAccessRulesProtected | Should -BeTrue
        (Get-Content -LiteralPath $result.ManifestPath -Raw) | Should -Not -Match 'InitialPassword|AccountPassword'
        Test-Path -LiteralPath (Join-Path $result.EvidencePath 'employees.csv') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $result.EvidencePath 'acl-inventory.csv') | Should -BeTrue
        $nextCommand = ($completion | ForEach-Object MessageData) -join "`n"
        $nextCommand | Should -Match '\-ResolveActiveDirectory:\$true'
        $nextCommand | Should -Match '\-HashOutputs:\$true'
    }

    It 'preserves a partial failure with its journal and never publishes a share' {
        Mock New-ADGroup { throw 'Injected group creation failure.' }
        { & $script:provisioner @parameters } | Should -Throw '*Injected group creation failure*'
        $manifest = Get-Content -LiteralPath (Join-Path $parameters.evidencePath 'manifest.json') -Raw | ConvertFrom-Json
        $manifest.Status | Should -Be 'Failed'
        $manifest.Error | Should -Match 'Injected group creation failure'
        $journal = @(Get-Content -LiteralPath (Join-Path $parameters.evidencePath 'operations.jsonl') |
            ForEach-Object { $_ | ConvertFrom-Json })
        @($journal | Where-Object Action -eq 'CreatedOU').Count | Should -Be 3
        Test-Path -LiteralPath $parameters.rootPath | Should -BeFalse
        Should -Invoke New-SmbShare -Times 0
        Should -Invoke Enable-ADAccount -Times 0
    }

    It 'does not write the employee inventory if evidence ACL restriction fails' {
        Mock Set-Acl { throw 'Injected evidence ACL failure.' }
        { & $script:provisioner @parameters } | Should -Throw '*Injected evidence ACL failure*'
        Test-Path -LiteralPath (Join-Path $parameters.evidencePath 'manifest.json') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $parameters.evidencePath 'employees.csv') | Should -BeFalse
        Should -Invoke New-ADOrganizationalUnit -Times 0
    }

    It 'rejects incorrect observed AD memberships before creating the share or broad ACLs' {
        $parameters.employeeCount = 17
        Mock Add-ADGroupMember {}
        { & $script:provisioner @parameters } | Should -Throw '*membership did not match*'
        Test-Path -LiteralPath $parameters.rootPath | Should -BeFalse
        Should -Invoke New-SmbShare -Times 0
    }

    It 'does not enable users if share publication fails' {
        $parameters.employeeCount = 17
        Mock New-SmbShare { throw 'Injected share failure.' }
        { & $script:provisioner @parameters -enableAccounts -initialPassword $password } |
            Should -Throw '*Injected share failure*'
        @($labState.Users.Values | Where-Object Enabled).Count | Should -Be 0
        Should -Invoke Enable-ADAccount -Times 0
        (Get-Content -LiteralPath (Join-Path $parameters.evidencePath 'manifest.json') -Raw |
            ConvertFrom-Json).Status | Should -Be 'Failed'
    }

    It 'enables explicitly requested users only after fixture and share provisioning' {
        $parameters.employeeCount = 17
        $result = & $script:provisioner @parameters -enableAccounts -initialPassword $password
        $result.Status | Should -Be 'Created'
        @($labState.Users.Values | Where-Object Enabled).Count | Should -Be 17
        Should -Invoke New-ADUser -Times 17 -Exactly -ParameterFilter {
            -not $Enabled -and $null -ne $AccountPassword -and $ChangePasswordAtLogon
        }
        $journal = @(Get-Content -LiteralPath (Join-Path $result.EvidencePath 'operations.jsonl') |
            ForEach-Object { $_ | ConvertFrom-Json })
        $shareIndex = [array]::IndexOf($journal.Action, 'CreatedShare')
        $enableIndex = [array]::IndexOf($journal.Action, 'EnabledUser')
        $enableIndex | Should -BeGreaterThan $shareIndex
        (Get-Content -LiteralPath $result.ManifestPath -Raw) | Should -Not -Match 'InitialPassword|AccountPassword'
    }
}
