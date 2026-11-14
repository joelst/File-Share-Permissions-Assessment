#requires -Version 5.1
<#
.SYNOPSIS
Safety checks for the disposable candidate validation runner.
#>
[CmdletBinding()]
param()

Describe 'Disposable candidate validation entry point' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    BeforeAll {
        $script:runner = Join-Path $PSScriptRoot 'Invoke-NtfsCandidateLabValidation.ps1'
        $script:parent = Join-Path ([IO.Path]::GetTempPath()) ('CandidateSafety_' + [guid]::NewGuid().ToString('N'))
        $password = [Security.SecureString]::new()
        $script:allowed = [pscredential]::new('LAB\Allowed', $password)
        $script:control = [pscredential]::new('LAB\Control', $password)
        $script:inputs = @{
            FixtureParent = $script:parent
            EvidenceRoot = (Join-Path $script:parent 'evidence')
            GroupName = 'LAB\Readers'
            AllowedCredential = $script:allowed
            ControlCredential = $script:control
            ChangeTicket = 'DISPOSABLE-TEST'
        }
    }

    Describe 'Disposable candidate probe guards' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        BeforeAll {
            $source = Join-Path $PSScriptRoot 'NtfsCandidateLabProbe.cs'
            $bytes = [IO.File]::ReadAllBytes($source)
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
            $type = 'NtfsCandidateLab.Probe' -as [type]
            if ($null -eq $type) {
                $code = [Text.UTF8Encoding]::new($false, $true).GetString($bytes).Replace('__SOURCE_SHA256__', $hash)
                Add-Type -TypeDefinition $code -ErrorAction Stop
            } elseif ($type::SourceSHA256 -cne $hash) { throw 'Probe source changed after assembly load.' }
        }

        It 'appends to and removes the known probe through an exclusive handle' {
            $path = Join-Path $TestDrive 'owned.txt'
            $marker = [guid]::NewGuid().ToString('N')
            [IO.File]::WriteAllText($path, $marker)
            [NtfsCandidateLab.Probe]::AppendKnown($path, $marker)
            [IO.File]::ReadAllText($path) | Should -BeExactly ($marker + '|modified')
            [NtfsCandidateLab.Probe]::RemoveKnown($path, $marker, $true, $false) | Should -BeTrue
            Test-Path -LiteralPath $path | Should -BeFalse
            [NtfsCandidateLab.Probe]::RemoveKnown($path, $marker, $false, $true) | Should -BeFalse
        }

        It 'deletes a generated probe by name' {
            $path = Join-Path $TestDrive 'delete-by-name.txt'
            [IO.File]::WriteAllText($path, [guid]::NewGuid().ToString('N'))
            [NtfsCandidateLab.Probe]::DeleteByName($path) | Should -BeTrue
            Test-Path -LiteralPath $path | Should -BeFalse
            { [NtfsCandidateLab.Probe]::DeleteByName('') } | Should -Throw '*path is required*'
        }

        It 'uses the parent delete right with marker readability=<Readable>' -ForEach @(
            @{ Readable = $true }
            @{ Readable = $false }
        ) {
            $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = [IO.Directory]::CreateDirectory($directory)
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $parentAcl = [Security.AccessControl.DirectorySecurity]::new()
            $parentAcl.SetOwner($sid)
            $parentAcl.SetAccessRuleProtection($true, $false)
            $parentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            Set-Acl -LiteralPath $directory -AclObject $parentAcl -ErrorAction Stop
            $path = Join-Path $directory 'read-guarded.txt'
            $marker = [guid]::NewGuid().ToString('N')
            [IO.File]::WriteAllText($path, $marker)
            $fileAcl = [Security.AccessControl.FileSecurity]::new()
            $fileAcl.SetOwner($sid)
            $fileAcl.SetAccessRuleProtection($true, $false)
            $rights = if ($Readable) { 'Read' } else { 'ReadPermissions' }
            $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, 'Allow'))
            Set-Acl -LiteralPath $path -AclObject $fileAcl -ErrorAction Stop
            if ($Readable) {
                [NtfsCandidateLab.Probe]::RemoveKnown($path, $marker, $false, $false) | Should -BeTrue
            } else {
                { [NtfsCandidateLab.Probe]::RemoveKnown($path, $marker, $false, $false) } |
                    Should -Throw '*Cannot access generated probe*'
                [NtfsCandidateLab.Probe]::DeleteByName($path) | Should -BeTrue
            }
            Test-Path -LiteralPath $path | Should -BeFalse
        }

        It 'retains a probe with unexpected same-length content' {
            $path = Join-Path $TestDrive 'changed.txt'
            $marker = [guid]::NewGuid().ToString('N')
            $unexpected = [guid]::NewGuid().ToString('N')
            [IO.File]::WriteAllText($path, $unexpected)
            { [NtfsCandidateLab.Probe]::AppendKnown($path, $marker) } | Should -Throw '*Probe content changed*'
            { [NtfsCandidateLab.Probe]::RemoveKnown($path, $marker, $true, $false) } | Should -Throw '*Probe content changed*'
            [IO.File]::ReadAllText($path) | Should -BeExactly $unexpected
        }

        It 'retains a probe while another data handle is open' {
            $path = Join-Path $TestDrive 'busy.txt'
            $marker = [guid]::NewGuid().ToString('N')
            [IO.File]::WriteAllText($path, $marker)
            $stream = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
            try {
                { [NtfsCandidateLab.Probe]::RemoveKnown($path, $marker, $false, $false) } |
                    Should -Throw '*Cannot open generated probe*'
            } finally { $stream.Dispose() }
            [IO.File]::ReadAllText($path) | Should -BeExactly $marker
        }

        It 'refuses a hard-linked probe without changing either name' {
            $path = Join-Path $TestDrive 'linked.txt'
            $alias = Join-Path $TestDrive 'alias.txt'
            $marker = [guid]::NewGuid().ToString('N')
            [IO.File]::WriteAllText($path, $marker)
            $null = New-Item -ItemType HardLink -Path $alias -Value $path -ErrorAction Stop
            { [NtfsCandidateLab.Probe]::RemoveKnown($path, $marker, $false, $false) } |
                Should -Throw '*Unexpected probe type or link*'
            [IO.File]::ReadAllText($path) | Should -BeExactly $marker
            [IO.File]::ReadAllText($alias) | Should -BeExactly $marker
        }
    }

    It 'requires acknowledgement before creating a fixture or evidence' {
        { & $script:runner @script:inputs } | Should -Throw '*DisposableAcknowledgement*'
        Test-Path -LiteralPath $script:parent | Should -BeFalse
    }

    It 'rejects the same account as both the permitted user and negative control before any writes' {
        $arguments = $script:inputs.Clone()
        $arguments.ControlCredential = $script:allowed
        { & $script:runner @arguments -DisposableAcknowledgement } | Should -Throw '*different accounts*'
        Test-Path -LiteralPath $script:parent | Should -BeFalse
    }

    It 'rejects a local credential before any writes' {
        $arguments = $script:inputs.Clone()
        $arguments.ControlCredential = [pscredential]::new('.\LocalUser', $script:control.Password)
        { & $script:runner @arguments -DisposableAcknowledgement } | Should -Throw '*domain credentials*'
        Test-Path -LiteralPath $script:parent | Should -BeFalse
    }

    It 'rejects a client share path instead of a computer name before any writes' {
        { & $script:runner @script:inputs -ClientComputerName '\\server\share' -DisposableAcknowledgement } |
            Should -Throw '*computer name*'
        Test-Path -LiteralPath $script:parent | Should -BeFalse
    }

    It 'rejects a ticket containing control characters before any writes' {
        $arguments = $script:inputs.Clone()
        $arguments.ChangeTicket = "LAB`n123"
        { & $script:runner @arguments -DisposableAcknowledgement } | Should -Throw '*ticket*'
        Test-Path -LiteralPath $script:parent | Should -BeFalse
    }
}
