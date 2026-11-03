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
Read-only qualification preflight scaffold. No mutation test or enable switch.
Opt-in environment: NTFS_PERMISSION_QUALIFICATION_TARGET=C:\disposable\folder or
\\isolated-server\disposable-share\folder, NTFS_PERMISSION_QUALIFICATION_PLATFORM=
Windows|NetApp|Nas|Auto, and NTFS_PERMISSION_QUALIFICATION_DISPOSABLE=YES.
This only inspects evidence for the declared platform. Windows results do not
qualify NetApp or generic NAS, nor does local NTFS qualify Windows SMB.
Passing these checks does NOT qualify a writer. Still required: controlled
inheritance/exclusive-handle experiments, stable identity, concurrent admin drift,
timeouts/crashes and guarded per-path rollback, both scopes, folders AND files,
direct backend proof and protected/reparse boundaries. Native writer absent.
#>
BeforeDiscovery {
    $enabled = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and
        $env:NTFS_PERMISSION_QUALIFICATION_DISPOSABLE -ceq 'YES' -and
        -not [string]::IsNullOrWhiteSpace($env:NTFS_PERMISSION_QUALIFICATION_TARGET)
}
Describe 'Opt-in disposable Windows read-only preflight (NOT write qualification)' -Skip:(-not $enabled) {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../NtfsPermissions.Common.ps1')
        $platform = if ($env:NTFS_PERMISSION_QUALIFICATION_PLATFORM) { $env:NTFS_PERMISSION_QUALIFICATION_PLATFORM } else { 'Auto' }
        $descriptor = Resolve-NpTarget $env:NTFS_PERMISSION_QUALIFICATION_TARGET $platform
        $target = $descriptor.CanonicalPath
    }
    It 'retains a separate platform gate and never qualifies mutation' {
        $descriptor.QualificationScope | Should -Be $descriptor.Platform
        $descriptor.PlanningStatus | Should -Be PlanningSupported
        $descriptor.MutationStatus | Should -Be MutationNotQualified
        $descriptor.NamespaceProof | Should -Be Unqualified
        $descriptor.AdapterProfile | Should -Be 'WindowsFileSystemAcl.ReadOnly/1'
        $descriptor.BackendProof | Should -Be Unverified
        $descriptor.SecurityStyleProof | Should -Be Unverified
        $descriptor.ObjectIdentityProof | Should -Be Unqualified
        if ($descriptor.Addressing -eq 'LocalFixed') {
            $descriptor.VolumeObservation.Status | Should -Be ObservedReadOnly
            $descriptor.VolumeObservation.ExecutionHost | Should -Be ([Environment]::MachineName)
            $descriptor.VolumeObservation.FileSystem | Should -Be NTFS
            $descriptor.VolumeObservation.VolumeDeviceId | Should -Not -BeNullOrEmpty
        } else {
            $descriptor.VolumeObservation.Status | Should -Be Unavailable
        }
    }
    It 'reads a real NTFS descriptor and owner group protection and canonical DACL' {
        $snapshot=Get-NpWindowsSnapshot $target
        $snapshot.Descriptor | Should -Match '^O:'
        Assert-NpSnapshot $snapshot
        $snapshot.Kind | Should -Be Folder
    }
    It 'captures files and protected boundaries without traversing protected branches' {
        $inventory=Get-NpWindowsInventory $target ThisFolderSubfoldersAndFiles 1000
        $inventory.Errors.Count | Should -Be 0
        @($inventory.Snapshots | Where-Object Kind -eq File).Count | Should -BeGreaterThan 0
        $inventory.Boundaries.Count | Should -BeGreaterThan 0
        foreach($boundary in $inventory.Boundaries){
            @($inventory.Snapshots | Where-Object { $_.Path.StartsWith($boundary+'\',[StringComparison]::OrdinalIgnoreCase) }).Count | Should -Be 0
        }
    }
    It 'does not qualify unstable observational identity as a writable plan' {
        (Get-NpWindowsSnapshot $target).Identity | Should -Match '^UNQUALIFIED:'
    }
}
