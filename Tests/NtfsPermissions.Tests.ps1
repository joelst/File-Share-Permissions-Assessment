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

BeforeAll {
    . (Join-Path $PSScriptRoot '../NtfsPermissions.Common.ps1')
    $script:work = Join-Path $PSScriptRoot ('PermissionsTests_' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($script:work)
    function New-TestSnapshot([string]$Path = '\\SERVER1\Share1\Folder', [string]$Kind = 'Folder', [bool]$Protected = $false) {
        [pscustomobject][ordered]@{
            Path=$Path; Kind=$Kind; Identity="fixture-volume:file-id:$Path"
            Owner='S-1-5-18'; Group='S-1-5-32-544'; Control=32772; Protected=$Protected
            DaclPresent=$true; Canonical=$true; Aces=@(); Descriptor="fixture-before:$Path"
        }
    }
    function New-TestAce([string]$SID='S-1-5-21-1-2-3-1001',[string]$Type='Allow',[long]$Mask=131241) {
        [pscustomobject][ordered]@{
            SID=$SID; Type=$Type; Mask=$Mask; Inherited=$false
            ContainerInherit=$true; ObjectInherit=$true; InheritOnly=$false; NoPropagate=$false
        }
    }
    function New-TestGrants {
        @(Get-NpGrants -GroupName 'Readers' -Permissions ReadAndExecute -Resolve { 'S-1-5-21-1-2-3-1001' })
    }
    function New-TestPlan($Snapshots = @((New-TestSnapshot)), [string]$Scope = 'ThisFolderSubfoldersAndFiles', $Errors = @()) {
        $inventory = [pscustomobject]@{
            Snapshots=@($Snapshots); Boundaries=@($Snapshots | Where-Object { $_.Protected -and $_.Path -ne '\\SERVER1\Share1\Folder' } | ForEach-Object Path); Errors=@($Errors)
        }
        New-NpPlan '\\SERVER1\Share1\Folder' (New-TestGrants) $Scope $inventory (Get-NpSourceHash)
    }
    function Save-TestPlan($Plan) {
        $path = Join-Path $script:work ([guid]::NewGuid().ToString('N')+'.json')
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes((Get-NpCanonicalJson $Plan))
        [IO.File]::WriteAllBytes($path,$bytes)
        [pscustomobject]@{Path=$path;Hash=(Get-NpBytesHash $bytes)}
    }
    function New-TestPlatformPlan($Descriptor) {
        $inventory = [pscustomobject]@{
            Snapshots=@((New-TestSnapshot $Descriptor.CanonicalPath),
                (New-TestSnapshot ($Descriptor.CanonicalPath+'\file.txt') File))
            Boundaries=@(); Errors=@()
        }
        New-NpPlan $Descriptor.CanonicalPath (New-TestGrants) ThisFolderSubfoldersAndFiles $inventory (Get-NpSourceHash) $Descriptor
    }
    function New-TestJournal {
        $dir = Join-Path $script:work ([guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($dir)
        New-NpJournal $dir 'Apply' 'CHG123' ('a'*64) '\\SERVER1\Share1\Folder'
    }
    function New-TestAdapter($Plan, [string]$Behavior='Success') {
        $bag = @{ State=@{}; Writes=[Collections.Generic.List[string]]::new(); Behavior=$Behavior; Reads=0 }
        foreach ($entry in $Plan.Entries) { $bag.State[$entry.Before.Path]=$entry.Before }
        $read = { param($Path) $bag.Reads++; return $bag.State[$Path] }.GetNewClosure()
        $write = {
            param($Path,$Desired)
            $bag.Writes.Add($Path)
            if ($bag.Behavior -eq 'Throw') { throw [TimeoutException]::new('Unknown outcome') }
            if ($bag.Behavior -ne 'Mismatch') { $bag.State[$Path]=$Desired }
        }.GetNewClosure()
        [pscustomobject]@{ Kind='OfflineFixture'; Read=$read; Write=$write; Bag=$bag }
    }
    function New-TestRecoveryEvidence($Descriptor = $null) {
        $plan = if ($null -eq $Descriptor) { New-TestPlan } else { New-TestPlatformPlan $Descriptor }
        $dir=Join-Path $script:work ([guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($dir)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((Get-NpCanonicalJson $plan))
        [IO.File]::WriteAllBytes((Join-Path $dir 'plan.json'),$bytes)
        $hash=Get-NpBytesHash $bytes
        $journal=New-NpJournal $dir Apply CHG123 $hash $plan.Target
        Write-NpEvent $journal WriteIntent Pending @($plan.Target)
        Write-NpEvent $journal PathVerified Verified @($plan.Target)
        $manifest=[ordered]@{
            Schema='NtfsPermissionsEvidence/1'; PlanSHA256=$hash; SourceHash=$plan.SourceHash
            Files=@([ordered]@{Name='plan.json';SHA256=$hash})
        }
        $manifestPath=Join-Path $dir 'manifest.json'
        [IO.File]::WriteAllText($manifestPath,(Get-NpCanonicalJson $manifest))
        [pscustomobject]@{
            ManifestPath=$manifestPath; PlanHash=$hash; JournalPath=$journal.Path
            JournalHash=(Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))); SourceHash=$plan.SourceHash
        }
    }
}
AfterAll {
    Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction Stop
}

Describe 'Strict UNC and grant validation' {
    It 'preserves deep UNC and removes only trailing separator' {
        ConvertTo-NpUnc '\\SERVER1\Share1\Folder\Subfolder\' | Should -Be '\\SERVER1\Share1\Folder\Subfolder'
    }
    It 'rejects ambiguous target <Path>' -ForEach @(
        @{Path='C:\Folder'}, @{Path='\\?\UNC\s\x'}, @{Path='\\.\s\x'},
        @{Path='\\s\x\..\a'}, @{Path='\\s\x\.'}, @{Path='\\s\x\a*'},
        @{Path='\\s\x\a?'}, @{Path='\\s\x\a:'}, @{Path='\\s\x\a.'},
        @{Path='\\s\x\a '}, @{Path='\\s\x\\a'}, @{Path='//s/x/a'}, @{Path='\\s\x\NUL'}
    ) { { ConvertTo-NpUnc $Path } | Should -Throw }
    It 'accepts a strict JSON array and resolves every group before returning' {
        $calls=[Collections.Generic.List[string]]::new()
        $resolve={param($n) $calls.Add($n); if($n -eq 'A'){'S-1-5-21-1-2-3-1001'}else{'S-1-5-21-1-2-3-1002'}}.GetNewClosure()
        $grants=@(Get-NpGrants -Json '[{"GroupName":"A","Permissions":"Read"},{"Permissions":"Modify","GroupName":"B"}]' -Resolve $resolve)
        $grants.Count | Should -Be 2
        $calls.Count | Should -Be 2
        $grants[1].Mask | Should -Be 197055
    }
    It 'accepts escaped domain names and JSON files' {
        $json='[{"GroupName":"DOMAIN\\Readers","Permissions":"Read"}]'
        $path=Join-Path $script:work 'grants.json'
        [IO.File]::WriteAllText($path,$json)
        (Get-NpGrants -JsonFile $path -Resolve {'S-1-5-21-1-2-3-1001'}).GroupName | Should -Be 'DOMAIN\Readers'
    }
    It 'rejects invalid strict JSON <Json>' -ForEach @(
        @{Json='{}'}, @{Json='null'}, @{Json='[]'}, @{Json='[null]'},
        @{Json='[{"GroupName":"A","Permissions":"Read","Extra":1}]'},
        @{Json='[{"GroupName":"A","GroupName":"B"}]'},
        @{Json='[{"GroupName":"A","Permissions":null}]'},
        @{Json='[{"GroupName":1,"Permissions":"Read"}]'},
        @{Json='[{"GroupName":"A","Permissions":"read"}]'},
        @{Json='[{"GroupName":"A","Permissions":"Read"},]'},
        @{Json='[{"GroupName":"A","Permissions":"Read"},{"GroupName":"B","Permissions":"Invented"}]'},
        @{Json='[{"GroupName":"A","Permissions":"Read"}] garbage'}
    ) { { Get-NpGrants -Json $Json -Resolve {'S-1-5-21-1-2-3-1001'} } | Should -Throw }
    It 'rejects mixed input forms and incomplete single input' {
        { Get-NpGrants -GroupName A -Permissions Read -Json '[]' -Resolve {} } | Should -Throw
        { Get-NpGrants -GroupName A -Resolve {} } | Should -Throw
        { Get-NpGrants -Json '[]' -JsonFile './x' -Resolve {} } | Should -Throw
    }
    It 'rejects duplicate SID aliases before any mutation' {
        { Get-NpGrants -Json '[{"GroupName":"A","Permissions":"Read"},{"GroupName":"Alias","Permissions":"Modify"}]' -Resolve {'S-1-5-21-1-2-3-1001'} } | Should -Throw '*Duplicate SID*'
    }
    It 'invalid last group leaves zero setter calls' {
        $plan=New-TestPlan
        $adapter=New-TestAdapter $plan
        { Get-NpGrants -Json '[{"GroupName":"A","Permissions":"Read"},{"GroupName":"Missing","Permissions":"Read"}]' -Resolve {param($n) if($n -eq 'Missing'){throw 'Not a group'}; 'S-1-5-21-1-2-3-1001'} } | Should -Throw
        $adapter.Bag.Writes.Count | Should -Be 0
    }
}

Describe 'Platform-aware canonical target and recovery scopes' {
    It 'binds observed local volume evidence without claiming stable identity or trust' {
        $observation = [pscustomobject][ordered]@{
            Status='ObservedReadOnly'; ExecutionHost=[Environment]::MachineName
            VolumeDeviceId='fixture-volume-id'; VolumeSerialNumber='1234'; FileSystem='NTFS'
        }
        Mock Get-NpDriveBinding {
            [pscustomobject]@{Kind='Fixed';MappingRoot='';HostName=[Environment]::MachineName;Observation=$observation}
        }
        $descriptor = Resolve-NpTarget 'Z:\share\folder' Windows
        $saved = Save-TestPlan (New-TestPlatformPlan $descriptor)
        $read = Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash)
        $read.TargetDescriptor.VolumeObservation.VolumeDeviceId | Should -Be fixture-volume-id
        $read.TargetDescriptor.ObjectIdentityProof | Should -Be Unqualified
        $read.TargetDescriptor.TrustStatus | Should -Be ReviewOnlyUnproven
        $read.Recovery.Executable | Should -BeFalse
        Assert-NpExecutionHost $read.TargetDescriptor
        $read.TargetDescriptor.VolumeObservation.VolumeSerialNumber = 'changed'
        $saved = Save-TestPlan $read
        { Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash) } | Should -Throw '*binding*'
    }
    It 'labels missing local observations and rejects NAS filesystem advertisements as local NTFS proof' {
        $descriptor = New-NpTargetDescriptor 'Z:\share\folder' Windows -LocalHost HOST
        $descriptor.VolumeObservation.Status | Should -Be Unavailable
        $descriptor.ObjectIdentityProof | Should -Be Unqualified
        $advertisement = [pscustomobject][ordered]@{
            Status='ObservedReadOnly'; ExecutionHost='NAS'; VolumeDeviceId='advertised'; VolumeSerialNumber='1'; FileSystem='NTFS'
        }
        { New-NpTargetDescriptor '\\nas\data\folder' Nas -Observation $advertisement } | Should -Throw '*not NTFS proof*'
        $nas = New-NpTargetDescriptor '\\nas\data\folder' Nas
        $nas.BackendProof | Should -Be Unverified
        $nas.SecurityStyleProof | Should -Be Unverified
        $nas.AdapterProfile | Should -Be 'WindowsFileSystemAcl.ReadOnly/1'
        $nas.TargetIdentityAuthority | Should -Be 'Unverified;SvmLocalGroupsUnsupported'
    }
    It 'rejects machine-local groups and labels unknown AD authority as unsupported rather than validated' {
        foreach ($name in @('.\Readers','BUILTIN\Users','S-1-5-32-544',([Environment]::MachineName+'\Readers'))) {
            { Resolve-NpWindowsGroup $name } | Should -Throw '*unsupported/unvalidated*'
        }
        function Get-ADGroup { throw 'Unknown directory authority' }
        { Resolve-NpWindowsGroup 'S-1-5-21-9-8-7-1001' } | Should -Throw '*target/SVM-local authority is not validated*'
    }
    It 'rejects local plan execution on another host without volume or mapping re-resolution' {
        Mock Resolve-NpTarget { throw 'Must not re-resolve reviewed addressing.' }
        Mock Get-NpDriveBinding { throw 'Must not re-resolve reviewed volumes.' }
        $descriptor = New-NpTargetDescriptor 'Z:\share\folder' Windows -LocalHost 'OTHER-EXECUTION-HOST'
        { Assert-NpExecutionHost $descriptor } | Should -Throw '*host mismatch*'
        $descriptor = New-NpTargetDescriptor 'Z:\share\folder' NetApp '\\filer\data\department'
        $saved = Save-TestPlan (New-TestPlatformPlan $descriptor)
        $read = Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash)
        Assert-NpExecutionHost $read.TargetDescriptor
        $read.Target | Should -Be '\\filer\data\department\share\folder'
        Should -Invoke Resolve-NpTarget -Times 0
        Should -Invoke Get-NpDriveBinding -Times 0
    }
    It 'keeps fixed NTFS addressing local and host-bound rather than guessing an administrative share' {
        Mock Get-NpDriveBinding { [pscustomobject]@{Kind='Fixed';MappingRoot='';HostName='WINDOWSHOST'} }
        $target = Resolve-NpTarget 'z:\share\folder\' Windows
        $target.CanonicalPath | Should -BeExactly 'Z:\share\folder'
        $target.Addressing | Should -Be LocalFixed
        $target.Platform | Should -Be LocalWindows
        $target.LocalHost | Should -Be WINDOWSHOST
        $plan = New-TestPlatformPlan $target
        $saved = Save-TestPlan $plan
        $read = Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash)
        $read.TargetDescriptor.LocalHost | Should -Be WINDOWSHOST
        $read.Entries[1].Before.Path | Should -Be 'Z:\share\folder\file.txt'
        $read.CoverageComplete | Should -BeTrue
    }
    It 'converts only a verified mapped drive to its deep UNC namespace' {
        Mock Get-NpDriveBinding { [pscustomobject]@{Kind='Mapped';MappingRoot='\\filer\data\department';HostName=''} }
        $target = Resolve-NpTarget 'Z:\share\folder' NetApp
        $target.CanonicalPath | Should -Be '\\filer\data\department\share\folder'
        $target.InputPath | Should -Be 'Z:\share\folder'
        $target.Addressing | Should -Be MappedDrive
        $target.Platform | Should -Be NetAppSMB
        $saved = Save-TestPlan (New-TestPlatformPlan $target)
        (Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash)).TargetDescriptor.MappingRoot | Should -Be '\\filer\data\department'
    }
    It 'fails explicitly on missing elevated mappings without reinterpreting a drive as local' {
        Mock Get-NpDriveBinding { throw 'Drive unavailable in this elevation context; use direct UNC.' }
        { Resolve-NpTarget 'Z:\share\folder' } | Should -Throw '*elevation*'
        Mock Get-NpDriveBinding { [pscustomobject]@{Kind='Unknown';MappingRoot='';HostName=''} }
        { Resolve-NpTarget 'Z:\share\folder' } | Should -Throw '*Unverified*'
    }
    It 'does not infer NetApp from hostnames and retains explicit platform declarations' {
        Mock Get-NpDriveBinding { throw 'UNC must not resolve a drive.' }
        foreach ($platform in @('Auto','Windows','NetApp','Nas')) {
            $target = Resolve-NpTarget '\\netapp-filer\data\deep\folder' $platform
            $expected = switch ($platform) { Windows {'WindowsSMB'}; NetApp {'NetAppSMB'}; default {'GenericSMB'} }
            $target.Platform | Should -Be $expected
            $target.RequestedPlatform | Should -Be $platform
            $target.QualificationScope | Should -Be $expected
            $target.PlanningStatus | Should -Be PlanningSupported
            $target.MutationStatus | Should -Be MutationNotQualified
            $target.AccessModel | Should -Be WindowsFileSystemAcl
            $saved = Save-TestPlan (New-TestPlatformPlan $target)
            (Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash)).TargetDescriptor.Platform | Should -Be $expected
        }
        Should -Invoke Get-NpDriveBinding -Times 0
    }
    It 'rejects ambiguous local forms and local NAS declarations' {
        foreach ($path in @('Z:folder','Z:\','Z:\share\..\folder','Z:\share\a.','Z:\share\NUL','Z:\share\\folder','Z:/share/folder')) {
            { ConvertTo-NpPath $path } | Should -Throw
        }
        { New-NpTargetDescriptor 'Z:\share\folder' NetApp -LocalHost HOST } | Should -Throw '*SMB*'
        { New-NpTargetDescriptor 'Z:\share\folder' } | Should -Throw '*host binding*'
    }
    It 'checks all local ancestors including the drive root before ACL reads' {
        Mock Get-Item { [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory} }
        Mock Get-NpWindowsSnapshot { param($Path) New-TestSnapshot $Path }
        $inventory = Get-NpWindowsInventory 'Z:\share\folder' ThisFolderOnly 10
        $inventory.Errors.Count | Should -Be 0
        Should -Invoke Get-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq 'Z:\' }
        Should -Invoke Get-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq 'Z:\share' }
        Should -Invoke Get-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq 'Z:\share\folder' }
    }
    It 'rejects legacy schema rather than silently reinterpreting an unbound target' {
        $plan = New-TestPlan
        $plan.Schema = 'NtfsPermissionsPlan/1'
        $saved = Save-TestPlan $plan
        { Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash) } | Should -Throw '*legacy*'
    }
    It 'rejects erased platform, mapping and recovery bindings even with reviewed replacement bytes' {
        foreach ($field in @('Platform','QualificationScope','Addressing','CanonicalPath','AdapterProfile','BackendProof','SecurityStyleProof','Recovery')) {
            $plan = New-TestPlatformPlan (New-NpTargetDescriptor 'Z:\share\folder' NetApp '\\filer\data')
            switch ($field) {
                Recovery { $plan.Recovery.Paths[0].ExpectedIntentSHA256 = '0'*64 }
                default { $plan.TargetDescriptor.$field = 'changed' }
            }
            $saved = Save-TestPlan $plan
            { Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash) } | Should -Throw '*binding*'
        }
    }
    It 'guards recovery against local host drift, remapped drives and remote platform drift' {
        $pairs = @(
            @((New-NpTargetDescriptor 'Z:\share\folder' Windows -LocalHost HOST1),(New-NpTargetDescriptor 'Z:\share\folder' Windows -LocalHost HOST2)),
            @((New-NpTargetDescriptor 'Z:\share\folder' NetApp '\\filer1\data'),(New-NpTargetDescriptor 'Z:\share\folder' NetApp '\\filer2\data')),
            @((New-NpTargetDescriptor '\\server\data\folder' Windows),(New-NpTargetDescriptor '\\server\data\folder' NetApp))
        )
        foreach ($pair in $pairs) {
            $plan = New-TestPlatformPlan $pair[0]
            Get-NpGuardedRecoveryDecision $plan $pair[1] $plan.Entries[0].Before | Should -Be NamespaceConflict
        }
    }
    It 'guards each local or remote recovery path using exact before and abstract expected state only' {
        foreach ($descriptor in @((New-NpTargetDescriptor 'Z:\share\folder' Windows -LocalHost HOST),
                (New-NpTargetDescriptor '\\filer\data\folder' NetApp))) {
            $plan = New-TestPlatformPlan $descriptor
            foreach ($entry in $plan.Entries) {
                Get-NpGuardedRecoveryDecision $plan $descriptor $entry.Before | Should -Be NoOp
                Get-NpGuardedRecoveryDecision $plan $descriptor $entry.Proposal.Intent | Should -Be RestoreBeforeIntentReviewOnly
                $current = (Get-NpCanonicalJson $entry.Before) | ConvertFrom-NpJson
                $current.Identity = 'replacement'
                Get-NpGuardedRecoveryDecision $plan $descriptor $current | Should -Be RevertConflict
            }
            $outside = New-TestSnapshot ($descriptor.CanonicalPath+'-sibling\file.txt') File
            Get-NpGuardedRecoveryDecision $plan $descriptor $outside | Should -Be RevertConflict
            $plan.Recovery.Executable | Should -BeFalse
        }
    }
}

Describe 'Read-only abstract ACL proposal safety' {
    It 'defaults aggregate grants to container and object inheritance without altering metadata' {
        $before=New-TestSnapshot
        $proposal=New-NpProposal $before (New-TestGrants) 'ThisFolderSubfoldersAndFiles'
        $proposal.Intent.Aces.Count | Should -Be 1
        $proposal.Intent.Aces[0].ContainerInherit | Should -BeTrue
        $proposal.Intent.Aces[0].ObjectInherit | Should -BeTrue
        $proposal.Intent.Owner | Should -Be $before.Owner
        $proposal.Intent.Group | Should -Be $before.Group
        $proposal.Intent.Control | Should -Be $before.Control
        $proposal.Intent.Protected | Should -Be $before.Protected
        $proposal.Intent.Descriptor | Should -Be $before.Descriptor
        $before.Aces.Count | Should -Be 0
    }
    It 'folder-only intent never enables inheritance' {
        $before=New-TestSnapshot -Protected $true
        $proposal=New-NpProposal $before (New-TestGrants) ThisFolderOnly
        $proposal.Intent.Aces[0].ContainerInherit | Should -BeFalse
        $proposal.Intent.Aces[0].ObjectInherit | Should -BeFalse
        $proposal.Intent.Protected | Should -BeTrue
    }
    It 'distinguishes all-NoOp and mixed grants using unconditional applicable coverage' {
        $before=New-TestSnapshot
        $before.Aces=@(New-TestAce)
        (New-NpProposal $before (New-TestGrants) ThisFolderSubfoldersAndFiles).NoOp | Should -BeTrue
        $grants=@(Get-NpGrants -Json '[{"GroupName":"A","Permissions":"ReadAndExecute"},{"GroupName":"B","Permissions":"Read"}]' -Resolve {param($n) if($n -eq 'A'){'S-1-5-21-1-2-3-1001'}else{'S-1-5-21-1-2-3-1002'}})
        $proposal=New-NpProposal $before $grants ThisFolderSubfoldersAndFiles
        $proposal.NoOp | Should -BeFalse
        $proposal.Intent.Aces.Count | Should -Be 2
    }
    It 'does not treat inherit-only or no-propagate entries as inheritable coverage' {
        foreach($flag in @('InheritOnly','NoPropagate')){
            $before=New-TestSnapshot
            $ace=New-TestAce
            $ace.$flag=$true
            $before.Aces=@($ace)
            (New-NpProposal $before (New-TestGrants) ThisFolderSubfoldersAndFiles).NoOp | Should -BeFalse
        }
    }
    It 'rejects absent/null DACL and noncanonical ACL' {
        foreach($flag in @('DaclPresent','Canonical')){
            $before=New-TestSnapshot
            $before.$flag=$false
            { New-NpProposal $before (New-TestGrants) ThisFolderOnly } | Should -Throw
        }
    }
    It 'rejects conditional/object/opaque ACE model' {
        $before=New-TestSnapshot
        $before.Aces=@(New-TestAce -Type Conditional)
        { New-NpProposal $before (New-TestGrants) ThisFolderOnly } | Should -Throw '*Unsupported*'
    }
    It 'fails closed for denies of any SID and inheritable inherit-only denies' {
        foreach($inheritOnly in @($false,$true)){
            $before=New-TestSnapshot
            $ace=New-TestAce -Type Deny -SID 'S-1-1-0'
            $ace.Inherited=$true
            $ace.InheritOnly=$inheritOnly
            $before.Aces=@($ace)
            { New-NpProposal $before (New-TestGrants) ThisFolderSubfoldersAndFiles } | Should -Throw '*deny*'
        }
    }
    It 'enforces aggregate ACL bounds' {
        $before=New-TestSnapshot
        $before.Aces=@(1..1500 | ForEach-Object { New-TestAce -SID 'S-1-1-0' -Mask 1 })
        { New-NpProposal $before (New-TestGrants) ThisFolderOnly } | Should -Throw '*size guard*'
    }
    It 'accounts for large SIDs rather than assuming a short ACE byte size' {
        $sid='S-1-5-' + ((1..15 | ForEach-Object {'4294967295'}) -join '-')
        $before=New-TestSnapshot
        $before.Aces=@(1..800 | ForEach-Object {New-TestAce -SID $sid -Mask 1})
        {New-NpProposal $before (New-TestGrants) ThisFolderOnly} | Should -Throw '*size guard*'
        {Get-NpSidSize 'S-1-5-4294967296'} | Should -Throw
    }
    It 'records folders files and protected boundaries without claiming executable qualification' {
        $plan=New-TestPlan @((New-TestSnapshot),(New-TestSnapshot '\\SERVER1\Share1\Folder\a.txt' File),(New-TestSnapshot '\\SERVER1\Share1\Folder\protected' Folder $true))
        $plan.Entries.Count | Should -Be 3
        $plan.Entries[1].Proposal.Intent.Aces[0].Inherited | Should -BeTrue
        $plan.Entries[1].Proposal.Intent.Aces[0].ContainerInherit | Should -BeFalse
        $plan.Entries[2].Proposal.NoOp | Should -BeTrue
        $plan.Boundaries.Count | Should -Be 1
        $plan.Executable | Should -BeFalse
        $plan.Status | Should -Be Blocked
    }
    It 'blocks incomplete inventory <Reason>' -ForEach @(
        @{Reason='Unreadable'},@{Reason='Missing'},@{Reason='Reparse'},@{Reason='Path limit reached'}
    ) {
        $plan=New-TestPlan -Errors @($Reason)
        $plan.CoverageComplete | Should -BeFalse
        $plan.Executable | Should -BeFalse
        $plan.Reasons | Should -Contain $Reason
    }
    It 'retains raw evidence when a descriptor cannot be proposed safely' {
        $snapshot=New-TestSnapshot
        $snapshot.DaclPresent=$false
        $plan=New-TestPlan @($snapshot)
        $plan.InventoryEvidence[0].Descriptor | Should -Be $snapshot.Descriptor
        $plan.CoverageComplete | Should -BeFalse
    }
}

Describe 'Read-only traversal coverage and local locking' {
    It 'records a protected boundary but never traverses its branch' {
        Mock Get-Item { [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory} }
        Mock Get-NpWindowsSnapshot {
            param($Path)
            if($Path -eq '\\SERVER1\Share1\Folder\protected'){New-TestSnapshot $Path Folder $true}
            elseif($Path.EndsWith('.txt')){New-TestSnapshot $Path File}
            else{New-TestSnapshot $Path}
        }
        Mock Get-ChildItem {
            [pscustomobject]@{FullName='\\SERVER1\Share1\Folder\protected'}
            [pscustomobject]@{FullName='\\SERVER1\Share1\Folder\a.txt'}
        }
        $inventory=Get-NpWindowsInventory '\\SERVER1\Share1\Folder' ThisFolderSubfoldersAndFiles 10
        $inventory.Snapshots.Count | Should -Be 3
        $inventory.Boundaries.Count | Should -Be 1
        $inventory.Errors.Count | Should -Be 0
        Should -Invoke Get-ChildItem -Times 1 -Exactly
    }
    It 'folder-only scope does not enumerate descendants' {
        Mock Get-Item { [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory} }
        Mock Get-NpWindowsSnapshot {param($Path) New-TestSnapshot $Path}
        Mock Get-ChildItem {throw 'Must not enumerate'}
        $inventory=Get-NpWindowsInventory '\\SERVER1\Share1\Folder' ThisFolderOnly 10
        $inventory.Snapshots.Count | Should -Be 1
        Should -Invoke Get-ChildItem -Times 0 -Exactly
    }
    It 'ancestor reparse detection stops before root ACL reads' {
        Mock Get-Item { [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint} }
        Mock Get-NpWindowsSnapshot {throw 'Must not read ACL'}
        $inventory=Get-NpWindowsInventory '\\SERVER1\Share1\Folder' ThisFolderSubfoldersAndFiles 10
        $inventory.Errors[0] | Should -Match 'Ancestor reparse'
        Should -Invoke Get-NpWindowsSnapshot -Times 0 -Exactly
    }
    It 'limit and unreadable child errors retain completed evidence and block coverage' {
        Mock Get-Item { [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory} }
        Mock Get-NpWindowsSnapshot {param($Path) New-TestSnapshot $Path File}
        # Root remains a folder.
        Mock Get-NpWindowsSnapshot {param($Path) New-TestSnapshot $Path} -ParameterFilter {$Path -eq '\\SERVER1\Share1\Folder'}
        Mock Get-ChildItem {
            [pscustomobject]@{FullName='\\SERVER1\Share1\Folder\a.txt'}
            [pscustomobject]@{FullName='\\SERVER1\Share1\Folder\b.txt'}
        }
        $inventory=Get-NpWindowsInventory '\\SERVER1\Share1\Folder' ThisFolderSubfoldersAndFiles 2
        $inventory.Snapshots.Count | Should -Be 2
        $inventory.Errors[0] | Should -Match 'limit'
        Mock Get-NpWindowsSnapshot {throw 'Unreadable'} -ParameterFilter {$Path -eq '\\SERVER1\Share1\Folder\a.txt'}
        $inventory=Get-NpWindowsInventory '\\SERVER1\Share1\Folder' ThisFolderSubfoldersAndFiles 10
        $inventory.Snapshots.Count | Should -Be 1
        $inventory.Errors[0] | Should -Match 'Unreadable'
    }
    It 'rejects a protected branch in a purported complete inventory' {
        $plan=New-TestPlan @((New-TestSnapshot),(New-TestSnapshot '\\SERVER1\Share1\Folder\protected' Folder $true),(New-TestSnapshot '\\SERVER1\Share1\Folder\protected\child.txt' File))
        $plan.CoverageComplete | Should -BeFalse
        ($plan.Reasons -join ';') | Should -Match 'protected branch'
    }
    It 'acquires and releases a host-local named target mutex' {
        $mutex=Enter-NpTargetLock '\\fixture-host\fixture-share\folder'
        try { $mutex.GetType().FullName | Should -Be 'System.Threading.Mutex' }
        finally {$mutex.ReleaseMutex();$mutex.Dispose()}
    }
}

Describe 'Immutable plans and exact reconstruction' {
    It 'round trips approved bytes and rejects a different reviewed hash' {
        $saved=Save-TestPlan (New-TestPlan)
        (Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash)).Target | Should -Be '\\SERVER1\Share1\Folder'
        { Read-NpPlan $saved.Path ('0'*64) (Get-NpSourceHash) } | Should -Throw '*hash mismatch*'
    }
    It 'rejects tampered proposal even with a recomputed plan hash' {
        $plan=New-TestPlan
        $plan.Entries[0].Proposal.Intent.Aces[0].Mask=2032127
        $saved=Save-TestPlan $plan
        { Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash) } | Should -Throw '*Reconstructed*'
    }
    It 'rejects stale future source-mismatched and executable claims' {
        foreach($mode in @('Stale','Future','Source','Executable')){
            $plan=New-TestPlan
            switch($mode){
                Stale {$plan.CreatedUtc=[DateTime]::UtcNow.AddHours(-25).ToString('o')}
                Future {$plan.CreatedUtc=[DateTime]::UtcNow.AddHours(1).ToString('o')}
                Source {$plan.SourceHash='other'}
                Executable {$plan.Executable=$true}
            }
            $saved=Save-TestPlan $plan
            { Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash) } | Should -Throw
        }
    }
    It 'rejects altered grant masks and before evidence binding' {
        $plan=New-TestPlan
        $plan.Grants[0].Mask=1
        $saved=Save-TestPlan $plan
        { Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash) } | Should -Throw '*grant*'
        $plan=New-TestPlan
        # JSON roundtrip prevents shared fixture references from hiding evidence divergence.
        $plan=(Get-NpCanonicalJson $plan)|ConvertFrom-Json
        $plan.InventoryEvidence[0].Identity='changed'
        $saved=Save-TestPlan $plan
        { Read-NpPlan $saved.Path $saved.Hash (Get-NpSourceHash) } | Should -Throw '*binding*'
    }
}

Describe 'Durable audit and offline-only coordinator' {
    It 'writes hash chained events with actor host UTC ticket version and operation binding' {
        $journal=New-TestJournal
        Write-NpEvent $journal Before Planned @('read-only intent')
        Write-NpEvent $journal After Blocked
        $read=Read-NpJournal $journal.Path
        $read.Status | Should -Be Verified
        $read.Events.Count | Should -Be 2
        $read.Events[0].Ticket | Should -Be CHG123
        $read.Events[0].Version | Should -Be $script:NtfsVersions.Permissions
        [IO.Path]::GetFileName($journal.Path) | Should -Be 'events.jsonl'
        $read.Events[0].Actor | Should -Not -BeNullOrEmpty
        $read.Events[0].Host | Should -Not -BeNullOrEmpty
        $read.Events[0].Utc | Should -Match 'Z$'
        $read.Events[0].OperationId | Should -Be $journal.OperationId
    }
    It 'retains torn final records conservatively and detects tampered complete records' {
        $journal=New-TestJournal
        Write-NpEvent $journal Before Planned
        [IO.File]::AppendAllText($journal.Path,'{"partial":')
        $before=[IO.File]::ReadAllBytes($journal.Path)
        $read=Read-NpJournal $journal.Path
        $read.Status | Should -Be Indeterminate
        $read.Events.Count | Should -Be 1
        (Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))) | Should -Be (Get-NpBytesHash $before)
        $journal=New-TestJournal
        Write-NpEvent $journal Before Planned
        $text=[IO.File]::ReadAllText($journal.Path).Replace('Planned','Hacked')
        [IO.File]::WriteAllText($journal.Path,$text)
        {Read-NpJournal $journal.Path} | Should -Throw '*hash mismatch*'
    }
    It 'retains a torn UTF8 tail and empty journal as Indeterminate' {
        $journal=New-TestJournal
        [IO.File]::WriteAllBytes($journal.Path,[byte[]]@(123,34,195))
        $read=Read-NpJournal $journal.Path
        $read.Status | Should -Be Indeterminate
        $read.Events.Count | Should -Be 0
        [IO.File]::WriteAllBytes($journal.Path,[byte[]]@())
        (Read-NpJournal $journal.Path).Status | Should -Be Indeterminate
    }
    It 'rejects native adapter injection' {
        {Invoke-NpOfflineCoordinator (New-TestPlan) (New-TestJournal) ([pscustomobject]@{Kind='Windows'})} | Should -Throw '*Native writer absent*'
    }
    It 'WhatIf and declined approvals make zero writes' {
        foreach($approved in @($true,$false)){
            $plan=New-TestPlan
            $adapter=New-TestAdapter $plan
            Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter -WhatIf:$approved -Approved $approved | Should -Be WhatIf
            $adapter.Bag.Writes.Count | Should -Be 0
        }
    }
    It 'rejects all pre-write drift including file identity owner group and control' {
        foreach($field in @('Identity','Owner','Group','Control','Descriptor')){
            $plan=New-TestPlan
            $adapter=New-TestAdapter $plan
            $current=(Get-NpCanonicalJson $plan.Entries[0].Before)|ConvertFrom-Json
            if($field -eq 'Control'){$current.Control=1}else{$current.$field='drift'}
            $adapter.Bag.State[$current.Path]=$current
            Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter | Should -Be Failed
            $adapter.Bag.Writes.Count | Should -Be 0
        }
    }
    It 'audit failure before intent blocks the setter' {
        $plan=New-TestPlan
        $adapter=New-TestAdapter $plan
        $journal=New-TestJournal
        $journal.Path=Join-Path $script:work 'missing/denied.jsonl'
        Invoke-NpOfflineCoordinator $plan $journal $adapter | Should -Be Failed
        $adapter.Bag.Writes.Count | Should -Be 0
    }
    It 'durable write-intent failure blocks mutation after successful drift checks' {
        $script:originalEventWriter=${function:Write-NpEvent}
        Mock Write-NpEvent {
            param($Journal,$Stage,$Result,$Changes)
            if($Stage -eq 'WriteIntent'){throw 'Audit disk full'}
            & $script:originalEventWriter $Journal $Stage $Result $Changes
        }
        $plan=New-TestPlan
        $adapter=New-TestAdapter $plan
        Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter | Should -Be Failed
        $adapter.Bag.Writes.Count | Should -Be 0
    }
    It 'post-write audit failure is Indeterminate with no retry or automatic revert' {
        $script:originalEventWriter=${function:Write-NpEvent}
        Mock Write-NpEvent {
            param($Journal,$Stage,$Result,$Changes)
            if($Stage -eq 'WriteReturned'){throw 'Audit disk full'}
            & $script:originalEventWriter $Journal $Stage $Result $Changes
        }
        $plan=New-TestPlan
        $adapter=New-TestAdapter $plan
        Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter | Should -Be Indeterminate
        $adapter.Bag.Writes.Count | Should -Be 1
    }
    It 'descendant identity drift blocks the root setter before any changes' {
        $plan=New-TestPlan @((New-TestSnapshot),(New-TestSnapshot '\\SERVER1\Share1\Folder\a.txt' File))
        $adapter=New-TestAdapter $plan
        $current=(Get-NpCanonicalJson $plan.Entries[1].Before)|ConvertFrom-Json
        $current.Identity='replacement-file'
        $adapter.Bag.State[$current.Path]=$current
        Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter | Should -Be Failed
        $adapter.Bag.Writes.Count | Should -Be 0
    }
    It 'invalid last normalized grant and incomplete coverage block every setter' {
        foreach($condition in @('Grant','Coverage')){
            $plan=New-TestPlan
            if($condition -eq 'Grant'){
                $plan.Grants+= [pscustomobject]@{GroupName='Invalid';SID='S-1-5-21-1-2-3-1002';Permissions='Invented';Mask=1}
            }else{$plan.CoverageComplete=$false}
            $adapter=New-TestAdapter $plan
            Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter | Should -Be Failed
            $adapter.Bag.Writes.Count | Should -Be 0
        }
    }
    It 'uses a single aggregate setter for multiple group grants on one fixture root' {
        $grants=@(Get-NpGrants -Json '[{"GroupName":"A","Permissions":"Read"},{"GroupName":"B","Permissions":"Modify"}]' -Resolve {param($n) if($n -eq 'A'){'S-1-5-21-1-2-3-1001'}else{'S-1-5-21-1-2-3-1002'}})
        $snapshot=New-TestSnapshot
        $inventory=[pscustomobject]@{Snapshots=@($snapshot);Boundaries=@();Errors=@()}
        $plan=New-NpPlan $snapshot.Path $grants ThisFolderSubfoldersAndFiles $inventory (Get-NpSourceHash)
        $adapter=New-TestAdapter $plan
        Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter | Should -Be Verified
        $adapter.Bag.Writes.Count | Should -Be 1
        $adapter.Bag.State[$snapshot.Path].Aces.Count | Should -Be 2
    }
    It 'write throw or verification mismatch stops as Indeterminate without retry rollback' {
        foreach($behavior in @('Throw','Mismatch')){
            $plan=New-TestPlan
            $adapter=New-TestAdapter $plan $behavior
            Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter | Should -Be Indeterminate
            $adapter.Bag.Writes.Count | Should -Be 1
        }
    }
    It 'mock success has durable intent then returned then per-path proof and final verification' {
        $plan=New-TestPlan @((New-TestSnapshot),(New-TestSnapshot '\\SERVER1\Share1\Folder\a.txt' File))
        $adapter=New-TestAdapter $plan
        $journal=New-TestJournal
        Invoke-NpOfflineCoordinator $plan $journal $adapter | Should -Be Verified
        $adapter.Bag.Writes.Count | Should -Be 2
        $events=(Read-NpJournal $journal.Path).Events
        ($events.Stage -join ',') | Should -Be 'Preflight,WriteIntent,WriteReturned,PathVerified,WriteIntent,WriteReturned,PathVerified,Complete'
    }
    It 'all NoOp does not call the setter' {
        $snapshot=New-TestSnapshot
        $snapshot.Aces=@(New-TestAce)
        $plan=New-TestPlan @($snapshot)
        $adapter=New-TestAdapter $plan
        Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter | Should -Be NoOp
        $adapter.Bag.Writes.Count | Should -Be 0
    }
    It 'revert is per-path exact guarded restore or already-before NoOp' {
        $plan=New-TestPlan
        $adapter=New-TestAdapter $plan
        Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter Revert | Should -Be NoOp
        $entry=$plan.Entries[0]
        $adapter.Bag.State[$entry.Before.Path]=$entry.Proposal.Intent
        Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter Revert | Should -Be Reverted
        (Get-NpCanonicalJson $adapter.Bag.State[$entry.Before.Path]) | Should -Be (Get-NpCanonicalJson $entry.Before)
    }
    It 'conflicting revert never forces unrelated drift' {
        $plan=New-TestPlan
        $adapter=New-TestAdapter $plan
        $current=(Get-NpCanonicalJson $plan.Entries[0].Before)|ConvertFrom-Json
        $current.Owner='S-1-5-99'
        $adapter.Bag.State[$current.Path]=$current
        Invoke-NpOfflineCoordinator $plan (New-TestJournal) $adapter Revert | Should -Be RevertConflict
        $adapter.Bag.Writes.Count | Should -Be 0
    }
}

Describe 'Recovery source evidence validation without execution' {
    It 'binds reviewed manifest plan source and journal hashes and returns review-only status' {
        $fixture=New-TestRecoveryEvidence
        $result=Read-NpRecoveryEvidence $fixture.ManifestPath $fixture.PlanHash $fixture.JournalPath $fixture.JournalHash $fixture.SourceHash
        $result.Status | Should -Be ReviewRequired
        $result.Executable | Should -BeFalse
        $result.CurrentState | Should -Be Unverified
        $result.HasNativeStateProof | Should -BeFalse
    }
    It 'retains local host and remote platform recovery scopes without interpreting intent as native state proof' {
        foreach ($descriptor in @((New-NpTargetDescriptor 'Z:\share\folder' Windows -LocalHost HOST),
                (New-NpTargetDescriptor '\\filer\data\folder' NetApp))) {
            $fixture = New-TestRecoveryEvidence $descriptor
            $result = Read-NpRecoveryEvidence $fixture.ManifestPath $fixture.PlanHash $fixture.JournalPath $fixture.JournalHash $fixture.SourceHash
            $result.Plan.TargetDescriptor.Platform | Should -Be $descriptor.Platform
            $result.RecoveryModel.Paths.Count | Should -Be 2
            $result.RecoveryModel.StateModel | Should -Be AbstractIntentOnly
            $result.Executable | Should -BeFalse
        }
    }
    It 'rejects journal path events outside the reviewed canonical recovery scope' {
        $fixture = New-TestRecoveryEvidence
        $journal = New-NpJournal (Split-Path -Parent $fixture.JournalPath) Apply CHG123 $fixture.PlanHash '\\SERVER1\Share1\Folder'
        Remove-Item -LiteralPath $fixture.JournalPath -Force
        Write-NpEvent $journal PathVerified Verified @('\\SERVER1\Share1\Folder-sibling\file.txt')
        $hash = Get-NpBytesHash ([IO.File]::ReadAllBytes($journal.Path))
        { Read-NpRecoveryEvidence $fixture.ManifestPath $fixture.PlanHash $journal.Path $hash $fixture.SourceHash } | Should -Throw '*canonical scope*'
    }
    It 'rejects source journal hash mismatch and unrelated source binding' {
        $fixture=New-TestRecoveryEvidence
        {Read-NpRecoveryEvidence $fixture.ManifestPath $fixture.PlanHash $fixture.JournalPath ('0'*64) $fixture.SourceHash} | Should -Throw '*journal hash*'
        {Read-NpRecoveryEvidence $fixture.ManifestPath $fixture.PlanHash $fixture.JournalPath $fixture.JournalHash ('0'*64)} | Should -Throw '*binding*'
    }
    It 'does not discard a torn source journal to manufacture a recovery decision' {
        $fixture=New-TestRecoveryEvidence
        [IO.File]::AppendAllText($fixture.JournalPath,'{"torn":')
        $hash=Get-NpBytesHash ([IO.File]::ReadAllBytes($fixture.JournalPath))
        $result=Read-NpRecoveryEvidence $fixture.ManifestPath $fixture.PlanHash $fixture.JournalPath $hash $fixture.SourceHash
        $result.Status | Should -Be Indeterminate
        $result.Executable | Should -BeFalse
        [IO.File]::ReadAllText($fixture.JournalPath) | Should -Match 'torn'
    }
    It 'rejects an evidence path traversal even with a valid plan binding' {
        $fixture=New-TestRecoveryEvidence
        $manifest=[IO.File]::ReadAllText($fixture.ManifestPath)|ConvertFrom-Json
        $manifest.Files+= [pscustomobject]@{Name='../unrelated';SHA256=('0'*64)}
        [IO.File]::WriteAllText($fixture.ManifestPath,(Get-NpCanonicalJson $manifest))
        {Read-NpRecoveryEvidence $fixture.ManifestPath $fixture.PlanHash $fixture.JournalPath $fixture.JournalHash $fixture.SourceHash} | Should -Throw '*filename*'
    }
}

Describe 'Public qualification gate' {
    BeforeEach {
        # Public contract tests never modify even a test directory's Windows ACL.
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            Mock Set-Acl { param($LiteralPath,$AclObject) $script:testAuditAcl=$AclObject }
            Mock Get-Acl { $script:testAuditAcl }
            Mock Get-SmbShare { @() }
        }
    }
    It 'Apply and Revert are audited Blocked with zero writes, including WhatIf' {
        $saved=Save-TestPlan (New-TestPlan)
        foreach($mode in @('Apply','Revert')){
            foreach($preview in @($false,$true)){
                $result=& (Join-Path $PSScriptRoot '../Add-FileSharePermissions.ps1') -Mode $mode -PlanPath $saved.Path -PlanSHA256 $saved.Hash -ChangeTicket CHG123 -OutputDirectory $script:work -WhatIf:$preview
                $result.Status | Should -Be Blocked
                $result.TargetWrites | Should -Be 0
                $result.Qualification | Should -Be NotQualified
                $LASTEXITCODE | Should -Be 2
                $read=Read-NpJournal (Join-Path $result.RunDirectory 'events.jsonl')
                $read.Events.Result | Should -Contain 'Blocked/NotQualified'
            }
        }
    }
    It 'preserves each platform gate through public Apply and Revert without a native setter' {
        $descriptors = @(
            (New-NpTargetDescriptor 'Z:\share\folder' Windows -LocalHost ([Environment]::MachineName)),
            (New-NpTargetDescriptor '\\server\data\folder' Windows),
            (New-NpTargetDescriptor '\\filer\data\folder' NetApp),
            (New-NpTargetDescriptor '\\nas\data\folder' Nas)
        )
        foreach ($descriptor in $descriptors) {
            $saved = Save-TestPlan (New-TestPlatformPlan $descriptor)
            foreach ($mode in @('Apply','Revert')) {
                $result = & (Join-Path $PSScriptRoot '../Add-FileSharePermissions.ps1') -Mode $mode -PlanPath $saved.Path -PlanSHA256 $saved.Hash -ChangeTicket CHG123 -OutputDirectory $script:work
                $result.Status | Should -Be Blocked
                $result.MutationStatus | Should -Be MutationNotQualified
                $result.TargetDescriptor.QualificationScope | Should -Be $descriptor.Platform
                $result.TargetWrites | Should -Be 0
                $LASTEXITCODE | Should -Be 2
            }
        }
    }
    It 'does not allow Apply to override a reviewed platform' {
        $saved = Save-TestPlan (New-TestPlan)
        $result = & (Join-Path $PSScriptRoot '../Add-FileSharePermissions.ps1') -Mode Apply -PlanPath $saved.Path -PlanSHA256 $saved.Hash -TargetPlatform NetApp -ChangeTicket CHG123 -OutputDirectory $script:work
        $result.Status | Should -Be Blocked
        $result.Reason | Should -Match 'platform cannot be overridden'
    }
    It 'blocks a different execution host and never re-resolves frozen mapped UNC during Apply or Revert' {
        Mock Resolve-NpTarget { throw 'Must not resolve reviewed input again.' }
        Mock Get-NpDriveBinding { throw 'Must not resolve reviewed input again.' }
        foreach ($mode in @('Apply','Revert')) {
            $local = New-NpTargetDescriptor 'Z:\share\folder' Windows -LocalHost 'OTHER-EXECUTION-HOST'
            $saved = Save-TestPlan (New-TestPlatformPlan $local)
            $result = & (Join-Path $PSScriptRoot '../Add-FileSharePermissions.ps1') -Mode $mode -PlanPath $saved.Path -PlanSHA256 $saved.Hash -ChangeTicket CHG123 -OutputDirectory $script:work
            $result.Reason | Should -Match 'execution host mismatch'
            $result.TargetWrites | Should -Be 0
            $LASTEXITCODE | Should -Be 2
            $mapped = New-NpTargetDescriptor 'Z:\share\folder' NetApp '\\filer\data\department'
            $saved = Save-TestPlan (New-TestPlatformPlan $mapped)
            $result = & (Join-Path $PSScriptRoot '../Add-FileSharePermissions.ps1') -Mode $mode -PlanPath $saved.Path -PlanSHA256 $saved.Hash -ChangeTicket CHG123 -OutputDirectory $script:work
            $result.TargetDescriptor.CanonicalPath | Should -Be '\\filer\data\department\share\folder'
            $result.Reason | Should -Match 'MutationNotQualified/NetAppSMB'
            $result.TargetWrites | Should -Be 0
            $LASTEXITCODE | Should -Be 2
        }
        Should -Invoke Resolve-NpTarget -Times 0
        Should -Invoke Get-NpDriveBinding -Times 0
    }
    It 'public gate rejects invalid plans/tickets with preserved audit evidence' {
        $saved=Save-TestPlan (New-TestPlan)
        $result=& (Join-Path $PSScriptRoot '../Add-FileSharePermissions.ps1') -Mode Apply -PlanPath $saved.Path -PlanSHA256 ('0'*64) -ChangeTicket CHG123 -OutputDirectory $script:work
        $result.Status | Should -Be Blocked
        $result.TargetWrites | Should -Be 0
        $result.Reason | Should -Match 'hash mismatch'
        (Read-NpJournal (Join-Path $result.RunDirectory 'events.jsonl')).Events.Count | Should -Be 2
    }
    It 'has no public mutation bypass parameter' {
        $command=Get-Command (Join-Path $PSScriptRoot '../Add-FileSharePermissions.ps1')
        foreach($name in @('Force','Experimental','Adapter','Qualified','Writer')){
            $command.Parameters.ContainsKey($name) | Should -BeFalse
        }
        $command.Parameters['TargetPath'].Aliases | Should -Contain ShareName
    }
}
