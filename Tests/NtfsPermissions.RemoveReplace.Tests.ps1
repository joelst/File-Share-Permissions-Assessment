#requires -Version 5.1
<#
.SYNOPSIS
Regression tests for the disposable local remove/replace workflow.
.DESCRIPTION
Uses only uniquely named, actor-restricted fixtures under Tests and synthetic
SIDs. No customer paths or directory-service objects are used.
#>
[CmdletBinding()]
param()

Describe 'Disposable local remove and replace permissions' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    BeforeAll {
        $script:work = $null
        $script:workIdentity = $null
        $script:caseWork = $null
        $script:caseIdentity = $null
        $script:unsafeCleanup = $false
        . (Join-Path (Split-Path $PSScriptRoot -Parent) 'NtfsPermissions.Local.ps1')
        Initialize-NpLocalNative

        $script:entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'Add-FileSharePermissions.ps1'
        $command = Get-Command -Name $script:entry -ErrorAction Stop
        foreach ($name in @('Operation', 'RemovePrincipal')) {
            if (-not $command.Parameters.ContainsKey($name)) {
                throw "The public entry point does not yet expose -$name."
            }
        }

        $script:sourceSid = 'S-1-5-21-100-200-300-401'
        $script:replacementSid = 'S-1-5-21-100-200-300-402'
        $script:unrelatedSid = 'S-1-5-21-100-200-300-999'
        $script:driftSid = 'S-1-5-21-100-200-300-998'
        $script:actorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($script:actorSid.Value -in @($script:sourceSid, $script:replacementSid, $script:unrelatedSid, $script:driftSid)) {
            throw 'The current actor unexpectedly matches a synthetic test SID.'
        }
        function Get-FixtureIdentity {
            param([Parameter(Mandatory = $true)][string] $Path)
            $lease = [NtfsPermissions.LocalCandidate.Lease]::Open($Path, $false)
            try { return $lease.Read().Identity } finally { $lease.Dispose() }
        }

        function Set-RestrictedFixtureAcl {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Restricts a newly created test fixture.')]
            [CmdletBinding()]
            param([Parameter(Mandatory = $true)][string] $Path)
            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $acl.SetAccessRuleProtection($true, $false)
            $acl.SetOwner($script:actorSid)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $script:actorSid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        }

        function Add-FixtureAce {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes only a newly created test fixture.')]
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)][string] $Path,
                [Parameter(Mandatory = $true)][string] $Sid,
                [Parameter(Mandatory = $true)][string] $Rights,
                [ValidateSet('Allow', 'Deny')][string] $Type = 'Allow'
            )
            $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($Sid), $Rights, 'None', 'None', $Type))
            Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        }

        function New-RemovalFixture {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates only a uniquely owned disposable fixture.')]
            [CmdletBinding()]
            param(
                [string] $SourceSid = $script:sourceSid,
                [bool] $IncludeSource = $true,
                [bool] $InheritableSource = $true,
                [bool] $ExplicitDescendants = $true,
                [bool] $IncludeReplacement = $false,
                [string] $TargetName = 'target'
            )
            if ([string]::IsNullOrWhiteSpace($TargetName) -or $TargetName -in @('.', '..') -or
                $TargetName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                throw 'Fixture target name must be a single valid path component.'
            }
            $target = Join-Path $script:caseWork $TargetName
            if (Test-Path -LiteralPath $target) { throw "Fixture already exists: $target" }
            [void][IO.Directory]::CreateDirectory($target)

            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $acl.SetAccessRuleProtection($true, $false)
            $acl.SetOwner($script:actorSid)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $script:actorSid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($script:unrelatedSid),
                'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            if ($IncludeSource) {
                $inheritance = if ($InheritableSource) { 'ContainerInherit, ObjectInherit' } else { 'None' }
                # Even the Everyone fixture grants no file-data read or write.
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new($SourceSid),
                    'ReadPermissions', $inheritance, 'None', 'Allow'))
            }
            if ($IncludeReplacement) {
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new($script:replacementSid),
                    'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            }
            Set-Acl -LiteralPath $target -AclObject $acl -ErrorAction Stop

            $child = Join-Path $target 'child'
            $rootFile = Join-Path $target 'root.txt'
            $childFile = Join-Path $child 'child.txt'
            $protected = Join-Path $target 'protected'
            $protectedFile = Join-Path $protected 'sentinel.txt'
            [void][IO.Directory]::CreateDirectory($child)
            [IO.File]::WriteAllText($rootFile, 'root fixture content')
            [IO.File]::WriteAllText($childFile, 'child fixture content')
            [void][IO.Directory]::CreateDirectory($protected)
            $protectedAcl = Get-Acl -LiteralPath $protected -ErrorAction Stop
            $protectedAcl.SetAccessRuleProtection($true, $true)
            Set-Acl -LiteralPath $protected -AclObject $protectedAcl -ErrorAction Stop
            [IO.File]::WriteAllText($protectedFile, 'protected fixture content')

            if ($IncludeSource -and $ExplicitDescendants) {
                Add-FixtureAce -Path $child -Sid $SourceSid -Rights ReadAttributes
                Add-FixtureAce -Path $childFile -Sid $SourceSid -Rights ReadAttributes
            }
            $fixture = [pscustomobject]@{
                Target = $target; Child = $child; RootFile = $rootFile; ChildFile = $childFile
                Protected = $protected; ProtectedFile = $protectedFile; SourceSid = $SourceSid
                IncludeSource = $IncludeSource; InheritableSource = $InheritableSource
                ExplicitDescendants = $ExplicitDescendants
            }
            Write-Information ("Fixture target={0}; child={1}; file={2}; protected={3}; evidence={4}" -f
                $target, $child, $childFile, $protected, (Join-Path $script:caseWork 'evidence')) -InformationAction Continue
            return $fixture
        }

        function New-UnmanagedInheritanceFixture {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates only an owned disposable fixture.')]
            [CmdletBinding()]
            param([string] $Parent = $script:caseWork, [bool] $IncludeSource = $true)

            $target = Join-Path $Parent ('raw_' + [guid]::NewGuid().ToString('N').Substring(0, 12))
            if (Test-Path -LiteralPath $target) { throw "Fixture already exists: $target" }
            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $acl.SetAccessRuleProtection($true, $false)
            $acl.SetOwner($script:actorSid)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $script:actorSid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            if ($IncludeSource) {
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new($script:sourceSid),
                    'ReadPermissions', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            }
            if ($PSVersionTable.PSEdition -ceq 'Desktop') {
                [void][IO.Directory]::CreateDirectory($target, $acl)
            } else {
                [void][IO.FileSystemAclExtensions]::CreateDirectory($acl, $target)
            }
            $child = Join-Path $target 'child'
            [void][IO.Directory]::CreateDirectory($child)
            $file = Join-Path $child 'sentinel.txt'
            [IO.File]::WriteAllText($file, 'unmanaged inheritance fixture')
            return [pscustomobject]@{
                Target = $target; Child = $child; ChildFile = $file; SourceSid = $script:sourceSid
                Protected = ''; ProtectedFile = ''
            }
        }

        function Get-FixtureState {
            param([Parameter(Mandatory = $true)] $Fixture)
            return @(Get-NpLocalInventory -targetPath $Fixture.Target | Sort-Object -Property Path)
        }

        function Get-PathSnapshot {
            param([Parameter(Mandatory = $true)] $State, [Parameter(Mandatory = $true)][string] $Path)
            $foundSnapshots = @($State | Where-Object { $_.Path -ieq $Path })
            if ($foundSnapshots.Count -ne 1) { throw "Expected one snapshot for '$Path'; found $($foundSnapshots.Count)." }
            return $foundSnapshots[0]
        }

        function Assert-FixtureContent {
            param([Parameter(Mandatory = $true)] $Fixture)
            [IO.File]::ReadAllText($Fixture.RootFile) | Should -BeExactly 'root fixture content' -Because $Fixture.RootFile
            [IO.File]::ReadAllText($Fixture.ChildFile) | Should -BeExactly 'child fixture content' -Because $Fixture.ChildFile
            [IO.File]::ReadAllText($Fixture.ProtectedFile) | Should -BeExactly 'protected fixture content' -Because $Fixture.ProtectedFile
        }

        function Assert-InitialFixture {
            param([Parameter(Mandatory = $true)] $Fixture, [Parameter(Mandatory = $true)] $State)
            @($State).Count | Should -Be 6 -Because "fixture tree at $($Fixture.Target)"
            foreach ($path in @($Fixture.Target, $Fixture.Child, $Fixture.RootFile, $Fixture.ChildFile,
                    $Fixture.Protected, $Fixture.ProtectedFile)) {
                Test-Path -LiteralPath $path | Should -BeTrue -Because "fixture path $path"
                $snapshot = Get-PathSnapshot $State $path
                @($snapshot.Aces | Where-Object { $_.SID -eq $script:unrelatedSid -and $_.Type -eq 'Allow' }).Count |
                    Should -BeGreaterThan 0 -Because "unrelated sentinel ACE at $path"
            }
            (Get-PathSnapshot $State $Fixture.Protected).Protected | Should -BeTrue -Because $Fixture.Protected
            $root = Get-PathSnapshot $State $Fixture.Target
            $source = @($root.Aces | Where-Object { $_.SID -eq $Fixture.SourceSid -and $_.Type -eq 'Allow' })
            if ($Fixture.IncludeSource) {
                @($source | Where-Object { -not $_.Inherited }).Count |
                    Should -BeGreaterThan 0 -Because "explicit source ACE at $($Fixture.Target)"
                if ($Fixture.InheritableSource) {
                    @($source | Where-Object { $_.ContainerInherit -and $_.ObjectInherit }).Count |
                        Should -BeGreaterThan 0 -Because "inheritable source ACE at $($Fixture.Target)"
                    foreach ($path in @($Fixture.Child, $Fixture.RootFile, $Fixture.ChildFile, $Fixture.ProtectedFile)) {
                        $snapshot = Get-PathSnapshot $State $path
                        @($snapshot.Aces | Where-Object {
                            $_.SID -eq $Fixture.SourceSid -and $_.Type -eq 'Allow' -and $_.Inherited
                        }).Count | Should -BeGreaterThan 0 -Because "inherited source ACE at $path"
                    }
                } else {
                    @($source | Where-Object { $_.ContainerInherit -or $_.ObjectInherit }).Count |
                        Should -Be 0 -Because "non-inheritable source ACE at $($Fixture.Target)"
                }
                if ($Fixture.ExplicitDescendants) {
                    foreach ($path in @($Fixture.Child, $Fixture.ChildFile)) {
                        $snapshot = Get-PathSnapshot $State $path
                        @($snapshot.Aces | Where-Object {
                            $_.SID -eq $Fixture.SourceSid -and $_.Type -eq 'Allow' -and -not $_.Inherited
                        }).Count | Should -BeGreaterThan 0 -Because "explicit source ACE at $path"
                    }
                }
            } else {
                $source.Count | Should -Be 0 -Because "source is initially absent at $($Fixture.Target)"
            }
            Assert-FixtureContent $Fixture
        }

        function Assert-SameFixtureState {
            param([Parameter(Mandatory = $true)] $Before, [Parameter(Mandatory = $true)] $After)
            @($After).Count | Should -Be @($Before).Count
            foreach ($entry in $Before) {
                $current = Get-PathSnapshot $After $entry.Path
                (Get-NpCanonicalJson $current) | Should -BeExactly (Get-NpCanonicalJson $entry) -Because $entry.Path
            }
        }

        function Assert-UnrelatedState {
            param(
                [Parameter(Mandatory = $true)] $Before,
                [Parameter(Mandatory = $true)] $After,
                [Parameter(Mandatory = $true)][string[]] $ChangedSids
            )
            foreach ($entry in $Before) {
                $current = Get-PathSnapshot $After $entry.Path
                foreach ($name in @('Identity', 'Owner', 'Group', 'Control', 'Protected')) {
                    $current.$name | Should -Be $entry.$name -Because "$name at $($entry.Path)"
                }
                $beforeAces = @($entry.Aces | Where-Object { $ChangedSids -notcontains $_.SID })
                $afterAces = @($current.Aces | Where-Object { $ChangedSids -notcontains $_.SID })
                (Get-NpCanonicalJson $afterAces) | Should -BeExactly (Get-NpCanonicalJson $beforeAces) -Because "unrelated ACEs at $($entry.Path)"
            }
        }

        function Assert-SourceAbsent {
            param([Parameter(Mandatory = $true)] $State, [Parameter(Mandatory = $true)][string] $Sid,
                [Parameter(Mandatory = $true)][string[]] $Paths)
            foreach ($path in $Paths) {
                $snapshot = Get-PathSnapshot $State $path
                @($snapshot.Aces | Where-Object { $_.SID -eq $Sid -and $_.Type -eq 'Allow' }).Count |
                    Should -Be 0 -Because "removed allow ACEs at $path"
            }
        }

        function Assert-ReplacementGrant {
            param([Parameter(Mandatory = $true)] $State, [Parameter(Mandatory = $true)][string[]] $Paths,
                [Parameter(Mandatory = $true)][string] $Rights, [bool] $Recursive)
            $expected = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($script:replacementSid), $Rights, 'Allow')
            foreach ($path in $Paths) {
                $snapshot = Get-PathSnapshot $State $path
                $aces = @($snapshot.Aces | Where-Object {
                    $_.SID -eq $script:replacementSid -and $_.Type -eq 'Allow' -and -not $_.InheritOnly
                })
                $aces.Count | Should -BeGreaterThan 0 -Because "replacement allow ACE at $path"
                [long]$mask = 0
                foreach ($ace in $aces) { $mask = $mask -bor [long]$ace.Mask }
                $mask | Should -Be ([long][int]$expected.FileSystemRights) -Because "exact replacement rights at $path"
                if ($snapshot.Kind -eq 'Folder' -and $Recursive) {
                    @($aces | Where-Object { $_.ContainerInherit -and $_.ObjectInherit -and -not $_.NoPropagate }).Count |
                        Should -BeGreaterThan 0 -Because "recursive replacement inheritance at $path"
                } elseif ($snapshot.Kind -eq 'Folder') {
                    @($aces | Where-Object { $_.ContainerInherit -or $_.ObjectInherit }).Count |
                        Should -Be 0 -Because "folder-only replacement at $path"
                }
            }
        }

        function Get-ChangeArgument {
            param([Parameter(Mandatory = $true)] $Fixture, [string] $Operation = 'Remove')
            return @{
                Mode = 'Apply'; DisposableLocalLab = $true; DisposableAcknowledgement = $true
                TargetPath = $Fixture.Target; Operation = $Operation; RemovePrincipal = $Fixture.SourceSid
                Scope = 'ThisFolderSubfoldersAndFiles'; OutputDirectory = (Join-Path $script:caseWork 'evidence')
                ChangeTicket = 'DISPOSABLE-REMOVE-REPLACE-TEST'; Confirm = $false
            }
        }

        function Get-ResultText {
            param([Parameter(Mandatory = $true)] $Result)
            $parts = foreach ($property in $Result.PSObject.Properties) {
                foreach ($value in @($property.Value)) {
                    if ($value -is [string]) { $value }
                }
            }
            return ($parts -join ' ')
        }

        function Get-FixtureReport {
            param([AllowEmptyString()][string] $Directory)
            if ([string]::IsNullOrWhiteSpace($Directory) -or
                -not (Test-Path -LiteralPath $Directory -PathType Container)) { return }
            $fullPath = [IO.Path]::GetFullPath($Directory)
            if (-not $fullPath.StartsWith($script:caseWork + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to inspect evidence outside the owned case: $fullPath"
            }
            foreach ($file in @(Get-ChildItem -LiteralPath $fullPath -Filter '*.csv' -File -Recurse -ErrorAction Stop)) {
                $header = [IO.File]::ReadLines($file.FullName) | Select-Object -First 1
                if ($header -match 'BeforeDescriptor' -and $header -match 'AfterDescriptor' -and
                    $header -match 'BeforeAces' -and $header -match 'AfterAces') {
                    $file.FullName
                }
            }
        }

        function Assert-NoAuditReport {
            param([Parameter(Mandatory = $true)] $Result)
            foreach ($name in @('AuditReportPath', 'AuditReportSHA256')) {
                $property = $Result.PSObject.Properties[$name]
                if ($null -ne $property) { [string]$property.Value | Should -BeNullOrEmpty -Because "$name must be absent for unverified work" }
            }
            $runProperty = $Result.PSObject.Properties['RunDirectory']
            if ($null -ne $runProperty -and $runProperty.Value) {
                $reports = @(Get-FixtureReport ([string]$runProperty.Value))
                $reports.Count | Should -Be 0 -Because "unverified run $($runProperty.Value) must not create an audit report"
            }
        }

        function Invoke-ExpectRefusal {
            [CmdletBinding()]
            param([Parameter(Mandatory = $true)][hashtable] $Arguments)
            $outputDirectory = if ($Arguments.ContainsKey('OutputDirectory')) { [string]$Arguments.OutputDirectory } else { '' }
            $reportsBefore = @(Get-FixtureReport $outputDirectory)
            try {
                $result = & $script:entry @Arguments
            } catch {
                if ($_.FullyQualifiedErrorId -match 'NamedParameterNotFound') { throw }
                $newReports = @(Get-FixtureReport $outputDirectory | Where-Object { $reportsBefore -notcontains $_ })
                $newReports.Count | Should -Be 0 -Because "a refused operation must not create an audit report: $newReports"
                return [pscustomobject]@{ Status = 'Exception'; Reason = $_.Exception.Message }
            }
            if ($null -eq $result -or $null -eq $result.PSObject.Properties['Status']) {
                throw 'Expected an explicit refusal result or a terminating validation error.'
            }
            $result.Status | Should -Match '(?i)block|reject|refus|fail|error' -Because (Get-ResultText $result)
            Assert-NoAuditReport $result
            $newReports = @(Get-FixtureReport $outputDirectory | Where-Object { $reportsBefore -notcontains $_ })
            $newReports.Count | Should -Be 0 -Because "a refused operation must not create an audit report: $newReports"
            return $result
        }

        function Assert-ChangedResult {
            param([Parameter(Mandatory = $true)] $Result)
            $Result.Status | Should -Not -Match '(?i)block|reject|refus|fail|error|indeterminate|whatif|declin|no.?op' `
                -Because (Get-ResultText $Result)
        }

        function Assert-FileHash {
            param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $Hash)
            $Path | Should -Not -BeNullOrEmpty
            $Hash | Should -Match '^[a-fA-F0-9]{64}$'
            Test-Path -LiteralPath $Path -PathType Leaf | Should -BeTrue -Because $Path
            (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash | Should -Be $Hash -Because $Path
        }

        function Assert-ApplyEvidence {
            param([Parameter(Mandatory = $true)] $Result, [Parameter(Mandatory = $true)] $Fixture)
            Assert-FileHash $Result.ReceiptPath $Result.ReceiptSHA256
            Assert-FileHash $Result.RecoveryRecordPath $Result.RecoveryRecordSHA256
            Assert-FileHash $Result.ApplyJournalPath $Result.ApplyJournalSHA256
            $receipt = [IO.File]::ReadAllText($Result.ReceiptPath) | ConvertFrom-NpJson
            $receipt.Target | Should -Be $Fixture.Target
            $receipt.SourceHash | Should -Be (Get-NpSourceHash)
            $receipt.PlanPath | Should -Be $Result.RecoveryRecordPath
            $receipt.PlanSHA256 | Should -Be $Result.RecoveryRecordSHA256
            $receipt.JournalPath | Should -Be $Result.ApplyJournalPath
            $plan = [IO.File]::ReadAllText($Result.RecoveryRecordPath) | ConvertFrom-NpJson
            $plan.SourceHash | Should -Be $receipt.SourceHash
            $plan.TargetDescriptor.CanonicalPath | Should -Be $Fixture.Target
            $journal = Read-NpJournal -Path $Result.ApplyJournalPath
            $journal.Status | Should -Be 'Verified'
            $journal.SHA256 | Should -Be $Result.ApplyJournalSHA256
            foreach ($record in $journal.Events) {
                $record.Target | Should -Be $Fixture.Target
                $record.SourceHash | Should -Be $receipt.SourceHash
                $record.PlanHash | Should -Be $Result.RecoveryRecordSHA256
            }
        }

        function ConvertTo-ComparableAceJson {
            param([AllowEmptyCollection()][object[]] $Aces)
            $normalized = @(
                foreach ($ace in $Aces) {
                    foreach ($name in @('SID', 'Type', 'Mask', 'Inherited', 'ContainerInherit',
                            'ObjectInherit', 'InheritOnly', 'NoPropagate')) {
                        if ($null -eq $ace.PSObject.Properties[$name]) { throw "ACE evidence is missing $name." }
                    }
                    [pscustomobject][ordered]@{
                        SID = [string]$ace.SID; Type = [string]$ace.Type; Mask = [long]$ace.Mask
                        Inherited = [bool]$ace.Inherited; ContainerInherit = [bool]$ace.ContainerInherit
                        ObjectInherit = [bool]$ace.ObjectInherit; InheritOnly = [bool]$ace.InheritOnly
                        NoPropagate = [bool]$ace.NoPropagate
                    }
                }
            )
            return Get-NpCanonicalJson $normalized
        }

        function ConvertFrom-AceJson {
            param([Parameter(Mandatory = $true)][string] $Json)
            if ($Json -notmatch '^\s*\[[\s\S]*\]\s*$') { throw 'ACE evidence must be a JSON array.' }
            $parsed = $Json | ConvertFrom-NpJson
            if ($null -ne $parsed) {
                foreach ($ace in $parsed) { $ace }
            }
        }

        function Get-ExpectedAceDifference {
            param([AllowEmptyCollection()][object[]] $Left, [AllowEmptyCollection()][object[]] $Right)
            $counts = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::Ordinal)
            foreach ($ace in $Right) {
                $key = ConvertTo-ComparableAceJson @($ace)
                if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
            }
            foreach ($ace in $Left) {
                $key = ConvertTo-ComparableAceJson @($ace)
                if ($counts.ContainsKey($key) -and $counts[$key] -gt 0) {
                    $counts[$key]--
                } else { $ace }
            }
        }

        function ConvertTo-AceMultisetJson {
            param([AllowEmptyCollection()][object[]] $Aces)
            $keys = @(foreach ($ace in $Aces) { ConvertTo-ComparableAceJson @($ace) })
            return Get-NpCanonicalJson @($keys | Sort-Object -CaseSensitive)
        }

        function Assert-ApplyAuditReport {
            param(
                [Parameter(Mandatory = $true)] $Result, [Parameter(Mandatory = $true)] $Fixture,
                [Parameter(Mandatory = $true)] $Before, [Parameter(Mandatory = $true)] $After,
                [Parameter(Mandatory = $true)][string] $Scope,
                [Parameter(Mandatory = $true)][string] $Operation
            )
            Assert-FileHash $Result.AuditReportPath $Result.AuditReportSHA256
            $journal = Read-NpJournal -Path $Result.ApplyJournalPath
            @($journal.Events).Count | Should -BeGreaterThan 0
            $audit = $journal.Events[0]
            $rows = @(Import-Csv -LiteralPath $Result.AuditReportPath -ErrorAction Stop)
            $rows.Count | Should -Be @($Before).Count -Because "one report row per path in $($Fixture.Target)"
            foreach ($entry in $Before) {
                $pathRows = @($rows | Where-Object { $_.Path -ieq $entry.Path })
                $pathRows.Count | Should -Be 1 -Because "audit report row for $($entry.Path)"
                $row = $pathRows[0]
                $current = Get-PathSnapshot $After $entry.Path
                $row.Kind | Should -Be $entry.Kind -Because $entry.Path
                $row.OperationId | Should -BeExactly $audit.OperationId -Because $entry.Path
                $row.Host | Should -BeExactly $audit.Host -Because $entry.Path
                $row.Mode | Should -BeExactly 'Apply' -Because $entry.Path
                $row.Operation | Should -BeExactly $Operation -Because $entry.Path
                $row.Actor | Should -BeExactly $audit.Actor -Because $entry.Path
                if ($audit.Ticket -match '^[\s]*[=+\-@]') {
                    $row.ChangeTicket | Should -Not -BeExactly $audit.Ticket -Because 'spreadsheet formulas must be neutralized'
                    $row.ChangeTicket.EndsWith([string]$audit.Ticket, [StringComparison]::Ordinal) |
                        Should -BeTrue -Because 'the neutralized ticket must retain the original value'
                    $row.ChangeTicket | Should -Not -Match '^[\s]*[=+\-@]' -Because 'the report must not expose a spreadsheet formula'
                } else {
                    $row.ChangeTicket | Should -BeExactly $audit.Ticket -Because $entry.Path
                }
                $verifiedTime = [DateTimeOffset]::MinValue
                [DateTimeOffset]::TryParse([string]$row.VerifiedUtc, [ref]$verifiedTime) |
                    Should -BeTrue -Because "verified UTC timestamp at $($entry.Path)"
                $verifiedTime.Offset | Should -Be ([TimeSpan]::Zero) -Because "verified UTC timestamp at $($entry.Path)"
                $row.BeforeDescriptor | Should -BeExactly $entry.Descriptor -Because "before descriptor at $($entry.Path)"
                $row.AfterDescriptor | Should -BeExactly $current.Descriptor -Because "actual after descriptor at $($entry.Path)"
                if ($entry.Descriptor -ceq $current.Descriptor) {
                    $row.Result | Should -Match '(?i)unchanged|no.?op|no.?change|excluded' -Because $entry.Path
                } else {
                    $row.Result | Should -Match '(?i)^changed$|^applied$|^verified.?change' -Because $entry.Path
                }
                $beforeAces = @(ConvertFrom-AceJson $row.BeforeAces)
                $afterAces = @(ConvertFrom-AceJson $row.AfterAces)
                (ConvertTo-ComparableAceJson $beforeAces) | Should -BeExactly (ConvertTo-ComparableAceJson @($entry.Aces)) `
                    -Because "before ACE data at $($entry.Path)"
                (ConvertTo-ComparableAceJson $afterAces) | Should -BeExactly (ConvertTo-ComparableAceJson @($current.Aces)) `
                    -Because "actual after ACE data at $($entry.Path)"
                [string]$row.RemovedAces | Should -Not -BeNullOrEmpty -Because "removed ACE multiset at $($entry.Path)"
                [string]$row.AddedAces | Should -Not -BeNullOrEmpty -Because "added ACE multiset at $($entry.Path)"
                $removed = @(ConvertFrom-AceJson $row.RemovedAces)
                $added = @(ConvertFrom-AceJson $row.AddedAces)
                $expectedRemoved = @(Get-ExpectedAceDifference @($entry.Aces) @($current.Aces))
                $expectedAdded = @(Get-ExpectedAceDifference @($current.Aces) @($entry.Aces))
                (ConvertTo-AceMultisetJson $removed) | Should -BeExactly (ConvertTo-AceMultisetJson $expectedRemoved) `
                    -Because "removed ACE multiset at $($entry.Path)"
                (ConvertTo-AceMultisetJson $added) | Should -BeExactly (ConvertTo-AceMultisetJson $expectedAdded) `
                    -Because "added ACE multiset at $($entry.Path)"
                if ($entry.Path -in @($Fixture.Protected, $Fixture.ProtectedFile)) {
                    $row.Scope | Should -Match '(?i)protect|exclud' -Because "protected path $($entry.Path)"
                    $row.BeforeDescriptor | Should -BeExactly $row.AfterDescriptor -Because $entry.Path
                } elseif ($Scope -eq 'ThisFolderOnly' -and $entry.Path -ne $Fixture.Target) {
                    $row.Scope | Should -Match '(?i)outside|exclud' -Because "outside selected scope: $($entry.Path)"
                    $row.BeforeDescriptor | Should -BeExactly $row.AfterDescriptor -Because $entry.Path
                } else {
                    $row.Scope | Should -Match '(?i)in.?scope|includ' -Because "included path $($entry.Path)"
                }
            }
        }

        function Assert-PreviewIsNotVerified {
            param([Parameter(Mandatory = $true)] $Result)
            $Result.Status | Should -Not -Match '(?i)^verified$|^success$'
            Assert-NoAuditReport $Result
        }

        function Invoke-OrdinaryRevert {
            param([Parameter(Mandatory = $true)] $Apply)
            return & $script:entry -Mode Revert -DisposableLocalLab -DisposableAcknowledgement `
                -ReceiptPath $Apply.ReceiptPath -ReceiptSHA256 $Apply.ReceiptSHA256 `
                -ReviewedApplyJournalSHA256 $Apply.ApplyJournalSHA256 `
                -OutputDirectory (Join-Path $script:caseWork 'evidence') `
                -ChangeTicket 'DISPOSABLE-REVERT-TEST' -Confirm:$false
        }

        $script:work = Join-Path $PSScriptRoot ('RemoveReplace_' + [guid]::NewGuid().ToString('N').Substring(0, 12))
        if (Test-Path -LiteralPath $script:work) { throw "Fixture root already exists: $($script:work)" }
        [void][IO.Directory]::CreateDirectory($script:work)
        Set-RestrictedFixtureAcl -Path $script:work
        $script:workIdentity = Get-FixtureIdentity $script:work
    }

    BeforeEach {
        # A local stub also prevents accidental AD access if the mock is not invoked.
        function Get-ADGroup { throw 'Real AD discovery is forbidden in these tests.' }
        Mock Get-ADGroup {
            param($Identity)
            if ([string]$Identity -notin @('S-1-5-21-100-200-300-401', 'S-1-5-21-100-200-300-402', 'S-1-1-0')) {
                throw "Unexpected test group identity: $Identity"
            }
            [pscustomobject]@{ GroupCategory = 'Security'; SID = [string]$Identity }
        }
        $script:caseWork = Join-Path $script:work ('case_' + [guid]::NewGuid().ToString('N').Substring(0, 12))
        $script:caseIdentity = $null
        if (Test-Path -LiteralPath $script:caseWork) { throw "Fixture case already exists: $($script:caseWork)" }
        [void][IO.Directory]::CreateDirectory($script:caseWork)
        $script:caseIdentity = Get-FixtureIdentity $script:caseWork
    }

    AfterEach {
        if ($script:caseWork -and (Test-Path -LiteralPath $script:caseWork)) {
            if (-not $script:caseIdentity -or (Get-FixtureIdentity $script:caseWork) -cne $script:caseIdentity) {
                $script:unsafeCleanup = $true
                throw "Refusing to delete a fixture with changed identity: $($script:caseWork)"
            }
            Remove-Item -LiteralPath $script:caseWork -Recurse -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
        }
    }

    AfterAll {
        if ($script:work -and (Test-Path -LiteralPath $script:work)) {
            if ($script:unsafeCleanup -or -not $script:workIdentity -or
                (Get-FixtureIdentity $script:work) -cne $script:workIdentity) {
                Write-Warning "Preserved fixture root for identity review: $($script:work)"
            } else {
                Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
            }
        }
    }

    It 'recursively removes <Principal>, preserves the protected branch, reports evidence, and reverts' -ForEach @(
        @{ Principal = 'Everyone'; Sid = 'S-1-1-0' }
        @{ Principal = 'S-1-1-0'; Sid = 'S-1-1-0' }
        @{ Principal = 'S-1-5-21-100-200-300-401'; Sid = 'S-1-5-21-100-200-300-401' }
    ) {
        $fixture = New-RemovalFixture -SourceSid $Sid
        $initial = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $initial
        $arguments = Get-ChangeArgument $fixture
        $arguments.RemovePrincipal = $Principal

        $preview = & $script:entry @arguments -WhatIf
        Assert-PreviewIsNotVerified $preview
        Assert-SameFixtureState $initial @(Get-FixtureState $fixture)
        Test-Path -LiteralPath $preview.RecoveryRecordPath -PathType Leaf | Should -BeTrue

        Add-FixtureAce -Path $fixture.ChildFile -Sid $script:driftSid -Rights ReadAttributes
        $before = @(Get-FixtureState $fixture)
        (Get-PathSnapshot $before $fixture.ChildFile).Descriptor |
            Should -Not -BeExactly (Get-PathSnapshot $initial $fixture.ChildFile).Descriptor -Because $fixture.ChildFile

        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $apply.RecoveryRecordPath | Should -Not -Be $preview.RecoveryRecordPath
        $apply.ExcludedPathCount | Should -Be 2 -Because "protected directory and file under $($fixture.Protected)"
        $after = @(Get-FixtureState $fixture)
        Assert-SourceAbsent $after $Sid @($fixture.Target, $fixture.Child, $fixture.RootFile, $fixture.ChildFile)
        Assert-UnrelatedState $before $after @($Sid)
        foreach ($path in @($fixture.Protected, $fixture.ProtectedFile)) {
            (Get-PathSnapshot $after $path).Descriptor |
                Should -BeExactly (Get-PathSnapshot $before $path).Descriptor -Because "protected $path"
        }
        Assert-FixtureContent $fixture
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Remove'

        $again = & $script:entry @arguments
        $again.Status | Should -Be 'NoOp' -Because (Get-ResultText $again)
        $again.ExcludedPathCount | Should -Be 2 -Because $fixture.Protected
        Assert-SameFixtureState $after @(Get-FixtureState $fixture)
        Assert-ApplyEvidence $again $fixture
        Assert-ApplyAuditReport $again $fixture $after $after 'ThisFolderSubfoldersAndFiles' 'Remove'
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'recursively replaces the source with the specified rights and leaves protected data intact' {
        $fixture = New-RemovalFixture
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture 'Replace'
        $arguments.GroupName = $script:replacementSid
        $arguments.Permissions = 'Modify'
        $preview = & $script:entry @arguments -WhatIf
        Assert-PreviewIsNotVerified $preview
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)

        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $apply.RecoveryRecordPath | Should -Not -Be $preview.RecoveryRecordPath
        $apply.ExcludedPathCount | Should -Be 2 -Because $fixture.Protected
        $after = @(Get-FixtureState $fixture)
        $included = @($fixture.Target, $fixture.Child, $fixture.RootFile, $fixture.ChildFile)
        Assert-SourceAbsent $after $fixture.SourceSid $included
        Assert-ReplacementGrant $after $included 'Modify' $true
        Assert-UnrelatedState $before $after @($fixture.SourceSid, $script:replacementSid)
        foreach ($path in @($fixture.Protected, $fixture.ProtectedFile)) {
            (Get-PathSnapshot $after $path).Descriptor |
                Should -BeExactly (Get-PathSnapshot $before $path).Descriptor -Because "protected $path"
        }
        Assert-FixtureContent $fixture
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Replace'
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
    }

    It 'counts duplicate ACE differences with their full multiset multiplicity' {
        $fixture = New-RemovalFixture
        $snapshot = Get-PathSnapshot @(Get-FixtureState $fixture) $fixture.ChildFile
        $source = @($snapshot.Aces | Where-Object {
            $_.SID -eq $fixture.SourceSid -and $_.Type -eq 'Allow' -and -not $_.Inherited
        })[0]
        $unrelated = @($snapshot.Aces | Where-Object SID -eq $script:unrelatedSid)[0]
        $oneRemoved = @(Get-NpLocalAceDifference @($source, $source, $unrelated) @($source, $unrelated))
        $oneRemoved.Count | Should -Be 1
        (Get-NpCanonicalJson $oneRemoved[0]) | Should -BeExactly (Get-NpCanonicalJson $source)
        $bothRemoved = @(Get-NpLocalAceDifference @($source, $source, $unrelated) @($unrelated))
        $bothRemoved.Count | Should -Be 2
        (ConvertTo-AceMultisetJson $bothRemoved) | Should -BeExactly (ConvertTo-AceMultisetJson @($source, $source))
    }

    It 'allows audit report renames while keeping the evidence directory pinned' {
        $run = New-NpRun -OutputDirectory $script:caseWork
        $pending = Join-Path $run 'report.pending'
        $final = Join-Path $run 'report.csv'
        [IO.File]::WriteAllText($pending, 'verified')
        $lease = [NtfsPermissions.LocalCandidate.Lease]::OpenAuditDirectory($run)
        try {
            [IO.File]::Move($pending, $final)
            [IO.File]::ReadAllText($final) | Should -BeExactly 'verified'
            { [IO.Directory]::Move($run, ($run + '_moved')) } | Should -Throw
        } finally { $lease.Dispose() }
    }

    It 'blocks <Operation> before writing when a DACL lacks auto-inherited control' -ForEach @(
        @{ Operation = 'Add' }
        @{ Operation = 'Remove' }
        @{ Operation = 'Replace' }
    ) {
        $fixture = New-UnmanagedInheritanceFixture
        $before = @(Get-FixtureState $fixture)
        @($before | Where-Object { -not ([int]$_.Control -band 1024) }).Count | Should -BeGreaterThan 0
        $arguments = Get-ChangeArgument $fixture $Operation
        if ($Operation -ceq 'Add') { $null = $arguments.Remove('RemovePrincipal') }
        if ($Operation -cne 'Remove') {
            $arguments.GroupName = $script:replacementSid
            $arguments.Permissions = 'ReadAndExecute'
        }

        $result = Invoke-ExpectRefusal $arguments
        (Get-ResultText $result) | Should -Match '(?i)auto.inherit'
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        [IO.File]::ReadAllText($fixture.ChildFile) | Should -BeExactly 'unmanaged inheritance fixture'
    }

    It 'leaves an excluded descendant with unmanaged inheritance unchanged' {
        $fixture = New-RemovalFixture
        $excluded = New-UnmanagedInheritanceFixture -Parent $fixture.Target
        $before = @(Get-FixtureState $fixture)
        [bool]((Get-PathSnapshot $before $fixture.Target).Control -band 1024) | Should -BeTrue
        [bool]((Get-PathSnapshot $before $excluded.Target).Control -band 1024) | Should -BeFalse
        (Get-PathSnapshot $before $excluded.Target).Protected | Should -BeTrue

        $arguments = Get-ChangeArgument $fixture
        $result = & $script:entry @arguments
        Assert-ChangedResult $result
        $result.ExcludedPathCount | Should -Be 5
        $after = @(Get-FixtureState $fixture)
        foreach ($path in @($excluded.Target, $excluded.Child, $excluded.ChildFile)) {
            (Get-NpCanonicalJson (Get-PathSnapshot $after $path)) |
                Should -BeExactly (Get-NpCanonicalJson (Get-PathSnapshot $before $path)) -Because $path
        }
        Assert-ApplyEvidence $result $fixture
        Assert-FixtureContent $fixture
        [IO.File]::ReadAllText($excluded.ChildFile) | Should -BeExactly 'unmanaged inheritance fixture'
        $revert = Invoke-OrdinaryRevert $result
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
    }

    It 'checks an unchanged unprotected descendant before a folder-only write' {
        $fixture = New-RemovalFixture -InheritableSource $false -ExplicitDescendants $false
        $unmanaged = New-UnmanagedInheritanceFixture
        $root = Get-PathSnapshot @(Get-FixtureState $fixture) $fixture.Target
        $child = Get-PathSnapshot @(Get-FixtureState $unmanaged) $unmanaged.Child
        [bool]($root.Control -band 1024) | Should -BeTrue
        [bool]($child.Control -band 1024) | Should -BeFalse
        $child.Protected | Should -BeFalse
        $desired = New-NpLocalDesiredSnapshot -before $root -scope ThisFolderOnly -isRoot $true `
            -operation Remove -removal ([pscustomobject]@{ Principal = $fixture.SourceSid; SID = $fixture.SourceSid })
        $entries = @(
            [pscustomobject]@{ Before = $root; Desired = $desired; Boundary = $false }
            [pscustomobject]@{ Before = $child; Desired = $child; Boundary = $false }
        )
        { Assert-NpLocalInheritanceSafety -entries $entries } | Should -Throw '*auto-inherited*'
    }

    It 'allows a no-op removal without changing unmanaged inheritance control' {
        $fixture = New-UnmanagedInheritanceFixture -IncludeSource $false
        $before = @(Get-FixtureState $fixture)
        [bool]((Get-PathSnapshot $before $fixture.Target).Control -band 1024) | Should -BeFalse
        $arguments = Get-ChangeArgument $fixture
        $result = & $script:entry @arguments
        $result.Status | Should -Be 'NoOp' -Because (Get-ResultText $result)
        $after = @(Get-FixtureState $fixture)
        Assert-SameFixtureState $before $after
        Assert-ApplyEvidence $result $fixture
        Assert-ApplyAuditReport $result $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Remove'
        [IO.File]::ReadAllText($fixture.ChildFile) | Should -BeExactly 'unmanaged inheritance fixture'
    }

    It 'does not expand a replacement beyond the original source entries or their inheritance' {
        $fixture = New-RemovalFixture -InheritableSource $false
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture 'Replace'
        $arguments.GroupName = $script:replacementSid
        $arguments.Permissions = 'ReadAndExecute'

        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $after = @(Get-FixtureState $fixture)
        $sourcePaths = @($fixture.Target, $fixture.Child, $fixture.ChildFile)
        Assert-SourceAbsent $after $fixture.SourceSid $sourcePaths
        Assert-ReplacementGrant $after $sourcePaths 'ReadAndExecute' $false
        foreach ($path in @($fixture.RootFile, $fixture.Protected, $fixture.ProtectedFile)) {
            (Get-NpCanonicalJson (Get-PathSnapshot $after $path)) |
                Should -BeExactly (Get-NpCanonicalJson (Get-PathSnapshot $before $path)) -Because "source was absent or excluded at $path"
        }
        Assert-UnrelatedState $before $after @($fixture.SourceSid, $script:replacementSid)
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Replace'
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'preserves container-only inheritance when replacing a source ACE' {
        $fixture = New-RemovalFixture -IncludeSource $false -ExplicitDescendants $false
        $acl = Get-Acl -LiteralPath $fixture.Target -ErrorAction Stop
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($fixture.SourceSid),
            'ReadPermissions', 'ContainerInherit', 'None', 'Allow'))
        Set-Acl -LiteralPath $fixture.Target -AclObject $acl -ErrorAction Stop
        $before = @(Get-FixtureState $fixture)
        $arguments = Get-ChangeArgument $fixture 'Replace'
        $arguments.GroupName = $script:replacementSid
        $arguments.Permissions = 'ReadAndExecute'
        foreach ($path in @($fixture.Target, $fixture.Child)) {
            $source = @((Get-PathSnapshot $before $path).Aces | Where-Object SID -eq $fixture.SourceSid)
            $source.Count | Should -Be 1 -Because "source ACE at $path"
            $source[0].ContainerInherit | Should -BeTrue
            $source[0].ObjectInherit | Should -BeFalse
        }

        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $after = @(Get-FixtureState $fixture)
        foreach ($path in @($fixture.Target, $fixture.Child)) {
            $source = @((Get-PathSnapshot $before $path).Aces | Where-Object SID -eq $fixture.SourceSid)[0]
            $replacement = @((Get-PathSnapshot $after $path).Aces | Where-Object SID -eq $script:replacementSid)
            $replacement.Count | Should -Be 1 -Because "replacement ACE at $path"
            foreach ($flag in @('Inherited', 'ContainerInherit', 'ObjectInherit', 'InheritOnly', 'NoPropagate')) {
                $replacement[0].$flag | Should -Be $source.$flag -Because "$flag at $path"
            }
        }
        foreach ($path in @($fixture.RootFile, $fixture.ChildFile, $fixture.Protected, $fixture.ProtectedFile)) {
            (Get-NpCanonicalJson (Get-PathSnapshot $after $path)) |
                Should -BeExactly (Get-NpCanonicalJson (Get-PathSnapshot $before $path)) -Because "source was absent or excluded at $path"
        }
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Replace'
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'preserves <Propagation> propagation flags and the original source scope' -ForEach @(
        @{ Propagation = 'InheritOnly' }
        @{ Propagation = 'NoPropagateInherit' }
    ) {
        $fixture = New-RemovalFixture -IncludeSource $false -ExplicitDescendants $false
        $acl = Get-Acl -LiteralPath $fixture.Target -ErrorAction Stop
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($fixture.SourceSid),
            'ReadPermissions', 'ContainerInherit, ObjectInherit', $Propagation, 'Allow'))
        Set-Acl -LiteralPath $fixture.Target -AclObject $acl -ErrorAction Stop
        $before = @(Get-FixtureState $fixture)
        $rootSource = @((Get-PathSnapshot $before $fixture.Target).Aces | Where-Object SID -eq $fixture.SourceSid)
        $rootSource.Count | Should -Be 1
        if ($Propagation -ceq 'InheritOnly') { $rootSource[0].InheritOnly | Should -BeTrue }
        else { $rootSource[0].NoPropagate | Should -BeTrue }

        $arguments = Get-ChangeArgument $fixture 'Replace'
        $arguments.GroupName = $script:replacementSid
        $arguments.Permissions = 'ReadAndExecute'
        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $after = @(Get-FixtureState $fixture)
        $expectedMask = [long][int]([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($script:replacementSid), 'ReadAndExecute', 'Allow')).FileSystemRights
        foreach ($entry in $before) {
            $current = Get-PathSnapshot $after $entry.Path
            if ($entry.Path -in @($fixture.Protected, $fixture.ProtectedFile)) {
                (Get-NpCanonicalJson $current) | Should -BeExactly (Get-NpCanonicalJson $entry) -Because $entry.Path
                continue
            }
            $sources = @($entry.Aces | Where-Object { $_.SID -eq $fixture.SourceSid -and $_.Type -eq 'Allow' })
            $replacements = @($current.Aces | Where-Object { $_.SID -eq $script:replacementSid -and $_.Type -eq 'Allow' })
            $replacements.Count | Should -Be $sources.Count -Because $entry.Path
            @($current.Aces | Where-Object SID -eq $fixture.SourceSid).Count | Should -Be 0 -Because $entry.Path
            for ($index = 0; $index -lt $sources.Count; $index++) {
                $replacements[$index].Mask | Should -Be $expectedMask -Because $entry.Path
                foreach ($flag in @('Inherited', 'ContainerInherit', 'ObjectInherit', 'InheritOnly', 'NoPropagate')) {
                    $replacements[$index].$flag | Should -Be $sources[$index].$flag -Because "$flag at $($entry.Path)"
                }
            }
            if ($sources.Count -eq 0) {
                (Get-NpCanonicalJson $current) | Should -BeExactly (Get-NpCanonicalJson $entry) -Because $entry.Path
            }
        }
        Assert-UnrelatedState $before $after @($fixture.SourceSid, $script:replacementSid)
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Replace'
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'imports Unicode and neutralizes a <Prefix> ticket while retaining its raw journal value' -ForEach @(
        @{ Prefix = '=' }
        @{ Prefix = '+' }
        @{ Prefix = '-' }
        @{ Prefix = '@' }
    ) {
        $unicode = [string][char]0x96EA + [string][char]0x03A9
        $fixture = New-RemovalFixture -TargetName ('target_' + $unicode)
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $ticket = $Prefix + 'SUM(1,2)&"' + $unicode + '"'
        $arguments = Get-ChangeArgument $fixture
        $arguments.ChangeTicket = $ticket
        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $after = @(Get-FixtureState $fixture)
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Remove'

        # Deliberately use the default Import-Csv encoding in both PowerShell editions.
        $rows = @(Import-Csv -LiteralPath $apply.AuditReportPath -ErrorAction Stop)
        $rootRows = @($rows | Where-Object { $_.Path -ceq $fixture.Target })
        $rootRows.Count | Should -Be 1 -Because "Unicode target path $($fixture.Target)"
        $rootRows[0].ChangeTicket.EndsWith($ticket, [StringComparison]::Ordinal) |
            Should -BeTrue -Because 'the exported ticket must retain its Unicode text'
        $rootRows[0].ChangeTicket | Should -Not -Match '^[\s]*[=+\-@]' -Because 'the CSV ticket must be spreadsheet-neutralized'
        $rootRows[0].ChangeTicket | Should -Not -BeExactly $ticket
        $journal = Read-NpJournal -Path $apply.ApplyJournalPath
        foreach ($record in $journal.Events) {
            $record.Ticket | Should -BeExactly $ticket -Because 'the journal retains the unmodified ticket'
        }
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'retains a partial pending report and advertises no CSV after an injected late audit failure' {
        $fixture = New-RemovalFixture
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture
        $script:originalCsvRecord = ${function:ConvertTo-NtfsCsvRecord}
        $script:auditSerializationActive = $false
        $script:auditSerializationCount = 0
        Mock ConvertTo-NtfsCsvRecord {
            param([object[]]$Values)
            if ($Values -contains 'BeforeDescriptor' -and $Values -contains 'AfterAces') {
                $script:auditSerializationActive = $true
            }
            if ($script:auditSerializationActive) {
                $script:auditSerializationCount++
                if ($script:auditSerializationCount -eq 3) { throw 'Injected partial audit serialization failure.' }
            }
            & $script:originalCsvRecord $Values
        }
        $direct = @{
            Mode = 'Apply'; TargetPath = $fixture.Target; TargetPlatform = 'Auto'
            Operation = 'Remove'; RemovePrincipal = $fixture.SourceSid
            Scope = 'ThisFolderSubfoldersAndFiles'; OutputDirectory = $arguments.OutputDirectory
            ChangeTicket = $arguments.ChangeTicket; MaxPaths = 10000; DisposableAcknowledgement = $true
            Preview = $false; BoundParameters = $arguments; CallerConfirmPreference = 'None'
        }
        $result = Invoke-NpDisposableLab @direct
        $script:auditSerializationCount | Should -Be 3 -Because 'the audit header and one row must precede the injected fault'
        $result.Status | Should -Match '(?i)indeterminate|fail|error|block' -Because (Get-ResultText $result)
        $after = @(Get-FixtureState $fixture)
        (Get-PathSnapshot $after $fixture.Target).Descriptor |
            Should -Not -BeExactly (Get-PathSnapshot $before $fixture.Target).Descriptor -Because 'the failure was injected after the ACL write'
        Assert-SourceAbsent $after $fixture.SourceSid @($fixture.Target, $fixture.Child, $fixture.RootFile, $fixture.ChildFile)
        Assert-NoAuditReport $result
        $pending = @(Get-ChildItem -LiteralPath $result.RunDirectory -Filter '*.pending' -File -ErrorAction Stop)
        $pending.Count | Should -Be 1 -Because 'partial evidence must remain for review'
        $partialRows = @(Import-Csv -LiteralPath $pending[0].FullName -ErrorAction Stop)
        $partialRows.Count | Should -Be 1 -Because $pending[0].FullName
        $partialRows[0].Path | Should -Be $fixture.Target
        $finalPath = $pending[0].FullName.Substring(0, $pending[0].FullName.Length - '.pending'.Length)
        Test-Path -LiteralPath $finalPath | Should -BeFalse -Because 'an incomplete report must not be renamed to the final CSV'
        @(Get-ChildItem -LiteralPath $result.RunDirectory -Filter '*.csv' -File -ErrorAction Stop).Count | Should -Be 0
        Assert-FixtureContent $fixture
    }

    It 'limits non-inheritable folder-only <Operation> to the target' -ForEach @(
        @{ Operation = 'Remove' }
        @{ Operation = 'Replace' }
    ) {
        $fixture = New-RemovalFixture -InheritableSource $false
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture $Operation
        $arguments.Scope = 'ThisFolderOnly'
        if ($Operation -eq 'Replace') {
            $arguments.GroupName = $script:replacementSid
            $arguments.Permissions = 'ReadAndExecute'
        }
        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $apply.ExcludedPathCount | Should -Be 2 -Because $fixture.Protected
        $after = @(Get-FixtureState $fixture)
        Assert-SourceAbsent $after $fixture.SourceSid @($fixture.Target)
        if ($Operation -eq 'Replace') {
            Assert-ReplacementGrant $after @($fixture.Target) 'ReadAndExecute' $false
        }
        foreach ($path in @($fixture.Child, $fixture.RootFile, $fixture.ChildFile, $fixture.Protected, $fixture.ProtectedFile)) {
            (Get-NpCanonicalJson (Get-PathSnapshot $after $path)) |
                Should -BeExactly (Get-NpCanonicalJson (Get-PathSnapshot $before $path)) -Because "outside scope: $path"
        }
        Assert-UnrelatedState $before $after @($fixture.SourceSid, $script:replacementSid)
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderOnly' $Operation
        Assert-FixtureContent $fixture
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
    }

    It 'refuses folder-only <Operation> of an inheritable source ACE before changing descendants' -ForEach @(
        @{ Operation = 'Remove' }
        @{ Operation = 'Replace' }
    ) {
        $fixture = New-RemovalFixture
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture $Operation
        $arguments.Scope = 'ThisFolderOnly'
        if ($Operation -eq 'Replace') {
            $arguments.GroupName = $script:replacementSid
            $arguments.Permissions = 'Read'
        }
        $null = Invoke-ExpectRefusal $arguments
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'refuses an inherited source at the target and identifies its parent for review' {
        $fixture = New-RemovalFixture -ExplicitDescendants $false
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $child = Get-PathSnapshot $before $fixture.Child
        @($child.Aces | Where-Object { $_.SID -eq $fixture.SourceSid -and -not $_.Inherited }).Count |
            Should -Be 0 -Because "source at $($fixture.Child) must be inherited only"
        $arguments = Get-ChangeArgument $fixture
        $arguments.TargetPath = $fixture.Child
        $result = Invoke-ExpectRefusal $arguments
        (Get-ResultText $result) | Should -Match ([regex]::Escape($fixture.Target)) -Because 'the source parent must be identified for review'
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'refuses <Operation> when a matching deny is present at <Location>' -ForEach @(
        @{ Operation = 'Remove'; Location = 'Child' }
        @{ Operation = 'Replace'; Location = 'ChildFile' }
    ) {
        $fixture = New-RemovalFixture
        Add-FixtureAce -Path $fixture.$Location -Sid $fixture.SourceSid -Rights ReadAttributes -Type Deny
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $deny = Get-PathSnapshot $before $fixture.$Location
        @($deny.Aces | Where-Object { $_.SID -eq $fixture.SourceSid -and $_.Type -eq 'Deny' }).Count |
            Should -BeGreaterThan 0 -Because "matching deny at $($fixture.$Location)"
        $arguments = Get-ChangeArgument $fixture $Operation
        if ($Operation -eq 'Replace') {
            $arguments.GroupName = $script:replacementSid
            $arguments.Permissions = 'Modify'
        }
        $null = Invoke-ExpectRefusal $arguments
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'preserves a matching deny inside an excluded protected branch without blocking removal' {
        $fixture = New-RemovalFixture
        Add-FixtureAce -Path $fixture.ProtectedFile -Sid $fixture.SourceSid -Rights ReadAttributes -Type Deny
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $protectedFile = Get-PathSnapshot $before $fixture.ProtectedFile
        @($protectedFile.Aces | Where-Object { $_.SID -eq $fixture.SourceSid -and $_.Type -eq 'Deny' }).Count |
            Should -BeGreaterThan 0 -Because "matching deny outside the writable scope at $($fixture.ProtectedFile)"
        $arguments = Get-ChangeArgument $fixture
        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $apply.ExcludedPathCount | Should -Be 2 -Because $fixture.Protected
        $after = @(Get-FixtureState $fixture)
        Assert-SourceAbsent $after $fixture.SourceSid @($fixture.Target, $fixture.Child, $fixture.RootFile, $fixture.ChildFile)
        (Get-NpCanonicalJson (Get-PathSnapshot $after $fixture.ProtectedFile)) |
            Should -BeExactly (Get-NpCanonicalJson $protectedFile) -Because $fixture.ProtectedFile
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Remove'
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'does not introduce replacement access when the source is missing and replacement is <Scenario>' -ForEach @(
        @{ Scenario = 'absent' }
        @{ Scenario = 'partial' }
    ) {
        $fixture = New-RemovalFixture -IncludeSource $false
        if ($Scenario -eq 'partial') {
            Add-FixtureAce -Path $fixture.Target -Sid $script:replacementSid -Rights Read
        }
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        Assert-SourceAbsent $before $fixture.SourceSid @($fixture.Target, $fixture.Child, $fixture.RootFile, $fixture.ChildFile)
        $root = Get-PathSnapshot $before $fixture.Target
        $existing = @($root.Aces | Where-Object { $_.SID -eq $script:replacementSid -and $_.Type -eq 'Allow' })
        if ($Scenario -eq 'partial') {
            $existing.Count | Should -BeGreaterThan 0 -Because "partial replacement at $($fixture.Target)"
        } else { $existing.Count | Should -Be 0 -Because $fixture.Target }
        $arguments = Get-ChangeArgument $fixture 'Replace'
        $arguments.GroupName = $script:replacementSid
        $arguments.Permissions = 'Modify'
        $null = Invoke-ExpectRefusal $arguments
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'does not change an already satisfied replacement when its source is absent' {
        $fixture = New-RemovalFixture -IncludeSource $false -IncludeReplacement $true
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $included = @($fixture.Target, $fixture.Child, $fixture.RootFile, $fixture.ChildFile)
        Assert-SourceAbsent $before $fixture.SourceSid $included
        Assert-ReplacementGrant $before $included 'Modify' $true
        $arguments = Get-ChangeArgument $fixture 'Replace'
        $arguments.GroupName = $script:replacementSid
        $arguments.Permissions = 'Modify'
        try {
            $result = & $script:entry @arguments
        } catch {
            if ($_.FullyQualifiedErrorId -match 'NamedParameterNotFound') { throw }
            $result = [pscustomobject]@{ Status = 'Exception'; Reason = $_.Exception.Message }
        }
        $result.Status | Should -Match '(?i)^noop$|block|reject|refus|exception' -Because (Get-ResultText $result)
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'returns NoOp without changing anything when the removal principal is absent' {
        $fixture = New-RemovalFixture -IncludeSource $false
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture
        $result = & $script:entry @arguments
        $result.Status | Should -Be 'NoOp' -Because (Get-ResultText $result)
        $result.ExcludedPathCount | Should -Be 2 -Because $fixture.Protected
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'executes public Apply and Revert without -DisposableLocalLab across <Operation>' -ForEach @(
        @{ Operation = 'Add' }
        @{ Operation = 'Remove' }
        @{ Operation = 'Replace' }
    ) {
        $fixture = New-RemovalFixture -IncludeSource ($Operation -ne 'Add')
        $before = @(Get-FixtureState $fixture)
        $evidenceRoot = Join-Path $script:caseWork 'evidence'
        $arguments = @{
            Mode = 'Apply'
            TargetPath = $fixture.Target
            TargetPlatform = 'Windows'
            Operation = $Operation
            Scope = 'ThisFolderSubfoldersAndFiles'
            ChangeTicket = 'PUBLIC-CHG-01'
            OutputDirectory = $evidenceRoot
            Confirm = $false
        }
        if ($Operation -ne 'Add') { $arguments.RemovePrincipal = $fixture.SourceSid }
        if ($Operation -in @('Add', 'Replace')) {
            $arguments.GroupName = $script:replacementSid
            $arguments.Permissions = 'ReadAndExecute'
        }
        $apply = & $script:entry @arguments
        $apply.Status | Should -Be 'Verified' -Because (Get-ResultText $apply)
        $apply.WriterQualification | Should -Be 'VerifiedPureSmbAndNtfs'
        (Test-Path -LiteralPath $apply.ReceiptPath) | Should -BeTrue
        (Test-Path -LiteralPath $apply.AuditReportPath) | Should -BeTrue
        $revert = & $script:entry -Mode Revert -ReceiptPath $apply.ReceiptPath `
            -ReceiptSHA256 $apply.ReceiptSHA256 -ReviewedApplyJournalSHA256 $apply.ApplyJournalSHA256 `
            -ChangeTicket 'PUBLIC-CHG-01-REV' -OutputDirectory $evidenceRoot -Confirm:$false
        $revert.Status | Should -Be 'Verified' -Because (Get-ResultText $revert)
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'isolates public NtfsPermissionReceipt/1 receipts from -DisposableLocalLab NtfsDisposableReceipt/2 receipts' {
        $fixture = New-RemovalFixture
        $before = @(Get-FixtureState $fixture)
        $evidenceRoot = Join-Path $script:caseWork 'evidence'
        $publicApply = & $script:entry -Mode Apply -TargetPath $fixture.Target -TargetPlatform Windows `
            -Operation Remove -RemovePrincipal $fixture.SourceSid -Scope ThisFolderSubfoldersAndFiles `
            -ChangeTicket 'PUBLIC-ISO-01' -OutputDirectory $evidenceRoot -Confirm:$false
        $publicApply.Status | Should -Be 'Verified'
        $crossDisposable = Invoke-ExpectRefusal @{
            Mode = 'Revert'; DisposableLocalLab = $true; DisposableAcknowledgement = $true
            ReceiptPath = $publicApply.ReceiptPath; ReceiptSHA256 = $publicApply.ReceiptSHA256
            ReviewedApplyJournalSHA256 = $publicApply.ApplyJournalSHA256
            ChangeTicket = 'PUBLIC-ISO-CROSS'; OutputDirectory = $evidenceRoot; Confirm = $false
        }
        (Get-ResultText $crossDisposable) | Should -Match 'Receipt schema'
        $publicRevert = & $script:entry -Mode Revert -ReceiptPath $publicApply.ReceiptPath `
            -ReceiptSHA256 $publicApply.ReceiptSHA256 -ReviewedApplyJournalSHA256 $publicApply.ApplyJournalSHA256 `
            -ChangeTicket 'PUBLIC-ISO-REV' -OutputDirectory $evidenceRoot -Confirm:$false
        $publicRevert.Status | Should -Be 'Verified'
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)

        $labArgs = Get-ChangeArgument $fixture
        $labApply = & $script:entry @labArgs
        $labApply.Status | Should -Be 'Verified'
        $crossPublic = Invoke-ExpectRefusal @{
            Mode = 'Revert'
            ReceiptPath = $labApply.ReceiptPath; ReceiptSHA256 = $labApply.ReceiptSHA256
            ReviewedApplyJournalSHA256 = $labApply.ApplyJournalSHA256
            ChangeTicket = 'LAB-ISO-CROSS'; OutputDirectory = $evidenceRoot; Confirm = $false
        }
        (Get-ResultText $crossPublic) | Should -Match 'Receipt schema'
        $labRevert = Invoke-OrdinaryRevert $labApply
        $labRevert.Status | Should -Be 'Verified'
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
    }

    It 'executes pure-SMB UNC and frozen MappedDrive Apply and Revert across <Platform>' -ForEach @(
        @{ Platform = 'Windows'; UseMapped = $false }
        @{ Platform = 'NetApp'; UseMapped = $false }
        @{ Platform = 'Nas'; UseMapped = $false }
        @{ Platform = 'NetApp'; UseMapped = $true }
    ) {
        $fixture = New-RemovalFixture
        $driveLetter = $fixture.Target.Substring(0, 1).ToUpperInvariant()
        $uncShareRoot = "\\$([Environment]::MachineName)\$($driveLetter)`$"
        if (-not (Test-Path -LiteralPath $uncShareRoot)) {
            Set-ItResult -Skipped -Because "Administrative loopback share $uncShareRoot is unavailable in this session."
            return
        }
        $relativeSubpath = $fixture.Target.Substring(3)
        $uncTarget = Join-Path $uncShareRoot $relativeSubpath
        $before = @(Get-FixtureState $fixture)
        $evidenceRoot = Join-Path $script:caseWork 'evidence'
        if ($UseMapped) {
            Mock Get-NpDriveBinding {
                [pscustomobject]@{ Kind = 'Mapped'; MappingRoot = $uncShareRoot; HostName = '' }
            }
        }
        $inputPath = if ($UseMapped) { 'Q:\' + $relativeSubpath } else { $uncTarget }
        $apply = & $script:entry -Mode Apply -TargetPath $inputPath -TargetPlatform $Platform `
            -Operation Replace -RemovePrincipal $fixture.SourceSid -GroupName $script:replacementSid `
            -Permissions Modify -Scope ThisFolderSubfoldersAndFiles -ChangeTicket "SMB-$Platform-01" `
            -OutputDirectory $evidenceRoot -Confirm:$false
        $apply.Status | Should -Be 'Verified' -Because (Get-ResultText $apply)
        $apply.WriterQualification | Should -Be 'VerifiedPureSmbAndNtfs'
        $planData = Get-Content -LiteralPath $apply.RecoveryRecordPath -Raw | ConvertFrom-NpJson
        $planData.TargetDescriptor.CanonicalPath | Should -Be $uncTarget
        if ($UseMapped) {
            $planData.TargetDescriptor.Addressing | Should -Be 'MappedDrive'
            Mock Get-NpDriveBinding { throw 'Revert must never re-resolve a frozen mapped drive.' }
        } else {
            $planData.TargetDescriptor.Addressing | Should -Be 'DirectUNC'
        }
        $revert = & $script:entry -Mode Revert -ReceiptPath $apply.ReceiptPath `
            -ReceiptSHA256 $apply.ReceiptSHA256 -ReviewedApplyJournalSHA256 $apply.ApplyJournalSHA256 `
            -ChangeTicket "SMB-$Platform-REV" -OutputDirectory $evidenceRoot -Confirm:$false
        $revert.Status | Should -Be 'Verified' -Because (Get-ResultText $revert)
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'does not mutate without the required <Missing> safety gate' -ForEach @(
        @{ Missing = 'whatif preview' }
        @{ Missing = 'lab opt-in' }
        @{ Missing = 'acknowledgement' }
        @{ Missing = 'change ticket' }
        @{ Missing = 'output directory' }
    ) {
        $fixture = New-RemovalFixture
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture
        switch ($Missing) {
            'whatif preview' {
                [void]$arguments.Remove('DisposableLocalLab')
                [void]$arguments.Remove('DisposableAcknowledgement')
                $arguments.WhatIf = $true
            }
            'lab opt-in' { [void]$arguments.Remove('DisposableLocalLab') }
            'acknowledgement' { [void]$arguments.Remove('DisposableAcknowledgement') }
            'change ticket' { [void]$arguments.Remove('ChangeTicket') }
            'output directory' { $arguments.OutputDirectory = '' }
        }
        if ($Missing -eq 'whatif preview') {
            $preview = & $script:entry @arguments
            $preview.Status | Should -Be 'WhatIfOrDeclined' -Because (Get-ResultText $preview)
        } else {
            $null = Invoke-ExpectRefusal $arguments
        }
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'rejects <Scenario> without changing any target ACL' -ForEach @(
        @{ Scenario = 'Remove missing principal' }
        @{ Scenario = 'Remove malformed SID' }
        @{ Scenario = 'Remove with GroupName' }
        @{ Scenario = 'Remove with Permissions' }
        @{ Scenario = 'Remove with JSON grants' }
        @{ Scenario = 'Replace missing principal' }
        @{ Scenario = 'Replace missing GroupName' }
        @{ Scenario = 'Replace missing Permissions' }
        @{ Scenario = 'Replace invalid Permissions' }
        @{ Scenario = 'Replace identical SID' }
        @{ Scenario = 'Replace Everyone with its SID alias' }
    ) {
        $source = if ($Scenario -eq 'Replace Everyone with its SID alias') { 'S-1-1-0' } else { $script:sourceSid }
        $fixture = New-RemovalFixture -SourceSid $source
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $operation = if ($Scenario -like 'Replace*') { 'Replace' } else { 'Remove' }
        $arguments = Get-ChangeArgument $fixture $operation
        if ($operation -eq 'Replace') {
            $arguments.GroupName = $script:replacementSid
            $arguments.Permissions = 'Read'
        }
        switch ($Scenario) {
            'Remove missing principal' { [void]$arguments.Remove('RemovePrincipal') }
            'Remove malformed SID' { $arguments.RemovePrincipal = 'S-1-not-a-valid-sid' }
            'Remove with GroupName' { $arguments.GroupName = $script:replacementSid }
            'Remove with Permissions' { $arguments.Permissions = 'Read' }
            'Remove with JSON grants' {
                $arguments.GroupPermissionsJson = '[{"GroupName":"S-1-5-21-100-200-300-402","Permissions":"Read"}]'
            }
            'Replace missing principal' { [void]$arguments.Remove('RemovePrincipal') }
            'Replace missing GroupName' { [void]$arguments.Remove('GroupName') }
            'Replace missing Permissions' { [void]$arguments.Remove('Permissions') }
            'Replace invalid Permissions' { $arguments.Permissions = 'Write' }
            'Replace identical SID' { $arguments.GroupName = $fixture.SourceSid }
            'Replace Everyone with its SID alias' {
                $arguments.RemovePrincipal = 'Everyone'
                $arguments.GroupName = 'S-1-1-0'
            }
        }
        $null = Invoke-ExpectRefusal $arguments
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        Assert-FixtureContent $fixture
    }

    It 'refuses to execute a prepared remove preview as an Apply plan' {
        $fixture = New-RemovalFixture
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture
        $preview = & $script:entry @arguments -WhatIf
        Assert-PreviewIsNotVerified $preview
        Test-Path -LiteralPath $preview.RecoveryRecordPath -PathType Leaf | Should -BeTrue
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
        $arguments.PlanPath = $preview.RecoveryRecordPath
        $arguments.PlanSHA256 = $preview.RecoveryRecordSHA256
        $null = Invoke-ExpectRefusal $arguments
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
    }

    It 'rejects rehashed receipt source and target changes before ordinary Revert' {
        $fixture = New-RemovalFixture
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture
        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $after = @(Get-FixtureState $fixture)
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderSubfoldersAndFiles' 'Remove'

        $original = [IO.File]::ReadAllBytes($apply.ReceiptPath)
        try {
            foreach ($field in @('SourceHash', 'Target')) {
                $receipt = [Text.UTF8Encoding]::new($false, $true).GetString($original) | ConvertFrom-NpJson
                if ($field -eq 'SourceHash') { $receipt.SourceHash = '0' * 64 } else { $receipt.Target = $fixture.Child }
                [IO.File]::WriteAllText($apply.ReceiptPath, (Get-NpCanonicalJson $receipt), [Text.UTF8Encoding]::new($false))
                $forgedHash = (Get-FileHash -LiteralPath $apply.ReceiptPath -Algorithm SHA256).Hash
                $revertArguments = @{
                    Mode = 'Revert'; DisposableLocalLab = $true; DisposableAcknowledgement = $true
                    ReceiptPath = $apply.ReceiptPath; ReceiptSHA256 = $forgedHash
                    ReviewedApplyJournalSHA256 = $apply.ApplyJournalSHA256
                    OutputDirectory = (Join-Path $script:caseWork 'evidence')
                    ChangeTicket = 'DISPOSABLE-REVERT-TEST'; Confirm = $false
                }
                $null = Invoke-ExpectRefusal $revertArguments
                Assert-SameFixtureState $after @(Get-FixtureState $fixture)
            }
        } finally {
            [IO.File]::WriteAllBytes($apply.ReceiptPath, $original)
        }
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
    }

    It 'keeps Add as the default operation and reports its actual folder-only grant' {
        $fixture = New-RemovalFixture -IncludeSource $false
        $before = @(Get-FixtureState $fixture)
        Assert-InitialFixture $fixture $before
        $arguments = Get-ChangeArgument $fixture
        [void]$arguments.Remove('Operation')
        [void]$arguments.Remove('RemovePrincipal')
        $arguments.Scope = 'ThisFolderOnly'
        $arguments.GroupName = $script:replacementSid
        $arguments.Permissions = 'ReadAndExecute'
        $apply = & $script:entry @arguments
        Assert-ChangedResult $apply
        $after = @(Get-FixtureState $fixture)
        Assert-ReplacementGrant $after @($fixture.Target) 'ReadAndExecute' $false
        Assert-UnrelatedState $before $after @($script:replacementSid)
        Assert-ApplyEvidence $apply $fixture
        Assert-ApplyAuditReport $apply $fixture $before $after 'ThisFolderOnly' 'Add'
        $revert = Invoke-OrdinaryRevert $apply
        Assert-ChangedResult $revert
        Assert-SameFixtureState $before @(Get-FixtureState $fixture)
    }
}
