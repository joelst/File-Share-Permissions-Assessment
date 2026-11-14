#requires -Version 5.1
<#
.SYNOPSIS
Collects targeted, reviewable permission-test evidence on a Windows lab server.
.DESCRIPTION
The default run records environment and source hashes only. An optional target
is read-only and bounded; an optional AD group is resolved without changing
membership or permissions. Pester suites are opt-in and require a disposable acknowledgement: they create and
change ACLs on their own fixtures under this checkout's Tests directory. The
candidate fixtures are preserved so their audit logs can be reviewed; synthetic
fixtures are removed by their tests.
No existing target is modified.

Evidence is written to a new restrictive local directory via New-NpRun. It can
contain server names, identities, paths, security descriptors and error details.
Review and protect it before sharing. Neither this runner nor its results qualify
a writer or enable public Apply/Revert. Pester 5.2+ is required only for requested
suites; the ActiveDirectory module is required only for requested group lookup.

.PARAMETER outputRoot
Trusted local fixed-volume parent for a new evidence directory, outside the
checkout's Tests directory and any selected target or its backing storage.
.PARAMETER groupName
Optional existing AD security group to resolve using the current user's context.
.PARAMETER readOnlyTarget
Optional approved local or direct UNC directory to inspect without target writes.
.PARAMETER targetPlatform
Operator declaration for the read-only target, not backend verification.
.PARAMETER readOnlyScope
Inspect just the selected directory by default, or its directory/file descendants.
.PARAMETER maxPaths
Maximum objects in the selected read-only inventory.
.PARAMETER runSyntheticTests
Run the existing mocked permission and validation Pester suites.
.PARAMETER runDisposableCandidateTests
Run the existing local NTFS candidate Pester suite on newly created fixtures.
.PARAMETER disposableAcknowledgement
Confirms independent approval for the selected suites and disposable checkout.
.EXAMPLE
.\Tests\Invoke-NtfsLabEvidence.ps1 -outputRoot C:\NtfsLabEvidence
.EXAMPLE
.\Tests\Invoke-NtfsLabEvidence.ps1 -outputRoot C:\NtfsLabEvidence -groupName 'LAB\Readers' -readOnlyTarget 'D:\DisposableLab\Case1' -targetPlatform Windows
.EXAMPLE
.\Tests\Invoke-NtfsLabEvidence.ps1 -outputRoot C:\NtfsLabEvidence -runSyntheticTests -runDisposableCandidateTests -disposableAcknowledgement
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $outputRoot,
    [string] $groupName,
    [string] $readOnlyTarget,
    [ValidateSet('Auto', 'Windows', 'NetApp', 'Nas')][string] $targetPlatform = 'Auto',
    [ValidateSet('ThisFolderOnly', 'ThisFolderSubfoldersAndFiles')][string] $readOnlyScope = 'ThisFolderOnly',
    [ValidateRange(1, 100000)][int] $maxPaths = 1000,
    [switch] $runSyntheticTests,
    [switch] $runDisposableCandidateTests,
    [switch] $disposableAcknowledgement
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The lab evidence runner requires Windows.'
}
if (($runSyntheticTests -or $runDisposableCandidateTests) -and -not $disposableAcknowledgement) {
    throw 'Selected Pester suites create and remove disposable fixtures; DisposableAcknowledgement is required.'
}
if ($readOnlyTarget -and $readOnlyTarget -match '[\x00-\x1f]') {
    throw 'The read-only target cannot contain control characters.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'NtfsPermissions.Common.ps1')
$outputRoot = [IO.Path]::GetFullPath($outputRoot)
Assert-NtfsOutputOutsideScope $outputRoot $PSScriptRoot
$run = New-NpRun -OutputDirectory $outputRoot -Target $readOnlyTarget
$checks = [Collections.Generic.List[object]]::new()
$startedUtc = [DateTime]::UtcNow.ToString('o')
$transcriptStarted = $false
$fatalMessage = ''
$candidateFixturePath = ''
$copiedAuditFiles = [Collections.Generic.List[string]]::new()

function Add-LabCheck {
    <#
    .SYNOPSIS
    Adds a bounded test outcome to the evidence summary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $name,
        [Parameter(Mandatory = $true)][ValidateSet('Observed', 'Failed', 'Incomplete', 'NotRun')][string] $status,
        [string] $detail = ''
    )
    $checks.Add([pscustomobject][ordered]@{
        Name = $name
        Status = $status
        Detail = $detail
        Utc = [DateTime]::UtcNow.ToString('o')
    })
}

function Write-LabJson {
    <#
    .SYNOPSIS
    Writes one structured evidence file in the protected run directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $name,
        [Parameter(Mandatory = $true)] $value
    )
    $value | ConvertTo-Json -Depth 40 |
        Set-Content -LiteralPath (Join-Path $run $name) -Encoding UTF8 -ErrorAction Stop
}

try {
    try {
        Start-Transcript -Path (Join-Path $run 'transcript.txt') -ErrorAction Stop | Out-Null
        $transcriptStarted = $true
        Add-LabCheck -name 'Transcript' -status Observed
    } catch {
        Add-LabCheck -name 'Transcript' -status Failed -detail $_.Exception.Message
        Write-Warning "Transcript could not start: $($_.Exception.Message)"
    }

    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $modules = @(Get-Module -ListAvailable Pester, ActiveDirectory |
            Select-Object Name, Version, Path)
        $environment = [ordered]@{
            CapturedUtc = [DateTime]::UtcNow.ToString('o')
            HostName = [Environment]::MachineName
            Actor = [Environment]::UserDomainName + '\' + [Environment]::UserName
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            PowerShellEdition = $PSVersionTable.PSEdition
            OS = [ordered]@{
                Caption = $operatingSystem.Caption
                Version = $operatingSystem.Version
                BuildNumber = $operatingSystem.BuildNumber
                ProductType = $operatingSystem.ProductType
            }
            Computer = [ordered]@{
                Domain = $system.Domain
                DomainRole = $system.DomainRole
                PartOfDomain = $system.PartOfDomain
            }
            Modules = $modules
            Qualification = 'NotQualified'
        }
        Write-LabJson -name 'environment.json' -value $environment
        Add-LabCheck -name 'Environment' -status Observed
    } catch {
        Add-LabCheck -name 'Environment' -status Failed -detail $_.Exception.Message
        Write-Warning "Environment collection failed: $($_.Exception.Message)"
    }

    try {
        $sourceFiles = @(
            Get-ChildItem -LiteralPath $repositoryRoot -File -ErrorAction Stop |
                Where-Object Extension -in @('.ps1', '.cs')
            Get-ChildItem -LiteralPath $PSScriptRoot -File -ErrorAction Stop |
                Where-Object Extension -in @('.ps1', '.cs')
        )
        $sourceFiles | Sort-Object FullName | Get-FileHash -Algorithm SHA256 -ErrorAction Stop |
            Select-Object Path, Algorithm, Hash |
            Export-Csv -LiteralPath (Join-Path $run 'source-hashes.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Add-LabCheck -name 'SourceHashes' -status Observed -detail "$($sourceFiles.Count) source files hashed."
    } catch {
        Add-LabCheck -name 'SourceHashes' -status Failed -detail $_.Exception.Message
        Write-Warning "Source hashing failed: $($_.Exception.Message)"
    }

    if ($groupName) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $sid = Resolve-NpWindowsGroup -Name $groupName
            Write-LabJson -name 'ad-group.json' -value ([ordered]@{
                RequestedGroup = $groupName
                SID = $sid
                Resolution = 'ClientActiveDirectorySecurityGroup'
                TargetAuthorityAndTrust = 'NotAssessed'
                EffectiveAccess = 'NotAssessed'
            })
            Add-LabCheck -name 'ActiveDirectoryGroup' -status Observed -detail 'Security group resolved; target authority and effective access were not assessed.'
        } catch {
            Add-LabCheck -name 'ActiveDirectoryGroup' -status Failed -detail $_.Exception.Message
            Write-Warning "AD group resolution failed: $($_.Exception.Message)"
        }
    } else {
        Add-LabCheck -name 'ActiveDirectoryGroup' -status NotRun -detail 'No group was requested.'
    }

    if ($readOnlyTarget) {
        try {
            $descriptor = Resolve-NpTarget -Path $readOnlyTarget -TargetPlatform $targetPlatform
            $inventory = Get-NpWindowsInventory -Target $descriptor.CanonicalPath -Scope $readOnlyScope -Limit $maxPaths
            $validationErrors = [Collections.Generic.List[string]]::new()
            foreach ($snapshot in $inventory.Snapshots) {
                try { Assert-NpSnapshot $snapshot }
                catch { $validationErrors.Add($_.Exception.Message) }
            }
            $targetEvidence = [ordered]@{
                TargetDescriptor = $descriptor
                Scope = $readOnlyScope
                MaxPaths = $maxPaths
                Snapshots = @($inventory.Snapshots)
                Boundaries = @($inventory.Boundaries)
                InventoryErrors = @($inventory.Errors)
                DescriptorErrors = @($validationErrors.ToArray())
                StableIdentity = 'Unqualified'
                EffectiveAccess = 'NotAssessed'
                WriterQualification = 'NotQualified'
            }
            Write-LabJson -name 'read-only-inventory.json' -value $targetEvidence
            if ($inventory.Errors.Count -gt 0 -or $validationErrors.Count -gt 0 -or $inventory.Snapshots.Count -eq 0) {
                Add-LabCheck -name 'ReadOnlyTarget' -status Incomplete -detail "Snapshots=$($inventory.Snapshots.Count); inventory errors=$($inventory.Errors.Count); descriptor errors=$($validationErrors.Count)."
            } else {
                Add-LabCheck -name 'ReadOnlyTarget' -status Observed -detail "Snapshots=$($inventory.Snapshots.Count); protected boundaries=$($inventory.Boundaries.Count)."
            }
        } catch {
            Add-LabCheck -name 'ReadOnlyTarget' -status Failed -detail $_.Exception.Message
            Write-Warning "Read-only target inspection failed: $($_.Exception.Message)"
        }
    } else {
        Add-LabCheck -name 'ReadOnlyTarget' -status NotRun -detail 'No target was requested.'
    }

    $testPaths = [Collections.Generic.List[string]]::new()
    if ($runSyntheticTests) {
        $testPaths.Add((Join-Path $PSScriptRoot 'NtfsPermissions.Tests.ps1'))
        $testPaths.Add((Join-Path $PSScriptRoot 'NtfsPermissionValidation.Tests.ps1'))
    }
    if ($runDisposableCandidateTests) {
        $testPaths.Add((Join-Path $PSScriptRoot 'NtfsPermissions.Local.Tests.ps1'))
        $testPaths.Add((Join-Path $PSScriptRoot 'NtfsPermissions.RemoveReplace.Tests.ps1'))
        $candidateId = [guid]::NewGuid().ToString('N')
        $candidateFixturePath = Join-Path $PSScriptRoot ('LocalCandidateTests_' + $candidateId)
    }
    if ($testPaths.Count -gt 0) {
        try {
            $checkoutDescriptor = Resolve-NpTarget -Path $PSScriptRoot -TargetPlatform Windows
            if ($checkoutDescriptor.Addressing -cne 'LocalFixed') {
                throw 'Pester fixture suites require a direct local fixed NTFS checkout.'
            }
            $checkoutProbe = Get-NpWindowsInventory -Target $checkoutDescriptor.CanonicalPath -Scope ThisFolderOnly -Limit 1
            if ($checkoutProbe.Errors.Count -gt 0 -or $checkoutProbe.Snapshots.Count -ne 1) {
                throw "Checkout ancestry/ACL inspection failed: $($checkoutProbe.Errors -join '; ')"
            }
            $loadedPester = @(Get-Module Pester)
            if ($loadedPester.Count -eq 0) {
                Import-Module Pester -MinimumVersion 5.2 -ErrorAction Stop
                $loadedPester = @(Get-Module Pester)
            }
            if ($loadedPester.Count -ne 1 -or $loadedPester[0].Version -lt [version]'5.2') {
                throw 'Exactly one Pester 5.2+ module must be loaded; start a fresh PowerShell session.'
            }
            $configuration = New-PesterConfiguration
            $configuration.Run.Path = $testPaths.ToArray()
            $configuration.Run.PassThru = $true
            $configuration.Output.Verbosity = 'Detailed'
            $configuration.TestResult.Enabled = $true
            $configuration.TestResult.OutputFormat = 'NUnitXml'
            $configuration.TestResult.OutputPath = Join-Path $run 'pester-results.xml'
            $previousCandidateId = [Environment]::GetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', 'Process')
            try {
                if ($runDisposableCandidateTests) {
                    if (Test-Path -LiteralPath $candidateFixturePath) { throw 'Candidate fixture path already exists.' }
                    [Environment]::SetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', $candidateId, 'Process')
                }
                $testResult = Invoke-Pester -Configuration $configuration
            } finally {
                [Environment]::SetEnvironmentVariable('NTFS_LAB_CANDIDATE_ID', $previousCandidateId, 'Process')
            }
            if ($null -eq $testResult) { throw 'Pester did not return a result.' }
            $inconclusiveCount = if ($testResult.PSObject.Properties['InconclusiveCount']) {
                $testResult.InconclusiveCount
            } else {
                @($testResult.Tests | Where-Object Result -ceq 'Inconclusive').Count
            }
            $skippedTests = @($testResult.Tests | Where-Object Result -ceq 'Skipped' |
                Select-Object -ExpandProperty ExpandedPath)
            $unexpectedSkips = @($skippedTests | Where-Object {
                $_ -cne 'Public read-only Windows gate and CLI contract.rejects real non-Windows execution before creating evidence'
            })
            $testSummary = [ordered]@{
                PesterVersion = $loadedPester[0].Version.ToString()
                Paths = $testPaths.ToArray()
                Result = $testResult.Result
                Passed = $testResult.PassedCount
                Failed = $testResult.FailedCount
                Skipped = $testResult.SkippedCount
                Inconclusive = $inconclusiveCount
                NotRun = $testResult.NotRunCount
                SkippedTests = $skippedTests
                Qualification = 'NotQualified'
            }
            Write-LabJson -name 'pester-summary.json' -value $testSummary
            if ($testResult.Result -cne 'Passed' -or $testResult.FailedCount -gt 0 -or $inconclusiveCount -gt 0 -or $testResult.PassedCount -eq 0) {
                Add-LabCheck -name 'Pester' -status Failed -detail "Result=$($testResult.Result); passed=$($testResult.PassedCount); failed=$($testResult.FailedCount); skipped=$($testResult.SkippedCount); inconclusive=$($inconclusiveCount)."
            } elseif ($unexpectedSkips.Count -gt 0 -or $testResult.NotRunCount -gt 0) {
                Add-LabCheck -name 'Pester' -status Incomplete -detail "Passed=$($testResult.PassedCount); unexpected skips=$($unexpectedSkips.Count); not run=$($testResult.NotRunCount); inspect XML."
            } else {
                Add-LabCheck -name 'Pester' -status Observed -detail "Passed=$($testResult.PassedCount); failed=0; expected Windows-inapplicable skips=$($skippedTests.Count)."
            }
        } catch {
            Add-LabCheck -name 'Pester' -status Failed -detail $_.Exception.Message
            Write-Warning "Pester execution failed: $($_.Exception.Message)"
        }
    } else {
        Add-LabCheck -name 'Pester' -status NotRun -detail 'No disposable Pester suite was requested.'
    }

    if ($runDisposableCandidateTests) {
        try {
            if (Test-Path -LiteralPath $candidateFixturePath -PathType Container) {
                $fixtureItem = Get-Item -LiteralPath $candidateFixturePath -Force -ErrorAction Stop
                if ($fixtureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Candidate fixture is a reparse point.' }
                $candidateEvidence = Join-Path $candidateFixturePath 'evidence'
                if (Test-Path -LiteralPath $candidateEvidence -PathType Container) {
                    $candidateEvidenceItem = Get-Item -LiteralPath $candidateEvidence -Force -ErrorAction Stop
                    if ($candidateEvidenceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Candidate evidence directory is a reparse point.' }
                    foreach ($auditDirectory in @(Get-ChildItem -LiteralPath $candidateEvidence -Directory -Force -ErrorAction Stop)) {
                        if ($auditDirectory.Name -cnotmatch '^Permissions_[a-f0-9]{32}$' -or
                            $auditDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                            throw 'Unexpected candidate audit directory or reparse point.'
                        }
                        foreach ($fileName in @(
                            'events.jsonl', 'candidate.lock', 'interruption.json',
                            'interruption-request.clixml', 'child-stdout.txt', 'child-stderr.txt'
                        )) {
                            $auditPath = Join-Path $auditDirectory.FullName $fileName
                            if (Test-Path -LiteralPath $auditPath -PathType Leaf) {
                                $auditFile = Get-Item -LiteralPath $auditPath -Force -ErrorAction Stop
                                if ($auditFile.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Candidate audit file is a reparse point.' }
                                $destinationDirectory = Join-Path (Join-Path $run 'candidate-audits') $auditDirectory.Name
                                [void][IO.Directory]::CreateDirectory($destinationDirectory)
                                $destination = Join-Path $destinationDirectory $fileName
                                Copy-Item -LiteralPath $auditPath -Destination $destination -ErrorAction Stop
                                $copiedAuditFiles.Add($destination)
                            }
                        }
                    }
                }
                Write-LabJson -name 'candidate-fixture.json' -value ([ordered]@{
                    Path = $candidateFixturePath
                    Status = 'Preserved'
                    AuditFilesCopied = $copiedAuditFiles.Count
                    Note = 'Generated disposable fixture; preserve for review before approved cleanup.'
                })
                Add-LabCheck -name 'CandidateFixtureEvidence' -status Observed -detail "Preserved fixture and copied $($copiedAuditFiles.Count) audit files."
            } else {
                Add-LabCheck -name 'CandidateFixtureEvidence' -status Incomplete -detail 'Selected candidate tests did not create the expected fixture.'
            }
        } catch {
            Add-LabCheck -name 'CandidateFixtureEvidence' -status Failed -detail $_.Exception.Message
            Write-Warning "Candidate fixture evidence collection failed: $($_.Exception.Message)"
        }
    } else {
        Add-LabCheck -name 'CandidateFixtureEvidence' -status NotRun -detail 'Candidate tests were not requested.'
    }
} catch {
    $fatalMessage = $_.Exception.Message
    Add-LabCheck -name 'Runner' -status Failed -detail $fatalMessage
    Write-Warning "Evidence runner failed: $($fatalMessage)"
} finally {
    if ($transcriptStarted) {
        try { Stop-Transcript -ErrorAction Stop | Out-Null }
        catch {
            Add-LabCheck -name 'TranscriptStop' -status Failed -detail $_.Exception.Message
            Write-Warning "Transcript could not be stopped: $($_.Exception.Message)"
        }
    }
    $issues = @($checks | Where-Object Status -in @('Failed', 'Incomplete'))
    $summary = [ordered]@{
        Schema = 'NtfsLabEvidence/1'
        StartedUtc = $startedUtc
        CompletedUtc = [DateTime]::UtcNow.ToString('o')
        Status = $(if ($issues.Count -gt 0) { 'AttentionRequired' } else { 'Collected' })
        WriterQualification = 'NotQualified'
        Requested = [ordered]@{
            Group = [bool]$groupName
            ReadOnlyTarget = [bool]$readOnlyTarget
            SyntheticTests = [bool]$runSyntheticTests
            DisposableCandidateTests = [bool]$runDisposableCandidateTests
        }
        Checks = @($checks.ToArray())
        Limitations = @(
            'No production change authorization or writer qualification.'
            'No effective-access, external-client, OS-crash, power-loss, storage-failure or backend-disconnect tests.'
            'Fixture Pester tests use synthetic SIDs; the selected candidate fixture is preserved for review.'
            'Read-only inventory is scoped, non-atomic and does not prove target authority or physical identity.'
        )
    }
    Write-LabJson -name 'summary.json' -value $summary
    $files = @(
        Get-ChildItem -LiteralPath $run -File -ErrorAction Stop | Where-Object Name -ne 'SHA256SUMS.csv'
        foreach ($auditFile in $copiedAuditFiles) { Get-Item -LiteralPath $auditFile -ErrorAction Stop }
    )
    $files | Sort-Object FullName | Get-FileHash -Algorithm SHA256 -ErrorAction Stop |
        Select-Object Path, Algorithm, Hash |
        Export-Csv -LiteralPath (Join-Path $run 'SHA256SUMS.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
}

$result = [pscustomobject]@{
    Status = $summary.Status
    EvidencePath = $run
    SummaryPath = Join-Path $run 'summary.json'
    WriterQualification = 'NotQualified'
}
$result
if ($summary.Status -cne 'Collected' -or $fatalMessage) {
    throw "Evidence requires review. See $($result.SummaryPath)"
}
