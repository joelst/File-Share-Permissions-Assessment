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
    . (Join-Path $PSScriptRoot '../NtfsPermissions.Validation.ps1')
    $script:work = Join-Path $PSScriptRoot ('ValidationTests_' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($script:work)
    function New-VSnapshot([string]$Path='\\server\lab\case', [string]$Kind='Folder', [bool]$Protected=$false) {
        [pscustomobject][ordered]@{
            Path=$Path; Kind=$Kind; Identity="UNQUALIFIED:fixture:$Path"
            Owner='S-1-5-18'; Group='S-1-5-32-544'
            Control=[int]([Security.AccessControl.ControlFlags]::SelfRelative -bor [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)
            Protected=$Protected
            DaclPresent=$true; Canonical=$true; Aces=@(); Descriptor="fixture-original:$Path"
        }
    }
    function New-VBinding([string]$Platform='Auto', [string]$Scope='ThisFolderSubfoldersAndFiles') {
        $d = New-NpTargetDescriptor '\\server\lab\case' $Platform
        $g = @(Get-NpGrants -GroupName Readers -Permissions Read -Resolve { 'S-1-5-21-1-2-3-1001' })
        New-NvBinding $d $g $Scope 100 CHG123
    }
    function New-VInventory($Snapshots=@((New-VSnapshot),(New-VSnapshot '\\server\lab\case\f.txt' File)), $Errors=@()) {
        [pscustomobject]@{
            Snapshots=@($Snapshots); Boundaries=@($Snapshots | Where-Object { $_.Protected -and $_.Path -ine '\\server\lab\case' } | ForEach-Object Path)
            Errors=@($Errors)
        }
    }
    function New-VCase($Binding=(New-VBinding)) {
        $dir = New-NpRun $script:work '\\server\lab\case'
        $null = Invoke-NvStage $dir Initialize $Binding
        $dir
    }
    function Invoke-VThrough([string]$Case, [string]$Last='CaptureAfterRevert') {
        foreach ($s in @('CaptureBefore','CaptureAfterApply','CaptureAfterRevert')) {
            $null=Invoke-NvStage $Case $s -ManualAcknowledged $true
            if ($s -ceq $Last) { break }
        }
    }
    function Get-VObserved($Snapshots=@((New-VSnapshot)), $Errors=@()) {
        $script:fixture=New-VInventory $Snapshots $Errors
        Get-NvCapture (New-VBinding)
    }
}
AfterAll { Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction Stop }

Describe 'Read-only validation evidence workflow' {
    BeforeEach {
        Mock Assert-NvWindows {}
        # Portable fixtures replace only internal OS boundaries, never a public adapter.
        Mock Assert-NvLocalCase {
            param($CasePath)
            if (-not [IO.Path]::IsPathRooted($CasePath) -or -not (Test-Path -LiteralPath $CasePath -PathType Container)) { throw 'Invalid case path' }
        }
        Mock Get-NpWindowsInventory { $script:fixture }
        Mock ConvertTo-NvCapturedSnapshot { param($Snapshot) $Snapshot }
        $script:fixture=New-VInventory
    }
    It 'seals all stages and independently recomputes observational revert evidence' {
        $case=New-VCase
        Invoke-VThrough $case
        $result=Invoke-NvStage $case Report
        $result.WriterQualification | Should -Be NotQualified
        $result.TargetWrites | Should -Be 0
        $state=Read-NvCase $case
        $state.Count | Should -Be 5
        foreach ($stage in $script:NvStages) {
            $lines=@(Get-Content -LiteralPath (Join-Path $case "$stage/stage.log"))
            $lines.Count | Should -Be 2
            foreach ($line in $lines) {
                $line | Should -Match ([regex]::Escape("Version=$($script:NtfsVersions.PermissionValidation)"))
            }
            $state.Stages[$stage].Files.Name | Should -Contain 'stage.log'
        }
        $result.Version | Should -Be $script:NtfsVersions.PermissionValidation
        $report=Read-NvJson (Join-Path $case 'Report/report.json')
        $report.IndependentComparison.Revert.DescriptorResult | Should -Be ExactCapturedDescriptorsObservedOnly
        $report.IndependentComparison.Apply.DescriptorResult | Should -Be NoChangeObserved
        $report.IndependentComparison.Apply.Status | Should -Be Failed
        $report.Status | Should -Be Failed
        $result.Diagnostics.Warnings | Should -BeGreaterThan 0
        ($result.Diagnostics.Reasons.Reason -join "`n") | Should -Match 'Apply comparison: Failed'
        $report.PhysicalIdentityProof | Should -Be Unqualified
        $report.ManualMatrixStatus | Should -Be NotRun
        $manifest=Read-NvJson (Join-Path $case 'CaptureBefore/manifest.json')
        $manifest.Files.Name | Should -Contain snapshots.csv
        $manifest.Files.Name | Should -Contain intent-review.json
    }
    It 'records an already covered no-op without calling it a successful change' {
        $s=New-VSnapshot
        $s.Aces=@([pscustomobject][ordered]@{
            SID='S-1-5-21-1-2-3-1001';Type='Allow';Mask=1179785L;Inherited=$false
            ContainerInherit=$true;ObjectInherit=$true;InheritOnly=$false;NoPropagate=$false
        })
        $script:fixture=New-VInventory @($s)
        $case=New-VCase
        Invoke-VThrough $case
        $null=Invoke-NvStage $case Report
        $report=Read-NvJson (Join-Path $case 'Report/report.json')
        $report.IndependentComparison.Apply.Status | Should -Be Observed
        $report.IndependentComparison.Apply.DescriptorResult | Should -Be NoChangeObserved
        $report.WriterQualification | Should -Be NotQualified
    }
    It 'preserves WhatIf as local evidence, not target write simulation' {
        $case=New-VCase
        $r=Invoke-NvStage $case CaptureBefore -WhatIfRecorded $true
        $r.TargetWrites | Should -Be 0
        (Read-NvJson (Join-Path $case 'CaptureBefore/manifest.json')).WhatIf | Should -BeTrue
    }
    It 'rejects out of order capture before a baseline exists' {
        $case=New-VCase
        { Invoke-NvStage $case CaptureAfterApply -ManualAcknowledged $true } | Should -Throw '*order*'
        Test-Path (Join-Path $case CaptureAfterApply) | Should -BeFalse
    }
    It 'rejects after-action capture without explicit external acknowledgement' {
        $case=New-VCase
        $null=Invoke-NvStage $case CaptureBefore
        { Invoke-NvStage $case CaptureAfterApply } | Should -Throw '*acknowledgement*'
    }
    It 'cannot overwrite any completed stage or reopen a report' {
        $case=New-VCase
        $null=Invoke-NvStage $case Report
        $hash=Get-NvFileHash (Join-Path $case 'Report/report.json')
        { Invoke-NvStage $case Report } | Should -Throw '*immutable*'
        Get-NvFileHash (Join-Path $case 'Report/report.json') | Should -Be $hash
    }
    It 'reports missing required stages as incomplete rather than qualification' {
        $case=New-VCase
        $r=Invoke-NvStage $case Report
        $r.Status | Should -Be Incomplete
        $report=Read-NvJson (Join-Path $case 'Report/report.json')
        $report.MissingStages.Count | Should -Be 3
        $r.Diagnostics.MissingEvidence | Should -Be 3
        $r.Diagnostics.Warnings | Should -Be 1
        ($r.Diagnostics.Reasons.Reason -join "`n") | Should -Match 'CaptureBefore, CaptureAfterApply, CaptureAfterRevert'
        @($r.Diagnostics.Reasons | Where-Object Reason -like 'Missing required captures*')[0].Status | Should -Be 'NotAssessed'
        $report.WriterQualification | Should -Be NotQualified
    }
    It 'counts unresolved comparisons and prevents an external-action next step' {
        Mock Compare-NvCapture {
            [pscustomobject]@{
                Status='NotAssessed';Mode='Apply';Namespace='ObservedSameCapturedPaths'
                DescriptorResult='ChangedDescriptorsObservedNotExpectedDescriptorVerified'
                Missing=@();Added=@();Rows=@()
            }
        }
        $case=New-VCase
        $null=Invoke-NvStage $case CaptureBefore
        $result=Invoke-NvStage $case CaptureAfterApply -ManualAcknowledged $true
        $result.Diagnostics.MissingEvidence | Should -Be 1
        $result.Diagnostics.Warnings | Should -Be 1
        $result.NextStep | Should -BeLike '*stop external actions*'
        ($result.Diagnostics.Reasons.Reason -join "`n") | Should -Match 'Apply comparison: NotAssessed'
        @($result.Diagnostics.Reasons | Where-Object Reason -like 'Apply comparison: NotAssessed*')[0].Status | Should -Be 'NotAssessed'
        $reportResult=Invoke-NvStage $case Report
        @($reportResult.Diagnostics.Reasons | Where-Object Reason -like 'Apply comparison: NotAssessed*')[0].Status | Should -Be 'NotAssessed'
    }
    It 'prioritizes capture and report evidence gaps ahead of more frequent intent warnings' {
        $snapshots=@((New-VSnapshot))
        foreach($group in 1..5){
            foreach($item in 1..3){
                $snapshots+=New-VSnapshot -Path "\\server\lab\case\group$($group)-item$($item)"
            }
        }
        $script:fixture=New-VInventory -Snapshots $snapshots -Errors @('Synthetic capture evidence unavailable')
        Mock New-NpProposal {
            param($Before)
            if($Before.Path -match 'group(\d+)'){throw "Intent warning group $($Matches[1])"}
            throw 'Intent warning for root'
        }
        $case=New-VCase
        $capture=Invoke-NvStage $case CaptureBefore
        $captureMessages=@(Write-NtfsCompletion -component Validation -status Incomplete -reasonSummary $capture.Diagnostics.Reasons -nextStep 'Review evidence.' 6>&1)
        $captureReasons=@($captureMessages.MessageData | Where-Object {$_ -like '  - (*'})
        $captureReasons.Count | Should -Be 5
        $captureReasons[0] | Should -Match 'NotAssessed: Synthetic capture evidence unavailable'
        $reportResult=Invoke-NvStage $case Report
        $reportMessages=@(Write-NtfsCompletion -component Validation -status Incomplete -reasonSummary $reportResult.Diagnostics.Reasons -nextStep 'Review evidence.' 6>&1)
        $reportReasons=@($reportMessages.MessageData | Where-Object {$_ -like '  - (*'})
        $reportReasons.Count | Should -Be 5
        ($reportReasons[0..1] -join "`n") | Should -Match 'NotAssessed: CaptureBefore: Synthetic capture evidence unavailable'
        ($reportReasons[0..1] -join "`n") | Should -Match 'NotAssessed: Missing required captures'
    }
    It 'prioritizes missing baseline paths without misclassifying failed comparisons' {
        $case=New-VCase
        $null=Invoke-NvStage $case CaptureBefore
        $script:fixture=New-VInventory -Snapshots @((New-VSnapshot))
        $capture=Invoke-NvStage $case CaptureAfterApply -ManualAcknowledged $true
        @($capture.Diagnostics.Reasons | Where-Object Reason -like 'Paths present in the baseline*')[0].Status | Should -Be 'NotAssessed'
        $failedCapture=@($capture.Diagnostics.Reasons | Where-Object Reason -like 'Apply comparison: Failed*')[0]
        $failedCapture.PSObject.Properties.Name | Should -Not -Contain 'Status'
        $reportResult=Invoke-NvStage $case Report
        @($reportResult.Diagnostics.Reasons | Where-Object Reason -like 'Apply: baseline paths missing*')[0].Status | Should -Be 'NotAssessed'
        $failedReport=@($reportResult.Diagnostics.Reasons | Where-Object Reason -like 'Apply comparison: Failed*')[0]
        $failedReport.PSObject.Properties.Name | Should -Not -Contain 'Status'
    }
    It 'detects exact-byte tampering of prior evidence' {
        $case=New-VCase
        $null=Invoke-NvStage $case CaptureBefore
        [IO.File]::AppendAllText((Join-Path $case 'CaptureBefore/inventory.json'),' ')
        { Read-NvCase $case } | Should -Throw '*hash mismatch*'
    }
    It 'detects case target/platform binding tampering' {
        $case=New-VCase
        $path=Join-Path $case 'Initialize/case.json'
        $c=Read-NvJson $path
        $c.TargetDescriptor.Platform='NetAppSMB'
        [IO.File]::WriteAllText($path,(Get-NpCanonicalJson $c))
        { Read-NvCase $case } | Should -Throw '*hash mismatch*'
    }
    It 'rejects changed source hashes even when stage evidence remains untouched' {
        $case=New-VCase
        Mock Get-NvSources { @([pscustomobject]@{Name='changed';SHA256=('a'*64)}) }
        { Read-NvCase $case } | Should -Throw '*Source hashes changed*'
    }
    It 'rejects changed host/operator binding' {
        $b=New-VBinding
        $b.ExecutionHost='another-host'
        { Assert-NvBinding $b } | Should -Throw '*host/operator*'
    }
    It 'rejects source and binding overrides during resume' {
        $case=New-VCase
        { Invoke-NvStage $case CaptureBefore (New-VBinding) } | Should -Throw '*overrides*'
    }
    It 'rejects a torn commit without recovering a successful tail' {
        $case=New-VCase
        [IO.File]::WriteAllText((Join-Path $case '002-CaptureBefore.commit.json'),'{')
        { Read-NvCase $case } | Should -Throw
    }
    It 'rejects orphan pending artifacts and preserves them unchanged' {
        $case=New-VCase
        $path=Join-Path $case '002-CaptureBefore.commit.json.pending'
        [IO.File]::WriteAllText($path,'partial')
        { Read-NvCase $case } | Should -Throw '*torn*'
        [IO.File]::ReadAllText($path) | Should -Be partial
    }
    It 'rejects orphan stage directories after a disconnect' {
        $case=New-VCase
        [void][IO.Directory]::CreateDirectory((Join-Path $case CaptureBefore))
        { Read-NvCase $case } | Should -Throw '*torn*'
    }
    It 'fails closed on a preexisting crashed or concurrent lock' {
        $case=New-VCase
        [IO.File]::WriteAllText((Join-Path $case '.case.lock'),'crashed')
        { Invoke-NvStage $case CaptureBefore } | Should -Throw
        Test-Path (Join-Path $case CaptureBefore) | Should -BeFalse
    }
    It 'retains a failed audit stage and lock and never continues automatically' {
        $case=New-VCase
        Mock Export-NtfsCsvData { throw 'audit write failed' }
        { Invoke-NvStage $case CaptureBefore } | Should -Throw '*audit write failed*'
        Test-Path (Join-Path $case '.case.lock') | Should -BeTrue
        Test-Path (Join-Path $case CaptureBefore) | Should -BeTrue
        { Read-NvCase $case } | Should -Throw '*torn*'
    }
    It 'rejects missing evidence rather than certifying an empty capture' {
        $case=New-VCase
        $null=Invoke-NvStage $case CaptureBefore
        Remove-Item -LiteralPath (Join-Path $case 'CaptureBefore/inventory.json')
        { Read-NvCase $case } | Should -Throw
    }
    It 'rejects invalid case paths' {
        { Read-NvCase (Join-Path $script:work nonexistent) } | Should -Throw
        { Read-NvCase relative } | Should -Throw
    }
    It 'binds each explicitly declared SMB platform independently <Requested>' -ForEach @(
        @{Requested='Auto';Expected='GenericSMB'},@{Requested='Windows';Expected='WindowsSMB'},
        @{Requested='NetApp';Expected='NetAppSMB'},@{Requested='Nas';Expected='GenericSMB'}
    ) {
        $case=New-VCase (New-VBinding $Requested)
        (Read-NvCase $case).Binding.TargetDescriptor.Platform | Should -Be $Expected
        (Read-NvCase $case).Binding.WriterQualification | Should -Be NotQualified
    }
    It 'does not resolve the original mapped drive again' {
        $b=New-VBinding
        $b.TargetDescriptor=New-NpTargetDescriptor 'Z:\case' Windows '\\server\lab'
        Mock Resolve-NpTarget { throw 'must not re-resolve mapping' }
        Mock Get-NpDriveBinding { throw 'must not consult mapped drive' }
        $case=New-VCase $b
        $null=Invoke-NvStage $case CaptureBefore
        Should -Invoke Resolve-NpTarget -Times 0
        Should -Invoke Get-NpDriveBinding -Times 0
        (Read-NvCase $case).Binding.TargetDescriptor.CanonicalPath | Should -Be '\\server\lab\case'
    }
    It 'detects local volume drift without remapping a drive' {
        $observation=[pscustomobject][ordered]@{
            Status='ObservedReadOnly';ExecutionHost=[Environment]::MachineName
            VolumeDeviceId='volume1';VolumeSerialNumber='1';FileSystem='NTFS'
        }
        $b=New-VBinding
        $b.TargetDescriptor=New-NpTargetDescriptor 'C:\case' Windows -LocalHost ([Environment]::MachineName) -Observation $observation
        Mock Get-NpDriveBinding {
            [pscustomobject]@{Kind='Fixed';HostName=[Environment]::MachineName;Observation=[pscustomobject]@{Status='different'}}
        }
        { Get-NvEnvironment $b } | Should -Throw '*namespace drift*'
    }
    It 'records capture errors and withholds every comparison claim' {
        $script:fixture=New-VInventory -Errors @('unreadable','reparse','limit')
        $case=New-VCase
        $null=Invoke-NvStage $case CaptureBefore
        $after=Invoke-NvStage $case CaptureAfterApply -ManualAcknowledged $true
        @($after.Diagnostics.Reasons | Where-Object Reason -like 'Apply comparison: Incomplete*')[0].Status | Should -Be 'NotAssessed'
        $null=Invoke-NvStage $case CaptureAfterRevert -ManualAcknowledged $true
        $r=Invoke-NvStage $case Report
        $r.Status | Should -Be Incomplete
        $report=Read-NvJson (Join-Path $case 'Report/report.json')
        $report.IndependentComparison.Revert.Status | Should -Be Incomplete
        $report.IndependentComparison.Revert.DescriptorResult | Should -Be NotAssessed
        $r.Diagnostics.MissingEvidence | Should -Be ($report.EvidenceErrors.Count+2)
        ($r.Diagnostics.Reasons.Reason -join "`n") | Should -Match 'unreadable'
        @($r.Diagnostics.Reasons | Where-Object Reason -like 'Apply comparison: Incomplete*')[0].Status | Should -Be 'NotAssessed'
        $r.NextStep | Should -Not -Match 'Report may close'
    }
    It 'records all manual tests as NotRun with explicit external evidence fields' {
        $matrix=Get-NvManualMatrix
        @($matrix.Cases | Where-Object Status -ne NotRun).Count | Should -Be 0
        $matrix.Cases.Test | Should -Contain ParentRollbackMustNotModifyDriftRefusedDescendants
        $matrix.Cases.Test | Should -Contain TestAccountDelete
        $matrix.Cases[0].Keys | Should -Contain SourceHashes
    }
    It 'imports externally observed commands/results without claiming independent execution or qualification' {
        $case=New-VCase
        $matrix=Read-NvJson (Join-Path $case 'Initialize/manual-matrix.json')
        foreach ($item in $matrix.Cases | Where-Object Test -like 'TestAccount*') {
            $item.Status='Observed'; $item.Command='External approved test command'
            $item.ActualResult='External recorded result'; $item.Account='DOMAIN\TestAccount'
            $item.Utc=[DateTime]::UtcNow.ToString('o'); $item.Reviewer='Reviewer'
        }
        $path=Join-Path $script:work ('external-observations-'+[guid]::NewGuid().ToString('N')+'.json')
        Write-NvNewJson $path $matrix
        Invoke-VThrough $case
        $null=Invoke-NvStage $case Report -ManualObservationsFile $path
        $report=Read-NvJson (Join-Path $case 'Report/report.json')
        $report.FunctionalAccess | Should -Be Observed
        $report.ManualEvidenceAuthority | Should -Be OperatorSubmittedNotIndependentlyVerified
        $report.WriterQualification | Should -Be NotQualified
        Test-Path (Join-Path $case 'Report/manual-observations.json') | Should -BeTrue
        $null=Read-NvCase $case
    }
    It 'rejects external observations with wrong <Field>' -ForEach @(
        @{Field='SourceHashes'},@{Field='Platform'},@{Field='CaseBindingSHA256'},@{Field='Command'}
    ) {
        $case=New-VCase
        $matrix=Read-NvJson (Join-Path $case 'Initialize/manual-matrix.json')
        $item=$matrix.Cases[0]
        $item.Status='Observed';$item.Command='command';$item.ActualResult='result'
        $item.Account='test';$item.Utc=[DateTime]::UtcNow.ToString('o');$item.Reviewer='reviewer'
        switch ($Field) {
            SourceHashes { $item.SourceHashes[0].SHA256='bad' }
            Platform { $item.Platform='NetAppSMB' }
            CaseBindingSHA256 { $matrix.CaseBindingSHA256='bad' }
            Command { $item.Command='' }
        }
        $path=Join-Path $script:work ([guid]::NewGuid().ToString('N')+'.json')
        Write-NvNewJson $path $matrix
        { Read-NvManualObservations $path (Read-NvCase $case) } | Should -Throw
    }
    It 'includes failed operator observations in report warning counts and reasons' {
        $case=New-VCase
        $matrix=Read-NvJson (Join-Path $case 'Initialize/manual-matrix.json')
        $item=$matrix.Cases[0]
        $item.Status='Failed';$item.Command='External approved test command';$item.ActualResult='External test failed'
        $item.Account='test';$item.Utc=[DateTime]::UtcNow.ToString('o');$item.Reviewer='reviewer'
        $path=Join-Path $script:work ('failed-observation-'+[guid]::NewGuid().ToString('N')+'.json')
        Write-NvNewJson $path $matrix
        $result=Invoke-NvStage $case Report -ManualObservationsFile $path
        $result.Diagnostics.Warnings | Should -Be 1
        ($result.Diagnostics.Reasons.Reason -join "`n") | Should -Match ([regex]::Escape("Manual observation failed: $($item.Test)"))
    }
    It 'keeps user metadata strictly typed and unverified' {
        $json='{"Session":"operator session","Volume":"reported volume","Nas":"reported NAS","Backend":"NetApp","SecurityStyle":"ntfs","Namespace":"reviewed externally","EvidenceStorage":"trusted local"}'
        $value=ConvertTo-NvOperatorMetadata $json
        $value.Status | Should -Be OperatorDeclarationUnverified
        { ConvertTo-NvOperatorMetadata '{"Backend":"Windows"}' } | Should -Throw
        { ConvertTo-NvOperatorMetadata ($json.Replace('"operator session"','true')) } | Should -Throw
        { ConvertTo-NvOperatorMetadata ($json.Replace('operator session','bad\nmetadata')) } | Should -Throw
        { ConvertTo-NvOperatorMetadata ($json.Replace('{"Session":','{"Session":"duplicate","Session":')) } | Should -Throw
    }
    It 'records applicable denies as failed intent review and tells the operator to stop' {
        $s=New-VSnapshot
        $s.Aces=@([pscustomobject][ordered]@{
            SID='S-1-5-21-1-2-3-1001';Type='Deny';Mask=131209L;Inherited=$false
            ContainerInherit=$true;ObjectInherit=$true;InheritOnly=$false;NoPropagate=$false
        })
        $script:fixture=New-VInventory @($s)
        $case=New-VCase
        $r=Invoke-NvStage $case CaptureBefore
        $r.Status | Should -Be Failed
        $r.NextStep | Should -BeLike '*stop external actions*'
        $intent=Read-NvJson (Join-Path $case 'CaptureBefore/intent-review.json')
        $intent.Entries[0].Error | Should -BeLike '*deny overlap*'
        $report=Invoke-NvStage $case Report
        $report.Diagnostics.Warnings | Should -Be 2
        ($report.Diagnostics.Reasons.Reason -join "`n") | Should -BeLike '*Intent review:*deny overlap*'
    }
    It 'always asks the inventory adapter for folder AND file descendants for either intent scope' {
        $b=New-VBinding -Scope ThisFolderOnly
        $null=Get-NvCapture $b
        Should -Invoke Get-NpWindowsInventory -Times 2 -ParameterFilter { $Scope -ceq 'ThisFolderSubfoldersAndFiles' -and $Limit -eq 100 }
    }
    It 'rejects evidence under the direct target or a known local share backing alias' {
        $d=New-NpTargetDescriptor 'C:\lab\case' Windows -LocalHost ([Environment]::MachineName)
        { Assert-NvEvidenceSeparation 'C:\lab\case\Evidence' $d } | Should -Throw '*outside*'
        Mock Get-NvKnownBackingPaths { @('C:\lab\case') }
        $d=New-NpTargetDescriptor '\\alias\lab\case' Windows
        { Assert-NvEvidenceSeparation 'C:\lab\case\Evidence' $d } | Should -Throw '*outside*'
    }
    It 'blocks a concurrent stage while evidence publication is in progress' {
        $case=New-VCase
        $script:concurrentRejected=$false
        Mock Export-NtfsCsvData {
            try { $null=Invoke-NvStage $case CaptureAfterApply -ManualAcknowledged $true }
            catch { $script:concurrentRejected=$true }
        }
        $null=Invoke-NvStage $case CaptureBefore
        $script:concurrentRejected | Should -BeTrue
        (Read-NvCase $case).Count | Should -Be 2
        Test-Path (Join-Path $case CaptureAfterApply) | Should -BeFalse
    }
    It 'does not silently reseal a stage when manifest publication fails' {
        $case=New-VCase
        $script:actualWriteNvNewJson=${function:Write-NvNewJson}
        Mock Write-NvNewJson {
            param($Path,$Value)
            if ($Path -like '*manifest.json') { throw 'manifest seal fault' }
            & $script:actualWriteNvNewJson $Path $Value
        }
        { Invoke-NvStage $case CaptureBefore } | Should -Throw '*manifest seal fault*'
        Test-Path (Join-Path $case '002-CaptureBefore.commit.json') | Should -BeFalse
        Test-Path (Join-Path $case 'CaptureBefore/inventory.json') | Should -BeTrue
        { Read-NvCase $case } | Should -Throw '*torn*'
        { Invoke-NvStage $case CaptureBefore } | Should -Throw
    }
}

Describe 'Conservative independent descriptor and namespace comparisons' {
    BeforeEach {
        Mock Assert-NvWindows {}
        Mock Get-NpWindowsInventory { $script:fixture }
        Mock ConvertTo-NvCapturedSnapshot { param($Snapshot) $Snapshot }
    }
    It 'compares full SDDL ordinally without DACL canonical reordering' {
        $before=Get-VObserved
        $s=New-VSnapshot
        $s.Descriptor='reordered-or-drifted'
        $after=Get-VObserved @($s)
        $c=Compare-NvCapture $before $after (New-VBinding) Revert
        $c.Status | Should -Be Failed
        $c.Rows[0].DescriptorExactMatch | Should -BeFalse
        $c.PhysicalReversionProof | Should -Be NotAssessed
    }
    It 'flags <Field> drift even with an unchanged descriptor' -ForEach @(
        @{Field='Owner';Value='other'},@{Field='Group';Value='other'},@{Field='Control';Value=4},
        @{Field='Identity';Value='UNQUALIFIED:replacement'},@{Field='Kind';Value='File'}
    ) {
        $before=Get-VObserved
        $s=New-VSnapshot
        $s.$Field=$Value
        $after=[pscustomobject]@{Status='Observed';DescriptorSections='OwnerGroupDacl';Snapshots=@($s);Boundaries=@()}
        (Compare-NvCapture $before $after (New-VBinding) Revert).Status | Should -Be Failed
    }
    It 'does not mistake deleted, renamed or added paths for reversion <Scenario>' -ForEach @(
        @{Scenario='Delete'},@{Scenario='Rename'},@{Scenario='Add'}
    ) {
        $root=New-VSnapshot
        $file=New-VSnapshot '\\server\lab\case\f.txt' File
        $before=Get-VObserved @($root,$file)
        $snapshots=switch($Scenario) {
            Delete { @($root) }
            Rename { @($root,(New-VSnapshot '\\server\lab\case\renamed.txt' File)) }
            Add { @($root,$file,(New-VSnapshot '\\server\lab\case\added.txt' File)) }
        }
        $after=Get-VObserved $snapshots
        $c=Compare-NvCapture $before $after (New-VBinding) Revert
        $c.Status | Should -Be Failed
        $c.Namespace | Should -Be DriftObserved
    }
    It 'withholds all revert claims when before preimages are missing or partial' {
        $before=Get-VObserved @() @('missing preimages')
        $after=Get-VObserved
        $c=Compare-NvCapture $before $after (New-VBinding) Revert
        $c.Status | Should -Be Incomplete
        $c.DescriptorResult | Should -Be NotAssessed
    }
    It 'requires captured protected boundaries unchanged and never proves their contents' {
        $root=New-VSnapshot
        $protected=New-VSnapshot '\\server\lab\case\protected' Folder $true
        $before=Get-VObserved @($root,$protected)
        $protected.Descriptor='drift'
        $after=Get-VObserved @($root,$protected)
        # Captures have independent object graphs, just as their persisted JSON does.
        $before=Get-NpCanonicalJson $before | ConvertFrom-NpJson
        $before.Snapshots[1].Descriptor='original'
        $c=Compare-NvCapture $before $after (New-VBinding) Apply
        $c.Status | Should -Be Failed
        $c.ProtectedBranchContents | Should -Be NotAssessed
        @($c.Rows | Where-Object ProtectedBoundary)[0].Status | Should -Be Failed
    }
    It 'marks traversed protected branches incomplete' {
        $root=New-VSnapshot
        $protected=New-VSnapshot '\\server\lab\case\protected' Folder $true
        $child=New-VSnapshot '\\server\lab\case\protected\child' File
        (Get-VObserved @($root,$protected,$child)).Status | Should -Be Incomplete
    }
    It 'detects unsupported ACLs and duplicate paths as incomplete' {
        $s=New-VSnapshot
        $s.Canonical=$false
        (Get-VObserved @($s)).Status | Should -Be Incomplete
        (Get-VObserved @((New-VSnapshot),(New-VSnapshot))).Status | Should -Be Incomplete
    }
    It 'distinguishes null DACL from a present empty DACL and never equates missing ACL evidence' {
        $empty=Get-VObserved @((New-VSnapshot))
        $empty.Status | Should -Be Observed
        $nullDacl=New-VSnapshot
        $nullDacl.DaclPresent=$false
        $missing=Get-VObserved @($nullDacl)
        $missing.Status | Should -Be Incomplete
        (Compare-NvCapture $empty $missing (New-VBinding) Revert).DescriptorResult | Should -Be NotAssessed
    }
    It 'captures descendant evidence even for ThisFolderOnly and detects descendant changes' {
        $binding=New-VBinding -Scope ThisFolderOnly
        $root=New-VSnapshot
        $file=New-VSnapshot '\\server\lab\case\f.txt' File
        $before=Get-VObserved @($root,$file)
        $after=Get-NpCanonicalJson $before | ConvertFrom-NpJson
        $after.Snapshots[1].Descriptor='unexpected-descendant-change'
        (Compare-NvCapture $before $after $binding Apply).Status | Should -Be Failed
    }
    It 'rejects auto-inheritance control-flag propagation into unaffected descendants' {
        $binding=New-VBinding -Scope ThisFolderOnly
        $root=New-VSnapshot
        $file=New-VSnapshot '\\server\lab\case\f.txt' File
        $root.Descriptor='O:SYG:SYD:(A;ID;FA;;;WD)'
        $file.Descriptor='O:SYG:SYD:(A;ID;FA;;;WD)'
        $before=Get-VObserved @($root,$file)
        $after=Get-NpCanonicalJson $before | ConvertFrom-NpJson
        $after.Snapshots[0].Descriptor='O:SYG:SYD:AI(A;;FR;;;S-1-5-21-1-2-3-1001)(A;ID;FA;;;WD)'
        $after.Snapshots[0].Control=[int]([Security.AccessControl.ControlFlags]$root.Control -bor
            [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)
        $after.Snapshots[0].Aces=@([pscustomobject][ordered]@{
            SID='S-1-5-21-1-2-3-1001';Type='Allow';Mask=1179785L;Inherited=$false
            ContainerInherit=$false;ObjectInherit=$false;InheritOnly=$false;NoPropagate=$false
        })
        $after.Snapshots[1].Descriptor='O:SYG:SYD:AI(A;ID;FA;;;WD)'
        $after.Snapshots[1].Control=[int]([Security.AccessControl.ControlFlags]$file.Control -bor
            [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)

        $comparison=Compare-NvCapture $before $after $binding Apply
        $comparison.Status | Should -Be Failed
        $comparison.DescriptorResult | Should -Be DriftObserved
        $comparison.Rows[0].MetadataUnchanged | Should -BeFalse
        $comparison.Rows[0].ObservedGrant | Should -Be ObservedAllowCoverageOnly
        $comparison.Rows[0].UnrelatedRawAcl | Should -Be ObservedUnchanged
        $comparison.Rows[1].DescriptorExactMatch | Should -BeFalse
        $comparison.Rows[1].MetadataUnchanged | Should -BeFalse
        $comparison.Rows[1].Status | Should -Be Failed
    }
    It 'never treats a synthesized abstract intent as an exact expected descriptor' {
        $before=Get-VObserved
        $after=Get-NpCanonicalJson $before | ConvertFrom-NpJson
        $after.Snapshots[0].Descriptor='observed-different'
        $after.Snapshots[0].Aces=@([pscustomobject][ordered]@{
            SID='S-1-5-21-1-2-3-1001';Type='Allow';Mask=1179785L;Inherited=$false
            ContainerInherit=$true;ObjectInherit=$true;InheritOnly=$false;NoPropagate=$false
        })
        Mock Get-NvUnrelatedAcl { 'NotAssessed' }
        $c=Compare-NvCapture $before $after (New-VBinding) Apply
        $c.Status | Should -Be NotAssessed
        $c.ExpectedPostPropagationDescriptor | Should -Be NotAssessed
        $c.EffectiveAccess | Should -Be NotAssessed
        $c.Rows[0].ObservedGrant | Should -Be ObservedAllowCoverageOnly
    }
    It 'does not treat approved grants plus unrelated drift as a successful apply' {
        $before=Get-VObserved
        $after=Get-NpCanonicalJson $before | ConvertFrom-NpJson
        $after.Snapshots[0].Descriptor='grant-plus-unrelated-drift'
        $after.Snapshots[0].Aces=@([pscustomobject][ordered]@{
            SID='S-1-5-21-1-2-3-1001';Type='Allow';Mask=1179785L;Inherited=$false
            ContainerInherit=$true;ObjectInherit=$true;InheritOnly=$false;NoPropagate=$false
        })
        Mock Get-NvUnrelatedAcl { 'Failed' }
        $c=Compare-NvCapture $before $after (New-VBinding) Apply
        $c.Rows[0].ObservedGrant | Should -Be ObservedAllowCoverageOnly
        $c.Status | Should -Be Failed
    }
    It 'does not treat a nonempty delta with an ungranted file as a successful partial apply' {
        $before=Get-VObserved @((New-VSnapshot),(New-VSnapshot '\\server\lab\case\f.txt' File))
        $after=Get-NpCanonicalJson $before | ConvertFrom-NpJson
        $after.Snapshots[0].Descriptor='root-only-grant'
        $after.Snapshots[0].Aces=@([pscustomobject][ordered]@{
            SID='S-1-5-21-1-2-3-1001';Type='Allow';Mask=1179785L;Inherited=$false
            ContainerInherit=$true;ObjectInherit=$true;InheritOnly=$false;NoPropagate=$false
        })
        Mock Get-NvUnrelatedAcl { 'ObservedUnchanged' }
        $c=Compare-NvCapture $before $after (New-VBinding) Apply
        $c.Status | Should -Be Failed
        @($c.Rows | Where-Object Status -ceq Failed).Count | Should -Be 1
    }
    It 'cannot prove physical identity even for delete/recreate with identical observational evidence' {
        $before=Get-VObserved
        $after=Get-NpCanonicalJson $before | ConvertFrom-NpJson
        $c=Compare-NvCapture $before $after (New-VBinding) Revert
        $c.DescriptorResult | Should -Be ExactCapturedDescriptorsObservedOnly
        $c.PhysicalReversionProof | Should -Be NotAssessed
        $c.StableIdentity | Should -Be Unqualified
        $c.SaclEquality | Should -Be NotAssessed
    }
    It 'never equates unknown or uncollected descriptor sections' {
        $before=Get-VObserved
        $after=Get-NpCanonicalJson $before | ConvertFrom-NpJson
        $after.DescriptorSections='Unknown'
        $c=Compare-NvCapture $before $after (New-VBinding) Revert
        $c.Status | Should -Be Incomplete
        $c.DescriptorResult | Should -Be NotAssessed
    }
    It 'detects interval churn but never calls matching observations atomic' {
        $script:reads=0
        Mock Get-NpWindowsInventory {
            $script:reads++
            $s=New-VSnapshot
            if ($script:reads -eq 2) { $s.Descriptor='concurrent-drift' }
            New-VInventory @($s)
        }
        $c=Get-NvCapture (New-VBinding)
        $c.Status | Should -Be Incomplete
        $c.Stability | Should -Be ChurnObserved
        $c.AtomicSnapshot | Should -BeFalse
        $c.Errors -join ';' | Should -BeLike '*Churn observed*'
    }
    It 'distinguishes unreadable objects from removed objects by withholding namespace comparisons' {
        $before=Get-VObserved @((New-VSnapshot),(New-VSnapshot '\\server\lab\case\f.txt' File))
        $after=Get-VObserved @((New-VSnapshot)) @('Access denied reading f.txt')
        $c=Compare-NvCapture $before $after (New-VBinding) Revert
        $c.Status | Should -Be Incomplete
        $c.Namespace | Should -Be NotAssessed
        $c.Missing.Count | Should -Be 0
    }
}

Describe 'Windows descriptor section fidelity (read-only, no target calls)' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    It 'preserves ordered DACL SID masks flags and protection while excluding SACL equality' {
        $s=New-VSnapshot
        $s.Group='S-1-5-18'
        $s.Descriptor='O:SYG:SYD:PAI(D;;FW;;;BU)(A;OICI;FR;;;WD)(A;OICI;FA;;;BA)S:(AU;SA;FR;;;WD)'
        $result=ConvertTo-NvCapturedSnapshot $s
        $result.Descriptor | Should -Not -Match 'S:'
        $a=[Security.AccessControl.RawSecurityDescriptor]::new($s.Descriptor)
        $b=[Security.AccessControl.RawSecurityDescriptor]::new($result.Descriptor)
        $b.Owner.Value | Should -Be $a.Owner.Value
        $b.Group.Value | Should -Be $a.Group.Value
        $b.DiscretionaryAcl.Count | Should -Be $a.DiscretionaryAcl.Count
        for ($i=0; $i -lt $a.DiscretionaryAcl.Count; $i++) {
            $x=New-Object byte[] $a.DiscretionaryAcl[$i].BinaryLength
            $y=New-Object byte[] $b.DiscretionaryAcl[$i].BinaryLength
            $a.DiscretionaryAcl[$i].GetBinaryForm($x,0)
            $b.DiscretionaryAcl[$i].GetBinaryForm($y,0)
            [Convert]::ToBase64String($x) | Should -Be ([Convert]::ToBase64String($y))
        }
    }
    It 'proves unchanged unrelated raw ACEs only when their ordered bytes match' {
        $a=New-VSnapshot; $b=New-VSnapshot
        $a.Descriptor='O:SYG:SYD:(A;OICI;FA;;;BA)'
        $b.Descriptor='O:SYG:SYD:(A;OICI;FA;;;BA)(A;OICI;FR;;;S-1-5-21-1-2-3-1001)'
        $grants=(New-VBinding).Grants
        Get-NvUnrelatedAcl $a $b $grants | Should -Be ObservedUnchanged
        $b.Descriptor='O:SYG:SYD:(A;OICI;FR;;;BA)(A;OICI;FR;;;S-1-5-21-1-2-3-1001)'
        Get-NvUnrelatedAcl $a $b $grants | Should -Be Failed
    }
}

Describe 'Public read-only Windows gate and CLI contract' {
    It 'preserves result objects and only suggests a safe report command after complete observations' {
        Mock Assert-NvWindows {}
        Mock Invoke-NvStage {
            param($CasePath,$Stage)
            $observedStatus=Split-Path $CasePath -Leaf
            [pscustomobject]@{
                CasePath=$CasePath;Stage=$Stage;Status=$observedStatus
                CommitSHA256=('a'*64);TargetWrites=0;WriterQualification='NotQualified'
                NextStep=$(if($observedStatus -eq 'Observed'){'Review observations, then generate the report.'}else{'Stop external actions and preserve incomplete or failed evidence.'})
                Diagnostics=@{
                    MissingEvidence=$(if($observedStatus -eq 'Observed'){0}else{2})
                    Warnings=0
                    Reasons=@(if($observedStatus -ne 'Observed'){[pscustomobject]@{Count=2;Reason='Synthetic missing evidence.'}})
                }
            }
        }
        foreach($status in @('Observed','Incomplete','Failed','NotAssessed')){
            $casePath=Join-Path $script:work $status
            $result=& (Join-Path $PSScriptRoot '../Invoke-NtfsPermissionValidation.ps1') -Stage CaptureAfterRevert -CasePath $casePath -ManualActionAcknowledgement -NonInteractive -InformationVariable completionMessages
            $result.Status | Should -Be $status
            $result.TargetWrites | Should -Be 0
            $result.WriterQualification | Should -Be NotQualified
            $console=$completionMessages.MessageData -join "`n"
            $console | Should -Match ([regex]::Escape("Output: $($casePath)"))
            $console | Should -Match 'Archive commit SHA256'
            if($status -eq 'Observed'){
                $console | Should -Not -Match 'Resolve/review:'
                $console | Should -Match "-Stage 'Report'"
                $console | Should -Match ([regex]::Escape("-CasePath '$($casePath.Replace("'","''"))'"))
            }else{
                $console | Should -Match 'Stop external actions'
                $console | Should -Match 'Resolve 2 missing evidence records'
                $console | Should -Not -Match '\b0 validation warnings\b'
                $console | Should -Match '- \(2 records\): Synthetic missing evidence'
                $console | Should -Not -Match "-Stage 'Report'"
            }
        }
        foreach($checkpoint in @(
            @{Stage='CaptureBefore';Next='CaptureAfterApply'},
            @{Stage='CaptureAfterApply';Next='CaptureAfterRevert'}
        )){
            $arguments=@{Stage=$checkpoint.Stage;CasePath=(Join-Path $script:work 'Observed');NonInteractive=$true}
            if($checkpoint.Stage -eq 'CaptureAfterApply'){$arguments.ManualActionAcknowledgement=$true}
            $null=& (Join-Path $PSScriptRoot '../Invoke-NtfsPermissionValidation.ps1') @arguments -InformationVariable checkpointMessages
            $command=@($checkpointMessages.MessageData|Where-Object{$_ -like "  & '*'"})[-1]
            $command | Should -Match ([regex]::Escape("-Stage '$($checkpoint.Next)'"))
            $command | Should -Not -Match 'ManualActionAcknowledgement|NonInteractive'
        }
    }
    It 'preserves validation errors and warns against retrying or deleting locks' {
        Mock Assert-NvWindows {}
        Mock Invoke-NvStage { throw 'Synthetic immutable-stage failure.' }
        { & (Join-Path $PSScriptRoot '../Invoke-NtfsPermissionValidation.ps1') -Stage CaptureBefore -CasePath $script:work -InformationVariable script:failureMessages } | Should -Throw '*Synthetic immutable-stage failure*'
        ($script:failureMessages.MessageData -join "`n") | Should -Match 'Permission validation: Failed\.'
        (($script:failureMessages.MessageData -join "`n") -replace '\s+',' ') | Should -Match 'do not delete locks or automatically retry'
    }
    It 'rejects real non-Windows execution before creating evidence' -Skip:([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        { & (Join-Path $PSScriptRoot '../Invoke-NtfsPermissionValidation.ps1') -Stage Initialize -NonInteractive } | Should -Throw '*Windows read-only*'
    }
    It 'has no public injectable adapter or writer qualification bypass' {
        $command=Get-Command (Join-Path $PSScriptRoot '../Invoke-NtfsPermissionValidation.ps1')
        foreach ($name in @('Adapter','Writer','Force','AllowMutation','SetAcl')) {
            $command.Parameters.ContainsKey($name) | Should -BeFalse
        }
    }
}
