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
Read-only evidence-based best-practices evaluation and reporting helpers.
.NOTES
Version 1.0.0. Script versions are independent of policy and manifest schema versions.
#>
Set-StrictMode -Version Latest
$script:NtfsBestPracticesVersion = '1.0.0'

$script:NtfsBpCheckDefinitions = @{
    SMB1Enabled = @{ Reference='https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'; Recommendation='Review whether SMB1 is required; disable it only through the server change process.'; Severity='High' }
    SMBRequireSecuritySignature = @{ Reference='https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing'; Recommendation='Review the captured inbound server setting against the organization''s threat model. Do not infer settings from OS defaults.'; Severity='Medium' }
    ShareEncryptionEnabled = @{ Reference='https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security'; Recommendation='Review whether encryption is required for this share and client population.'; Severity='Medium' }
    ShareABEEnabled = @{ Reference='https://learn.microsoft.com/en-us/windows-server/storage/dfs-namespaces/enable-access-based-enumeration-on-a-namespace'; Recommendation='Consider access-based enumeration when hiding names from users without access is appropriate; it does not authorize access.'; Severity='Informational' }
    ShareAclEvidence = @{ Reference='https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control'; Recommendation='Review share-level ACL evidence together with NTFS permissions and source completeness; this report does not calculate effective access.'; Severity='Informational' }
    AuditFileShareSuccess = @{ Reference='https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-share'; Recommendation='Review success auditing scope and volume; File Share policy can generate high event volume.'; Severity='Informational' }
    AuditFileSystemSuccess = @{ Reference='https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system'; Recommendation='Review success auditing together with matching filesystem SACLs; policy alone does not audit files.'; Severity='Informational' }
    DirectUserAllow = @{ Reference='https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control'; Recommendation='Review confirmed direct user grants; groups can improve administration, but exceptions may be intentional.'; Severity='Medium' }
    BroadPrincipalWrite = @{ Reference='https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control'; Recommendation='Review broad-principal allow entries with write-capable rights in context; do not infer effective access.'; Severity='High' }
    InheritanceProtected = @{ Reference='https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control'; Recommendation='Review protected inheritance as informational context. Do not enable inheritance blindly; protected ACLs can be intentional.'; Severity='Informational' }
    NullDacl = @{ Reference='https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control'; Recommendation='Urgently validate the null DACL and intended access; a null DACL grants unrestricted access. Do not change it automatically.'; Severity='Critical' }
    UnresolvedPrincipal = @{ Reference='https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control'; Recommendation='Review whether the SID still represents an intended principal; name lookup failure alone does not establish a stale account.'; Severity='Low' }
    RootSaclPresent = @{ Reference='https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system'; Recommendation='Review the root SACL with applicable audit policy; this sample does not establish SACL coverage below the share root.'; Severity='Informational' }
}
$script:NtfsBpWriteBits = @(2,4,16,64,256,65536,262144,524288,33554432,268435456,1073741824)

function Read-NtfsBestPracticesPolicy([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    try { $document = ConvertFrom-Json -InputObject $raw -ErrorAction Stop }
    catch { throw "Invalid best-practices policy JSON: $($_.Exception.Message)" }
    $top = @($document.PSObject.Properties.Name | Sort-Object)
    if ((ConvertTo-NtfsCsvRecord $top) -cne (ConvertTo-NtfsCsvRecord @('rules','schemaVersion'))) {
        throw 'Policy must contain exactly schemaVersion and rules.'
    }
    if (($document.schemaVersion -isnot [int] -and $document.schemaVersion -isnot [long]) -or $document.schemaVersion -ne 1) {
        throw 'Policy schemaVersion must be integer 1.'
    }
    if ($document.rules -isnot [array]) { throw 'Policy rules must be a JSON array.' }
    $rules = @{}
    foreach ($rule in $document.rules) {
        if ($null -eq $rule -or $rule -is [array] -or $rule -is [string]) { throw 'Each policy rule must be an object.' }
        $names = @($rule.PSObject.Properties.Name | Sort-Object)
        if ((ConvertTo-NtfsCsvRecord $names) -cne (ConvertTo-NtfsCsvRecord @('checkId','expectedValue'))) {
            throw 'Each policy rule must contain exactly checkId and expectedValue.'
        }
        $id = [string]$rule.checkId
        if (-not $script:NtfsBpCheckDefinitions.ContainsKey($id)) { throw "Unknown policy checkId: $id" }
        if ($rules.ContainsKey($id)) { throw "Duplicate policy checkId: $id" }
        if ($rule.expectedValue -isnot [bool]) { throw "Policy expectedValue for $id must be a JSON boolean." }
        if ($id -notin @('SMB1Enabled','SMBRequireSecuritySignature','ShareEncryptionEnabled','ShareABEEnabled','AuditFileShareSuccess','AuditFileSystemSuccess','DirectUserAllow','BroadPrincipalWrite')) {
            throw "Check $id does not support a configured policy value."
        }
        $rules[$id] = [bool]$rule.expectedValue
    }
    return [pscustomobject]@{ SchemaVersion=1; Rules=$rules; Raw=$raw; Path=$Path; SHA256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function Get-NtfsBpObservedBoolean($Value) {
    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ([string]$Value -match '^(?i:true|1|yes|enabled|accessbased|success|success and failure)$') { return $true }
    if ([string]$Value -match '^(?i:false|0|no|disabled|unrestricted|no auditing)$') { return $false }
    return $null
}

function Get-NtfsBpProperty($Object,[string]$Name,$Default=$null) {
    if($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name){return $Object.$Name}
    return $Default
}

function Set-NtfsBpEvidenceContext([string]$SourceDataset,[string]$SourceRowKey,$ShareRow,[string]$Vserver='') {
    $script:NtfsBpContext=[ordered]@{
        RunId=$(if($null -ne $ShareRow -and $ShareRow.PSObject.Properties.Name -contains 'RunId'){$ShareRow.RunId}else{''})
        CollectorHost=$(if($null -ne $ShareRow -and $ShareRow.PSObject.Properties.Name -contains 'CollectorHost'){$ShareRow.CollectorHost}else{''})
        CollectionMode=$(if($null -ne $ShareRow -and $ShareRow.PSObject.Properties.Name -contains 'CollectionMode'){$ShareRow.CollectionMode}else{''})
        Vserver=$Vserver;EvidenceSource=$SourceDataset;EvidenceSourceKey=$SourceRowKey
        AssessmentCompletedUtc=$script:NtfsBpAssessmentCompletedUtc;ReportGeneratedUtc=$script:NtfsBpReportGeneratedUtc
    }
}

function Write-NtfsBestPracticesCheck($Writer,[hashtable]$Counts,[string]$Server,[string]$Share,[string]$Path,[string]$CheckId,[string]$Status,[string]$Observed,[string]$Evidence,[string]$Limitations,[string]$PolicyExpected='') {
    $definition = $script:NtfsBpCheckDefinitions[$CheckId]
    $row = @(
        $script:NtfsBpContext.RunId,$script:NtfsBpContext.CollectorHost,$script:NtfsBpContext.CollectionMode,
        $Server,$script:NtfsBpContext.Vserver,$Share,$Path,$script:NtfsBpContext.EvidenceSource,
        $script:NtfsBpContext.EvidenceSourceKey,$script:NtfsBpContext.AssessmentCompletedUtc,$script:NtfsBpContext.ReportGeneratedUtc,
        $CheckId,$Status,$definition.Severity,$Observed,$PolicyExpected,$script:NtfsBpPolicySource,$Evidence,
        $definition.Recommendation,$definition.Reference,'2026-10-30',$Limitations
    )
    $Writer.WriteLine((ConvertTo-NtfsCsvRecord $row))
    if (-not $Counts.ContainsKey($Status)) { $Counts[$Status]=0 }
    $Counts[$Status]++
    if (-not $Counts.ContainsKey("Severity:$($definition.Severity)")) { $Counts["Severity:$($definition.Severity)"]=0 }
    $Counts["Severity:$($definition.Severity)"]++
}

function Get-NtfsBpStatus([string]$CheckId,$Observed,$Applicable,$Policy,[string]$NoEvidenceReason='Evidence was unavailable or ambiguous.') {
    if ($Applicable -eq $false) { return 'NotApplicable' }
    $value = Get-NtfsBpObservedBoolean $Observed
    if ($null -eq $value) { return 'NotAssessed' }
    if ($null -ne $Policy -and $Policy.Rules.ContainsKey($CheckId)) {
        if ($value -eq [bool]$Policy.Rules[$CheckId]) { return 'MeetsConfiguredPolicy' }
        return 'DoesNotMeetConfiguredPolicy'
    }
    return 'Review'
}

function Get-NtfsBpAuditPolicyEvidence([string]$Setting) {
    if ([string]::IsNullOrWhiteSpace($Setting)) { return $null }
    switch -Regex ($Setting.Trim()) {
        '^(?i:success|success and failure)$' { return $true }
        '^(?i:no auditing)$' { return $false }
        default { return $null }
    }
}

function Get-NtfsBpAuditPolicyLocal {
    $result = @{ FileShareSuccess=$null; FileSystemSuccess=$null; Status='NotAssessed'; Detail='auditpol evidence not collected.' }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $result.Detail='auditpol is supported only on Windows.'; return $result }
    try {
        foreach ($guid in @('{0CCE9225-69AE-11D9-BED3-505054503030}','{0CCE921D-69AE-11D9-BED3-505054503030}')) {
            $output = @(& auditpol.exe /get "/subcategory:$guid" /r 2>&1)
            if ($LASTEXITCODE -ne 0) { throw "auditpol failed for ${guid}: $($output -join ' ')" }
            $text = $output -join "`n"
            $parsed = @($text | ConvertFrom-Csv -ErrorAction Stop)
            $match = @($parsed | Where-Object { ([string]$_.'Subcategory GUID').Trim('{}') -ieq $guid.Trim('{}') })
            if ($match.Count -ne 1) { throw "Could not uniquely parse auditpol subcategory $guid." }
            $setting = [string]$match[0].'Inclusion Setting'
            if ($guid -like '*9225*') { $result.FileShareSuccess=Get-NtfsBpAuditPolicyEvidence $setting }
            else { $result.FileSystemSuccess=Get-NtfsBpAuditPolicyEvidence $setting }
            if ($null -eq $(if ($guid -like '*9225*') {$result.FileShareSuccess}else{$result.FileSystemSuccess})) {
                throw "Unrecognized localized auditpol setting for $guid."
            }
        }
        $result.Status='Collected';$result.Detail='Parsed auditpol output by subcategory GUID; success policy only.'
    } catch { $result.Status='NotAssessed';$result.Detail=$_.Exception.Message }
    return $result
}

function Write-NtfsBestPracticesReport([string]$RunFolder,[string]$OutputFolder,$PolicyPath,[switch]$PolicyAlreadyParsed) {
    $policy = if ($PolicyAlreadyParsed) {$PolicyPath} elseif ($PolicyPath) {Read-NtfsBestPracticesPolicy ([string]$PolicyPath)} else {$null}
    $policyFilePath = if ($null -ne $policy -and $policy -isnot [string]) {[string]$policy.Path} else {''}
    if ($policy -is [string]) { throw 'Internal policy argument must be a parsed policy object.' }
    $shares = @(Get-NtfsCsvFiles $RunFolder 'Shares.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName })
    $identities = @(Get-NtfsCsvFiles $RunFolder 'Identities.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName })
    $auditRows = @(Get-NtfsCsvFiles $RunFolder 'AuditEvidence.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName })
    $identityClasses = @{}
    $identityByName = @{}
    foreach ($identity in $identities) {
        $identityByName[[string]$identity.Identity]=$identity
        if ($identity.ObjectClass -eq 'user') { $identityClasses[[string]$identity.Identity]= $true }
    }
    $auditByShare = @{}
    foreach ($row in $auditRows) { $auditByShare[("{0}|{1}" -f $row.Server,$row.Share).ToLowerInvariant()]=$row }
    $shareByKey = @{}
    foreach($share in $shares){$shareByKey[("{0}|{1}" -f $share.Server,$share.Share).ToLowerInvariant()]=$share}
    $script:NtfsBpAssessmentCompletedUtc=''
    $sourceManifest=Join-Path $RunFolder 'manifest.json'
    if(Test-Path -LiteralPath $sourceManifest){
        try{$sourceMeta=Get-Content -LiteralPath $sourceManifest -Raw|ConvertFrom-Json;$script:NtfsBpAssessmentCompletedUtc=[string]$sourceMeta.CompletedUtc}catch{$script:NtfsBpAssessmentCompletedUtc='NotAvailable'}
    }
    $script:NtfsBpReportGeneratedUtc=[datetime]::UtcNow.ToString('o')
    $script:NtfsBpPolicySource=if($null -ne $policy){"BestPracticesPolicy.json (SHA256 $($policy.SHA256))"}else{'No policy supplied'}
    Set-NtfsBpEvidenceContext '' '' $null
    $maxBytes = 100000000
    $writer = New-NtfsCsvWriter (Join-Path $OutputFolder 'BestPracticeChecks.csv') $maxBytes
    $counts = @{}
    $columns = @('RunId','CollectorHost','CollectionMode','Server','Vserver','Share','Path','EvidenceSource','EvidenceSourceKey','AssessmentCompletedUtc','ReportGeneratedUtc','CheckId','Status','Severity','ObservedValue','PolicyExpectedValue','PolicySource','Evidence','Recommendation','Reference','ReferenceRetrievedUtc','CollectionLimitations')
    $writer.WriteLine((ConvertTo-NtfsCsvRecord $columns))
    try {
        foreach ($share in $shares) {
            $server=[string]$share.Server;$name=[string]$share.Share;$key=("{0}|{1}" -f $server,$name).ToLowerInvariant()
            $targetIsWindows=$share.CollectionMode -in @('LocalWindows','RemoteWindowsCIM')
            Set-NtfsBpEvidenceContext 'Shares.csv' "$server|$name|ShareMetadataStatus" $share
            $shareMetadataStatus=[string](Get-NtfsBpProperty $share 'ShareMetadataStatus' 'NotCollected')
            $shareAclStatus=if($shareMetadataStatus -eq 'Collected'){'Review'}else{'NotAssessed'}
            $shareAclEvidence=if($shareMetadataStatus -eq 'Collected'){'Windows share permissions were collected; this is not a completeness or effective-access determination.'}else{"Share permission evidence unavailable or unsupported (ShareMetadataStatus=$shareMetadataStatus); no permissions were inferred."}
            Write-NtfsBestPracticesCheck $writer $counts $server $name '' 'ShareAclEvidence' $shareAclStatus $shareMetadataStatus $shareAclEvidence 'Share-level permissions are separate from NTFS ACLs; imported NAS ACLs do not establish completeness.'
            foreach ($check in @(
                @{Id='SMB1Enabled';Column='SMB1Enabled';Applicable=$(if($targetIsWindows){$true}else{$null})},
                @{Id='SMBRequireSecuritySignature';Column='RequireSecuritySignature';Applicable=$(if($targetIsWindows){$true}else{$null})},
                @{Id='ShareEncryptionEnabled';Column='EncryptData';Applicable=$true},
                @{Id='ShareABEEnabled';Column='FolderEnumerationMode';Applicable=$(if($targetIsWindows){$true}else{$null})}
            )) {
                Set-NtfsBpEvidenceContext 'Shares.csv' ("$server|$name|$($check.Column)") $share
                $observed=$null
                if ($share.PSObject.Properties.Name -contains $check.Column) { $observed=$share.($check.Column) }
                if ($check.Id -eq 'ShareABEEnabled' -and [string]$observed -ieq 'AccessBased') {$observed=$true}
                if ($check.Id -eq 'ShareABEEnabled' -and [string]$observed -ieq 'Unrestricted') {$observed=$false}
                if ($check.Id -eq 'ShareEncryptionEnabled') {
                    if ([string]$observed -in @('True','False')) {$observed=([string]$observed -eq 'True')}
                    elseif ([string]$observed -eq 'NotCollected') {$observed=$null}
                }
                $status=Get-NtfsBpStatus $check.Id $observed $check.Applicable $policy
                $knownValue=Get-NtfsBpObservedBoolean $observed
                $observedText=if($null -eq $knownValue){''}else{[string]$knownValue}
                $expect=''
                if ($null -ne $policy -and $policy.Rules.ContainsKey($check.Id)) {$expect=[string]$policy.Rules[$check.Id]}
                if ($null -eq $knownValue) {
                    if ($check.Id -in @('SMB1Enabled','SMBRequireSecuritySignature') -and $share.PSObject.Properties.Name -contains 'SMBServerConfigurationDetail') {
                        $statusColumn=if($check.Id -eq 'SMB1Enabled'){'SMB1ConfigurationStatus'}else{'SMBSigningConfigurationStatus'}
                        $settingStatus=if($share.PSObject.Properties.Name -contains $statusColumn){[string]$share.($statusColumn)}else{'NotAssessed'}
                        $evidence="Configuration unavailable (status=$settingStatus): $($share.SMBServerConfigurationDetail)"
                    } elseif($check.Id -eq 'ShareABEEnabled' -and [string]$share.CollectionMode -notin @('LocalWindows','RemoteWindowsCIM')) {
                        $evidence='Server type is NAS/unknown; share enumeration mode was not exposed and was not inferred.'
                    } elseif($check.Id -in @('ShareABEEnabled','ShareEncryptionEnabled')) {
                        $evidence="Share metadata setting was not exposed (ShareMetadataStatus=$shareMetadataStatus); no setting was inferred."
                    } else { $evidence="Configuration $($check.Column) was not collected, unavailable, or could not be parsed; no value was inferred." }
                } else {$evidence="Captured $($check.Column)=$knownValue; no client negotiation or protocol proof."}
                $limit=if ($check.Id -eq 'SMBRequireSecuritySignature') {'Captured server configuration only; not a client negotiation or proof of effective connection signing.'} elseif($check.Id -eq 'ShareABEEnabled') {'Captured share enumeration mode only; visibility filtering is not authorization.'} else {'Observed configuration only; no compliance or effective-access determination.'}
                Write-NtfsBestPracticesCheck $writer $counts $server $name '' $check.Id $status $observedText $evidence $limit $expect
            }
            $audit=$auditByShare[$key]
            Set-NtfsBpEvidenceContext 'AuditEvidence.csv' "$server|$name|AuditPolicy" $share
            foreach($check in @(
                @{Id='AuditFileShareSuccess';Column='FileShareSuccessPolicy'},
                @{Id='AuditFileSystemSuccess';Column='FileSystemSuccessPolicy'}
            )){
                $observed=$null
                if ($targetIsWindows -and $share.CollectionMode -eq 'LocalWindows' -and $null -ne $audit) {
                    $observed=Get-NtfsObservedBoolean $audit.($check.Column)
                }
                $auditApplicable=if($share.CollectionMode -eq 'LocalWindows'){$true}elseif($share.CollectionMode -eq 'RemoteWindowsCIM'){$true}else{$null}
                $status=Get-NtfsBpStatus $check.Id $observed $auditApplicable $policy
                $expect='';if($null -ne $policy -and $policy.Rules.ContainsKey($check.Id)){$expect=[string]$policy.Rules[$check.Id]}
                $evidence=if($null -eq $observed){
                    if($share.CollectionMode -eq 'RemoteWindowsCIM'){'Remote audit policy was not queried; local auditpol does not apply.'}
                    elseif($null -ne (Get-NtfsBpProperty $audit 'AuditPolicyDetail')){"Audit policy unavailable: $(Get-NtfsBpProperty $audit 'AuditPolicyDetail')"}
                    else{'Audit policy evidence was absent, ambiguous, or not collected.'}
                }else{"Local audit policy success setting=$observed."}
                Write-NtfsBestPracticesCheck $writer $counts $server $name '' $check.Id $status ([string]$observed) $evidence 'Audit policy alone does not establish matching SACLs, event collection, retention, or audited object coverage.' $expect
            }
            $saclObserved=$null
            Set-NtfsBpEvidenceContext 'AuditEvidence.csv' "$server|$name|RootSACL" $share
            $auditCount=Get-NtfsBpProperty $audit 'RootSaclAuditRuleCount'
            if ($null -ne $audit -and [string](Get-NtfsBpProperty $audit 'RootSaclStatus') -eq 'Collected' -and $null -ne $auditCount -and [string]$auditCount -match '^\d+$') { $saclObserved=([int]$auditCount -gt 0) }
            $saclApplicable=if($share.CollectionMode -eq 'LocalWindows'){$true}elseif($share.CollectionMode -eq 'RemoteWindowsCIM'){$true}else{$null}
            $saclStatus=Get-NtfsBpStatus 'RootSaclPresent' $saclObserved $saclApplicable $policy
            $saclEvidence=if($null -eq $saclObserved){
                if($null -ne (Get-NtfsBpProperty $audit 'RootSaclDetail')){"Root SACL unavailable: $(Get-NtfsBpProperty $audit 'RootSaclDetail')"}else{'Root SACL was not collected or read.'}
            }else{"Share-root SACL rule count=$auditCount; this is not descendant coverage and does not exclude global/backend audit controls."}
            Write-NtfsBestPracticesCheck $writer $counts $server $name ([string]$share.ScanRoot) 'RootSaclPresent' $saclStatus ([string]$saclObserved) $saclEvidence 'Filesystem audit policy and matching SACLs are both required; an empty share-root SACL does not exclude global/backend audit controls, and descendant SACLs were not assessed.' ''
        }
        foreach ($ace in (Get-NtfsCsvFiles $RunFolder 'NtfsAcls.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName })) {
            $server=[string]$ace.Server;$name=[string]$ace.Share;$key=("$server|$name").ToLowerInvariant()
            $shareMeta=$shareByKey[$key]
            $aceKey=if($ace.PSObject.Properties.Name -contains 'AceHash' -and $ace.AceHash) {[string]$ace.AceHash}else{"$($ace.Path)|$($ace.Identity)|$($ace.Rights)|$($ace.AccessControlType)"}
            $identity=[string]$ace.Identity
            if ([string]$ace.Resolved -eq 'False' -or [string]$ace.Resolved -eq 'NotCollected') {
                Set-NtfsBpEvidenceContext 'NtfsAcls.csv' $aceKey $shareMeta
                $status=if([string]$ace.Resolved -eq 'False'){'Review'}else{'NotAssessed'}
                $identityEvidence=$identityByName[$identity]
                $resolutionDetail=if($null -ne $identityEvidence){"LookupStatus=$(Get-NtfsBpProperty $identityEvidence 'LookupStatus' 'NotRecorded'); ResolvedBy=$(Get-NtfsBpProperty $identityEvidence 'ResolvedBy' 'NotRecorded'); DirectoryServer=$(Get-NtfsBpProperty $identityEvidence 'DirectoryServer' 'NotRecorded')."}else{'No matching identity-resolution row was collected.'}
                Write-NtfsBestPracticesCheck $writer $counts $server $name ([string]$ace.Path) 'UnresolvedPrincipal' $status '' "Collected identity $identity could not be resolved. $resolutionDetail" 'Resolution failure does not establish a stale or invalid account.'
            }
            if ([string]$ace.AccessControlType -ne 'Allow') { continue }
            $rights=[string]$ace.Rights
            [long]$mask=0
            $hasMask=[long]::TryParse([string]$ace.RightsValue,[ref]$mask)
            $write= $rights -match '(?i)FullControl|GenericAll|GenericWrite|Modify|Write|Append|Delete|ChangePermissions|TakeOwnership|MaximumAllowed' -or
                ($hasMask -and @($script:NtfsBpWriteBits|Where-Object{($mask -band [long]$_) -ne 0}).Count -gt 0)
            $sid=[string]$ace.SID
            $broad=$sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546') -or
                $identity -match '(?i)(^|\\)(everyone|authenticated users|domain users|domain guests|users|guests)$'
            if ($broad -and $write) {
                Set-NtfsBpEvidenceContext 'NtfsAcls.csv' $aceKey $shareMeta
                $expect='';if($null -ne $policy -and $policy.Rules.ContainsKey('BroadPrincipalWrite')){$expect=[string]$policy.Rules['BroadPrincipalWrite']}
                $observed=$true;$status=Get-NtfsBpStatus 'BroadPrincipalWrite' $observed $true $policy
                Write-NtfsBestPracticesCheck $writer $counts $server $name ([string]$ace.Path) 'BroadPrincipalWrite' $status 'True' "Allow ACE for broad principal $identity ($sid), rights=$rights." 'Directory-only ACL inventory; no effective-access calculation, deny evaluation, group expansion, or file ACL coverage.' $expect
            }
            if ($identityClasses.ContainsKey($identity)) {
                Set-NtfsBpEvidenceContext 'NtfsAcls.csv' $aceKey $shareMeta
                $expect='';if($null -ne $policy -and $policy.Rules.ContainsKey('DirectUserAllow')){$expect=[string]$policy.Rules['DirectUserAllow']}
                $status=Get-NtfsBpStatus 'DirectUserAllow' $true $true $policy
                Write-NtfsBestPracticesCheck $writer $counts $server $name ([string]$ace.Path) 'DirectUserAllow' $status 'True' "Confirmed user identity $identity has an Allow ACE; rights=$rights." 'Identity classification reflects collected lookup evidence only; not effective access or proof that a direct grant is inappropriate.' $expect
            }
        }
        foreach ($ace in (Get-NtfsCsvFiles $RunFolder 'SharePermissions.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName })) {
            if ([string]$ace.AccessControlType -ne 'Allow') { continue }
            $server=[string]$ace.Server;$name=[string]$ace.Share;$identity=[string]$ace.AccountName
            $shareMeta=$shareByKey[("$server|$name").ToLowerInvariant()]
            $shareAceKey=("$($ace.AccountName)|$($ace.SID)|$($ace.AccessControlType)|$($ace.AccessRight)|$($ace.Source)|$($ace.Vserver)")
            $rights=[string]$ace.AccessRight
            $write=$rights -match '(?i)Full|Change|Write'
            $sid=[string]$ace.SID
            $broad=$sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546') -or
                $identity -match '(?i)(^|\\)(everyone|authenticated users|domain users|domain guests|users|guests)$'
            if($broad -and $write){
                Set-NtfsBpEvidenceContext 'SharePermissions.csv' $shareAceKey $shareMeta ([string]$ace.Vserver)
                $expect='';if($null -ne $policy -and $policy.Rules.ContainsKey('BroadPrincipalWrite')){$expect=[string]$policy.Rules['BroadPrincipalWrite']}
                $status=Get-NtfsBpStatus 'BroadPrincipalWrite' $true $true $policy
                Write-NtfsBestPracticesCheck $writer $counts $server $name '' 'BroadPrincipalWrite' $status 'True' "Share Allow for broad principal $identity ($sid), rights=$rights." 'Share ACL evidence only; no effective-access calculation, deny evaluation, group expansion, or NTFS ACL evaluation.' $expect
            }
            if($identityClasses.ContainsKey($identity)){
                Set-NtfsBpEvidenceContext 'SharePermissions.csv' $shareAceKey $shareMeta ([string]$ace.Vserver)
                $expect='';if($null -ne $policy -and $policy.Rules.ContainsKey('DirectUserAllow')){$expect=[string]$policy.Rules['DirectUserAllow']}
                $status=Get-NtfsBpStatus 'DirectUserAllow' $true $true $policy
                Write-NtfsBestPracticesCheck $writer $counts $server $name '' 'DirectUserAllow' $status 'True' "Confirmed user $identity has a share Allow entry; rights=$rights." 'Identity classification reflects collected lookup evidence only; not effective access or proof that a direct grant is inappropriate.' $expect
            }
        }
        foreach ($folder in (Get-NtfsCsvFiles $RunFolder 'Folders.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName })) {
            if ([string]$folder.CollectionStatus -ne 'Read') { continue }
            $server=[string]$folder.Server;$name=[string]$folder.Share
            $shareMeta=$shareByKey[("$server|$name").ToLowerInvariant()]
            $folderKey=if($folder.PSObject.Properties.Name -contains 'DescriptorHash'){"$($folder.DescriptorHash)|$($folder.Path)"}else{[string]$folder.Path}
            if ([string]$folder.DaclState -eq 'NullDacl') {
                Set-NtfsBpEvidenceContext 'Folders.csv' $folderKey $shareMeta
                Write-NtfsBestPracticesCheck $writer $counts $server $name ([string]$folder.Path) 'NullDacl' 'Review' 'True' 'Collected directory descriptor reports a null DACL.' 'Directory-only inventory; no access test or automatic remediation.'
            }
            if ([string]$folder.InheritanceProtected -eq 'True') {
                Set-NtfsBpEvidenceContext 'Folders.csv' $folderKey $shareMeta
                Write-NtfsBestPracticesCheck $writer $counts $server $name ([string]$folder.Path) 'InheritanceProtected' 'Review' 'True' 'Collected directory descriptor has inheritance protected.' 'Inheritance protection may be intentional; do not enable inheritance as a blanket recommendation.'
            }
        }
    } finally { $writer.Dispose() }
    if ($policyFilePath -and [IO.Path]::GetFullPath($policyFilePath) -ne [IO.Path]::GetFullPath((Join-Path $OutputFolder 'BestPracticesPolicy.json'))) {
        Copy-Item -LiteralPath $policyFilePath -Destination (Join-Path $OutputFolder 'BestPracticesPolicy.json') -Force
    }
    $checkCount=0
    foreach($statusName in @('Review','MeetsConfiguredPolicy','DoesNotMeetConfiguredPolicy','NotAssessed','NotApplicable')){if($counts.ContainsKey($statusName)){$checkCount+=[int]$counts[$statusName]}}
    $summary=[ordered]@{
        Version=$script:NtfsBestPracticesVersion
        SchemaVersion=1;GeneratedUtc=[datetime]::UtcNow.ToString('o');ReadOnly=$true
        RunFolder=(Split-Path -Leaf $RunFolder);CheckCount=$checkCount
        StatusInterpretation='MeetsConfiguredPolicy means only that the directly observed value matched that individual JSON rule. It is not system or share compliance; zero findings do not establish compliance.'
        StatusCounts=@{Review=$(if($counts.ContainsKey('Review')){$counts.Review}else{0});MeetsConfiguredPolicy=$(if($counts.ContainsKey('MeetsConfiguredPolicy')){$counts.MeetsConfiguredPolicy}else{0});DoesNotMeetConfiguredPolicy=$(if($counts.ContainsKey('DoesNotMeetConfiguredPolicy')){$counts.DoesNotMeetConfiguredPolicy}else{0});NotAssessed=$(if($counts.ContainsKey('NotAssessed')){$counts.NotAssessed}else{0});NotApplicable=$(if($counts.ContainsKey('NotApplicable')){$counts.NotApplicable}else{0})}
        Policy=$(if($null -ne $policy){[ordered]@{SchemaVersion=$policy.SchemaVersion;SHA256=$policy.SHA256;FileName='BestPracticesPolicy.json';SourceFileName=[IO.Path]::GetFileName($policy.Path);SourceLastWriteTimeUtc=(Get-Item -LiteralPath $policy.Path).LastWriteTimeUtc.ToString('o')} }else{$null})
        SourceCoverage=$(if (@(Get-NtfsCsvFiles $RunFolder 'ShareCoverage.csv').Count -gt 0) {
            $coverage=@(Get-NtfsCsvFiles $RunFolder 'ShareCoverage.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName })
            $scanErrors=@(Get-NtfsCsvFiles $RunFolder 'ScanErrors.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName }).Count
            $skippedPaths=@(Get-NtfsCsvFiles $RunFolder 'SkippedPaths.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName }).Count
            $bpErrors=@(Get-NtfsCsvFiles $RunFolder 'BestPracticesErrors.csv' | ForEach-Object { Read-NtfsCsvFile $_.FullName }).Count
            [ordered]@{CoverageRows=$coverage.Count;PartialRows=@($coverage|Where-Object Status -match 'Partial|Skipped').Count;Errors=(($coverage|Measure-Object -Property Errors -Sum).Sum);SkippedPaths=(($coverage|Measure-Object -Property SkippedPaths -Sum).Sum);ScanErrors=$scanErrors;SkippedPathRows=$skippedPaths;BestPracticesEvidenceErrors=$bpErrors;Dataset='ShareCoverage.csv'}
        }else{[ordered]@{CoverageRows=0;PartialRows=0;Errors=0;SkippedPaths=0;ScanErrors=0;SkippedPathRows=0;BestPracticesEvidenceErrors=0;Dataset='NotAvailable'}})
        Limitations=@('Recommendations are evidence-based review prompts, not compliance certification or effective-access calculations.','Only collected directory ACLs are assessed; individual file ACLs and complete coverage are not established.','Unknown, missing, ambiguous, unsupported, or failed evidence remains NotAssessed.','No result authorizes mutation or supports a compliance qualification.','No server, share, ACL, audit, or policy settings were modified.')
    }
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputFolder 'BestPracticeSummary.json') -Encoding UTF8
    return $summary
}

function Get-NtfsObservedBoolean($Value) { return Get-NtfsBpObservedBoolean $Value }

function Invoke-NtfsBestPracticesOfflineReport([string]$InputRunFolder,[string]$OutputFolder,[string]$PolicyPath) {
    $source=[IO.Path]::GetFullPath($InputRunFolder).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $destination=[IO.Path]::GetFullPath($OutputFolder).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($destination.Equals($source,[StringComparison]::OrdinalIgnoreCase) -or $destination.StartsWith($source+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Offline report OutputFolder must be outside the source run folder.'
    }
    if (Test-Path -LiteralPath $destination) {
        if (@(Get-ChildItem -LiteralPath $destination -Force).Count -gt 0) { throw 'Offline report OutputFolder must be new or empty.' }
    } else { [void](New-Item -ItemType Directory -Path $destination -Force) }
    $manifestPath=Join-Path $source 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Source run is missing manifest.json.' }
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.ReadOnly -ne $true -or $manifest.FatalError) { throw 'Source run is not a successful read-only assessment.' }
    if ($manifest.PSObject.Properties.Name -notcontains 'Datasets' -or @($manifest.Datasets).Count -eq 0) {
        throw 'Source run does not contain a verified dataset inventory.'
    }
    foreach ($dataset in @('Shares.csv','SharePermissions.csv','NtfsAcls.csv','Folders.csv','Identities.csv','ShareCoverage.csv','ScanErrors.csv','SkippedPaths.csv')) {
        $parts=@(Get-NtfsCsvFiles $source $dataset)
        if ($parts.Count -eq 0) { throw "Source run is missing required dataset $dataset." }
    }
    $policy=if ($PolicyPath) {Read-NtfsBestPracticesPolicy $PolicyPath} else {$null}
    $result=Write-NtfsBestPracticesReport $source $destination $policy -PolicyAlreadyParsed
    $outputInventory=@(Get-NtfsDatasetInventory $destination)
    $offlineManifest=[ordered]@{
        Version=$script:NtfsBestPracticesVersion
        SchemaVersion=1;GeneratedUtc=[datetime]::UtcNow.ToString('o');SourceRunId=$manifest.RunId
        SourceManifestSHA256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
        PolicySHA256=$(if($null -ne $policy){$policy.SHA256}else{''})
        Datasets=$outputInventory;SummaryFile='BestPracticeSummary.json'
        SummarySHA256=(Get-FileHash -LiteralPath (Join-Path $destination 'BestPracticeSummary.json') -Algorithm SHA256).Hash
        PolicyCopySHA256=$(if($policy){(Get-FileHash -LiteralPath (Join-Path $destination 'BestPracticesPolicy.json') -Algorithm SHA256).Hash}else{''})
        ReadOnly=$true;SourceRunFolder=(Split-Path -Leaf $source);SourceManifestFile='manifest.json'
    }
    $offlineManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $destination 'BestPracticesManifest.json') -Encoding UTF8
    return $result
}
