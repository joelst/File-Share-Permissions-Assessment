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
  Read-only SMB and NTFS permissions collector for local Windows, remote Windows, NAS servers, and explicit UNC shares.

.NOTES
  Toolkit Version 1.6.6. 
  
  Collects read-only SMB and NTFS permission evidence.

  Directory ACL inventory only; individual file ACLs are not collected.
  Does not change ACLs, ownership, shares, users, groups, files, folders, or audit policy.
  CSV parts are limited to 100,000,000 bytes including UTF-8 BOM, headers and record terminators.
  Requires NtfsAssessment.Common.ps1 alongside this script.
  OutputRoot must be outside assessed trees; known local SMB mappings are checked
  before creating output. Newly discovered unsafe scopes are rejected before scanning.
  Overlapping explicit child scopes use parent-scope evidence and coverage limitations.
  Mixed local/UNC roots for one share are rejected; use one addressing form.
  ONTAP CSV imports are atomic and scope-bound, with optional sid and vserver columns.
  Imports never establish directory or complete share-ACL coverage.
  -BestPractices and -CollectAuditEvidence opt in to read-only best-practice evidence;
  results are review prompts, not compliance certification or effective-access calculations.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputRoot,
 [string[]]$ComputerName=@(),
 [string[]]$NasServer=@(),
 [string[]]$UncPath=@(),
 [string]$NasShareListCsv,
 [pscredential]$CimCredential,
 [pscredential]$OntapCredential,
 [string]$OntapSharePermissionsCsv,
 [string]$DomainServerCsv,
 [string[]]$IncludeShare=@('*'),
 [string[]]$ExcludeShare=@('ADMIN$','C$','IPC$','print$'),
 [ValidateRange(0,256)][int]$MaxDepth=10,
 [ValidateRange(1,2000000)][int]$MaxFolders=100000,
 [switch]$ResolveActiveDirectory,
 [ValidateRange(1,500000)][int]$MaxExpandedMembers=50000,
 [switch]$IncludeLocalGroups,
 [switch]$UseIcaclsVerify,
 [switch]$CaptureAclBackup,
 [switch]$FollowReparsePoints,
 [switch]$SplitOutputByShare,
 [switch]$HashOutputs,
 [switch]$BestPractices,
 [string]$BestPracticesPolicyPath,
 [switch]$CollectAuditEvidence
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
. (Join-Path $PSScriptRoot 'NtfsAssessment.Common.ps1')
if ($CollectAuditEvidence -and -not $BestPractices) { throw '-CollectAuditEvidence requires -BestPractices.' }
if ($BestPracticesPolicyPath -and -not $BestPractices) { throw '-BestPracticesPolicyPath requires -BestPractices.' }
if ($BestPractices) {
 . (Join-Path $PSScriptRoot 'NtfsAssessment.BestPractices.ps1')
 $BpPolicy=$null
 if ($BestPracticesPolicyPath) { $BpPolicy=Read-NtfsBestPracticesPolicy $BestPracticesPolicyPath }
}
if ($FollowReparsePoints) { throw 'Following reparse points is not supported safely. Remove -FollowReparsePoints; excluded paths will be recorded.' }
if ($OntapCredential) { throw 'Unstructured ONTAP SSH tables are not supported. Use -OntapSharePermissionsCsv with smb_server,smb_share,user_or_group,permission columns and optional vserver.' }
$ToolkitVersion='1.6.6';$RunId=[guid]::NewGuid().Guid;$CollectorHost=$env:COMPUTERNAME;$CurrentTarget=$CollectorHost
if($ComputerName.Length -eq 0 -and $NasServer.Length -eq 0 -and $UncPath.Length -eq 0 -and [string]::IsNullOrWhiteSpace($NasShareListCsv)){$ComputerName=@($env:COMPUTERNAME)}
$MandatoryExcludedShares=@('ADMIN$','C$','D$','IPC$','print$')
# Auto-exclude share matching the runner's sAMAccountName (auto-created by net view)
$runnerSam=$env:USERNAME
if(-not [string]::IsNullOrWhiteSpace($runnerSam)){$MandatoryExcludedShares+=@("$runnerSam","$runnerSam-*")}
$EffectiveExcludeShare=@($MandatoryExcludedShares+$ExcludeShare|Where-Object{$_}|Sort-Object -Unique)
function Test-ShareSelection([string]$Name){$included=$false;foreach($p in $IncludeShare){if($Name -like $p){$included=$true;break}};if(-not $included){return $false};foreach($p in $EffectiveExcludeShare){if($Name -like $p){return $false}};return $true}
$OutputRoot=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)
$localShares=@{}
$localPathMappings=[Collections.ArrayList]::new()
$localTargets=@($ComputerName|Where-Object{$_ -in @('.','localhost',$CollectorHost)})
foreach($source in $UncPath){
 $key=Get-NtfsPathKey $source
 if(@(@('.','localhost',$CollectorHost)|Where-Object{$_ -and $key.StartsWith("\\$_\",[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0){$localTargets+=@($CollectorHost)}
}
foreach($target in @($localTargets|Sort-Object -Unique)){
  $localShares[$target]=@(Get-SmbShare -ErrorAction Stop|Where-Object{$_.Path})
  foreach($share in $localShares[$target]){
   foreach($alias in @($target,'.','localhost',$CollectorHost)){
    [void]$localPathMappings.Add([pscustomobject]@{UNC="\\$alias\$($share.Name)";LocalPath=$share.Path})
   }
  }
}
foreach($target in $ComputerName){
 if($localShares.ContainsKey($target)){
  foreach($share in $localShares[$target]){
   if(Test-ShareSelection $share.Name){Assert-NtfsOutputOutsideScope $OutputRoot $share.Path $localPathMappings}
  }
 }
}
foreach($source in $UncPath){Assert-NtfsOutputOutsideScope $OutputRoot $source $localPathMappings}
if($NasShareListCsv){
 foreach($source in @(Read-NtfsCsvFile $NasShareListCsv @('NasServer','ShareName'))){
  if((Get-NtfsPathKey ([string]$source.NasServer)) -and [string]$source.ShareName){
   Assert-NtfsOutputOutsideScope $OutputRoot "\\$($source.NasServer)\$($source.ShareName)" $localPathMappings
  }
 }
}
$RunFolder=Join-Path $OutputRoot ("ASSESS_{0}_{1}_{2}" -f $CollectorHost,(Get-Date -Format yyyyMMdd_HHmmss),$RunId.Substring(0,8))
New-Item -ItemType Directory -Path $RunFolder -Force|Out-Null
$script:TotalFolders=0;$script:TotalAces=0;$script:LargeBufferFlushes=0;$Log=Join-Path $RunFolder 'run.log';$Errors=New-Object Collections.ArrayList;$SkippedPaths=New-Object Collections.ArrayList;$ShareCoverage=New-Object Collections.ArrayList;$Servers=New-Object Collections.ArrayList;$Shares=New-Object Collections.ArrayList;$ShareAcl=New-Object Collections.ArrayList;$Folders=New-Object Collections.ArrayList;$Aces=New-Object Collections.ArrayList;$Members=New-Object Collections.ArrayList;$LocalMembers=New-Object Collections.ArrayList;$Identities=@{};$GroupAces=New-Object Collections.ArrayList
$script:BpServerConfig=@{}
$BpAuditRows=New-Object Collections.ArrayList
$BpEvidenceErrors=New-Object Collections.ArrayList
function Add-BestPracticeEvidenceError([string]$Server,[string]$Share,[string]$Stage,[string]$Detail){
 [void]$BpEvidenceErrors.Add([pscustomobject]@{RunId=$RunId;CollectorHost=$CollectorHost;Server=$Server;Share=$Share;Stage=$Stage;Detail=$Detail;Utc=[datetime]::UtcNow.ToString('o')})
}
function Write-RunLog([string]$Level,[string]$Stage,[string]$Message){$line="{0:o}`t{1}`t{2}`t{3}" -f (Get-Date),$Level,$Stage,$Message;Add-Content -LiteralPath $Log -Value $line -Encoding UTF8;Write-Verbose $line}
function Add-RunError([string]$Stage,[string]$Path,[Exception]$Exception){
 $utc=(Get-Date).ToUniversalTime().ToString('o')
 [void]$Errors.Add([pscustomobject]@{RunId=$RunId;Target=$CurrentTarget;Stage=$Stage;Path=$Path;Error=$Exception.Message;HResult=$Exception.HResult;Utc=$utc})
 $reason=Get-NtfsFailureReason $Exception
 if($Stage -in @('ValidateUNC','EnumerateDirectory','ReadACL','ReadAccessRules')){[void]$SkippedPaths.Add([pscustomobject]@{RunId=$RunId;Target=$CurrentTarget;Stage=$Stage;Path=$Path;Reason=$reason;Detail=$Exception.Message;Utc=$utc})}
 Write-RunLog ERROR $Stage ("{0}: {1}" -f $Path,$Exception.Message)
}
$script:CsvWriters=@{}
function Export-Safe($Rows,[string]$File){Export-NtfsCsvData $Rows (Join-Path $RunFolder $File)}
function Append-Safe($Rows,[string]$File){
 foreach($row in $Rows){
  if(-not $script:CsvWriters.ContainsKey($File)){
   $columns=@($row.PSObject.Properties.Name)
   $writer=New-NtfsCsvWriter (Join-Path $RunFolder $File)
   $script:CsvWriters[$File]=@{Writer=$writer;Columns=$columns}
   $writer.WriteLine((ConvertTo-NtfsCsvRecord $columns))
  }
  $state=$script:CsvWriters[$File]
  $state.Writer.WriteLine((ConvertTo-NtfsCsvRecord @($state.Columns|ForEach-Object{$row.$_})))
 }
}
function Flush-LargeBuffers {
 $folderCount=$Folders.Count;$aceCount=$Aces.Count
 if($folderCount -gt 0){
  Append-Safe $Folders 'Folders.csv'
  if($SplitOutputByShare){
   $groups=@($Folders|Group-Object -Property {"{0}|{1}"-f$_.Server,$_.Share})
   foreach($g in $groups){$safeName=Get-NtfsHash $g.Name.ToLowerInvariant();$dir=Join-Path $RunFolder 'PerShare';New-Item -ItemType Directory -Path $dir -Force|Out-Null;Append-Safe @($g.Group) (Join-Path 'PerShare' "FOL_$safeName.csv")}
  }
  $script:TotalFolders+=$folderCount;$Folders.Clear()
 }
 if($aceCount -gt 0){
  Append-Safe $Aces 'NtfsAcls.csv'
  if($SplitOutputByShare){
   $groups=@($Aces|Group-Object -Property {"{0}|{1}"-f$_.Server,$_.Share})
   foreach($g in $groups){$safeName=Get-NtfsHash $g.Name.ToLowerInvariant();$dir=Join-Path $RunFolder 'PerShare';New-Item -ItemType Directory -Path $dir -Force|Out-Null;Append-Safe @($g.Group) (Join-Path 'PerShare' "ACE_$safeName.csv")}
  }
  $script:TotalAces+=$aceCount;$Aces.Clear()
 }
 if($folderCount -gt 0 -or $aceCount -gt 0){$script:LargeBufferFlushes++;Write-RunLog INFO MemoryFlush ("Flushed folders={0}; aces={1}; totalFolders={2}; totalAces={3}" -f $folderCount,$aceCount,$script:TotalFolders,$script:TotalAces)}
 # Flush GroupAces incrementally to avoid OOM
 $gaCount=$GroupAces.Count
 if($gaCount -gt 0){Append-Safe $GroupAces 'GroupAcesFound.csv';$GroupAces.Clear()}
}
function ConvertTo-ExtendedPath([string]$Path){
 if([string]::IsNullOrWhiteSpace($Path)){return $Path}
 if($Path.StartsWith('\\?\')){return $Path}
 if($Path.StartsWith('\\')){return '\\?\UNC\'+$Path.TrimStart('\')}
 if($Path -match '^[A-Za-z]:\\'){return '\\?\'+$Path}
 return $Path
}
function ConvertTo-DisplayPath([string]$Path){
 if([string]::IsNullOrWhiteSpace($Path)){return $Path}
 if($Path.StartsWith('\\?\UNC\',[StringComparison]::OrdinalIgnoreCase)){return '\\'+$Path.Substring(8)}
 if($Path.StartsWith('\\?\')){return $Path.Substring(4)}
 return $Path
}
function Get-Hash([string]$Text){$s=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
# Load domain servers for multi-domain SID resolution
$DomainServers=@()
if(-not [string]::IsNullOrWhiteSpace($DomainServerCsv)){
 try {
  $dsRows=@(Read-NtfsCsvFile $DomainServerCsv)
  foreach($dsr in $dsRows){
   $ds=''
   if($null -ne $dsr -and $dsr.PSObject.Properties.Name -contains 'DomainServer'){$ds=[string]$dsr.DomainServer}
   elseif($null -ne $dsr -and $dsr.PSObject.Properties.Name -contains 'Server'){$ds=[string]$dsr.Server}
   elseif($null -ne $dsr -and $dsr.PSObject.Properties.Name -contains 'Domain'){$ds=[string]$dsr.Domain}
   if(-not [string]::IsNullOrWhiteSpace($ds)){$DomainServers+=$ds}
  }
  if($DomainServers.Count -eq 0){throw 'DomainServerCsv requires DomainServer, Server or Domain values.'}
 } catch { Add-RunError DomainServerCsv $DomainServerCsv $_.Exception; throw }
}
function Resolve-Identity([string]$Name){
 $result=[pscustomobject][ordered]@{Identity=$Name;SID='';Resolved=$false;ResolvedBy='None';ResolvedName='';ObjectClass='Unknown';DirectoryServer='';DistinguishedName='';LookupStatus='Unresolved'}
 try{
  if($Name -match '^S-1-'){
   $sid=New-Object Security.Principal.SecurityIdentifier($Name)
   $result.SID=$sid.Value
   $result.ResolvedName=$sid.Translate([Security.Principal.NTAccount]).Value
  }else{
   $result.SID=(New-Object Security.Principal.NTAccount($Name)).Translate([Security.Principal.SecurityIdentifier]).Value
   $result.ResolvedName=$Name
  }
  $result.Resolved=$true;$result.ResolvedBy='Local';$result.LookupStatus='NameResolved'
 }catch{Write-RunLog WARN IdentityResolution "$Name : $($_.Exception.Message)"}
 if($AdReady -and $result.SID -match '^S-1-5-21-(\d+-){2}\d+-\d+$'){
  $lookupErrors=[Collections.ArrayList]::new()
  $servers=@($DomainServers)
  if($servers.Count -eq 0){$servers=@('')}
  foreach($ds in $servers){
   try{
    $args=@{Filter="objectSid -eq '$($result.SID)'";Properties=@('sAMAccountName','objectClass');ErrorAction='Stop'}
    if($ds){$args.Server=$ds}
    $objects=@(Get-ADObject @args)
    if($objects.Count -gt 1){throw "SID lookup returned multiple objects: $($result.SID)"}
    if($objects.Count -eq 0){continue}
    $o=$objects[0]
    $result.ObjectClass=[string]$o.ObjectClass;$result.DistinguishedName=[string]$o.DistinguishedName
    $result.DirectoryServer=$ds;$result.LookupStatus='DirectoryResolved';$result.Resolved=$true
    $result.ResolvedBy=$(if($ds){$ds}else{'DefaultDomain'})
    if(-not $result.ResolvedName){$result.ResolvedName=[string]$o.sAMAccountName}
    break
   }catch{[void]$lookupErrors.Add($_.Exception);Write-RunLog WARN IdentityResolution "$Name on '$ds': $($_.Exception.Message)"}
  }
  if($result.LookupStatus -ne 'DirectoryResolved'){
   $result.LookupStatus=if($lookupErrors.Count -gt 0){'DirectoryLookupFailed'}else{'DirectoryObjectNotFound'}
   if($lookupErrors.Count -gt 0){Add-RunError IdentityDirectoryLookup $Name $lookupErrors[0]}
  }
 }
 return $result
}
function Get-FolderQueue([string]$Root){
 $q=New-Object Collections.Queue
 $q.Enqueue([pscustomobject]@{Path=$Root;Depth=0})
 $n=0
 while($q.Count -gt 0){
  $x=$q.Dequeue();$x;$n++
  if($n -ge $MaxFolders){Add-SkippedPath $x.Path 'MaxFoldersReached' "Enumeration stopped at MaxFolders=$MaxFolders; coverage is conservative and incomplete.";break}
  if($x.Depth -ge $MaxDepth){Add-SkippedPath $x.Path 'MaxDepthReached' "Descendants were not enumerated beyond MaxDepth=$MaxDepth.";continue}
  try{
   $nativeParent=ConvertTo-ExtendedPath $x.Path
   $parent=[IO.DirectoryInfo]::new($nativeParent)
   if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){Add-SkippedPath $x.Path 'ReparsePointExcluded' 'Directory became or is a reparse point; descendants were not enumerated.';continue}
   foreach($child in $parent.EnumerateDirectories()){
    if($child.Attributes -band [IO.FileAttributes]::ReparsePoint){
     Add-SkippedPath $child.FullName 'ReparsePointExcluded' 'Reparse point and descendants were not followed.'
     continue
    }
    if($child.Name -ieq '~snapshot'){
     Add-SkippedPath $child.FullName 'SnapshotFolderExcluded' 'Folder named ~snapshot and descendants were excluded.'
     continue
    }
    $displayChild=Join-Path -Path $x.Path -ChildPath $child.Name
    if($n+$q.Count -ge $MaxFolders){
     Add-SkippedPath $x.Path 'MaxFoldersReached' "Queue capped at MaxFolders=$MaxFolders; additional descendants were omitted."
     break
    }
    $q.Enqueue([pscustomobject]@{Path=$displayChild;Depth=$x.Depth+1})
   }
  }catch{Add-RunError EnumerateDirectory $x.Path $_.Exception}
 }
}
function Add-SkippedPath([string]$Path,[string]$Reason,[string]$Detail){
 [void]$SkippedPaths.Add([pscustomobject]@{RunId=$RunId;Target=$CurrentTarget;Stage='EnumerateDirectory';Path=$Path;Reason=$Reason;Detail=$Detail;Utc=[datetime]::UtcNow.ToString('o')})
 Write-RunLog WARN EnumerateDirectory "$Reason : $Path : $Detail"
}
function Add-ShareAndAclData([string]$Server,[string]$Share,[string]$Root,[string]$Mode,[string]$MetadataStatus,$SmbObject=$null,$ShareAccess=$null){
 Assert-NtfsOutputOutsideScope $OutputRoot $Root $localPathMappings
 if($null -ne $SmbObject -and $Mode -eq 'LocalWindows'){Assert-NtfsOutputOutsideScope $OutputRoot $SmbObject.Path $localPathMappings}
 $scopeRoot=if($null -ne $SmbObject -and $Mode -eq 'LocalWindows'){$SmbObject.Path}else{$Root}
 Assert-NtfsScopeRoots @(@($Shares)+@([pscustomobject]@{Server=$Server;Share=$Share;ScanRoot=$scopeRoot}))
 $shareRow=[pscustomobject]@{RunId=$RunId;CollectorHost=$CollectorHost;Server=$Server;CollectionMode=$Mode;Share=$Share;UNC=$Root;ScanRoot=$Root;LocalPath=$(if($null -ne $SmbObject){$SmbObject.Path}else{'NotAvailable'});Description=$(if($null -ne $SmbObject){$SmbObject.Description}else{'NotCollected'});EncryptData=$(if($null -ne $SmbObject){$SmbObject.EncryptData}else{'NotCollected'});ContinuouslyAvailable=$(if($null -ne $SmbObject){$SmbObject.ContinuouslyAvailable}else{'NotCollected'});ShareMetadataStatus=$MetadataStatus}
 $bpEnabled=Get-Variable -Name BestPractices -ValueOnly -ErrorAction SilentlyContinue
 if($bpEnabled){
  $serverConfig=if($script:BpServerConfig.ContainsKey($Server)){$script:BpServerConfig[$Server]}else{$null}
  $shareRow|Add-Member -NotePropertyName SMB1Enabled -NotePropertyValue $(if($null -ne $serverConfig){$serverConfig.SMB1Enabled}else{'NotAssessed'})
  $shareRow|Add-Member -NotePropertyName RequireSecuritySignature -NotePropertyValue $(if($null -ne $serverConfig){$serverConfig.RequireSecuritySignature}else{'NotAssessed'})
  $shareRow|Add-Member -NotePropertyName SMB1ConfigurationStatus -NotePropertyValue $(if($null -ne $serverConfig){$serverConfig.SMB1Status}else{'NotAssessed'})
  $shareRow|Add-Member -NotePropertyName SMBSigningConfigurationStatus -NotePropertyValue $(if($null -ne $serverConfig){$serverConfig.SigningStatus}else{'NotAssessed'})
  $shareRow|Add-Member -NotePropertyName SMBServerConfigurationStatus -NotePropertyValue $(if($null -ne $serverConfig){$serverConfig.Status}else{'NotAssessed'})
  $shareRow|Add-Member -NotePropertyName SMBServerConfigurationDetail -NotePropertyValue $(if($null -ne $serverConfig){$serverConfig.Detail}else{'Windows SMB server configuration was not queried for this NAS/unknown target.'})
  $shareRow|Add-Member -NotePropertyName FolderEnumerationMode -NotePropertyValue $(if($null -ne $SmbObject -and $SmbObject.PSObject.Properties.Name -contains 'FolderEnumerationMode'){$SmbObject.FolderEnumerationMode}else{'NotCollected'})
 }
 [void]$Shares.Add($shareRow)
 foreach($sa in @($ShareAccess)){if($null -eq $sa){continue};$account=Get-AclPropertySafe $sa 'AccountName' 'NotExposed';$controlType=Get-AclPropertySafe $sa 'AccessControlType' 'NotExposed';$accessRight=Get-AclPropertySafe $sa 'AccessRight' 'NotExposed';$sid=Get-NtfsPrincipalKey $account (Get-AclPropertySafe $sa 'SID' '');if(-not $sid){$sid=(Resolve-Identity $account).SID};[void]$ShareAcl.Add([pscustomobject]@{RunId=$RunId;Server=$Server;Share=$Share;AccountName=[string]$account;SID=$sid;AccessControlType=[string]$controlType;AccessRight=[string]$accessRight;Source='WindowsSmbShare';Vserver=''})}
}
function Invoke-UniqueScopeScan([string]$Server,[string]$Share,[string]$Root,[string]$Mode){
 Assert-NtfsOutputOutsideScope $OutputRoot $Root $localPathMappings
 $key=ConvertTo-NtfsCsvRecord @($Server.ToLowerInvariant(),$Share.ToLowerInvariant(),(Get-NtfsPathKey $Root))
 if(-not $script:ScannedScopes.Add($key)){Write-RunLog INFO DuplicateScope "Skipping previously collected scope $Root";return}
 Scan-UncRoot $Server $Share $Root $Mode
}
function Get-UniqueSharePermissions($Rows){
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($row in $Rows){
  $right=([string]$row.AccessRight).Replace('_',' ')
  if($right -eq 'full control'){$right='full'}
  $key=ConvertTo-NtfsCsvRecord @($row.Server,$row.Share,$row.AccountName,(Get-AclPropertySafe $row 'SID' ''),$row.AccessControlType,$right,$row.Source,$row.Vserver)
  if($seen.Add($key)){$row}
 }
}
function Import-OntapPermissions([string]$Path) {
  $staged=[Collections.ArrayList]::new()
  $svms=@{}
  foreach($row in @(Read-NtfsCsvFile $Path @('smb_server','smb_share','user_or_group','permission'))){
   $server=[string]$row.smb_server;$share=[string]$row.smb_share;$account=[string]$row.user_or_group
   if([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($share) -or [string]::IsNullOrWhiteSpace($account)){throw 'ONTAP CSV contains a blank server, share or account.'}
   $scopes=@($Shares|Where-Object{$_.Server -eq $server -and $_.Share -eq $share})
   if($scopes.Count -eq 0){throw "ONTAP permission is outside assessment scopes: $server\$share"}
   if(@($scopes|Where-Object{$_.CollectionMode -in @('LocalWindows','RemoteWindowsCIM')}).Count -gt 0 -or
      @($ShareAcl|Where-Object{$_.Server -eq $server -and $_.Share -eq $share -and $_.Source -ne 'NetAppONTAP_CSV'}).Count -gt 0){
    throw "Conflicting Windows/ONTAP share evidence: $server\$share"
   }
   $permission=([string]$row.permission).Replace('_',' ')
   if($permission -notin @('read','change','full control','full','no access')){throw "Unknown ONTAP permission: $permission"}
   $vserver=[string](Get-AclPropertySafe $row 'vserver' '')
   $key=ConvertTo-NtfsCsvRecord @($server,$share)
   if($svms.ContainsKey($key) -and $svms[$key] -ne $vserver){throw "Ambiguous ONTAP server/share across SVMs: $server\$share"}
   foreach($existing in @($ShareAcl|Where-Object{$_.Server -eq $server -and $_.Share -eq $share})){
    if([string](Get-AclPropertySafe $existing 'Vserver' '') -ne $vserver){throw "Ambiguous ONTAP server/share across SVMs: $server\$share"}
   }
   $svms[$key]=$vserver
   $sid=Get-NtfsPrincipalKey $account (Get-AclPropertySafe $row 'sid' '')
   [void]$staged.Add([pscustomobject]@{RunId=$RunId;Server=$server;Share=$share;AccountName=$account;SID=$sid;AccessControlType=$(if($permission -eq 'no access'){'Deny'}else{'Allow'});AccessRight=$permission;Source='NetAppONTAP_CSV';Vserver=$vserver})
  }
  foreach($row in $staged){[void]$ShareAcl.Add($row)}
  Write-RunLog INFO OntapCsvImport "Imported $($staged.Count) ONTAP share permission entries; completeness remains unknown."
}
function Get-AclRulesSafe($Acl,[string]$Path){
 $rules=@()
 try{
  if($Acl.PSObject.Methods.Name -contains 'GetAccessRules'){
   try{$rules=@($Acl.GetAccessRules($true,$true,[Security.Principal.NTAccount]))}
   catch{$rules=@($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))}
  }elseif($Acl.PSObject.Properties.Name -contains 'Access'){$rules=@($Acl.Access)}
  else{throw "No Access property or GetAccessRules method exposed for $Path"}
 }catch{throw [IO.InvalidDataException]::new("Unable to read access rules for $Path : $($_.Exception.Message)",$_.Exception)}
 return @($rules)
}
function Get-AclPropertySafe($Object,[string]$Name,$DefaultValue){
 if($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name){return $Object.$Name}
 return $DefaultValue
}
function Scan-UncRoot([string]$Server,[string]$Share,[string]$Root,[string]$Mode){
 $script:CurrentTarget=$Server;Write-RunLog INFO ScanShare "Starting $Root ($Mode)"
 Write-Host ("[{0}] Scanning \\{1}\{2}" -f (Get-Date -Format 'HH:mm:ss'),$Server,$Share)
 $startFolders=$script:TotalFolders+$Folders.Count;$startAces=$script:TotalAces+$Aces.Count;$startErrors=$Errors.Count;$startSkipped=$SkippedPaths.Count
 $nativeRoot=ConvertTo-ExtendedPath $Root
 try{
  $exists=Test-Path -LiteralPath $nativeRoot -ErrorAction Stop
  if($exists){
   $rootItem=Get-Item -LiteralPath $nativeRoot -Force -ErrorAction Stop
   if(-not ($rootItem.Attributes -band [IO.FileAttributes]::Directory)){throw [IO.InvalidDataException]::new("Assessment root is not a directory: $Root")}
  }
 }catch{
  $reason=Get-NtfsFailureReason $_.Exception
  Add-RunError ValidateUNC $Root $_.Exception
  [void]$ShareCoverage.Add([pscustomobject]@{RunId=$RunId;Server=$Server;Share=$Share;UNC=$Root;CollectionMode=$Mode;Status="Skipped$reason";FoldersCollected=0;AcesCollected=0;SkippedPaths=1;Errors=1;Detail=$_.Exception.Message})
  Write-RunLog WARN ScanShare "Skipped $Root : $reason";return
 }
 if(-not $exists){$ex=[IO.DirectoryNotFoundException]::new("UNC path was not found: $Root");Add-RunError ValidateUNC $Root $ex;[void]$ShareCoverage.Add([pscustomobject]@{RunId=$RunId;Server=$Server;Share=$Share;UNC=$Root;CollectionMode=$Mode;Status='SkippedPathNotFound';FoldersCollected=0;AcesCollected=0;SkippedPaths=1;Errors=1;Detail=$ex.Message});Write-RunLog WARN ScanShare "Skipped $Root because the path was not found";return}
 Get-FolderQueue $Root | ForEach-Object {
  $f=$_
  try{
   $displayPath=ConvertTo-DisplayPath $f.Path;$nativePath=ConvertTo-ExtendedPath $displayPath
   $item=Get-Item -LiteralPath $nativePath -Force -ErrorAction Stop
   if(-not ($item.Attributes -band [IO.FileAttributes]::Directory)){throw [IO.InvalidDataException]::new("Not a directory: $displayPath")}
   if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Scan root or enumerated directory is a reparse point; refusing to follow it.'}
   try{$acl=Get-Acl -LiteralPath $nativePath -ErrorAction Stop}
   catch{
    Write-RunLog WARN ReadACL "LiteralPath ACL read failed for $displayPath; retrying with InputObject: $($_.Exception.Message)"
    $acl=Get-Acl -InputObject $item -ErrorAction Stop
   }
   $rules=@(Get-AclRulesSafe $acl $displayPath)
   $ph=Get-Hash $displayPath.ToLowerInvariant()
   $sddl=[string](Get-AclPropertySafe $acl 'Sddl' '')
   $daclState='Unknown'
   if($sddl){
    $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
    $daclState=if($null -eq $descriptor.DiscretionaryAcl){'NullDacl'}elseif($descriptor.DiscretionaryAcl.Count -eq 0){'EmptyDacl'}else{'Present'}
   }
   [void]$Folders.Add([pscustomobject][ordered]@{
    RunId=$RunId;CollectorHost=$CollectorHost;Server=$Server;Share=$Share;ScanRoot=$Root;CollectionMode=$Mode
    Path=$displayPath;PathHash=$ph;Depth=$f.Depth;PathLength=$displayPath.Length
    Owner=(Get-AclPropertySafe $acl 'Owner' 'NotExposed');InheritanceProtected=(Get-AclPropertySafe $acl 'AreAccessRulesProtected' 'NotExposed')
    LastWriteUtc=$item.LastWriteTimeUtc.ToString('o');Attributes=$item.Attributes.ToString();SDDL=$sddl
    CollectionStatus='Read';DaclState=$daclState;DescriptorHash=(Get-Hash $sddl)
   })
   $ordinal=0
   foreach($a in $rules){
    $identity=Get-AclPropertySafe $a 'IdentityReference' $null
    if($null -eq $identity){throw 'Access rule has no identity reference.'}
    $id=[string](Get-AclPropertySafe $identity 'Value' ([string]$identity))
    if(-not $Identities.ContainsKey($id)){$Identities[$id]=Resolve-Identity $id}
    $type=[string](Get-AclPropertySafe $a 'AccessControlType' 'NotExposed')
    $rightsObj=Get-AclPropertySafe $a 'FileSystemRights' (Get-AclPropertySafe $a 'AccessMask' $null)
    if($null -eq $rightsObj){throw 'Access rule has no rights mask.'}
    $rights=[string]$rightsObj;$rightsValue=[int64]$rightsObj
    $inherited=Get-AclPropertySafe $a 'IsInherited' 'NotExposed'
    $inheritFlags=[string](Get-AclPropertySafe $a 'InheritanceFlags' 'NotExposed')
    $propFlags=[string](Get-AclPropertySafe $a 'PropagationFlags' 'NotExposed')
    $k=ConvertTo-NtfsCsvRecord @($displayPath.ToLowerInvariant(),$id,$type,$rightsValue,$inherited,$inheritFlags,$propFlags,$ordinal)
    [void]$Aces.Add([pscustomobject][ordered]@{
     RunId=$RunId;CollectorHost=$CollectorHost;Server=$Server;Share=$Share;ScanRoot=$Root;CollectionMode=$Mode
     Path=$displayPath;PathHash=$ph;AceHash=(Get-Hash $k);AceOrdinal=$ordinal;DescriptorHash=(Get-Hash $sddl)
     Identity=$id;SID=$Identities[$id].SID;Resolved=$Identities[$id].Resolved
     AccessControlType=$type;Rights=$rights;RightsValue=$rightsValue;IsInherited=$inherited;InheritanceFlags=$inheritFlags;PropagationFlags=$propFlags
    })
    $ordinal++
    if($id -notmatch '(?i)(^NT AUTHORITY\\|^BUILTIN\\|^CREATOR OWNER$|^NT SERVICE\\|\\SYSTEM$)'){
     [void]$GroupAces.Add([pscustomobject]@{RunId=$RunId;Server=$Server;Share=$Share;ScanRoot=$Root;Path=$displayPath;Identity=$id;SID=$Identities[$id].SID;Rights=$rights;AccessControlType=$type;IsInherited=$inherited;InheritanceFlags=$inheritFlags;PropagationFlags=$propFlags})
    }
    if($Aces.Count -ge 10000){Flush-LargeBuffers}
   }
   if($Folders.Count -ge 1000){Flush-LargeBuffers}
  }catch{Add-RunError ReadACL $f.Path $_.Exception}
 }
 $folderDelta=$script:TotalFolders+$Folders.Count-$startFolders;$aceDelta=$script:TotalAces+$Aces.Count-$startAces;$errorDelta=$Errors.Count-$startErrors;$skippedDelta=$SkippedPaths.Count-$startSkipped
 $status=if($errorDelta -eq 0 -and $skippedDelta -eq 0){'CompletedDirectoriesOnly'}elseif($folderDelta -gt 0){'PartialDirectoriesOnly'}else{'SkippedNoReadableFolders'}
 [void]$ShareCoverage.Add([pscustomobject]@{RunId=$RunId;Server=$Server;Share=$Share;UNC=$Root;CollectionMode=$Mode;Status=$status;FoldersCollected=$folderDelta;AcesCollected=$aceDelta;SkippedPaths=$skippedDelta;Errors=$errorDelta;Detail='Directory ACLs only; individual file ACLs are not collected. Review SkippedPaths.csv and ScanErrors.csv.'})
 Write-RunLog INFO ScanShare "Completed $Root; status=$status; folders=$folderDelta; aces=$aceDelta; skipped=$skippedDelta; errors=$errorDelta"
 Write-Host ("[{0}] Completed \\{1}\{2} - Folders={3}; ACEs={4}; Skipped={5}" -f (Get-Date -Format 'HH:mm:ss'),$Server,$Share,$folderDelta,$aceDelta,$skippedDelta)
 Flush-LargeBuffers
}
function Discover-NasShares([string]$Server){
 $script:CurrentTarget=$Server;$found=New-Object Collections.ArrayList;Write-RunLog INFO NasDiscovery "Running net view against $Server"
 try{$raw=@(& net.exe view "\\$Server" /all 2>&1);$exit=$LASTEXITCODE;if($exit -ne 0){throw "net view exited with code $exit. Output: $($raw -join ' ')"};$inData=$false;foreach($line in $raw){$text=[string]$line;if($text -match '^-{3,}'){$inData=$true;continue};if(-not$inData){continue};if([string]::IsNullOrWhiteSpace($text)){continue};if($text -match 'completed successfully|command completed|se complet|commande.*termin'){break};$cols=@($text.Trim() -split '\s{2,}');if($cols.Length -lt 1){continue};$name=$cols[0].Trim();if($name -and (Test-ShareSelection $name)){[void]$found.Add($name)}}}catch{Add-RunError NasDiscovery $Server $_.Exception}
 return @($found|Sort-Object -Unique)
}
Write-RunLog INFO Start "Toolkit $ToolkitVersion read-only collection started"
if(($UseIcaclsVerify -or $CaptureAclBackup) -and ($NasServer.Count -gt 0 -or $UncPath.Count -gt 0 -or $NasShareListCsv)){
 Add-RunError IcaclsScope '' ([NotSupportedException]::new('UseIcaclsVerify and CaptureAclBackup apply only to local Windows shares, not NAS/explicit UNC scopes. Collection will continue without those operations for unsupported scopes.'))
}
$AdReady=$false;if($ResolveActiveDirectory){try{Import-Module ActiveDirectory -ErrorAction Stop;$AdReady=$true}catch{Add-RunError ActiveDirectory '' $_.Exception}}
$Fatal=$null
$script:ScannedScopes=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
try{
 foreach($Target in @($ComputerName|Sort-Object -Unique)){
  $CurrentTarget=$Target;$local=$Target -in @('.','localhost',$env:COMPUTERNAME);$session=$null
  $server=if($local){$CollectorHost}else{$Target};$mode=if($local){'LocalWindows'}else{'RemoteWindowsCIM'}
  try{
   Write-RunLog INFO WindowsTarget "Starting $server"
   $cimArgs=@{}
   if(-not $local){
    $ca=@{ComputerName=$Target;ErrorAction='Stop'};if($CimCredential){$ca.Credential=$CimCredential}
    $session=New-CimSession @ca;$cimArgs.CimSession=$session
   }
   $os=Get-CimInstance Win32_OperatingSystem @cimArgs
   $cs=Get-CimInstance Win32_ComputerSystem @cimArgs
   $all=if($local){@($localShares[$Target])}else{@(Get-SmbShare @cimArgs -ErrorAction Stop|Where-Object{$_.Path})}
   [void]$Servers.Add([pscustomobject]@{RunId=$RunId;CollectorHost=$CollectorHost;Server=$server;CollectionMode=$mode;Domain=$cs.Domain;OS=$os.Caption;Version=$os.Version;DiscoveryStatus='Complete'})
   if($BestPractices){
    $serverEvidence=@{SMB1Enabled='NotAssessed';RequireSecuritySignature='NotAssessed';SMB1Status='NotAssessed';SigningStatus='NotAssessed';Status='NotAssessed';Detail='SMB server configuration could not be collected.'}
    try{
     $smbConfig=Get-SmbServerConfiguration @cimArgs -ErrorAction Stop
     $serverEvidence.SMB1Enabled=Get-AclPropertySafe $smbConfig 'EnableSMB1Protocol' 'NotAssessed'
     $serverEvidence.RequireSecuritySignature=Get-AclPropertySafe $smbConfig 'RequireSecuritySignature' 'NotAssessed'
     if($null -ne (Get-NtfsBpObservedBoolean $serverEvidence.SMB1Enabled)){$serverEvidence.SMB1Status='Collected'}
     if($null -ne (Get-NtfsBpObservedBoolean $serverEvidence.RequireSecuritySignature)){$serverEvidence.SigningStatus='Collected'}
     $serverEvidence.Status='Collected';$serverEvidence.Detail='Captured Get-SmbServerConfiguration values; no client negotiation or protocol proof.'
    }catch{$serverEvidence.Detail=$_.Exception.Message;Add-BestPracticeEvidenceError $server '' 'SMBServerConfiguration' $_.Exception.Message;Write-RunLog WARN BestPractices "SMB server configuration unavailable for $server : $($_.Exception.Message)"}
    if($serverEvidence.SMB1Status -ne 'Collected'){Add-BestPracticeEvidenceError $server '' 'SMB1Configuration' "EnableSMB1Protocol was not exposed or parsed. $($serverEvidence.Detail)"}
    if($serverEvidence.SigningStatus -ne 'Collected'){Add-BestPracticeEvidenceError $server '' 'SMBSigningConfiguration' "RequireSecuritySignature was not exposed or parsed. $($serverEvidence.Detail)"}
    $script:BpServerConfig[$server]=$serverEvidence
    if($CollectAuditEvidence -and $local){
     $script:BpAuditPolicyLocal=Get-NtfsBpAuditPolicyLocal
     if($script:BpAuditPolicyLocal.Status -ne 'Collected'){Add-BestPracticeEvidenceError $server '' 'LocalAuditPolicy' $script:BpAuditPolicyLocal.Detail}
    }
   }
   foreach($s in $all){
    if(-not(Test-ShareSelection $s.Name)){continue}
    $unc="\\$server\$($s.Name)";$metadata='Collected'
    try{$sa=@(Get-SmbShareAccess -Name $s.Name @cimArgs -ErrorAction Stop)}
    catch{Add-RunError ShareACL $unc $_.Exception;$sa=@();$metadata='ShareAclFailed'}
    Add-ShareAndAclData $server $s.Name $unc $mode $metadata $s $sa
    $scanRoot=if($local){$s.Path}else{$unc}
    $Shares[$Shares.Count-1].ScanRoot=$scanRoot
    if($CollectAuditEvidence){
     $fileSharePolicy='NotAssessed';$fileSystemPolicy='NotAssessed';$policyStatus='NotAssessed';$policyDetail='Audit policy evidence was not collected for this target.'
     if($local){
      $fileSharePolicy=if($null -ne $script:BpAuditPolicyLocal.FileShareSuccess){[string]$script:BpAuditPolicyLocal.FileShareSuccess}else{'NotAssessed'}
      $fileSystemPolicy=if($null -ne $script:BpAuditPolicyLocal.FileSystemSuccess){[string]$script:BpAuditPolicyLocal.FileSystemSuccess}else{'NotAssessed'}
      $policyStatus=$script:BpAuditPolicyLocal.Status;$policyDetail=$script:BpAuditPolicyLocal.Detail
     }elseif(-not $local){$policyDetail='Remote audit policy was not queried; collector-local auditpol evidence does not apply.';Add-BestPracticeEvidenceError $server $s.Name 'RemoteAuditPolicyUnsupported' $policyDetail}
     $saclStatus='NotAssessed';$saclCount='';$saclDetail='Share-root SACL was not read.'
     try{
      $rootAcl=Get-Acl -LiteralPath $scanRoot -Audit -ErrorAction Stop
      $saclRules=@($rootAcl.GetAuditRules($true,$true,[Security.Principal.SecurityIdentifier]))
      $saclCount=$saclRules.Count;$saclStatus='Collected';$saclDetail='Read SACL at share scan root only; descendant SACL coverage was not collected.'
     }catch{$saclDetail=$_.Exception.Message;Add-BestPracticeEvidenceError $server $s.Name 'RootSaclRead' $saclDetail;Write-RunLog WARN BestPractices "Root SACL unavailable for $scanRoot : $($_.Exception.Message)"}
     [void]$BpAuditRows.Add([pscustomobject]@{RunId=$RunId;Server=$server;Share=$s.Name;FileShareSuccessPolicy=$fileSharePolicy;FileSystemSuccessPolicy=$fileSystemPolicy;AuditPolicyStatus=$policyStatus;AuditPolicyDetail=$policyDetail;RootSaclStatus=$saclStatus;RootSaclAuditRuleCount=$saclCount;RootSaclDetail=$saclDetail})
    }
    $safeName=Get-NtfsHash "$server|$($s.Name)"
    if($local -and $UseIcaclsVerify){
     try{
      & icacls.exe $s.Path /verify /T /C /Q /L 2>&1|Set-Content (Join-Path $RunFolder "ICACLS_VERIFY_$safeName.txt") -Encoding UTF8
      if($LASTEXITCODE -ne 0){throw "icacls /verify exit code $LASTEXITCODE; review the verification log."}
     }catch{Add-RunError IcaclsVerify $s.Path $_.Exception}
    }elseif(-not $local -and $UseIcaclsVerify){Add-RunError IcaclsVerify $unc ([NotSupportedException]::new('UseIcaclsVerify supports local Windows shares only.'))}
    if($local -and $CaptureAclBackup){
     try{
      & icacls.exe $s.Path /save (Join-Path $RunFolder "ACL_BACKUP_$safeName.txt") /T /C /Q /L 2>&1|Set-Content (Join-Path $RunFolder "ACL_BACKUP_$safeName.log") -Encoding UTF8
      if($LASTEXITCODE -ne 0){throw "icacls /save exit code $LASTEXITCODE; backup may be incomplete."}
      Write-RunLog INFO AclBackup 'icacls /save captures DACLs only; this is not a complete remediation rollback package.'
     }catch{Add-RunError AclBackup $s.Path $_.Exception}
    }elseif(-not $local -and $CaptureAclBackup){Add-RunError AclBackup $unc ([NotSupportedException]::new('CaptureAclBackup supports local Windows shares only.'))}
    Invoke-UniqueScopeScan $server $s.Name $scanRoot $mode
   }
  }catch{Add-RunError WindowsTarget $server $_.Exception}
  finally{if($session){Remove-CimSession $session -ErrorAction Stop}}
 }
 $nasMap=@();if($NasShareListCsv){$nasMap=@(Read-NtfsCsvFile $NasShareListCsv @('NasServer','ShareName'));foreach($r in $nasMap){if([string]::IsNullOrWhiteSpace($r.NasServer) -or [string]::IsNullOrWhiteSpace($r.ShareName) -or $r.ShareName -match '[\\/]'){throw 'NasShareListCsv requires nonblank NasServer and ShareName values; ShareName must not contain path separators.'}}}
 foreach($Nas in @($NasServer|Sort-Object -Unique)){$CurrentTarget=$Nas;$names=@(Discover-NasShares $Nas);$csvNames=@($nasMap|Where-Object { $_.NasServer -eq $Nas -and (Get-AclPropertySafe $_ 'Enabled' 'True') -ne 'False' }|ForEach-Object{$_.ShareName});$names=@($names+$csvNames|Where-Object{$_ -and (Test-ShareSelection $_)}|Sort-Object -Unique);$status=$(if($names.Length -gt 0){'SharesDiscovered'}else{'NoSharesDiscovered'});[void]$Servers.Add([pscustomobject]@{RunId=$RunId;CollectorHost=$CollectorHost;Server=$Nas;CollectionMode='NasServerSMB';Domain='NotCollected';OS='NotCollected';Version='NotCollected';DiscoveryStatus=$status});foreach($name in $names){$unc="\\$Nas\$name";Add-ShareAndAclData $Nas $name $unc 'NasServerSMB' 'NotCollected_NAS';if($BestPractices){Add-BestPracticeEvidenceError $Nas $name 'UnsupportedServerConfiguration' 'NAS SMB server settings were not queried or inferred.'};if($CollectAuditEvidence){Add-BestPracticeEvidenceError $Nas $name 'UnsupportedAuditPolicy' 'NAS audit policy was not queried or inferred.';Add-BestPracticeEvidenceError $Nas $name 'UnsupportedRootSacl' 'NAS root SACL was not queried or inferred.'};Invoke-UniqueScopeScan $Nas $name $unc 'NasServerSMB'}}
 foreach($r in @($nasMap|Where-Object { (Get-AclPropertySafe $_ 'Enabled' 'True') -ne 'False' })){$key="$($r.NasServer)|$($r.ShareName)";$already=@($Shares|Where-Object{"$($_.Server)|$($_.Share)"-eq$key}).Length-gt0;if(-not $already -and (Test-ShareSelection $r.ShareName)){$unc="\\$($r.NasServer)\$($r.ShareName)";Add-ShareAndAclData $r.NasServer $r.ShareName $unc 'NasShareListCsv' 'ProvidedByCsv';if($BestPractices){Add-BestPracticeEvidenceError $r.NasServer $r.ShareName 'UnsupportedServerConfiguration' 'NAS SMB server settings were not queried or inferred.'};if($CollectAuditEvidence){Add-BestPracticeEvidenceError $r.NasServer $r.ShareName 'UnsupportedAuditPolicy' 'NAS audit policy was not queried or inferred.';Add-BestPracticeEvidenceError $r.NasServer $r.ShareName 'UnsupportedRootSacl' 'NAS root SACL was not queried or inferred.'};Invoke-UniqueScopeScan $r.NasServer $r.ShareName $unc 'NasShareListCsv'}}
 foreach($Root in @($UncPath|Sort-Object -Unique)){
  $Root=(ConvertTo-DisplayPath $Root).TrimEnd('\')
  if($Root -notmatch '^\\\\[^\\]+\\[^\\]+' -or @($Root.TrimStart('\').Split('\')|Where-Object{$_ -in @('.','..')}).Count -gt 0){
   Add-RunError GenericUNC $Root ([ArgumentException]::new('UNC path must use \\server\share format without dot or parent-directory segments.'));continue
  }
  $parts=$Root.TrimStart('\').Split('\');$srv=$parts[0];$shr=$parts[1]
  $scopeKey=ConvertTo-NtfsCsvRecord @($srv.ToLowerInvariant(),$shr.ToLowerInvariant(),(Get-NtfsPathKey $Root))
  if($script:ScannedScopes.Contains($scopeKey)){Write-RunLog INFO DuplicateScope "Skipping previously collected scope $Root";continue}
  $rootKey=Get-NtfsPathKey $Root
  if(@($Shares|Where-Object{$_.Server -eq $srv -and $_.Share -eq $shr -and $rootKey.StartsWith((Get-NtfsPathKey $_.ScanRoot)+'\')}).Count -gt 0){
   Write-RunLog INFO DuplicateScope "Skipping overlapping subtree; retaining parent-scope evidence and its coverage limitations: $Root";continue
  }
  Add-ShareAndAclData $srv $shr $Root 'GenericSMB_UNC' 'ExplicitUNC'
  if($BestPractices){Add-BestPracticeEvidenceError $srv $shr 'UnsupportedServerConfiguration' 'Explicit UNC target was not queried for SMB server configuration; no settings were inferred.'}
  if($CollectAuditEvidence){
   $saclStatus='NotAssessed';$saclCount='';$saclDetail='Explicit UNC audit policy was not queried; only a root SACL read was attempted.'
   try{$rootAcl=Get-Acl -LiteralPath $Root -Audit -ErrorAction Stop;$saclRules=@($rootAcl.GetAuditRules($true,$true,[Security.Principal.SecurityIdentifier]));$saclCount=$saclRules.Count;$saclStatus='Collected';$saclDetail='Read SACL at explicit UNC root only; descendant SACL coverage was not collected.'}
   catch{$saclDetail=$_.Exception.Message;Add-BestPracticeEvidenceError $srv $shr 'RootSaclRead' $saclDetail}
   [void]$BpAuditRows.Add([pscustomobject]@{RunId=$RunId;Server=$srv;Share=$shr;FileShareSuccessPolicy='NotAssessed';FileSystemSuccessPolicy='NotAssessed';AuditPolicyStatus='NotAssessed';AuditPolicyDetail='Explicit UNC audit policy was not queried; local auditpol does not apply.';RootSaclStatus=$saclStatus;RootSaclAuditRuleCount=$saclCount;RootSaclDetail=$saclDetail})
  }
  Invoke-UniqueScopeScan $srv $shr $Root 'GenericSMB_UNC'
 }
 if(-not [string]::IsNullOrWhiteSpace($OntapSharePermissionsCsv)){
  try{Import-OntapPermissions $OntapSharePermissionsCsv}
  catch{Add-RunError OntapCsvImport $OntapSharePermissionsCsv $_.Exception}
 }
 $GroupExpansion=New-Object Collections.ArrayList
 if($AdReady){
  function Expand-GroupRecursive([string]$RootIdentity,[string]$GroupDn,[string]$GroupSID,[string]$GroupPath,[string]$DirectoryServer,[int]$Depth,[hashtable]$Ancestors){
   if($Ancestors.ContainsKey($GroupDn)){$script:ExpansionStatus='PartialCycle';return}
   if($Depth -gt 10){$script:ExpansionStatus='PartialDepthLimit';return}
   $Ancestors[$GroupDn]=$true
   try{
    $args=@{Identity=$GroupDn;ErrorAction='Stop'};if($DirectoryServer){$args.Server=$DirectoryServer}
    $directMembers=@(Get-ADGroupMember @args)
    foreach($m in $directMembers){
     if($script:ExpandedCount -ge $MaxExpandedMembers){$script:ExpansionStatus='PartialMemberLimit';return}
     if($m.ObjectClass -notin @('group','user','computer')){$script:ExpansionStatus='PartialUnsupportedMember'}
     $enabled='N/A'
     if($m.ObjectClass -eq 'user'){
      $userArgs=@{Identity=$m.DistinguishedName;Properties='Enabled';ErrorAction='Stop'}
      if($DirectoryServer){$userArgs.Server=$DirectoryServer}
      try{$enabled=[string](Get-ADUser @userArgs).Enabled}
      catch{$enabled='Unknown';$script:ExpansionStatus='PartialLookupFailure';Add-RunError GroupUserLookup $m.DistinguishedName $_.Exception}
     }
     $nestedPath=if($m.ObjectClass -eq 'group'){"$GroupPath->$($m.Name)"}else{$GroupPath}
     [void]$Members.Add([pscustomobject]@{
      RunId=$RunId;GroupIdentity=$RootIdentity;GroupSID=$GroupSID;MemberSID=[string]$m.SID
      MemberName=$m.Name;MemberSamAccountName=$m.SamAccountName;MemberObjectClass=$m.ObjectClass
      MemberDistinguishedName=$m.DistinguishedName;MemberEnabled=$enabled;GroupPath=$GroupPath;NestedGroupPath=$nestedPath
     })
     $script:ExpandedCount++
     if($Members.Count -ge 1000){Append-Safe $Members 'GroupMemberships.csv';$Members.Clear()}
     if($m.ObjectClass -eq 'group'){Expand-GroupRecursive $RootIdentity $m.DistinguishedName $GroupSID $nestedPath $DirectoryServer ($Depth+1) $Ancestors}
    }
   }catch{$script:ExpansionStatus='PartialLookupFailure';Add-RunError GroupExpand $GroupDn $_.Exception}
   finally{[void]$Ancestors.Remove($GroupDn)}
  }
  foreach($id in @($Identities.Keys)){
   $identity=$Identities[$id]
   if($identity.ObjectClass -ne 'group'){continue}
   $script:ExpandedCount=0;$script:ExpansionStatus='Complete'
   Expand-GroupRecursive $id $identity.DistinguishedName $identity.SID $identity.ResolvedName $identity.DirectoryServer 0 @{}
   [void]$GroupExpansion.Add([pscustomobject]@{RunId=$RunId;GroupIdentity=$id;GroupSID=$identity.SID;Status=$script:ExpansionStatus;MemberCount=$script:ExpandedCount})
   if($script:ExpansionStatus -ne 'Complete'){Write-RunLog WARN GroupExpand "$id : $script:ExpansionStatus"}
  }
 }
 if($IncludeLocalGroups){try{foreach($g in @(Get-LocalGroup)){try{foreach($m in @(Get-LocalGroupMember $g.Name -ErrorAction Stop)){[void]$LocalMembers.Add([pscustomobject]@{Server=$CollectorHost;Group=$g.Name;Member=$m.Name;ObjectClass=$m.ObjectClass;PrincipalSource=$m.PrincipalSource;SID=$m.SID.Value})}}catch{Add-RunError LocalGroup $g.Name $_.Exception}}}catch{Add-RunError LocalGroups $CollectorHost $_.Exception}}
}catch{$Fatal=$_.Exception.Message;Write-RunLog ERROR Fatal $Fatal}
finally{
 try{
 try{
  Flush-LargeBuffers
  Append-Safe $Members 'GroupMemberships.csv'
  foreach($name in @('Folders.csv','NtfsAcls.csv','GroupAcesFound.csv','GroupMemberships.csv')){
   if(-not $script:CsvWriters.ContainsKey($name)){Export-Safe @() $name}
  }
  $uniqueShareAcl=@(Get-UniqueSharePermissions $ShareAcl)
  Export-Safe $Servers Servers.csv;Export-Safe $Shares Shares.csv;Export-Safe $uniqueShareAcl SharePermissions.csv
  Export-Safe @($Identities.Values) Identities.csv;Export-Safe $LocalMembers LocalGroupMemberships.csv
  Export-Safe $Errors ScanErrors.csv;Export-Safe $SkippedPaths SkippedPaths.csv;Export-Safe $ShareCoverage ShareCoverage.csv
  if(Get-Variable GroupExpansion -ErrorAction SilentlyContinue){Export-Safe $GroupExpansion GroupExpansion.csv}else{Export-Safe @() GroupExpansion.csv}
  if($BestPractices){
   if($CollectAuditEvidence){Export-Safe $BpAuditRows AuditEvidence.csv}
   Export-Safe $BpEvidenceErrors BestPracticesErrors.csv
   Write-NtfsBestPracticesReport $RunFolder $RunFolder $BpPolicy -PolicyAlreadyParsed
  }
 }finally{foreach($state in $script:CsvWriters.Values){$state.Writer.Dispose()}}
 $memberCount=if($script:CsvWriters.ContainsKey('GroupMemberships.csv')){$script:CsvWriters['GroupMemberships.csv'].Writer.Rows}else{0}
 $safeParameters=[ordered]@{}
 foreach($key in $PSBoundParameters.Keys){if($PSBoundParameters[$key] -isnot [pscredential]){$safeParameters[$key]=$PSBoundParameters[$key]}}
 if($safeParameters.Contains('BestPracticesPolicyPath') -and $BestPracticesPolicyPath){$safeParameters.BestPracticesPolicyPath=[IO.Path]::GetFileName($BestPracticesPolicyPath)}
 $partial=$Errors.Count -gt 0 -or $SkippedPaths.Count -gt 0
 if(Get-Variable GroupExpansion -ErrorAction SilentlyContinue){$partial=$partial -or @($GroupExpansion|Where-Object Status -ne 'Complete').Count -gt 0}
 Write-RunLog INFO Finalize "Targets=$($Servers.Count); Shares=$($Shares.Count); Folders=$($script:TotalFolders); ACEs=$($script:TotalAces); Errors=$($Errors.Count); Partial=$partial; Scope=DirectoriesOnly"
 $manifest=[ordered]@{
  SchemaVersion='1.3';ToolkitVersion=$ToolkitVersion;RunId=$RunId;ReadOnly=$true;CollectorHost=$CollectorHost
  Parameters=$safeParameters;EffectiveExcludeShare=$EffectiveExcludeShare;CompletedUtc=[datetime]::UtcNow.ToString('o');FatalError=$Fatal
  CollectionScope='DirectoriesOnly';CoverageStatus=$(if($partial){'Partial'}else{'CompleteDirectoriesOnly'});MaxCsvFileBytes=100000000
  Scopes=@($Shares|Select-Object Server,Share,ScanRoot);Datasets=@(Get-NtfsDatasetInventory $RunFolder)
  Counts=[ordered]@{Targets=$Servers.Count;Shares=$Shares.Count;ShareAces=$uniqueShareAcl.Count;Folders=$script:TotalFolders;NtfsAces=$script:TotalAces;LargeBufferFlushes=$script:LargeBufferFlushes;Identities=$Identities.Count;ExpandedMembers=$memberCount;SkippedPaths=$SkippedPaths.Count;CoverageRows=$ShareCoverage.Count;Errors=$Errors.Count}
 }
 if($BestPractices){
  $policyCopy=Join-Path $RunFolder 'BestPracticesPolicy.json';$summaryFile=Join-Path $RunFolder 'BestPracticeSummary.json'
  $manifest.BestPractices=[ordered]@{
   Version=$script:NtfsBestPracticesVersion
   Enabled=$true;AuditEvidenceCollected=[bool]$CollectAuditEvidence
   PolicySHA256=$(if($null -ne $BpPolicy){$BpPolicy.SHA256}else{''})
   PolicyFile=$(if($null -ne $BpPolicy){[ordered]@{Name='BestPracticesPolicy.json';Bytes=(Get-Item -LiteralPath $policyCopy).Length;SHA256=(Get-FileHash -LiteralPath $policyCopy -Algorithm SHA256).Hash}}else{$null})
   SummaryFile=[ordered]@{Name='BestPracticeSummary.json';Bytes=(Get-Item -LiteralPath $summaryFile).Length;SHA256=(Get-FileHash -LiteralPath $summaryFile -Algorithm SHA256).Hash}
   EvidenceErrorCount=$BpEvidenceErrors.Count
   EvidenceStatus=$(if($BpEvidenceErrors.Count -gt 0){'PartialEvidence'}else{'Collected'})
   EvidenceErrorDataset='BestPracticesErrors.csv'
   ReferenceRetrievedUtc='2026-10-30';ReadOnly=$true
  }
 }
 $pendingManifest=Join-Path $RunFolder 'manifest.pending'
 $manifest|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $pendingManifest -Encoding UTF8
 if($HashOutputs){
  $hashRows=@(
   foreach($file in (Get-ChildItem -LiteralPath $RunFolder -Recurse -File|Where-Object Name -ne 'manifest.pending')){
    Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256|Select-Object Path,Hash,Algorithm
   }
   [pscustomobject]@{Path=(Join-Path $RunFolder 'manifest.json');Hash=(Get-FileHash -LiteralPath $pendingManifest -Algorithm SHA256).Hash;Algorithm='SHA256'}
  )
  Export-Safe $hashRows SHA256SUMS.csv
 }
 Move-Item -LiteralPath $pendingManifest -Destination (Join-Path $RunFolder 'manifest.json') -ErrorAction Stop
 }catch{
  $Fatal="Output finalization failed: $($_.Exception.Message)"
  Write-Error -Message $Fatal -ErrorAction Continue
  try{Write-RunLog ERROR Finalization $Fatal}catch{Write-Error -Message "Unable to record finalization failure: $($_.Exception.Message)" -ErrorAction Continue}
 }
}
if($Fatal){exit 2}elseif($partial){exit 1}else{exit 0}
