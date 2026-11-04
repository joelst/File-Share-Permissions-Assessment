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

param([Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$FailChecksum,[switch]$DuplicateScopes,[switch]$LocalContainment,[switch]$LocalExplicitContainment,[switch]$ExplicitContainment,[switch]$ExcludedOnly,[string]$OntapCsv,[switch]$BestPractices,[string]$PolicyPath,[switch]$Audit,[switch]$FailServerConfiguration,[switch]$ExplicitUnc,[switch]$LocalScan)
$ErrorActionPreference='Stop'
$env:COMPUTERNAME='MOCK'
$global:NtfsTestFailChecksum=[bool]$FailChecksum
$global:NtfsTestFailServerConfiguration=[bool]$FailServerConfiguration
function New-Object {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$TypeName,[Parameter(Position=1)][object[]]$ArgumentList)
    if($TypeName -like 'Security.Principal.*'){throw 'Identity translation deliberately disabled by the offline test harness.'}
    $value=Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
    return ,$value
}
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath,[string]$PathType)
    if($LiteralPath.StartsWith('\\')){return $true}
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath,[switch]$Force)
    if($LiteralPath.StartsWith('\\')){
        return [pscustomobject]@{LastWriteTimeUtc=[datetime]::UtcNow;Attributes=[IO.FileAttributes]::Directory}
    }
    Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}
function Get-Acl {
    [CmdletBinding()]
    param([string]$LiteralPath,[switch]$Audit,$InputObject)
    if(-not $LiteralPath.StartsWith('\\') -and -not (Test-Path -LiteralPath $LiteralPath)){throw 'Mock ACL reader only accepts synthetic paths.'}
    [pscustomobject]@{
        Owner='TEST\Owner';AreAccessRulesProtected=$true;Sddl=''
        Access=@([pscustomobject]@{
            IdentityReference=[pscustomobject]@{Value='TEST\User'};AccessControlType='Allow'
            FileSystemRights=262144;IsInherited=$false;InheritanceFlags='ContainerInherit, ObjectInherit';PropagationFlags='InheritOnly'
        })
    }
}
function Get-FileHash {
    [CmdletBinding()]
    param([string]$LiteralPath,[string]$Algorithm)
    if($global:NtfsTestFailChecksum -and $LiteralPath.EndsWith('manifest.pending')){throw 'Synthetic checksum finalization failure.'}
    Microsoft.PowerShell.Utility\Get-FileHash @PSBoundParameters
}
function Get-SmbShare {
    [CmdletBinding()]param()
    [pscustomobject]@{Name=$(if($ExcludedOnly){'C$'}else{'data'});Path=$(if($BestPractices -or $LocalScan){Join-Path (Split-Path $OutputRoot -Parent) 'mock-share'}else{Split-Path $OutputRoot -Parent});Description='synthetic';EncryptData=$false;ContinuouslyAvailable=$false;FolderEnumerationMode='AccessBased'}
}
function Get-CimInstance {
    [CmdletBinding()]param([Parameter(Position=0)][string]$ClassName)
    [pscustomobject]@{Domain='Offline';Caption='Mock Windows';Version='Test'}
}
function Get-SmbServerConfiguration {
    [CmdletBinding()]param($CimSession)
    if($global:NtfsTestFailServerConfiguration){throw 'Synthetic access denied to SMB server configuration.'}
    [pscustomobject]@{EnableSMB1Protocol=$false;RequireSecuritySignature=$true}
}
function Get-SmbShareAccess {
    [CmdletBinding()]param([string]$Name,$CimSession)
    @([pscustomobject]@{AccountName='Everyone';SID='S-1-1-0';AccessControlType='Allow';AccessRight='Change'})
}
if($LocalContainment -or $ExcludedOnly){
    & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-NtfsAssessment.ps1') -OutputRoot $OutputRoot -ComputerName $env:COMPUTERNAME
    exit $LASTEXITCODE
}
if($ExplicitContainment){
    function New-Item {
        [CmdletBinding()]param([string]$ItemType,[string]$Path,[switch]$Force)
        throw 'Synthetic forbidden directory creation was attempted.'
    }
    & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-NtfsAssessment.ps1') -OutputRoot $OutputRoot -UncPath '\\server\data'
    exit $LASTEXITCODE
}
if($BestPractices -or $LocalScan){
    $mockShare=Join-Path (Split-Path $OutputRoot -Parent) 'mock-share'
    [void](New-Item -ItemType Directory -Path $mockShare -Force)
    $arguments=@{OutputRoot=$OutputRoot;ComputerName='MOCK';MaxDepth=1;BestPractices=[bool]$BestPractices}
    if($ExplicitUnc){
        $arguments.Remove('ComputerName')
        $arguments.UncPath='\\server\data'
        $arguments.MaxDepth=0
        $arguments.SplitOutputByShare=$true
        $arguments.HashOutputs=$true
    }
    if($PolicyPath){$arguments.BestPracticesPolicyPath=$PolicyPath}
    if($Audit){$arguments.CollectAuditEvidence=$true}
    & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-NtfsAssessment.ps1') @arguments
    exit $LASTEXITCODE
}
$paths=@('\\server\data')
if($LocalExplicitContainment){$paths=@('\\mock\data')}
if($DuplicateScopes){$paths=@('\\server\data','\\SERVER\DATA','\\server\data\','\\server\data\child')}
& (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-NtfsAssessment.ps1') -OutputRoot $OutputRoot -UncPath $paths -OntapSharePermissionsCsv $OntapCsv -MaxDepth 0 -SplitOutputByShare -HashOutputs
exit $LASTEXITCODE
