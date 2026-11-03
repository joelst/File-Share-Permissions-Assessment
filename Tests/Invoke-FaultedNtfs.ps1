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

param([string]$Tool,[string]$InputPath,[string]$Baseline,[string]$Comparison,[string]$OutputFolder,[switch]$FailAnalysis)
$ErrorActionPreference='Stop'
function Remove-Item {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string]$LiteralPath,[switch]$Recurse,[switch]$Force)
    if((Split-Path $LiteralPath -Leaf) -like '_temp_*'){throw [IO.IOException]::new('Synthetic cleanup deletion failure.')}
    Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
}
$arguments=@{OutputFolder=$OutputFolder}
if($FailAnalysis){$arguments.MaxRowsPerShare=1}
if($Tool -eq 'Merge'){
    $arguments.InputRoot=Split-Path $InputPath -Parent
    $arguments.RunSelection='Explicit';$arguments.RunFolder=@($InputPath)
    & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Merge-NtfsAssessment_v2.8.1.ps1') @arguments
}else{
    $arguments.BaselineRunFolder=$Baseline;$arguments.ComparisonRunFolder=$Comparison
    & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Compare-NtfsAssessment.ps1') @arguments
}
exit $LASTEXITCODE
