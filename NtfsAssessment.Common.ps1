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

Set-StrictMode -Version Latest

# Release versions are defined only here; schema versions and compatibility floors
# remain at their call sites. Shared engines and their entry points use the same key.
$script:NtfsVersions = @{
    Assessment = '1.7.2'
    Comparison = '1.0.4'
    Merge = '2.8.6'
    BestPractices = '1.1.2'
    Permissions = '0.2.3-unqualified'
    PermissionValidation = '0.1.2'
}

function Write-NtfsLog([string]$Path,[string]$Component,[string]$Level,[string]$Stage,[string]$Message='') {
    if (-not $script:NtfsVersions.ContainsKey($Component)) { throw "Unknown version component: $Component" }
    foreach ($messageLine in [regex]::Split($Message, '\r\n|\r|\n')) {
        $line = "{0:o}`t{1}`t{2}`tComponent={3}`tVersion={4}`t{5}" -f [datetime]::UtcNow,$Level,$Stage,$Component,$script:NtfsVersions[$Component],$messageLine
        Add-Content -LiteralPath $Path -Value $line -Encoding UTF8 -ErrorAction Stop
        Write-Verbose $line
    }
}

function Format-NtfsCompletionText {
    <#
    .SYNOPSIS
    Wraps completion prose without splitting words or long paths.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$text,
        [string]$prefix='  ',
        [string]$continuationPrefix='  '
    )
    $lines=New-Object 'Collections.Generic.List[string]'
    $paragraphPrefix=$prefix
    foreach($paragraph in [regex]::Split($text.Trim(),'(?<=[.!?])\s+(?=[A-Z])')){
        $line=$paragraphPrefix
        $hasWord=$false
        foreach($word in [regex]::Split($paragraph,'\s+')){
            $separator=if($hasWord){' '}else{''}
            if($hasWord -and $line.Length+$separator.Length+$word.Length -gt 100){
                $lines.Add($line)
                $line=$continuationPrefix
                $separator=''
            }
            $line+=$separator+$word
            $hasWord=$true
        }
        $lines.Add($line)
        $paragraphPrefix=$continuationPrefix
    }
    return $lines -join "`n"
}

function Write-NtfsCompletion {
    <#
    .SYNOPSIS
    Displays workflow status and review guidance without adding success-stream data.
    .DESCRIPTION
    Sections are separated by blank lines and prose is wrapped at 100 columns.
    Optional next-command arguments are quoted as literal strings for PowerShell
    and displayed on separate lines using PowerShell continuation characters.
    The command is displayed only; no next step is executed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$component,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$status,
        [string]$summary,
        [string]$outputPath,
        [string[]]$reviewPath=@(),
        [string]$requirements,
        [object[]]$reasonSummary=@(),
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$nextStep,
        [string]$nextScriptPath,
        [Collections.IDictionary]$nextParameters=@{}
    )
    Write-Information -MessageData '' -Tags 'NtfsCompletion' -InformationAction Continue
    Write-Information -MessageData "$($component): $($status)." -Tags 'NtfsCompletion' -InformationAction Continue
    if($summary){
        Write-Information -MessageData (Format-NtfsCompletionText -text $summary) -Tags 'NtfsCompletion' -InformationAction Continue
    }
    if ($outputPath) {
        Write-Information -MessageData '' -Tags 'NtfsCompletion' -InformationAction Continue
        Write-Information -MessageData "Output: $($outputPath)" -Tags 'NtfsCompletion' -InformationAction Continue
    }
    if($reviewPath.Count){
        Write-Information -MessageData '' -Tags 'NtfsCompletion' -InformationAction Continue
        Write-Information -MessageData 'Review:' -Tags 'NtfsCompletion' -InformationAction Continue
        foreach ($path in $reviewPath) {
            Write-Information -MessageData "  $($path)" -Tags 'NtfsCompletion' -InformationAction Continue
        }
    }
    if ($requirements) {
        Write-Information -MessageData '' -Tags 'NtfsCompletion' -InformationAction Continue
        Write-Information -MessageData 'Resolve/review:' -Tags 'NtfsCompletion' -InformationAction Continue
        Write-Information -MessageData (Format-NtfsCompletionText -text $requirements) -Tags 'NtfsCompletion' -InformationAction Continue
    }
    $reasons=@($reasonSummary | Sort-Object @{
        Expression={if($_.PSObject.Properties.Name -contains 'Status' -and $_.Status -eq 'NotAssessed'){0}else{1}}
    },@{Expression='Count';Descending=$true},Reason)
    if($reasons.Count){
        Write-Information -MessageData '' -Tags 'NtfsCompletion' -InformationAction Continue
        Write-Information -MessageData 'Reasons:' -Tags 'NtfsCompletion' -InformationAction Continue
    }
    foreach ($reason in @($reasons | Select-Object -First 5)) {
        $text=([string]$reason.Reason -replace '\r\n|\r|\n',' ').Trim()
        if($reason.PSObject.Properties.Name -contains 'Status'){
            if($reason.PSObject.Properties.Name -contains 'CheckId'){
                $diagnosticPrefix="$($reason.CheckId) [$($reason.Status)]: "
                if($text.StartsWith($diagnosticPrefix,[StringComparison]::Ordinal)){
                    $text=$text.Substring($diagnosticPrefix.Length)
                }
            }
            $text="$($reason.Status): $($text)"
        }
        $unit=if($reason.Count -eq 1){'record'}else{'records'}
        $prefix="  - ($($reason.Count) $($unit)): "
        Write-Information -MessageData (Format-NtfsCompletionText -text $text -prefix $prefix -continuationPrefix '    ') -Tags 'NtfsCompletion' -InformationAction Continue
    }
    if ($reasons.Count -gt 5) {
        Write-Information -MessageData "  More reasons: $($reasons.Count-5) additional groups; see the listed reports/logs." -Tags 'NtfsCompletion' -InformationAction Continue
    }
    Write-Information -MessageData '' -Tags 'NtfsCompletion' -InformationAction Continue
    Write-Information -MessageData 'Next:' -Tags 'NtfsCompletion' -InformationAction Continue
    Write-Information -MessageData (Format-NtfsCompletionText -text $nextStep) -Tags 'NtfsCompletion' -InformationAction Continue
    if ($nextScriptPath) {
        $command = "& '{0}'" -f $nextScriptPath.Replace("'","''")
        foreach ($entry in $nextParameters.GetEnumerator()) {
            $command += ' `'+ "`n" + ("    -{0} '{1}'" -f $entry.Key,([string]$entry.Value).Replace("'","''"))
        }
        Write-Information -MessageData '' -Tags 'NtfsCompletion' -InformationAction Continue
        Write-Information -MessageData "  $($command)" -Tags 'NtfsCompletion' -InformationAction Continue
    }
}

if ($null -eq ('NtfsAssessment.CsvPartWriter' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtfsAssessment {
    public sealed class CsvPartWriter : IDisposable {
        private readonly string path;
        private readonly long limit;
        private readonly UTF8Encoding encoding = new UTF8Encoding(true, true);
        private StreamWriter writer;
        private string header;
        private long bytes;
        private int part;
        private bool disposed;
        private int columns;
        public readonly List<string> Parts = new List<string>();
        public long Rows { get; private set; }
        public string Header { get { return header; } }
        public string Path { get { return path; } }

        public CsvPartWriter(string path, long limit) {
            this.path = System.IO.Path.GetFullPath(path);
            if (limit < 8) throw new ArgumentOutOfRangeException("limit");
            this.limit = limit;
        }
        private long Size(string value) { return encoding.GetByteCount(value) + 2L; }
        private void OpenPart() {
            if (writer != null) writer.Dispose();
            part++;
            string name = part == 1 ? path : System.IO.Path.Combine(
                System.IO.Path.GetDirectoryName(path),
                System.IO.Path.GetFileNameWithoutExtension(path) + "_" + part + ".csv");
            writer = new StreamWriter(new FileStream(name, FileMode.CreateNew, FileAccess.Write, FileShare.Read), encoding);
            writer.NewLine = "\r\n";
            Parts.Add(name);
            writer.WriteLine(header);
            bytes = encoding.GetPreamble().Length + Size(header);
        }
        public void WriteLine(string record) {
            if (disposed) throw new ObjectDisposedException("CsvPartWriter");
            if (record == null) throw new ArgumentNullException("record");
            string[] fields = Csv.Parse(record);
            if (header == null) {
                if (encoding.GetPreamble().Length + Size(record) > limit)
                    throw new InvalidDataException("CSV header exceeds the file size limit.");
                header = record;
                columns = fields.Length;
                OpenPart();
                return;
            }
            if (fields.Length != columns)
                throw new InvalidDataException("CSV record does not match the header column count.");
            long size = Size(record);
            if (encoding.GetPreamble().Length + Size(header) + size > limit)
                throw new InvalidDataException("One CSV record plus its header exceeds the file size limit.");
            if (bytes + size > limit) OpenPart();
            writer.WriteLine(record);
            bytes += size;
            Rows++;
        }
        public void Flush() { if (writer != null && !disposed) writer.Flush(); }
        public void Close() { Dispose(); }
        public void Dispose() {
            if (!disposed) {
                disposed = true;
                if (writer != null) writer.Dispose();
            }
        }
    }

    public static class Csv {
        public static string ReadRecord(StreamReader reader) {
            StringBuilder record = new StringBuilder();
            bool quoted = false;
            while (true) {
                int next = reader.Read();
                if (next < 0) {
                    if (quoted) throw new InvalidDataException("Unterminated quoted CSV record.");
                    return record.Length == 0 ? null : record.ToString();
                }
                char ch = (char)next;
                if (ch == '"') quoted = !quoted;
                if (!quoted && (ch == '\r' || ch == '\n')) {
                    if (ch == '\r' && reader.Peek() == '\n') reader.Read();
                    return record.ToString();
                }
                record.Append(ch);
                if (record.Length > 100000000)
                    throw new InvalidDataException("CSV input record exceeds the supported size.");
            }
        }
        public static string[] Parse(string record) {
            if (record == null) throw new ArgumentNullException("record");
            List<string> fields = new List<string>();
            StringBuilder field = new StringBuilder();
            bool quoted = false, closed = false, start = true;
            for (int i = 0; i < record.Length; i++) {
                char ch = record[i];
                if (quoted) {
                    if (ch == '"') {
                        if (i + 1 < record.Length && record[i + 1] == '"') { field.Append('"'); i++; }
                        else { quoted = false; closed = true; }
                    } else field.Append(ch);
                } else if (ch == ',') {
                    fields.Add(field.ToString()); field.Length = 0; closed = false; start = true;
                } else if (ch == '"' && start) {
                    quoted = true; start = false;
                } else {
                    if (closed || ch == '"' || ch == '\r' || ch == '\n')
                        throw new InvalidDataException("Malformed CSV record.");
                    field.Append(ch); start = false;
                }
            }
            if (quoted) throw new InvalidDataException("Unterminated quoted CSV field.");
            fields.Add(field.ToString());
            return fields.ToArray();
        }
    }
}
'@ -ErrorAction Stop
}

function Get-NtfsHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-NtfsPathKey([string]$Path) {
    $value=$Path.Replace('/','\')
    if($value.StartsWith('\\?\UNC\',[StringComparison]::OrdinalIgnoreCase)){$value='\\'+$value.Substring(8)}
    elseif($value.StartsWith('\\?\')){$value=$value.Substring(4)}
    return $value.TrimEnd('\').ToLowerInvariant()
}

function Get-NtfsPrincipalKey([string]$Name,[string]$SID='') {
    if($SID){
        if($SID -notmatch '^S-1-\d+(?:-\d+)+$'){throw "Invalid collected SID: $SID"}
        return $SID.ToUpperInvariant()
    }
    if($Name -match '^S-1-\d+(?:-\d+)+$'){return $Name.ToUpperInvariant()}
    $aliases=@{
        'Everyone'='S-1-1-0';'NT AUTHORITY\Authenticated Users'='S-1-5-11'
        'NT AUTHORITY\SYSTEM'='S-1-5-18';'BUILTIN\Administrators'='S-1-5-32-544'
        'BUILTIN\Users'='S-1-5-32-545';'BUILTIN\Guests'='S-1-5-32-546'
    }
    if($aliases.ContainsKey($Name)){return $aliases[$Name]}
    return ''
}

function Assert-NtfsScopeRoots($Scopes) {
    $groups=@{}
    foreach($scope in $Scopes){
        $key=ConvertTo-NtfsCsvRecord @($scope.Server,$scope.Share)
        $root=if($scope.PSObject.Properties.Name -contains 'ScanRoot'){[string]$scope.ScanRoot}else{''}
        if(-not $root -and $scope.PSObject.Properties.Name -contains 'UNC'){$root=[string]$scope.UNC}
        $root=Get-NtfsPathKey $root
        if(-not $groups.ContainsKey($key)){$groups[$key]=[Collections.ArrayList]::new()}
        foreach($other in $groups[$key]){
            if($root -eq $other -or -not $root -or -not $other){continue}
            if($root.StartsWith('\\') -ne $other.StartsWith('\\')){
                throw "Ambiguous mixed local/UNC addressing for $key. Collect one addressing form per share."
            }
            if($root.StartsWith($other+'\') -or $other.StartsWith($root+'\')){
                throw "Overlapping assessment roots for $key : $other and $root. Collect disjoint subtrees or one parent root."
            }
        }
        [void]$groups[$key].Add($root)
    }
}

function ConvertTo-NtfsMappedPath([string]$Path,$Mappings=@()) {
    $key=Get-NtfsPathKey $Path
    $mapped=$null
    foreach($mapping in $Mappings){
        $unc=Get-NtfsPathKey $mapping.UNC
        if($key -eq $unc -or $key.StartsWith($unc+'\',[StringComparison]::OrdinalIgnoreCase)){
            $candidate=(Get-NtfsPathKey $mapping.LocalPath)+$key.Substring($unc.Length)
            if($null -ne $mapped -and $mapped -ne $candidate){throw "Conflicting known local share mappings for $Path"}
            $mapped=$candidate
        }
    }
    if($null -ne $mapped){return $mapped}
    return $key
}

function Assert-NtfsOutputOutsideScope([string]$OutputPath,[string]$Root,$Mappings=@()) {
    if(-not $Root){return}
    $output=ConvertTo-NtfsMappedPath $OutputPath $Mappings
    $source=ConvertTo-NtfsMappedPath $Root $Mappings
    if($output -eq $source -or $output.StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase)){
        throw "Output path must be outside assessed tree: $Root"
    }
}

function Get-NtfsFailureReason([Exception]$Exception) {
    $current=$Exception
    while($null -ne $current){
        if($current -is [UnauthorizedAccessException] -or $current -is [Security.SecurityException]){return 'PermissionDenied'}
        if($current -is [TimeoutException]){return 'Timeout'}
        if($current -is [IO.FileNotFoundException] -or $current -is [IO.DirectoryNotFoundException] -or $current -is [Management.Automation.ItemNotFoundException]){return 'PathNotFound'}
        if($current -is [Net.Sockets.SocketException] -or $current -is [Net.WebException]){return 'NetworkError'}
        if($current -is [IO.IOException] -or $current -is [ComponentModel.Win32Exception]){
            $code=$current.HResult -band 65535
            if($current -is [ComponentModel.Win32Exception]){$code=$current.NativeErrorCode}
            if($code -in @(121,1460)){return 'Timeout'}
            if($code -in @(53,64,67,1231,1232)){return 'NetworkError'}
        }
        $current=$current.InnerException
    }
    return 'CollectionError'
}

function Invoke-NtfsCleanup([scriptblock[]]$Actions) {
    foreach($action in $Actions){
        try{& $action}catch{"Cleanup failed: $($_.Exception.Message)"}
    }
}

function ConvertTo-NtfsCsvRecord([object[]]$Values) {
    return '"' + ((@($Values | ForEach-Object { ([string]$_).Replace('"','""') })) -join '","') + '"'
}

function Get-NtfsCsvFiles([string]$Directory, [string]$FileName) {
    $manifestPath = Join-Path $Directory 'manifest.json'
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($FileName -ne 'SHA256SUMS.csv' -and $manifest.PSObject.Properties.Name -contains 'Datasets') {
            $dataset = @($manifest.Datasets | Where-Object { $_.Name -eq $FileName })
            if ($dataset.Count -eq 0) { return }
            if ($dataset.Count -ne 1) { throw "Duplicate dataset in manifest: $FileName" }
            if (@($dataset[0].Parts).Count -eq 0) { throw "Dataset has no parts: $FileName" }
            $number=0
            foreach ($part in $dataset[0].Parts) {
                $number++
                $name = [string]$part.Name
                $expected=if($number -eq 1){$FileName}else{[IO.Path]::GetFileNameWithoutExtension($FileName)+"_$number.csv"}
                if ($name -ne $expected) { throw "Missing or out-of-order CSV part: expected $expected, found $name" }
                if ([IO.Path]::GetFileName($name) -ne $name -or $name -match '[\\/]') { throw "Invalid dataset part: $name" }
                $file = Get-Item -LiteralPath (Join-Path $Directory $name) -ErrorAction Stop
                if ($file.Length -ne [long]$part.Bytes -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $part.SHA256) {
                    throw "Dataset integrity check failed: $($file.FullName)"
                }
                $file
            }
            return
        }
    }
    $base = [regex]::Escape([IO.Path]::GetFileNameWithoutExtension($FileName))
    $files=@(Get-ChildItem -LiteralPath $Directory -File -ErrorAction Stop |
        Where-Object { $_.Name -match "^${base}(_\d+)?\.csv$" } |
        Sort-Object @{Expression={if ($_.BaseName -match '_(\d+)$') {[int]$Matches[1]} else {1}}})
    for($i=0;$i -lt $files.Count;$i++){
        $expected=if($i -eq 0){$FileName}else{[IO.Path]::GetFileNameWithoutExtension($FileName)+"_$($i+1).csv"}
        if($files[$i].Name -ne $expected){throw "Missing CSV part: $expected"}
        $files[$i]
    }
}

function Read-NtfsCsvFile([string]$Path, [string[]]$RequiredColumns = @()) {
    $reader = [IO.StreamReader]::new($Path, [Text.Encoding]::UTF8, $true)
    try {
        $header = [NtfsAssessment.Csv]::ReadRecord($reader)
        if ([string]::IsNullOrWhiteSpace($header)) { return }
        $columns = [NtfsAssessment.Csv]::Parse($header)
        if (@($columns | Sort-Object -Unique).Count -ne $columns.Count -or $columns -contains '') {
            throw "Duplicate or empty CSV columns: $Path"
        }
        foreach ($required in $RequiredColumns) {
            if ($columns -notcontains $required) { throw "Missing column '$required': $Path" }
        }
        while ($null -ne ($record = [NtfsAssessment.Csv]::ReadRecord($reader))) {
            if ($record.Length -eq 0) { continue }
            $fields = [NtfsAssessment.Csv]::Parse($record)
            if ($fields.Length -ne $columns.Length) { throw "CSV column count mismatch: $Path" }
            $row = [ordered]@{}
            for ($i=0; $i -lt $columns.Length; $i++) { $row[$columns[$i]] = $fields[$i] }
            [pscustomobject]$row
        }
    } finally { $reader.Dispose() }
}

function New-NtfsCsvWriter([string]$Path, [long]$MaxBytes = 100000000) {
    return [NtfsAssessment.CsvPartWriter]::new($Path, $MaxBytes)
}

function Export-NtfsCsvData($Rows, [string]$Path, [long]$MaxBytes = 100000000) {
    $writer = New-NtfsCsvWriter $Path $MaxBytes
    try {
        $columns = $null
        foreach ($row in $Rows) {
            if ($null -eq $columns) {
                $columns = @($row.PSObject.Properties.Name)
                $writer.WriteLine((ConvertTo-NtfsCsvRecord $columns))
            }
            $writer.WriteLine((ConvertTo-NtfsCsvRecord @($columns | ForEach-Object { $row.$_ })))
        }
        if ($null -eq $columns) {
            $empty=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            $empty.Dispose()
        }
    } finally { $writer.Dispose() }
}

function Get-NtfsDatasetInventory([string]$Directory) {
    $sets = @{}
    foreach ($file in (Get-ChildItem -LiteralPath $Directory -File -Filter '*.csv' | Where-Object Name -ne 'SHA256SUMS.csv')) {
        $name = $file.Name -replace '_\d+\.csv$', '.csv'
        if (-not $sets.ContainsKey($name)) { $sets[$name] = [Collections.ArrayList]::new() }
        [void]$sets[$name].Add($file)
    }
    foreach ($name in @($sets.Keys | Sort-Object)) {
        $rowCount=0L;$columns=@()
        $parts = @(
            foreach ($file in ($sets[$name] | Sort-Object @{Expression={if ($_.BaseName -match '_(\d+)$') {[int]$Matches[1]} else {1}}})) {
                $reader=[IO.StreamReader]::new($file.FullName,[Text.Encoding]::UTF8,$true)
                $partRows=0L
                try{
                    $header=[NtfsAssessment.Csv]::ReadRecord($reader)
                    if(-not [string]::IsNullOrWhiteSpace($header)){
                        $partColumns=[NtfsAssessment.Csv]::Parse($header)
                        if($columns.Count -eq 0){$columns=$partColumns}
                        elseif((ConvertTo-NtfsCsvRecord $columns) -cne (ConvertTo-NtfsCsvRecord $partColumns)){throw "Schema mismatch between CSV parts: $name"}
                        while($null -ne ($record=[NtfsAssessment.Csv]::ReadRecord($reader))){
                            if($record.Length -eq 0){continue}
                            if([NtfsAssessment.Csv]::Parse($record).Length -ne $columns.Count){throw "Column count mismatch in $($file.FullName)"}
                            $partRows++
                        }
                    }
                }finally{$reader.Dispose()}
                $rowCount+=$partRows
                [pscustomobject]@{Name=$file.Name;Bytes=$file.Length;Rows=$partRows;SHA256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
            }
        )
        [pscustomobject]@{Name=$name;Columns=@($columns);Rows=$rowCount;Parts=$parts}
    }
}
