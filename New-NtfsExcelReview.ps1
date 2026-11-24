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
  Creates an optional Excel review workbook from a completed merged assessment report.
.DESCRIPTION
  The selected CSV parts are bound to the hashes and row counts in NTFS_QA.json.
  The original report is not changed. Formula-like values are stored as text and
  worksheets are split rather than silently truncated at Excel's row limit.
.EXAMPLE
  .\New-NtfsExcelReview.ps1 `
    -InputReportFolder D:\AssessmentReports\Baseline `
    -OutputPath D:\AssessmentExports\Baseline-Review.xlsx
.EXAMPLE
  .\New-NtfsExcelReview.ps1 `
    -InputReportFolder D:\AssessmentReports\Baseline `
    -OutputPath D:\AssessmentExports\Baseline-WithRaw.xlsx `
    -IncludeRawData
.EXAMPLE
  .\New-NtfsExcelReview.ps1 `
    -InputReportFolder D:\AssessmentReports\Baseline `
    -OutputPath D:\AssessmentExports\Findings.xlsx `
    -Dataset NTFS_Findings.csv,NTFS_RiskByShare.csv
.NOTES
  Release version: NtfsAssessment.Common.ps1, ExcelReview entry in NtfsVersions.
  This is a read-only convenience copy, not an assessment, effective-access result,
  remediation approval, rollback package, or substitute for the source report.
  -Dataset replaces the curated default set; -IncludeRawData adds raw folder/ACE
  datasets. Dataset names can be supplied with or without the .csv extension.
  The output must be a new .xlsx file outside InputReportFolder.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$InputReportFolder,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputPath,
    [string[]]$Dataset=@(),
    [switch]$IncludeRawData,
    [ValidateRange(1,1048575)][int]$MaxRowsPerSheet=1000000
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'NtfsAssessment.Common.ps1')

if ($null -eq ('NtfsAssessment.ExcelReviewWorkbook' -as [type])) {
    $excelWriterSource=@'
using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Xml;

namespace NtfsAssessment {
    public sealed class ExcelReviewWorkbook : IDisposable {
        private const string SpreadsheetNamespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
        private const string RelationshipNamespace = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
        private const string PackageRelationshipNamespace = "http://schemas.openxmlformats.org/package/2006/relationships";
        private static readonly string[] NumericColumns = new string[] {
            "AceCount", "AceOrdinal", "AcesCollected", "AssessedFolders", "BroadAceCount",
            "AverageRiskScore", "BroadAccessAces", "BrokenInheritance", "Count", "CriticalFolders", "DenyAces",
            "Depth", "DirectAssignments", "Errors", "ExplicitAceCount", "Findings",
            "FolderCount", "Folders", "FoldersCollected", "HighFolders", "MemberCount",
            "MaxRiskScore", "NotAssessedFolders", "NtfsAces", "PathLength", "PrivilegedRightsAces",
            "RiskScore", "RightsValue", "Rows", "ShareAceCount", "Shares", "SkippedPaths",
            "UniqueACEs", "UnreportedAclFailures", "UnresolvedAceCount", "UnresolvedIdentities"
        };
        private static readonly string[] BooleanColumns = new string[] {
            "InheritanceProtected", "IsInherited", "MemberEnabled", "Remediable", "Resolved",
            "UnknownDirectoryCoverage"
        };

        private sealed class SheetInfo {
            public string Name;
            public string RelationshipId;
            public string Path;
            public SheetInfo(string name, string relationshipId, string path) {
                Name = name;
                RelationshipId = relationshipId;
                Path = path;
            }
        }

        private readonly FileStream file;
        private readonly ZipArchive archive;
        private readonly ArrayList sheets = new ArrayList();
        private readonly ArrayList sheetNames = new ArrayList();
        private readonly string createdUtc;
        private readonly string version;
        private bool disposed;
        private bool completed;
        private Stream entryStream;
        private XmlWriter writer;
        private string[] headers = new string[0];
        private int rowNumber;

        public int SheetCount { get { return sheets.Count; } }
        public bool Completed { get { return completed; } }

        public ExcelReviewWorkbook(string path, string componentVersion) {
            if (String.IsNullOrWhiteSpace(path)) throw new ArgumentException("path");
            if (String.IsNullOrWhiteSpace(componentVersion)) throw new ArgumentException("componentVersion");
            file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            archive = new ZipArchive(file, ZipArchiveMode.Create, false);
            createdUtc = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
            version = componentVersion;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string path,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            IntPtr file,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static string GetFinalPath(string path) {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return Path.GetFullPath(path);
            const uint openExisting = 3;
            const uint backupSemantics = 0x02000000;
            const uint shareAll = 0x7;
            IntPtr invalid = new IntPtr(-1);
            IntPtr handle = CreateFile(path, 0, shareAll, IntPtr.Zero, openExisting, backupSemantics, IntPtr.Zero);
            if (handle == invalid)
                throw new IOException("Could not open a path for final-name resolution: " + path, new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
            try {
                StringBuilder buffer = new StringBuilder(512);
                while (true) {
                    uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
                    if (length == 0)
                        throw new IOException("Could not resolve the final filesystem path for: " + path, new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
                    if (length < buffer.Capacity) break;
                    buffer = new StringBuilder((int)length + 1);
                }
                string result = buffer.ToString();
                if (result.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                    return @"\\" + result.Substring(8);
                if (result.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                    return result.Substring(4);
                return result;
            } finally {
                CloseHandle(handle);
            }
        }

        private static void ValidateSheetName(string name) {
            if (String.IsNullOrWhiteSpace(name) || name.Length > 31)
                throw new ArgumentException("Worksheet names must contain 1-31 characters: " + name);
            if (name[0] == '\'' || name[name.Length - 1] == '\'')
                throw new ArgumentException("Worksheet names cannot start or end with an apostrophe: " + name);
            if (name.IndexOfAny(new char[] { '\\', '/', '?', '*', '[', ']', ':' }) >= 0)
                throw new ArgumentException("Worksheet name contains an invalid character: " + name);
            for (int i = 0; i < name.Length; i++)
                if (name[i] < 0x20)
                    throw new ArgumentException("Worksheet name contains an invalid control character: " + name);
        }

        public void BeginSheet(string name, string[] columnHeaders) {
            if (disposed || completed) throw new ObjectDisposedException("ExcelReviewWorkbook");
            if (writer != null) throw new InvalidOperationException("The previous worksheet is still open.");
            ValidateSheetName(name);
            foreach (string existing in sheetNames) {
                if (String.Equals(existing, name, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Duplicate worksheet name: " + name);
            }
            if (columnHeaders == null) throw new ArgumentNullException("columnHeaders");
            if (columnHeaders.Length > 16384)
                throw new InvalidDataException("Worksheet exceeds Excel's 16,384-column limit: " + name);

            headers = (string[])columnHeaders.Clone();
            rowNumber = 0;
            int number = sheets.Count + 1;
            string relationshipId = "rId" + number.ToString(CultureInfo.InvariantCulture);
            string path = "xl/worksheets/sheet" + number.ToString(CultureInfo.InvariantCulture) + ".xml";
            sheets.Add(new SheetInfo(name, relationshipId, path));
            sheetNames.Add(name);

            ZipArchiveEntry entry = archive.CreateEntry(path, CompressionLevel.Optimal);
            entryStream = entry.Open();
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Encoding = new UTF8Encoding(false);
            settings.NewLineHandling = NewLineHandling.Entitize;
            settings.CloseOutput = true;
            writer = XmlWriter.Create(entryStream, settings);
            writer.WriteStartDocument();
            writer.WriteStartElement("worksheet", SpreadsheetNamespace);
            writer.WriteStartElement("sheetViews", SpreadsheetNamespace);
            writer.WriteStartElement("sheetView", SpreadsheetNamespace);
            writer.WriteAttributeString("workbookViewId", "0");
            writer.WriteStartElement("pane", SpreadsheetNamespace);
            writer.WriteAttributeString("ySplit", "1");
            writer.WriteAttributeString("topLeftCell", "A2");
            writer.WriteAttributeString("activePane", "bottomLeft");
            writer.WriteAttributeString("state", "frozen");
            writer.WriteEndElement();
            writer.WriteStartElement("selection", SpreadsheetNamespace);
            writer.WriteAttributeString("pane", "bottomLeft");
            writer.WriteAttributeString("activeCell", "A2");
            writer.WriteAttributeString("sqref", "A2");
            writer.WriteEndElement();
            writer.WriteEndElement();
            writer.WriteEndElement();
            writer.WriteStartElement("sheetFormatPr", SpreadsheetNamespace);
            writer.WriteAttributeString("defaultRowHeight", "15");
            writer.WriteEndElement();
            if (headers.Length > 0) {
                writer.WriteStartElement("cols", SpreadsheetNamespace);
                for (int i = 0; i < headers.Length; i++) {
                    writer.WriteStartElement("col", SpreadsheetNamespace);
                    writer.WriteAttributeString("min", (i + 1).ToString(CultureInfo.InvariantCulture));
                    writer.WriteAttributeString("max", (i + 1).ToString(CultureInfo.InvariantCulture));
                    writer.WriteAttributeString("width", GetColumnWidth(headers[i]).ToString(CultureInfo.InvariantCulture));
                    writer.WriteAttributeString("customWidth", "1");
                    writer.WriteEndElement();
                }
                writer.WriteEndElement();
            }
            writer.WriteStartElement("sheetData", SpreadsheetNamespace);
            if (headers.Length > 0) WriteRowInternal(headers, true);
        }

        private static int GetColumnWidth(string header) {
            if (String.IsNullOrEmpty(header)) return 14;
            if (header.IndexOf("Recommendation", StringComparison.OrdinalIgnoreCase) >= 0 ||
                header.IndexOf("Limitation", StringComparison.OrdinalIgnoreCase) >= 0 ||
                header.IndexOf("Reason", StringComparison.OrdinalIgnoreCase) >= 0 ||
                header.IndexOf("Detail", StringComparison.OrdinalIgnoreCase) >= 0 ||
                header.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0) return 46;
            if (header.IndexOf("Path", StringComparison.OrdinalIgnoreCase) >= 0 ||
                header.IndexOf("Identity", StringComparison.OrdinalIgnoreCase) >= 0 ||
                header.IndexOf("Group", StringComparison.OrdinalIgnoreCase) >= 0 ||
                header.IndexOf("Folder", StringComparison.OrdinalIgnoreCase) >= 0 ||
                header.IndexOf("Hash", StringComparison.OrdinalIgnoreCase) >= 0) return 34;
            if (header.Length > 30) return 30;
            if (header.Length > 20) return 24;
            return 18;
        }

        public void WriteRow(string[] values) {
            if (writer == null) throw new InvalidOperationException("No worksheet is open.");
            WriteRowInternal(values, false);
        }

        private void WriteRowInternal(string[] values, bool headerRow) {
            if (values == null) throw new ArgumentNullException("values");
            if (values.Length != headers.Length)
                throw new InvalidDataException("Cell count does not match worksheet column count.");
            if (rowNumber >= 1048576)
                throw new InvalidDataException("Worksheet exceeds Excel's 1,048,576-row limit.");
            rowNumber++;
            writer.WriteStartElement("row", SpreadsheetNamespace);
            writer.WriteAttributeString("r", rowNumber.ToString(CultureInfo.InvariantCulture));
            if (headerRow) {
                writer.WriteAttributeString("ht", "22");
                writer.WriteAttributeString("customHeight", "1");
            }
            for (int i = 0; i < values.Length; i++) {
                string text = values[i] == null ? String.Empty : values[i];
                WriteCell(text, headers[i], i + 1, headerRow);
            }
            writer.WriteEndElement();
        }

        private static int CountSignificantDigits(string value) {
            string digits = value.Replace("+", String.Empty).Replace("-", String.Empty).Replace(".", String.Empty);
            int first = 0;
            while (first < digits.Length && digits[first] == '0') first++;
            return first == digits.Length ? 1 : digits.Length - first;
        }

        private void WriteCell(string text, string header, int column, bool headerRow) {
            if (text.Length > 32767)
                throw new InvalidDataException(String.Format(
                    CultureInfo.InvariantCulture,
                    "Cell {0}{1} exceeds Excel's 32,767-character text limit.",
                    GetColumnName(column), rowNumber));
            try { XmlConvert.VerifyXmlChars(text); }
            catch (XmlException ex) {
                throw new InvalidDataException(String.Format(
                    CultureInfo.InvariantCulture,
                    "Cell {0}{1} contains a character that XML 1.0 and Excel cannot represent.",
                    GetColumnName(column), rowNumber), ex);
            }

            writer.WriteStartElement("c", SpreadsheetNamespace);
            writer.WriteAttributeString("r", GetColumnName(column) + rowNumber.ToString(CultureInfo.InvariantCulture));
            if (headerRow) writer.WriteAttributeString("s", "1");
            if (!headerRow && ContainsColumn(BooleanColumns, header)) {
                bool boolean;
                if (Boolean.TryParse(text, out boolean)) {
                    writer.WriteAttributeString("t", "b");
                    writer.WriteStartElement("v", SpreadsheetNamespace);
                    writer.WriteString(boolean ? "1" : "0");
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                    return;
                }
            }
            if (!headerRow && ContainsColumn(NumericColumns, header)) {
                long number;
                if (Int64.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out number) &&
                    number >= -999999999999999L && number <= 999999999999999L) {
                    writer.WriteStartElement("v", SpreadsheetNamespace);
                    writer.WriteString(number.ToString(CultureInfo.InvariantCulture));
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                    return;
                }
                decimal decimalNumber;
                if (Decimal.TryParse(
                    text,
                    NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint,
                    CultureInfo.InvariantCulture,
                    out decimalNumber) &&
                    decimalNumber >= -999999999999999M && decimalNumber <= 999999999999999M &&
                    CountSignificantDigits(text) <= 15) {
                    writer.WriteStartElement("v", SpreadsheetNamespace);
                    writer.WriteString(decimalNumber.ToString(CultureInfo.InvariantCulture));
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                    return;
                }
            }
            writer.WriteAttributeString("t", "inlineStr");
            writer.WriteStartElement("is", SpreadsheetNamespace);
            writer.WriteStartElement("t", SpreadsheetNamespace);
            if (text.Length > 0 && (Char.IsWhiteSpace(text[0]) || Char.IsWhiteSpace(text[text.Length - 1])))
                writer.WriteAttributeString("xml", "space", "http://www.w3.org/XML/1998/namespace", "preserve");
            writer.WriteString(text);
            writer.WriteEndElement();
            writer.WriteEndElement();
            writer.WriteEndElement();
        }

        private static bool ContainsColumn(string[] columns, string header) {
            for (int i = 0; i < columns.Length; i++) {
                if (String.Equals(columns[i], header, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static string GetColumnName(int number) {
            StringBuilder result = new StringBuilder();
            while (number > 0) {
                number--;
                result.Insert(0, (char)('A' + (number % 26)));
                number /= 26;
            }
            return result.ToString();
        }

        public void EndSheet() {
            if (writer == null) throw new InvalidOperationException("No worksheet is open.");
            writer.WriteEndElement();
            if (headers.Length > 0) {
                writer.WriteStartElement("autoFilter", SpreadsheetNamespace);
                writer.WriteAttributeString(
                    "ref",
                    "A1:" + GetColumnName(headers.Length) + rowNumber.ToString(CultureInfo.InvariantCulture));
                writer.WriteEndElement();
            }
            writer.WriteStartElement("pageMargins", SpreadsheetNamespace);
            writer.WriteAttributeString("left", "0.25");
            writer.WriteAttributeString("right", "0.25");
            writer.WriteAttributeString("top", "0.5");
            writer.WriteAttributeString("bottom", "0.5");
            writer.WriteAttributeString("header", "0.25");
            writer.WriteAttributeString("footer", "0.25");
            writer.WriteEndElement();
            writer.WriteEndElement();
            writer.WriteEndDocument();
            writer.Dispose();
            writer = null;
            entryStream = null;
        }

        private static string Escape(string value) {
            return SecurityElement.Escape(value == null ? String.Empty : value);
        }

        private void WriteEntry(string path, string content) {
            ZipArchiveEntry entry = archive.CreateEntry(path, CompressionLevel.Optimal);
            Stream stream = entry.Open();
            try {
                StreamWriter streamWriter = new StreamWriter(stream, new UTF8Encoding(false));
                try { streamWriter.Write(content); }
                finally { streamWriter.Dispose(); }
            } finally {
                stream.Dispose();
            }
        }

        private void WriteContentTypes() {
            StringBuilder xml = new StringBuilder();
            xml.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            xml.Append("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">");
            xml.Append("<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>");
            xml.Append("<Default Extension=\"xml\" ContentType=\"application/xml\"/>");
            xml.Append("<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>");
            xml.Append("<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>");
            xml.Append("<Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/>");
            xml.Append("<Override PartName=\"/docProps/app.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.extended-properties+xml\"/>");
            for (int i = 0; i < sheets.Count; i++)
                xml.Append("<Override PartName=\"/" + ((SheetInfo)sheets[i]).Path + "\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>");
            xml.Append("</Types>");
            WriteEntry("[Content_Types].xml", xml.ToString());
        }

        private void WriteRootRelationships() {
            WriteEntry(
                "_rels/.rels",
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<Relationships xmlns=\"" + PackageRelationshipNamespace + "\">" +
                "<Relationship Id=\"rId1\" Type=\"" + RelationshipNamespace + "/officeDocument\" Target=\"xl/workbook.xml\"/>" +
                "<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\"/>" +
                "<Relationship Id=\"rId3\" Type=\"" + RelationshipNamespace + "/extended-properties\" Target=\"docProps/app.xml\"/>" +
                "</Relationships>");
        }

        private void WriteWorkbook() {
            StringBuilder xml = new StringBuilder();
            xml.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            xml.Append("<workbook xmlns=\"" + SpreadsheetNamespace + "\" xmlns:r=\"" + RelationshipNamespace + "\">");
            xml.Append("<bookViews><workbookView activeTab=\"0\"/></bookViews>");
            xml.Append("<sheets>");
            for (int i = 0; i < sheets.Count; i++) {
                SheetInfo sheet = (SheetInfo)sheets[i];
                xml.Append("<sheet name=\"");
                xml.Append(Escape(sheet.Name));
                xml.Append("\" sheetId=\"");
                xml.Append((i + 1).ToString(CultureInfo.InvariantCulture));
                xml.Append("\" r:id=\"");
                xml.Append(sheet.RelationshipId);
                xml.Append("\"/>");
            }
            xml.Append("</sheets>");
            xml.Append("<calcPr calcId=\"191029\"/>");
            xml.Append("</workbook>");
            WriteEntry("xl/workbook.xml", xml.ToString());
        }

        private void WriteWorkbookRelationships() {
            StringBuilder xml = new StringBuilder();
            xml.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            xml.Append("<Relationships xmlns=\"" + PackageRelationshipNamespace + "\">");
            for (int i = 0; i < sheets.Count; i++) {
                SheetInfo sheet = (SheetInfo)sheets[i];
                xml.Append("<Relationship Id=\"");
                xml.Append(sheet.RelationshipId);
                xml.Append("\" Type=\"" + RelationshipNamespace + "/worksheet\" Target=\"worksheets/sheet");
                xml.Append((i + 1).ToString(CultureInfo.InvariantCulture));
                xml.Append(".xml\"/>");
            }
            string stylesId = "rId" + (sheets.Count + 1).ToString(CultureInfo.InvariantCulture);
            xml.Append("<Relationship Id=\"" + stylesId + "\" Type=\"" + RelationshipNamespace + "/styles\" Target=\"styles.xml\"/>");
            xml.Append("</Relationships>");
            WriteEntry("xl/_rels/workbook.xml.rels", xml.ToString());
        }

        private void WriteStyles() {
            WriteEntry(
                "xl/styles.xml",
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<styleSheet xmlns=\"" + SpreadsheetNamespace + "\">" +
                "<fonts count=\"2\">" +
                "<font><sz val=\"11\"/><name val=\"Calibri\"/><family val=\"2\"/><scheme val=\"minor\"/></font>" +
                "<font><b/><color rgb=\"FFFFFFFF\"/><sz val=\"11\"/><name val=\"Calibri\"/><family val=\"2\"/><scheme val=\"minor\"/></font>" +
                "</fonts>" +
                "<fills count=\"3\">" +
                "<fill><patternFill patternType=\"none\"/></fill>" +
                "<fill><patternFill patternType=\"gray125\"/></fill>" +
                "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF1F4E78\"/><bgColor indexed=\"64\"/></patternFill></fill>" +
                "</fills>" +
                "<borders count=\"2\">" +
                "<border><left/><right/><top/><bottom/><diagonal/></border>" +
                "<border><left/><right/><top/><bottom style=\"thin\"><color rgb=\"FF17365D\"/></bottom><diagonal/></border>" +
                "</borders>" +
                "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>" +
                "<cellXfs count=\"2\">" +
                "<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>" +
                "<xf numFmtId=\"0\" fontId=\"1\" fillId=\"2\" borderId=\"1\" xfId=\"0\" applyFont=\"1\" applyFill=\"1\" applyBorder=\"1\" applyAlignment=\"1\"><alignment vertical=\"center\" wrapText=\"1\"/></xf>" +
                "</cellXfs>" +
                "<cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles>" +
                "<dxfs count=\"0\"/>" +
                "<tableStyles count=\"0\" defaultTableStyle=\"TableStyleMedium2\" defaultPivotStyle=\"PivotStyleLight16\"/>" +
                "</styleSheet>");
        }

        private void WriteProperties() {
            WriteEntry(
                "docProps/core.xml",
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" " +
                "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" " +
                "xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
                "<dc:title>NTFS assessment Excel review</dc:title>" +
                "<dc:creator>File Share Permissions Assessment</dc:creator>" +
                "<cp:lastModifiedBy>File Share Permissions Assessment " + Escape(version) + "</cp:lastModifiedBy>" +
                "<dcterms:created xsi:type=\"dcterms:W3CDTF\">" + createdUtc + "</dcterms:created>" +
                "<dcterms:modified xsi:type=\"dcterms:W3CDTF\">" + createdUtc + "</dcterms:modified>" +
                "</cp:coreProperties>");

            StringBuilder xml = new StringBuilder();
            xml.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            xml.Append("<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\" xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">");
            xml.Append("<Application>Microsoft Excel Compatible Export</Application>");
            xml.Append("<DocSecurity>0</DocSecurity>");
            xml.Append("<ScaleCrop>false</ScaleCrop>");
            xml.Append("<AppVersion>16.0300</AppVersion>");
            xml.Append("<HeadingPairs><vt:vector size=\"2\" baseType=\"variant\"><vt:variant><vt:lpstr>Worksheets</vt:lpstr></vt:variant><vt:variant><vt:i4>");
            xml.Append(sheets.Count.ToString(CultureInfo.InvariantCulture));
            xml.Append("</vt:i4></vt:variant></vt:vector></HeadingPairs>");
            xml.Append("<TitlesOfParts><vt:vector size=\"");
            xml.Append(sheets.Count.ToString(CultureInfo.InvariantCulture));
            xml.Append("\" baseType=\"lpstr\">");
            foreach (SheetInfo sheet in sheets) xml.Append("<vt:lpstr>" + Escape(sheet.Name) + "</vt:lpstr>");
            xml.Append("</vt:vector></TitlesOfParts>");
            xml.Append("</Properties>");
            WriteEntry("docProps/app.xml", xml.ToString());
        }

        public void Complete() {
            if (disposed || completed) throw new ObjectDisposedException("ExcelReviewWorkbook");
            if (writer != null) EndSheet();
            if (sheets.Count == 0) throw new InvalidOperationException("A workbook requires at least one worksheet.");
            WriteContentTypes();
            WriteRootRelationships();
            WriteWorkbook();
            WriteWorkbookRelationships();
            WriteStyles();
            WriteProperties();
            archive.Dispose();
            file.Dispose();
            completed = true;
        }

        public void Dispose() {
            if (disposed) return;
            disposed = true;
            if (writer != null) {
                try { writer.Dispose(); } catch { }
                writer = null;
            }
            if (entryStream != null) {
                try { entryStream.Dispose(); } catch { }
                entryStream = null;
            }
            if (!completed) {
                try { archive.Dispose(); } catch { }
                try { file.Dispose(); } catch { }
            }
        }
    }
}
'@
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    if($PSVersionTable.PSEdition -eq 'Core'){
        Add-Type -TypeDefinition $excelWriterSource -ErrorAction Stop
    }else{
        $excelReferencedAssemblies=@(
            [object].Assembly.Location,
            [Collections.ArrayList].Assembly.Location,
            [IO.Compression.ZipArchive].Assembly.Location,
            [Xml.XmlWriter].Assembly.Location
        )|Where-Object{$_}|Sort-Object -Unique
        Add-Type -TypeDefinition $excelWriterSource `
            -ReferencedAssemblies $excelReferencedAssemblies `
            -ErrorAction Stop
    }
}

function Get-NtfsExcelProperty($Object,[string]$Name,$Default=$null) {
    if($null -eq $Object){return $Default}
    $property=$Object.PSObject.Properties[$Name]
    if($null -eq $property){return $Default}
    return $property.Value
}

function Get-NtfsExcelCollection($Object,[string]$Name) {
    $value=Get-NtfsExcelProperty $Object $Name
    if($null -ne $value){$value}
}

function Test-NtfsExcelPathWithin([string]$Path,[string]$Root) {
    $rootPrefix=$Root.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    return $Path -eq $Root -or $Path.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)
}

function Get-NtfsExcelReparseAncestor([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while(-not [string]::IsNullOrWhiteSpace($current)){
        if(Test-Path -LiteralPath $current){
            $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $item.FullName}
        }
        $parent=[IO.Path]::GetDirectoryName($current)
        if([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current){break}
        $current=$parent
    }
    return $null
}

function Resolve-NtfsExcelFinalPath([string]$Path) {
    $fullPath=[IO.Path]::GetFullPath($Path)
    $current=$fullPath
    $relativeParts=[Collections.ArrayList]::new()
    while(-not(Test-Path -LiteralPath $current)){
        $leaf=[IO.Path]::GetFileName($current.TrimEnd('\','/'))
        if([string]::IsNullOrWhiteSpace($leaf)){throw "Cannot find an existing ancestor for path: $Path"}
        $relativeParts.Insert(0,$leaf)
        $parent=[IO.Path]::GetDirectoryName($current.TrimEnd('\','/'))
        if([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current){throw "Cannot find an existing ancestor for path: $Path"}
        $current=$parent
    }
    $resolved=[NtfsAssessment.ExcelReviewWorkbook]::GetFinalPath($current)
    foreach($part in $relativeParts){$resolved=Join-Path $resolved $part}
    return [IO.Path]::GetFullPath($resolved)
}

function Get-NtfsExcelDatasetMap($Qa) {
    $datasets=@(Get-NtfsExcelCollection $Qa 'Datasets')
    if(@($datasets).Count -eq 0){throw 'NTFS_QA.json contains no CSV dataset inventory.'}
    $map=@{}
    foreach($dataset in @($datasets)){
        $name=[string](Get-NtfsExcelProperty $dataset 'Name')
        if([string]::IsNullOrWhiteSpace($name) -or
            [IO.Path]::GetFileName($name) -ne $name -or $name -match '[\\/]'){
            throw "Invalid QA dataset name: $name"
        }
        if($map.ContainsKey($name)){throw "Duplicate QA dataset inventory entry: $name"}
        $map[$name]=$dataset
    }
    return $map
}

function Assert-NtfsExcelPartHash($Part) {
    $actualBytes=(Get-Item -LiteralPath $Part.Path -ErrorAction Stop).Length
    if($actualBytes -ne $Part.Bytes){
        throw "Source CSV size changed for $($Part.Name): expected $($Part.Bytes), actual $actualBytes."
    }
    $actualHash=(Get-FileHash -LiteralPath $Part.Path -Algorithm SHA256 -ErrorAction Stop).Hash
    if($actualHash -ne $Part.SHA256){
        throw "Source CSV hash mismatch for $($Part.Name). The report may have changed; rerun Merge-NtfsAssessment.ps1."
    }
}

function Get-NtfsExcelVerifiedDataset([string]$ReportFolder,$Dataset,[string]$Name) {
    $qaColumns=Get-NtfsExcelProperty $Dataset 'Columns'
    $columns=@()
    if($null -ne $qaColumns){$columns=@($qaColumns|ForEach-Object{[string]$_})}
    $parts=@(Get-NtfsExcelCollection $Dataset 'Parts')
    $expectedRows=[long](Get-NtfsExcelProperty $Dataset 'Rows' 0)
    if($parts.Count -eq 0){throw "QA dataset $Name has no parts."}
    if($expectedRows -lt 0){throw "QA dataset $Name has a negative row count."}
    if(@($columns|Sort-Object -Unique).Count -ne $columns.Count -or $columns -contains ''){
        throw "QA dataset $Name has duplicate or empty columns."
    }
    if($columns.Count -eq 0 -and $expectedRows -ne 0){
        throw "QA dataset $Name has rows but no columns."
    }

    $expectedNames=@()
    $base=[IO.Path]::GetFileNameWithoutExtension($Name)
    $verifiedParts=[Collections.ArrayList]::new()
    $totalRows=0L
    $index=0
    foreach($part in $parts){
        $index++
        $partName=[string](Get-NtfsExcelProperty $part 'Name')
        $expectedName=if($index -eq 1){$Name}else{"${base}_${index}.csv"}
        if($partName -cne $expectedName -or [IO.Path]::GetFileName($partName) -ne $partName -or $partName -match '[\\/]'){
            throw "Invalid or out-of-order QA part for ${Name}: expected $expectedName, found $partName."
        }
        $sha256=[string](Get-NtfsExcelProperty $part 'SHA256')
        if($sha256 -notmatch '^[a-fA-F0-9]{64}$'){throw "Invalid QA hash for ${Name}: ${partName}."}
        $bytes=[long](Get-NtfsExcelProperty $part 'Bytes' -1)
        $partRows=[long](Get-NtfsExcelProperty $part 'Rows' -1)
        if($bytes -lt 0 -or $partRows -lt 0){throw "Invalid QA size or row count for ${Name}: ${partName}."}
        $path=Join-Path $ReportFolder $partName
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Missing QA-bound source file: $path"}
        $verifiedPart=[pscustomobject]@{
            Name=$partName;Path=$path;Bytes=$bytes;Rows=$partRows;SHA256=$sha256
        }
        Assert-NtfsExcelPartHash $verifiedPart
        $reader=[IO.StreamReader]::new($path,[Text.Encoding]::UTF8,$true)
        try{
            $header=[NtfsAssessment.Csv]::ReadRecord($reader)
            if($columns.Count -eq 0){
                if($null -ne $header -or $bytes -ne 0 -or $partRows -ne 0){
                    throw "QA dataset $Name is marked empty, but $partName contains a header or records."
                }
            }else{
                if($null -eq $header){throw "Missing CSV header: $path"}
                $actualColumns=[NtfsAssessment.Csv]::Parse($header)
                if((ConvertTo-NtfsCsvRecord $actualColumns) -cne (ConvertTo-NtfsCsvRecord $columns)){
                    throw "CSV header does not match QA column order: $path"
                }
            }
        }finally{$reader.Dispose()}
        $totalRows+=$partRows
        $expectedNames+=$partName
        [void]$verifiedParts.Add($verifiedPart)
    }
    if($totalRows -ne $expectedRows){
        throw "QA part row counts do not reconcile for ${Name}: expected $expectedRows, total $totalRows."
    }

    $escapedBase=[regex]::Escape($base)
    $actualNames=@(Get-ChildItem -LiteralPath $ReportFolder -File -Filter '*.csv' |
        Where-Object{$_.Name -match "^${escapedBase}(_\d+)?\.csv$"} |
        ForEach-Object{$_.Name})
    if(@($actualNames|Sort-Object -Unique).Count -ne $expectedNames.Count -or
        @($actualNames|Where-Object{$expectedNames -cnotcontains $_}).Count -gt 0 -or
        @($expectedNames|Where-Object{$actualNames -cnotcontains $_}).Count -gt 0){
        throw "CSV parts on disk do not exactly match the QA inventory for $Name."
    }
    [pscustomobject]@{
        Name=$Name;Columns=$columns;Rows=$expectedRows;Parts=@($verifiedParts)
    }
}

function Get-NtfsExcelDatasetSheetName([string]$DatasetName) {
    $names=@{
        'MergeSourceRuns.csv'='Source Runs'
        'NTFS_AllAces.csv'='All ACEs'
        'NTFS_BroadAccess.csv'='Broad Access'
        'NTFS_BrokenInheritance.csv'='Broken Inheritance'
        'NTFS_DenyAces.csv'='Deny ACEs'
        'NTFS_DirectAssignments.csv'='Direct Assignments'
        'NTFS_Findings.csv'='Findings'
        'NTFS_FindingsSummary.csv'='Findings Summary'
        'NTFS_Folders.csv'='Folders'
        'NTFS_GroupReport.csv'='Group Detail'
        'NTFS_GroupReportByShare.csv'='Groups by Share'
        'NTFS_PrivilegedRights.csv'='Privileged Rights'
        'NTFS_RiskByFolder.csv'='Risk by Folder'
        'NTFS_RiskByShare.csv'='Risk by Share'
        'NTFS_ScanErrors.csv'='Scan Errors'
        'NTFS_ShareCoverage.csv'='Coverage'
        'NTFS_SharePermissions.csv'='Share Permissions'
        'NTFS_ShareVsNtfs.csv'='Share vs NTFS'
        'NTFS_Shares.csv'='Shares'
        'NTFS_SkippedPaths.csv'='Skipped Paths'
        'NTFS_UnresolvedIdentities.csv'='Unresolved Identities'
    }
    if($names.ContainsKey($DatasetName)){return $names[$DatasetName]}
    $name=[IO.Path]::GetFileNameWithoutExtension($DatasetName) -replace '^NTFS_',''
    $name=$name -creplace '([a-z0-9])([A-Z])','$1 $2'
    return ($name -replace '[\\/?*:\[\]]','_')
}

function Get-NtfsExcelWorksheetName([string]$BaseName,[int]$Part) {
    $suffix=if($Part -eq 1){''}else{" ($Part)"}
    $limit=31-$suffix.Length
    $base=$BaseName.Trim().Trim([char]"'")
    if($base.Length -gt $limit){$base=$base.Substring(0,$limit).TrimEnd()}
    $base=$base.TrimEnd([char]"'")
    if([string]::IsNullOrWhiteSpace($base)){$base='Sheet'}
    return $base+$suffix
}

function Test-NtfsExcelPackage([string]$Path,[int]$ExpectedSheets) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $archive=$null
    try{
        $archive=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$false)
        foreach($name in @(
            '[Content_Types].xml','_rels/.rels','docProps/app.xml','docProps/core.xml',
            'xl/workbook.xml','xl/_rels/workbook.xml.rels','xl/styles.xml'
        )){
            if($null -eq $archive.GetEntry($name)){throw "Generated workbook is missing package part: $name"}
        }
        $sheetEntries=@($archive.Entries|Where-Object{$_.FullName -match '^xl/worksheets/sheet\d+\.xml$'})
        if($sheetEntries.Count -ne $ExpectedSheets){
            throw "Generated workbook sheet count mismatch: expected $ExpectedSheets, found $($sheetEntries.Count)."
        }
        foreach($name in @('[Content_Types].xml','_rels/.rels','xl/workbook.xml','xl/_rels/workbook.xml.rels','xl/styles.xml')){
            $entry=$archive.GetEntry($name)
            $xml=[IO.StreamReader]::new($entry.Open(),[Text.Encoding]::UTF8,$true)
            try{
                $reader=[Xml.XmlReader]::Create($xml)
                try{while($reader.Read()){}}finally{$reader.Dispose()}
            }finally{$xml.Dispose()}
        }
    }finally{
        if($null -ne $archive){$archive.Dispose()}
        $stream.Dispose()
    }
}

$reportFolder=$null
$resolvedOutput=$null
$pendingPath=$null
$workbook=$null
$completedOutput=$false
try{
    $reportFolder=(Resolve-Path -LiteralPath $InputReportFolder -ErrorAction Stop).ProviderPath
    if(-not(Test-Path -LiteralPath $reportFolder -PathType Container)){
        throw "InputReportFolder is not a directory: $InputReportFolder"
    }
    $inputReparseAncestor=Get-NtfsExcelReparseAncestor $reportFolder
    if($inputReparseAncestor){
        throw "InputReportFolder traverses a reparse point and will not be used: $inputReparseAncestor"
    }
    $resolvedOutput=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    if([IO.Path]::GetExtension($resolvedOutput) -ine '.xlsx'){throw 'OutputPath must use the .xlsx extension.'}
    if(Test-Path -LiteralPath $resolvedOutput){throw "OutputPath already exists and will not be overwritten: $resolvedOutput"}
    $resolvedOutputParent=[IO.Path]::GetDirectoryName($resolvedOutput)
    if([string]::IsNullOrWhiteSpace($resolvedOutputParent)){throw "OutputPath has no parent directory: $resolvedOutput"}
    $outputReparseAncestor=Get-NtfsExcelReparseAncestor $resolvedOutputParent
    if($outputReparseAncestor){
        throw "OutputPath traverses a reparse point and will not be used: $outputReparseAncestor"
    }
    $finalReportFolder=Resolve-NtfsExcelFinalPath $reportFolder
    $finalOutputParent=Resolve-NtfsExcelFinalPath $resolvedOutputParent
    if(Test-NtfsExcelPathWithin (Join-Path $finalOutputParent ([IO.Path]::GetFileName($resolvedOutput))) $finalReportFolder){
        throw 'OutputPath must be outside InputReportFolder so source report evidence remains unchanged.'
    }

    $statePath=Join-Path $reportFolder 'merge-state.json'
    $qaPath=Join-Path $reportFolder 'NTFS_QA.json'
    $summaryPath=Join-Path $reportFolder 'NTFS_ExecutiveSummary.json'
    foreach($required in @($statePath,$qaPath,$summaryPath)){
        if(-not(Test-Path -LiteralPath $required -PathType Leaf)){
            throw "This is not a completed merge report folder; missing $([IO.Path]::GetFileName($required))."
        }
    }
    $state=Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
    $qa=Get-Content -LiteralPath $qaPath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
    $executive=Get-Content -LiteralPath $summaryPath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
    $sourceStatus=[string](Get-NtfsExcelProperty $state 'Status')
    if($sourceStatus -notin @('Completed','CompletedWithWarnings')){
        throw "Merge report status is '$sourceStatus'. Export requires Completed or CompletedWithWarnings."
    }
    $datasetMap=Get-NtfsExcelDatasetMap $qa

    $defaultDatasets=@(
        'MergeSourceRuns.csv','NTFS_FindingsSummary.csv','NTFS_RiskByShare.csv',
        'NTFS_Findings.csv','NTFS_RiskByFolder.csv','NTFS_GroupReportByShare.csv',
        'NTFS_BroadAccess.csv','NTFS_DirectAssignments.csv','NTFS_UnresolvedIdentities.csv',
        'NTFS_PrivilegedRights.csv','NTFS_DenyAces.csv','NTFS_BrokenInheritance.csv',
        'NTFS_ShareVsNtfs.csv','NTFS_ShareCoverage.csv','NTFS_ScanErrors.csv',
        'NTFS_SkippedPaths.csv','NTFS_Shares.csv','NTFS_SharePermissions.csv'
    )
    $selectedNames=[Collections.ArrayList]::new()
    $nameIndex=@{}
    $requested=if($Dataset.Count -gt 0){$Dataset}else{$defaultDatasets}
    foreach($candidate in @($requested)){
        $name=[string]$candidate
        if([string]::IsNullOrWhiteSpace($name)){throw 'Dataset names cannot be blank.'}
        if([IO.Path]::GetExtension($name) -ine '.csv'){$name+='.csv'}
        if([IO.Path]::GetFileName($name) -ne $name -or $name -match '[\\/]'){
            throw "Invalid Dataset name: $candidate"
        }
        if(-not $nameIndex.ContainsKey($name)){
            [void]$selectedNames.Add($name)
            $nameIndex[$name]=$true
        }
    }
    if($IncludeRawData){
        foreach($name in @('NTFS_AllAces.csv','NTFS_Folders.csv')){
            if(-not $nameIndex.ContainsKey($name)){
                [void]$selectedNames.Add($name)
                $nameIndex[$name]=$true
            }
        }
    }
    if($selectedNames.Count -eq 0){throw 'At least one dataset must be selected.'}

    $verifiedDatasets=@()
    foreach($name in @($selectedNames)){
        if(-not $datasetMap.ContainsKey($name)){
            throw "Dataset '$name' is unavailable in NTFS_QA.json. Use a CSV dataset name from this report."
        }
        $qaDataset=$datasetMap[$name]
        $canonicalName=[string](Get-NtfsExcelProperty $qaDataset 'Name')
        $verified=@(Get-NtfsExcelVerifiedDataset $reportFolder $qaDataset $canonicalName)
        $verifiedDatasets+=$verified
    }

    $overviewRows=[Collections.ArrayList]::new()
    $overview=@(
        [pscustomobject]@{Section='Workbook';Item='Purpose';Value='Optional Excel review copy; the source merge report remains authoritative.'},
        [pscustomobject]@{Section='Workbook';Item='Source report folder';Value=$reportFolder},
        [pscustomobject]@{Section='Workbook';Item='Merge status';Value=$sourceStatus},
        [pscustomobject]@{Section='Workbook';Item='Merge toolkit version';Value=[string](Get-NtfsExcelProperty $qa 'ToolkitVersion')},
        [pscustomobject]@{Section='Workbook';Item='Exporter version';Value=$script:NtfsVersions.ExcelReview},
        [pscustomobject]@{Section='Workbook';Item='Maximum data rows per sheet';Value=[string]$MaxRowsPerSheet},
        [pscustomobject]@{Section='Workbook';Item='Text safety';Value='Formula-like CSV values are stored as text cells; source files are never edited.'}
    )
    foreach($row in $overview){[void]$overviewRows.Add($row)}
    foreach($property in @($executive.PSObject.Properties)){
        if($property.Name -in @('Limitations','Warnings','Version')){continue}
        [void]$overviewRows.Add([pscustomobject]@{
            Section='Executive summary';Item=$property.Name;Value=[string]$property.Value
        })
    }
    foreach($path in @(Get-NtfsExcelCollection $qa 'SelectedRunFolders')){
        [void]$overviewRows.Add([pscustomobject]@{Section='Selected source run';Item='Run folder';Value=[string]$path})
    }
    foreach($limitation in @(Get-NtfsExcelCollection $qa 'Limitations')){
        [void]$overviewRows.Add([pscustomobject]@{Section='Limitation';Item='Interpretation';Value=[string]$limitation})
    }
    foreach($warning in @(Get-NtfsExcelCollection $qa 'Warnings')){
        [void]$overviewRows.Add([pscustomobject]@{Section='Warning';Item='Source report';Value=[string]$warning})
    }
    foreach($verifiedDataset in @($verifiedDatasets)){
        [void]$overviewRows.Add([pscustomobject]@{
            Section='Integrity-checked dataset';Item=$verifiedDataset.Name;
            Value="$($verifiedDataset.Rows) rows across $($verifiedDataset.Parts.Count) part(s); columns=$($verifiedDataset.Columns.Count)"
        })
    }

    $parent=$resolvedOutputParent
    if(-not(Test-Path -LiteralPath $parent -PathType Container)){
        [void](New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop)
    }
    $pendingPath=Join-Path $parent ('.'+[IO.Path]::GetFileName($resolvedOutput)+'.'+[guid]::NewGuid().ToString('N')+'.pending')
    $workbook=[NtfsAssessment.ExcelReviewWorkbook]::new($pendingPath,[string]$script:NtfsVersions.ExcelReview)
    $usedSheetNames=@{}
    $workbook.BeginSheet('Overview',[string[]]@('Section','Item','Value'))
    $usedSheetNames['Overview']=$true
    foreach($row in @($overviewRows)){
        $workbook.WriteRow([string[]]@([string]$row.Section,[string]$row.Item,[string]$row.Value))
    }
    $workbook.EndSheet()

    $totalDataRows=0L
    $continuationSheets=0
    foreach($verifiedDataset in @($verifiedDatasets)){
        $baseName=Get-NtfsExcelDatasetSheetName $verifiedDataset.Name
        $chunk=1
        $sheetName=Get-NtfsExcelWorksheetName $baseName $chunk
        if($usedSheetNames.ContainsKey($sheetName)){throw "Worksheet name collision for $sheetName."}
        $workbook.BeginSheet($sheetName,[string[]]$verifiedDataset.Columns)
        $usedSheetNames[$sheetName]=$true
        $sheetRows=0
        $datasetRows=0L
        foreach($part in @($verifiedDataset.Parts)){
            $partRows=0L
            Read-NtfsCsvFile $part.Path | ForEach-Object {
                $row=$_
                if($sheetRows -ge $MaxRowsPerSheet){
                    $workbook.EndSheet()
                    $chunk++
                    $sheetName=Get-NtfsExcelWorksheetName $baseName $chunk
                    if($usedSheetNames.ContainsKey($sheetName)){throw "Worksheet name collision for $sheetName."}
                    $workbook.BeginSheet($sheetName,[string[]]$verifiedDataset.Columns)
                    $usedSheetNames[$sheetName]=$true
                    $continuationSheets++
                    $sheetRows=0
                }
                $values=New-Object string[] $verifiedDataset.Columns.Count
                for($columnIndex=0;$columnIndex -lt $verifiedDataset.Columns.Count;$columnIndex++){
                    $column=[string]$verifiedDataset.Columns[$columnIndex]
                    $property=$row.PSObject.Properties[$column]
                    if($null -eq $property){throw "Missing CSV column '$column' in $($part.Name)."}
                    $values[$columnIndex]=[string]$property.Value
                }
                $workbook.WriteRow($values)
                $sheetRows++
                $partRows++
                $datasetRows++
            }
            if($partRows -ne $part.Rows){
                throw "CSV row-count mismatch while reading $($part.Name): expected $($part.Rows), actual $partRows."
            }
            Assert-NtfsExcelPartHash $part
        }
        $workbook.EndSheet()
        if($datasetRows -ne $verifiedDataset.Rows){
            throw "CSV dataset row-count mismatch for $($verifiedDataset.Name): expected $($verifiedDataset.Rows), actual $datasetRows."
        }
        $totalDataRows+=$datasetRows
    }
    $workbook.Complete()
    $workbook.Dispose()
    $workbook=$null
    Test-NtfsExcelPackage $pendingPath ($usedSheetNames.Count)
    [IO.File]::Move($pendingPath,$resolvedOutput)
    $pendingPath=$null
    $completedOutput=$true

    $qaWarnings=@(Get-NtfsExcelCollection $qa 'Warnings')
    $completion=@{
        component='Excel review';status=$(if($sourceStatus -eq 'CompletedWithWarnings' -or $qaWarnings.Count -gt 0){'CompletedWithWarnings'}else{'Completed'})
        summary="Datasets=$($verifiedDatasets.Count); Rows=$totalDataRows; Sheets=$($usedSheetNames.Count); Continuations=$continuationSheets."
        outputPath=$resolvedOutput
        reviewPath=@($resolvedOutput)
        requirements=$(if($qaWarnings.Count -gt 0){"Review $($qaWarnings.Count) source merge warning(s) before interpreting the workbook."}else{''})
        reasonSummary=@($qaWarnings|Group-Object|ForEach-Object{[pscustomobject]@{Count=$_.Count;Reason=$_.Name}})
        nextStep='Open the Overview worksheet first, then filter the report-specific sheets. The workbook is a convenience copy; retain and validate the original merge report for review or handoff.'
    }
    Write-NtfsCompletion @completion
    exit 0
}catch{
    if($null -ne $workbook){
        try{$workbook.Dispose()}catch{
            Write-Warning "Excel review workbook cleanup failed: $($_.Exception.Message)"
        }
        $workbook=$null
    }
    if($pendingPath -and (Test-Path -LiteralPath $pendingPath -PathType Leaf)){
        try{Remove-Item -LiteralPath $pendingPath -Force -ErrorAction Stop}catch{
            Write-Warning "Excel review pending-file cleanup failed for ${pendingPath}: $($_.Exception.Message)"
        }
    }
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    Write-Verbose $_.ScriptStackTrace
    Write-Verbose $_.InvocationInfo.PositionMessage
    $completion=@{
        component='Excel review';status='Failed'
        requirements='Resolve 1 Excel review export failure.'
        reasonSummary=@([pscustomobject]@{Count=1;Reason=$_.Exception.Message})
        nextStep='Next script: New-NtfsExcelReview.ps1, after resolving the recorded source status, QA inventory, dataset limit, output-path, or workbook error. Do not use a partial .pending file.'
    }
    Write-NtfsCompletion @completion
    exit 2
}finally{
    if(-not $completedOutput -and $pendingPath -and (Test-Path -LiteralPath $pendingPath -PathType Leaf)){
        try{Remove-Item -LiteralPath $pendingPath -Force -ErrorAction Stop}catch{
            Write-Warning "Excel review pending-file cleanup failed for ${pendingPath}: $($_.Exception.Message)"
        }
    }
}
