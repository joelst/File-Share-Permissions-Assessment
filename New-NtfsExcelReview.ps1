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
  The output must be a new .xlsx file outside InputReportFolder. On Windows,
  both report and output paths must use direct fixed drive-letter paths; UNC,
  mapped-drive, device-prefix, short-name, and reparse-point aliases are refused.
  The PowerShell 7 path on non-Windows remains a synthetic/offline test surface;
  native Windows share-mode and handle-publication guarantees are unavailable there.
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
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.Win32.SafeHandles;

namespace NtfsAssessment {
    internal static class ExcelReviewNative {
        internal const uint GenericRead = 0x80000000;
        internal const uint GenericWrite = 0x40000000;
        internal const uint Delete = 0x00010000;
        internal const uint ReadAttributes = 0x00000080;
        internal const uint Traverse = 0x00000020;
        internal const uint FileShareRead = 0x00000001;
        internal const uint FileShareWrite = 0x00000002;
        internal const uint CreateNew = 1;
        internal const uint OpenExisting = 3;
        internal const uint FileFlagBackupSemantics = 0x02000000;
        internal const uint FileFlagOpenReparsePoint = 0x00200000;
        internal const uint FileFlagWriteThrough = 0x80000000;
        internal const uint FileAttributeReparsePoint = 0x00000400;
        internal const uint FileAttributeDirectory = 0x00000010;
        internal const int FileRenameInfo = 3;
        internal const int FileIdInfo = 18;
        internal const uint DriveFixed = 3;

        public static bool IsWindows {
            get { return Environment.OSVersion.Platform == PlatformID.Win32NT; }
        }

        public static string NormalizeFinalPath(string path) {
            if (String.IsNullOrWhiteSpace(path)) return path;
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                return @"\\" + path.Substring(8);
            if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                return path.Substring(4);
            return path;
        }

        public static string TrimDirectoryPath(string path) {
            if (String.IsNullOrEmpty(path)) return path;
            string root = System.IO.Path.GetPathRoot(path);
            return String.Equals(path, root, StringComparison.OrdinalIgnoreCase)
                ? path
                : path.TrimEnd('\\', '/');
        }

        public static bool IsDirectDrivePath(string path) {
            if (!Regex.IsMatch(path, @"^[A-Za-z]:\\(?:[^\\]+(?:\\[^\\]+)*)?$")) return false;
            string relative = path.Substring(2);
            return relative.IndexOf(':') < 0 &&
                !Regex.IsMatch(relative, @"[/\x00-\x1f<>|?*""]");
        }

        public static void ThrowLastError(string operation) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error, operation + ": " + new Win32Exception(error).Message +
                " (Win32 " + error.ToString(CultureInfo.InvariantCulture) + ")");
        }

        public static SafeFileHandle OpenFile(string path, uint access, uint sharing, uint disposition, uint flags) {
            SafeFileHandle handle = CreateFileW(path, access, sharing, IntPtr.Zero, disposition, flags, IntPtr.Zero);
            if (handle.IsInvalid) {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Cannot open handle for " + path);
            }
            return handle;
        }

        public static FileInformation GetInformation(SafeFileHandle handle, string path) {
            FileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
                ThrowLastError("Read file information for " + path);
            return information;
        }

        public static string GetFinalPath(SafeFileHandle handle) {
            StringBuilder buffer = new StringBuilder(512);
            while (true) {
                uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
                if (length == 0) ThrowLastError("Resolve handle path");
                if (length < buffer.Capacity) break;
                buffer = new StringBuilder((int)length + 1);
            }
            return NormalizeFinalPath(buffer.ToString());
        }

        public static string GetStableIdentity(SafeFileHandle handle, string volumeName) {
            byte[] fileId = new byte[24];
            if (GetFileInformationByHandleEx(handle, FileIdInfo, fileId, (uint)fileId.Length)) {
                bool nonZero = false;
                for (int i = 8; i < fileId.Length; i++) {
                    if (fileId[i] != 0) {
                        nonZero = true;
                        break;
                    }
                }
                if (nonZero)
                    return volumeName.ToUpperInvariant() + "|" + BitConverter.ToString(fileId).Replace("-", "");
            }
            FileInformation information = GetInformation(handle, "file identity");
            ulong index = ((ulong)information.IndexHigh << 32) | information.IndexLow;
            if (index == 0) throw new InvalidOperationException("The file handle has no stable file identifier.");
            return volumeName.ToUpperInvariant() + "|" +
                information.VolumeSerial.ToString("X8", CultureInfo.InvariantCulture) + ":" +
                index.ToString("X16", CultureInfo.InvariantCulture);
        }

        public static string GetVolumeName(string driveRoot) {
            StringBuilder name = new StringBuilder(128);
            if (!GetVolumeNameForVolumeMountPointW(driveRoot, name, (uint)name.Capacity))
                ThrowLastError("Resolve drive volume");
            return name.ToString();
        }

        public static void RenameFile(SafeFileHandle file, SafeFileHandle directory, string relativeName) {
            if (file == null || file.IsInvalid) throw new ArgumentException("file");
            if (directory == null || directory.IsInvalid) throw new ArgumentException("directory");
            if (String.IsNullOrWhiteSpace(relativeName) ||
                relativeName.IndexOfAny(new char[] { '\\', '/', '\0' }) >= 0)
                throw new ArgumentException("The output name must be a direct child name.", "relativeName");

            // The Win32 wrapper expands relative names; use the pinned directory's full path.
            byte[] name = Encoding.Unicode.GetBytes(System.IO.Path.Combine(GetFinalPath(directory), relativeName));
            int headerSize = IntPtr.Size == 8 ? 20 : 12;
            int bufferSize = (IntPtr.Size == 8 ? 24 : 16) + name.Length;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try {
                for (int i = 0; i < bufferSize; i++) Marshal.WriteByte(buffer, i, 0);
                int lengthOffset = IntPtr.Size == 8 ? 16 : 8;
                Marshal.WriteInt32(buffer, lengthOffset, name.Length);
                Marshal.Copy(name, 0, IntPtr.Add(buffer, headerSize), name.Length);
                if (!SetFileInformationByHandle(file, FileRenameInfo, buffer, (uint)bufferSize))
                    ThrowLastError("Publish workbook by handle");
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME AccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME WriteTime;
            public uint VolumeSerial;
            public uint SizeHigh;
            public uint SizeLow;
            public uint NumberOfLinks;
            public uint IndexHigh;
            public uint IndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
            [Out] byte[] information, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder name, uint size, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool GetVolumeNameForVolumeMountPointW(string mountPoint, StringBuilder name, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern uint GetDriveTypeW(string root);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass,
            IntPtr information, uint size);
    }

    public sealed class ExcelReviewDirectoryLease : IDisposable {
        private readonly bool native;
        private readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        private readonly List<string> identities = new List<string>();
        private readonly string path;
        private bool disposed;

        private ExcelReviewDirectoryLease(string requestedPath, bool nativeLease) {
            path = ExcelReviewNative.TrimDirectoryPath(System.IO.Path.GetFullPath(requestedPath));
            native = nativeLease;
            if (!native) return;
            if (!ExcelReviewNative.IsDirectDrivePath(path))
                throw new ArgumentException("Windows Excel review paths must use direct drive-letter paths, not UNC, mapped-drive, or device aliases: " + requestedPath);
            string root = System.IO.Path.GetPathRoot(path);
            string volume = ExcelReviewNative.GetVolumeName(root);
            if (ExcelReviewNative.GetDriveTypeW(volume) != ExcelReviewNative.DriveFixed)
                throw new InvalidOperationException("Windows Excel review paths must be on a fixed local volume: " + requestedPath);
            string relative = path.Length == root.Length ? String.Empty : path.Substring(root.Length);
            List<string> components = new List<string>();
            components.Add(root);
            if (!String.IsNullOrEmpty(relative)) {
                string current = root;
                string[] names = relative.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < names.Length; i++) {
                    current = System.IO.Path.Combine(current, names[i]);
                    components.Add(current);
                }
            }
            try {
                foreach (string component in components) {
                    SafeFileHandle handle = ExcelReviewNative.OpenFile(
                        component,
                        // Attribute-only opens do not participate in share-access tracking.
                        ExcelReviewNative.ReadAttributes | ExcelReviewNative.Traverse,
                        ExcelReviewNative.FileShareRead | ExcelReviewNative.FileShareWrite,
                        ExcelReviewNative.OpenExisting,
                        ExcelReviewNative.FileFlagBackupSemantics | ExcelReviewNative.FileFlagOpenReparsePoint);
                    handles.Add(handle);
                    ExcelReviewNative.FileInformation information = ExcelReviewNative.GetInformation(handle, component);
                    if ((information.Attributes & ExcelReviewNative.FileAttributeReparsePoint) != 0 ||
                        (information.Attributes & ExcelReviewNative.FileAttributeDirectory) == 0) {
                        throw new InvalidOperationException("Reparse point or non-directory component in Excel review path: " + component);
                    }
                    string finalPath = ExcelReviewNative.TrimDirectoryPath(ExcelReviewNative.GetFinalPath(handle));
                    string expectedPath = ExcelReviewNative.TrimDirectoryPath(System.IO.Path.GetFullPath(component));
                    if (!String.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase)) {
                        throw new InvalidOperationException("Drive alias, short-name, mapped path, or physical namespace mismatch: " + component);
                    }
                    identities.Add(ExcelReviewNative.GetStableIdentity(handle, volume));
                }
            } catch {
                Dispose();
                throw;
            }
        }

        public static ExcelReviewDirectoryLease Open(string path) {
            if (String.IsNullOrWhiteSpace(path)) throw new ArgumentException("path");
            if (!Directory.Exists(path)) throw new DirectoryNotFoundException(path);
            if (!ExcelReviewNative.IsWindows) {
                string current = ExcelReviewNative.TrimDirectoryPath(System.IO.Path.GetFullPath(path));
                while (!String.IsNullOrEmpty(current)) {
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidOperationException("Reparse point in Excel review path: " + current);
                    string parent = System.IO.Path.GetDirectoryName(current);
                    if (String.Equals(parent, current, StringComparison.Ordinal)) break;
                    current = parent;
                }
            }
            return new ExcelReviewDirectoryLease(path, ExcelReviewNative.IsWindows);
        }

        public static ExcelReviewDirectoryLease CreateOutside(string path, ExcelReviewDirectoryLease source) {
            if (source == null) throw new ArgumentNullException("source");
            string current = ExcelReviewNative.TrimDirectoryPath(System.IO.Path.GetFullPath(path));
            Stack<string> missing = new Stack<string>();
            while (!Directory.Exists(current)) {
                missing.Push(current);
                string parent = System.IO.Path.GetDirectoryName(current);
                if (String.IsNullOrEmpty(parent) || String.Equals(parent, current, StringComparison.Ordinal))
                    throw new DirectoryNotFoundException(path);
                current = parent;
            }
            ExcelReviewDirectoryLease lease = Open(current);
            try {
                while (true) {
                    if (lease.RoutesThrough(source))
                        throw new InvalidOperationException("OutputPath is within or aliased to InputReportFolder so source report evidence remains unchanged.");
                    if (missing.Count == 0) return lease;
                    string child = missing.Pop();
                    // Pin each new component before creating anything below it.
                    Directory.CreateDirectory(child);
                    ExcelReviewDirectoryLease next = Open(child);
                    lease.Dispose();
                    lease = next;
                }
            } catch {
                lease.Dispose();
                throw;
            }
        }

        public bool IsNative { get { return native; } }
        public string Path { get { return path; } }
        public string TargetIdentity { get { return identities.Count == 0 ? path : identities[identities.Count - 1]; } }
        public SafeFileHandle TargetHandle { get { return handles.Count == 0 ? null : handles[handles.Count - 1]; } }

        public bool RoutesThrough(ExcelReviewDirectoryLease directory) {
            if (directory == null) throw new ArgumentNullException("directory");
            if (native != directory.native)
                throw new InvalidOperationException("Cannot compare mixed native and test path leases.");
            if (native) {
                string identity = directory.TargetIdentity;
                foreach (string routeIdentity in identities)
                    if (String.Equals(routeIdentity, identity, StringComparison.Ordinal)) return true;
                return false;
            }
            string root = ExcelReviewNative.TrimDirectoryPath(directory.path);
            string current = ExcelReviewNative.TrimDirectoryPath(path);
            if (String.Equals(current, root, StringComparison.Ordinal)) return true;
            return current.StartsWith(root + System.IO.Path.DirectorySeparatorChar, StringComparison.Ordinal);
        }

        public void Dispose() {
            if (disposed) return;
            disposed = true;
            for (int i = handles.Count - 1; i >= 0; i--) handles[i].Dispose();
        }
    }

    public sealed class ExcelReviewPinnedFile : IDisposable {
        private readonly FileStream stream;
        private readonly SafeFileHandle handle;
        private readonly bool native;
        private readonly string path;
        private bool disposed;

        private ExcelReviewPinnedFile(string requestedPath, SafeFileHandle nativeHandle, FileStream openedStream, bool nativeFile) {
            path = requestedPath;
            handle = nativeHandle;
            stream = openedStream;
            native = nativeFile;
        }

        public static ExcelReviewPinnedFile Open(string requestedPath) {
            if (String.IsNullOrWhiteSpace(requestedPath)) throw new ArgumentException("requestedPath");
            string fullPath = System.IO.Path.GetFullPath(requestedPath);
            if (ExcelReviewNative.IsWindows) {
                SafeFileHandle handle = ExcelReviewNative.OpenFile(
                    fullPath,
                    ExcelReviewNative.GenericRead,
                    ExcelReviewNative.FileShareRead,
                    ExcelReviewNative.OpenExisting,
                    ExcelReviewNative.FileFlagOpenReparsePoint);
                try {
                    ExcelReviewNative.FileInformation information = ExcelReviewNative.GetInformation(handle, fullPath);
                    if ((information.Attributes & ExcelReviewNative.FileAttributeReparsePoint) != 0)
                        throw new InvalidOperationException("Reparse-point source file is not allowed: " + fullPath);
                    if ((information.Attributes & ExcelReviewNative.FileAttributeDirectory) != 0)
                        throw new InvalidOperationException("Source path is not a file: " + fullPath);
                    if (information.NumberOfLinks != 1)
                        throw new InvalidOperationException("Hard-linked source file is not allowed: " + fullPath);
                    string finalPath = ExcelReviewNative.TrimDirectoryPath(ExcelReviewNative.GetFinalPath(handle));
                    string expectedPath = ExcelReviewNative.TrimDirectoryPath(System.IO.Path.GetFullPath(fullPath));
                    if (!String.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Aliased source file path is not allowed: " + fullPath);
                    FileStream stream = new FileStream(handle, FileAccess.Read);
                    return new ExcelReviewPinnedFile(fullPath, handle, stream, true);
                } catch {
                    handle.Dispose();
                    throw;
                }
            }

            if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Reparse-point source file is not allowed: " + fullPath);
            FileStream nonNative = new FileStream(
                fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
            try {
                if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Source file became a reparse point: " + fullPath);
                return new ExcelReviewPinnedFile(fullPath, null, nonNative, false);
            } catch {
                nonNative.Dispose();
                throw;
            }
        }

        public FileStream Stream { get { return stream; } }
        public long Length { get { return stream.Length; } }
        public bool IsNative { get { return native; } }
        public string Path { get { return path; } }

        public void Dispose() {
            if (disposed) return;
            disposed = true;
            stream.Dispose();
            if (handle != null) handle.Dispose();
        }
    }

    public sealed class ExcelReviewHashingReadStream : Stream {
        private readonly Stream source;
        private readonly SHA256 sha256 = SHA256.Create();
        private string hash;
        private bool disposed;
        private long bytesRead;

        public ExcelReviewHashingReadStream(Stream input) {
            if (input == null) throw new ArgumentNullException("input");
            if (!input.CanRead) throw new ArgumentException("input");
            source = input;
        }

        public long BytesRead { get { return bytesRead; } }
        public override bool CanRead { get { return !disposed; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int offset, int count) {
            int read = source.Read(buffer, offset, count);
            if (read > 0) {
                sha256.TransformBlock(buffer, offset, read, buffer, offset);
                bytesRead += read;
            }
            return read;
        }

        public string CompleteHash() {
            if (hash != null) return hash;
            sha256.TransformFinalBlock(new byte[0], 0, 0);
            hash = BitConverter.ToString(sha256.Hash).Replace("-", "").ToLowerInvariant();
            return hash;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }

        protected override void Dispose(bool disposing) {
            if (!disposed) {
                disposed = true;
                if (disposing) sha256.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    public sealed class ExcelReviewOutputFile : IDisposable {
        private readonly string pendingPath;
        private readonly string finalPath;
        private readonly FileStream stream;
        private readonly SafeFileHandle handle;
        private bool published;
        private bool disposed;

        private ExcelReviewOutputFile(string pending, string final, SafeFileHandle nativeHandle, FileStream openedStream) {
            pendingPath = pending;
            finalPath = final;
            handle = nativeHandle;
            stream = openedStream;
        }

        public static ExcelReviewOutputFile Create(string pending, string final) {
            if (File.Exists(final)) throw new IOException("OutputPath already exists and will not be overwritten: " + final);
            if (ExcelReviewNative.IsWindows) {
                SafeFileHandle handle = ExcelReviewNative.OpenFile(
                    pending,
                    ExcelReviewNative.GenericRead | ExcelReviewNative.GenericWrite | ExcelReviewNative.Delete,
                    ExcelReviewNative.FileShareRead,
                    ExcelReviewNative.CreateNew,
                    ExcelReviewNative.FileFlagWriteThrough);
                try {
                    FileStream stream = new FileStream(handle, FileAccess.ReadWrite);
                    return new ExcelReviewOutputFile(pending, final, handle, stream);
                } catch {
                    handle.Dispose();
                    throw;
                }
            }
            FileStream file = new FileStream(
                pending, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 65536, FileOptions.WriteThrough);
            return new ExcelReviewOutputFile(pending, final, null, file);
        }

        public FileStream Stream { get { return stream; } }
        public string PendingPath { get { return pendingPath; } }
        public bool Published { get { return published; } }

        public void Publish(ExcelReviewDirectoryLease directory) {
            if (disposed || published) throw new ObjectDisposedException("ExcelReviewOutputFile");
            stream.Flush(true);
            if (ExcelReviewNative.IsWindows) {
                if (directory == null || !directory.IsNative)
                    throw new InvalidOperationException("A native output-directory lease is required for publication.");
                if (!String.Equals(
                    ExcelReviewNative.TrimDirectoryPath(System.IO.Path.GetDirectoryName(finalPath)),
                    ExcelReviewNative.TrimDirectoryPath(directory.Path),
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("The workbook output lease does not match the requested directory.");
                ExcelReviewNative.RenameFile(handle, directory.TargetHandle, System.IO.Path.GetFileName(finalPath));
            } else {
                stream.Dispose();
                File.Move(pendingPath, finalPath);
            }
            published = true;
        }

        public void Dispose() {
            if (disposed) return;
            disposed = true;
            stream.Dispose();
            if (handle != null) handle.Dispose();
        }
    }

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
            "InheritanceProtected", "Inherited", "IsInherited", "MemberEnabled", "Remediable", "Resolved",
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

        private readonly Stream file;
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

        public ExcelReviewWorkbook(Stream output, string componentVersion) {
            if (output == null || !output.CanWrite || !output.CanSeek) throw new ArgumentException("A seekable, writable output stream is required.", "output");
            if (String.IsNullOrWhiteSpace(componentVersion)) throw new ArgumentException("componentVersion");
            file = output;
            archive = new ZipArchive(file, ZipArchiveMode.Create, true);
            createdUtc = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
            version = componentVersion;
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
            string encodedText = EscapeXstring(text);
            try { XmlConvert.VerifyXmlChars(encodedText); }
            catch (XmlException ex) {
                throw new InvalidDataException(String.Format(
                    CultureInfo.InvariantCulture,
                    "Cell {0}{1} could not be encoded as XML-safe OOXML text.",
                    GetColumnName(column), rowNumber), ex);
            }

            if (!headerRow && text.Length == 0) return;
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
            writer.WriteString(encodedText);
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

        private static string EscapeXstring(string text) {
            if (String.IsNullOrEmpty(text)) return text;
            StringBuilder escaped = null;
            int unchanged = 0;
            for (int i = 0; i < text.Length; i++) {
                if (Char.IsHighSurrogate(text[i]) && i + 1 < text.Length && Char.IsLowSurrogate(text[i + 1])) {
                    i++;
                    continue;
                }
                bool literalEscape = i + 6 < text.Length && text[i] == '_' &&
                    (text[i + 1] == 'x' || text[i + 1] == 'X') && text[i + 6] == '_';
                if (literalEscape) {
                    for (int digit = i + 2; digit <= i + 5; digit++) {
                        char value = text[digit];
                        if (!((value >= '0' && value <= '9') ||
                            (value >= 'A' && value <= 'F') ||
                            (value >= 'a' && value <= 'f'))) {
                            literalEscape = false;
                            break;
                        }
                    }
                }
                if (!literalEscape && XmlConvert.IsXmlChar(text[i])) continue;
                if (escaped == null) escaped = new StringBuilder(text.Length + 10);
                escaped.Append(text, unchanged, i - unchanged);
                escaped.Append("_x");
                escaped.Append(((int)text[i]).ToString("X4", CultureInfo.InvariantCulture));
                escaped.Append('_');
                // The trailing underscore may also start the next escape token.
                unchanged = i + 1;
            }
            if (escaped == null) return text;
            if (unchanged < text.Length) escaped.Append(text, unchanged, text.Length - unchanged);
            return escaped.ToString();
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
                xml.Append(Escape(EscapeXstring(sheet.Name)));
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
            foreach (SheetInfo sheet in sheets) xml.Append("<vt:lpstr>" + Escape(EscapeXstring(sheet.Name)) + "</vt:lpstr>");
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
            file.Flush();
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
            [Xml.XmlWriter].Assembly.Location,
            [Text.RegularExpressions.Regex].Assembly.Location,
            [ComponentModel.Win32Exception].Assembly.Location,
            [Microsoft.Win32.SafeHandles.SafeFileHandle].Assembly.Location,
            [Security.Cryptography.SHA256].Assembly.Location
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

function Read-NtfsExcelPinnedText([string]$Path,[long]$MaxBytes=268435456) {
    $pinned=$null
    $reader=$null
    try{
        $pinned=[NtfsAssessment.ExcelReviewPinnedFile]::Open($Path)
        if($pinned.Length -gt $MaxBytes){throw "Source text file exceeds the $MaxBytes-byte limit: $Path"}
        $reader=[IO.StreamReader]::new($pinned.Stream,[Text.Encoding]::UTF8,$true,16384,$true)
        return $reader.ReadToEnd()
    }finally{
        if($null -ne $reader){$reader.Dispose()}
        if($null -ne $pinned){$pinned.Dispose()}
    }
}

function Read-NtfsExcelJson([string]$Path) {
    return (Read-NtfsExcelPinnedText $Path|ConvertFrom-Json -ErrorAction Stop)
}

function Read-NtfsExcelCsvPart($Part,[string[]]$Columns) {
    $pinned=$null
    $hashing=$null
    $reader=$null
    try{
        $pinned=[NtfsAssessment.ExcelReviewPinnedFile]::Open($Part.Path)
        if($pinned.Length -ne $Part.Bytes){
            throw "Source CSV size changed for $($Part.Name): expected $($Part.Bytes), actual $($pinned.Length)."
        }
        $hashing=[NtfsAssessment.ExcelReviewHashingReadStream]::new($pinned.Stream)
        $reader=[IO.StreamReader]::new($hashing,[Text.Encoding]::UTF8,$true,16384,$true)
        $header=[NtfsAssessment.Csv]::ReadRecord($reader)
        if($Columns.Count -eq 0){
            if($null -ne $header -or $Part.Bytes -ne 0 -or $Part.Rows -ne 0){
                throw "QA dataset part $($Part.Name) is marked empty, but it contains a header or records."
            }
        }else{
            if($null -eq $header){throw "Missing CSV header: $($Part.Path)"}
            $actualColumns=[NtfsAssessment.Csv]::Parse($header)
            if((ConvertTo-NtfsCsvRecord $actualColumns) -cne (ConvertTo-NtfsCsvRecord $Columns)){
                throw "CSV header does not match QA column order: $($Part.Path)"
            }
        }

        $rows=0L
        while($null -ne ($record=[NtfsAssessment.Csv]::ReadRecord($reader))){
            if($record.Length -eq 0){continue}
            $fields=[NtfsAssessment.Csv]::Parse($record)
            if($fields.Length -ne $Columns.Length){
                throw "CSV column count mismatch in $($Part.Path)"
            }
            $row=[ordered]@{}
            for($i=0;$i -lt $Columns.Length;$i++){$row[$Columns[$i]]=$fields[$i]}
            $rows++
            [pscustomobject]$row
        }

        $hash=$hashing.CompleteHash()
        if($hashing.BytesRead -ne $pinned.Length){
            throw "CSV parser did not consume every byte in $($Part.Name): expected $($pinned.Length), read $($hashing.BytesRead)."
        }
        if($rows -ne $Part.Rows){
            throw "CSV row-count mismatch for $($Part.Name): expected $($Part.Rows), actual $rows."
        }
        if($hash -ne $Part.SHA256){
            throw "Source CSV hash mismatch for $($Part.Name). The report may have changed; rerun Merge-NtfsAssessment.ps1."
        }
    }finally{
        if($null -ne $reader){$reader.Dispose()}
        if($null -ne $hashing){$hashing.Dispose()}
        if($null -ne $pinned){$pinned.Dispose()}
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
        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if($item.PSIsContainer){throw "Source CSV path is not a file: $path"}
        $verifiedPart=[pscustomobject]@{
            Name=$partName;Path=$path;Bytes=$bytes;Rows=$partRows;SHA256=$sha256
        }
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

function Test-NtfsExcelPackage([IO.Stream]$Stream,[int]$ExpectedSheets) {
    if(-not $Stream.CanRead -or -not $Stream.CanSeek){throw 'Workbook package validation requires a seekable read stream.'}
    $Stream.Position=0
    $archive=$null
    try{
        $archive=[IO.Compression.ZipArchive]::new($Stream,[IO.Compression.ZipArchiveMode]::Read,$true)
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
        $Stream.Position=0
    }
}

$reportFolder=$null
$resolvedOutput=$null
$pendingPath=$null
$workbook=$null
$outputFile=$null
$sourceDirectoryLease=$null
$outputDirectoryLease=$null
$completedOutput=$false
try{
    $reportFolder=(Resolve-Path -LiteralPath $InputReportFolder -ErrorAction Stop).ProviderPath
    if(-not(Test-Path -LiteralPath $reportFolder -PathType Container)){
        throw "InputReportFolder is not a directory: $InputReportFolder"
    }
    $sourceDirectoryLease=[NtfsAssessment.ExcelReviewDirectoryLease]::Open($reportFolder)
    $resolvedOutput=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    if([IO.Path]::GetExtension($resolvedOutput) -ine '.xlsx'){throw 'OutputPath must use the .xlsx extension.'}
    $resolvedOutputLeaf=[IO.Path]::GetFileName($resolvedOutput)
    if($resolvedOutputLeaf -match ':'){throw 'OutputPath leaf cannot contain an alternate-data-stream separator.'}
    if(Test-Path -LiteralPath $resolvedOutput){throw "OutputPath already exists and will not be overwritten: $resolvedOutput"}
    $resolvedOutputParent=[IO.Path]::GetDirectoryName($resolvedOutput)
    if([string]::IsNullOrWhiteSpace($resolvedOutputParent)){throw "OutputPath has no parent directory: $resolvedOutput"}
    $outputDirectoryLease=[NtfsAssessment.ExcelReviewDirectoryLease]::CreateOutside($resolvedOutputParent,$sourceDirectoryLease)

    $statePath=Join-Path $reportFolder 'merge-state.json'
    $qaPath=Join-Path $reportFolder 'NTFS_QA.json'
    $summaryPath=Join-Path $reportFolder 'NTFS_ExecutiveSummary.json'
    foreach($required in @($statePath,$qaPath,$summaryPath)){
        if(-not(Test-Path -LiteralPath $required -PathType Leaf)){
            throw "This is not a completed merge report folder; missing $([IO.Path]::GetFileName($required))."
        }
    }
    $state=Read-NtfsExcelJson $statePath
    $qa=Read-NtfsExcelJson $qaPath
    $executive=Read-NtfsExcelJson $summaryPath
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

    $pendingPath=Join-Path $resolvedOutputParent ('.'+[IO.Path]::GetFileName($resolvedOutput)+'.'+[guid]::NewGuid().ToString('N')+'.pending')
    $outputFile=[NtfsAssessment.ExcelReviewOutputFile]::Create($pendingPath,$resolvedOutput)
    $workbook=[NtfsAssessment.ExcelReviewWorkbook]::new($outputFile.Stream,[string]$script:NtfsVersions.ExcelReview)
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
            Read-NtfsExcelCsvPart $part $verifiedDataset.Columns | ForEach-Object {
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
    Test-NtfsExcelPackage $outputFile.Stream ($usedSheetNames.Count)
    $outputFile.Publish($outputDirectoryLease)
    $outputFile.Dispose()
    $outputFile=$null
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
    if($null -ne $outputFile){
        try{$outputFile.Dispose()}catch{
            Write-Warning "Excel review output-handle cleanup failed: $($_.Exception.Message)"
        }
        $outputFile=$null
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
    foreach($lease in @($outputDirectoryLease,$sourceDirectoryLease)){
        if($null -ne $lease){
            try{$lease.Dispose()}catch{
                Write-Warning "Excel review directory-lease cleanup failed: $($_.Exception.Message)"
            }
        }
    }
}
