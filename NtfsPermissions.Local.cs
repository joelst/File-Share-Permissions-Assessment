using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace NtfsPermissions.LocalCandidate
{
    // Internal candidate only. Public Apply/Revert do not load or invoke this adapter.
    public sealed class Lease : IDisposable
    {
        public const string SourceSHA256 = "__SOURCE_SHA256__";
        private const uint ReadControl = 0x20000;
        private const uint WriteDac = 0x40000;
        private const uint ReadAttributes = 0x80;
        private const uint ReadDataOrListDirectory = 0x1;
        private const uint OpenExisting = 3;
        private const uint BackupAndOpenReparse = 0x02200000;
        private readonly List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
        private SafeFileHandle handle;
        private readonly bool writable;
        private readonly string volumeRoot;
        private readonly string identity;
        private bool disposed;

        public string Path { get; private set; }
        public string PhysicalPath { get { return volumeRoot + Path.Substring(3); } }
        public bool Writable { get { return writable; } }

        private Lease(string path, bool writeAccess, bool auditDirectory)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                throw new PlatformNotSupportedException("The local candidate requires Windows.");
            if (!Regex.IsMatch(path, @"^[A-Za-z]:\\[^\\]+(?:\\[^\\]+)*$") ||
                Regex.IsMatch(path.Substring(3), "[/\\x00-\\x1f:*?\"<>|]"))
                throw new ArgumentException("Only direct local paths below a fixed NTFS drive root are supported.");
            foreach (string part in path.Substring(3).Split('\\'))
                if (part == "." || part == ".." || part.EndsWith(".") || part.EndsWith(" ") ||
                    Regex.IsMatch(part, @"^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)"))
                    throw new ArgumentException("Ambiguous local path component.");

            Path = char.ToUpperInvariant(path[0]) + path.Substring(1);
            writable = writeAccess;
            string driveRoot = Path.Substring(0, 3);
            StringBuilder volume = new StringBuilder(128);
            if (!GetVolumeNameForVolumeMountPointW(driveRoot, volume, (uint)volume.Capacity))
                ThrowLastError("Resolve direct volume");
            volumeRoot = volume.ToString();
            if (GetDriveTypeW(volumeRoot) != 3)
                throw new InvalidOperationException("A fixed local volume is required.");

            try
            {
                // Deny delete sharing for every ancestor to pin the route, not just the leaf.
                string ancestor = driveRoot;
                ancestors.Add(OpenChecked(ancestor, ReadAttributes, 3));
                string[] parts = Path.Substring(3).Split('\\');
                for (int i = 0; i < parts.Length - 1; i++)
                {
                    ancestor = System.IO.Path.Combine(ancestor, parts[i]);
                    ancestors.Add(OpenChecked(ancestor, ReadAttributes, 3));
                }
                // Target handles remain zero-share during DACL operations. The audit directory
                // permits child-file renames while still denying delete sharing on its route.
                handle = OpenChecked(Path, ReadControl | ReadAttributes | ReadDataOrListDirectory | (writable ? WriteDac : 0),
                    auditDirectory ? 3u : 0u);
                identity = ReadIdentity(handle);
                Snapshot initial = Read();
                if (auditDirectory && initial.Kind != "Folder")
                    throw new InvalidOperationException("The audit namespace must be a directory.");
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public static Lease Open(string path, bool writable)
        {
            return new Lease(path, writable, false);
        }

        public static Lease OpenAuditDirectory(string path)
        {
            return new Lease(path, false, true);
        }

        private SafeFileHandle OpenChecked(string path, uint access, uint sharing)
        {
            SafeFileHandle result = CreateFileW(path, access, sharing, IntPtr.Zero,
                OpenExisting, BackupAndOpenReparse, IntPtr.Zero);
            if (result.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                result.Dispose();
                throw new Win32Exception(error, "Cannot pin local NTFS path: " + path);
            }
            try
            {
                CheckObject(result, path);
                return result;
            }
            catch
            {
                result.Dispose();
                throw;
            }
        }

        private void CheckObject(SafeFileHandle file, string path)
        {
            FileInformation info;
            if (!GetFileInformationByHandle(file, out info)) ThrowLastError("Read object attributes");
            if ((info.Attributes & 0x400) != 0)
                throw new InvalidOperationException("Reparse points and mounted-folder aliases are unsupported: " + path);
            if ((info.Attributes & 0x10) == 0 && info.NumberOfLinks != 1)
                throw new InvalidOperationException("Hard-linked files are unsupported: " + path);

            StringBuilder name = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(file, name, (uint)name.Capacity, 1);
            if (length == 0) ThrowLastError("Resolve handle namespace");
            if (length >= name.Capacity) throw new InvalidOperationException("Handle namespace exceeds the path bound.");
            string expected = volumeRoot + path.Substring(3);
            if (!String.Equals(name.ToString().TrimEnd('\\'), expected.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Drive alias, short-name, or physical namespace mismatch: " + path);

            StringBuilder filesystem = new StringBuilder(64);
            uint serial, maximum, flags;
            if (!GetVolumeInformationByHandleW(file, null, 0, out serial, out maximum, out flags,
                filesystem, (uint)filesystem.Capacity)) ThrowLastError("Read handle filesystem");
            if (!String.Equals(filesystem.ToString(), "NTFS", StringComparison.Ordinal))
                throw new InvalidOperationException("The pinned object is not on NTFS.");
        }

        private string ReadIdentity(SafeFileHandle file)
        {
            byte[] id = new byte[24]; // FILE_ID_INFO: volume serial (64 bits), file ID (128 bits).
            if (!GetFileInformationByHandleEx(file, 18, id, (uint)id.Length))
                ThrowLastError("Read stable FILE_ID_INFO");
            return "LocalNTFS:" + Environment.MachineName + ":" + volumeRoot + ":" +
                BitConverter.ToString(id).Replace("-", "");
        }

        public Snapshot Read()
        {
            if (disposed) throw new ObjectDisposedException("Lease");
            CheckObject(handle, Path);
            if (!String.Equals(identity, ReadIdentity(handle), StringComparison.Ordinal))
                throw new InvalidOperationException("Pinned object identity changed.");
            IntPtr owner, group, dacl, sacl, descriptor;
            uint error = GetSecurityInfo(handle, 1, 7, out owner, out group, out dacl, out sacl, out descriptor);
            if (error != 0) throw new Win32Exception((int)error, "Read handle security descriptor");
            try
            {
                uint length = GetSecurityDescriptorLength(descriptor);
                if (length == 0 || length > 100000)
                    throw new InvalidOperationException("Invalid security descriptor size.");
                byte[] bytes = new byte[length];
                Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                RawSecurityDescriptor raw = new RawSecurityDescriptor(bytes, 0);
                ValidateDescriptor(raw);
                FileInformation info;
                if (!GetFileInformationByHandle(handle, out info)) ThrowLastError("Read object kind");
                return new Snapshot {
                    Path = Path,
                    Kind = (info.Attributes & 0x10) != 0 ? "Folder" : "File",
                    Identity = identity,
                    Descriptor = raw.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Group |
                        AccessControlSections.Access)
                };
            }
            finally
            {
                if (descriptor != IntPtr.Zero) LocalFree(descriptor);
            }
        }

        private static void ValidateDescriptor(RawSecurityDescriptor raw)
        {
            if (raw.Owner == null || raw.Group == null || raw.DiscretionaryAcl == null ||
                (raw.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
                throw new InvalidOperationException("Missing owner/group or absent/null DACL.");
            if (raw.DiscretionaryAcl.Count > 1500 || raw.DiscretionaryAcl.BinaryLength > 60000)
                throw new InvalidOperationException("DACL size guard exceeded.");
            foreach (GenericAce ace in raw.DiscretionaryAcl)
            {
                CommonAce common = ace as CommonAce;
                if (common == null || common.IsCallback || common.OpaqueLength != 0 ||
                    (common.AceQualifier != AceQualifier.AccessAllowed && common.AceQualifier != AceQualifier.AccessDenied) ||
                    common.AccessMask < 0)
                    throw new InvalidOperationException("Conditional, object, opaque or unsupported ACE.");
            }
            if (!new CommonSecurityDescriptor(false, false, raw).IsDiscretionaryAclCanonical)
                throw new InvalidOperationException("Noncanonical DACL.");
            RawSecurityDescriptor roundTrip = new RawSecurityDescriptor(raw.GetSddlForm(
                AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access));
            if (raw.ControlFlags != roundTrip.ControlFlags || !raw.Owner.Equals(roundTrip.Owner) ||
                !raw.Group.Equals(roundTrip.Group) || roundTrip.DiscretionaryAcl == null ||
                raw.DiscretionaryAcl.BinaryLength != roundTrip.DiscretionaryAcl.BinaryLength)
                throw new InvalidOperationException("Security descriptor cannot be represented losslessly.");
            byte[] originalAcl = new byte[raw.DiscretionaryAcl.BinaryLength];
            byte[] roundTripAcl = new byte[roundTrip.DiscretionaryAcl.BinaryLength];
            raw.DiscretionaryAcl.GetBinaryForm(originalAcl, 0);
            roundTrip.DiscretionaryAcl.GetBinaryForm(roundTripAcl, 0);
            for (int i = 0; i < originalAcl.Length; i++)
                if (originalAcl[i] != roundTripAcl[i])
                    throw new InvalidOperationException("DACL cannot be represented losslessly.");
        }

        public Snapshot WriteDacl(string expectedDescriptor, string desiredDescriptor)
        {
            if (!writable) throw new InvalidOperationException("Lease has no write access.");
            Snapshot before = Read();
            if (!String.Equals(before.Descriptor, expectedDescriptor, StringComparison.Ordinal))
                throw new InvalidOperationException("Pre-write descriptor drift.");
            RawSecurityDescriptor current = new RawSecurityDescriptor(expectedDescriptor);
            RawSecurityDescriptor desired = new RawSecurityDescriptor(desiredDescriptor);
            ValidateDescriptor(desired);
            if (current.Owner != desired.Owner || current.Group != desired.Group ||
                current.ControlFlags != desired.ControlFlags)
                throw new InvalidOperationException("Only DACL changes are supported; owner/group/control must be preserved.");
            if (String.Equals(expectedDescriptor, desiredDescriptor, StringComparison.Ordinal)) return before;
            byte[] bytes = new byte[desired.DiscretionaryAcl.BinaryLength];
            desired.DiscretionaryAcl.GetBinaryForm(bytes, 0);
            GCHandle pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                // The coordinator writes and verifies each approved state separately. Zero-share
                // handles do not universally prevent implicit descendant inheritance changes.
                uint error = SetSecurityInfo(handle, 1, 4, IntPtr.Zero, IntPtr.Zero,
                    pinned.AddrOfPinnedObject(), IntPtr.Zero);
                if (error != 0) throw new Win32Exception((int)error, "Set handle DACL (outcome requires review)");
            }
            finally { pinned.Free(); }
            Snapshot after = Read();
            if (!String.Equals(after.Descriptor, desiredDescriptor, StringComparison.Ordinal))
                throw new InvalidOperationException("Post-write descriptor mismatch; outcome is indeterminate.");
            return after;
        }

        public string[] GetChildPaths(int limit)
        {
            if (limit < 1 || limit > 100000) throw new ArgumentOutOfRangeException("limit");
            if (Read().Kind != "Folder") throw new InvalidOperationException("Only directories can be enumerated.");
            List<string> children = new List<string>();
            HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool restart = true;
            while (true)
            {
                byte[] buffer = new byte[65536];
                if (!GetFileInformationByHandleEx(handle, restart ? 15 : 14, buffer, (uint)buffer.Length))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 18) break; // ERROR_NO_MORE_FILES is the only successful end of enumeration.
                    throw new Win32Exception(error, "Enumerate pinned directory");
                }
                restart = false;
                int offset = 0;
                while (true)
                {
                    // FILE_FULL_DIR_INFO has its variable UTF-16 FileName at byte offset 68.
                    if (offset < 0 || offset > buffer.Length - 68)
                        throw new InvalidOperationException("Invalid native directory record offset.");
                    uint next = BitConverter.ToUInt32(buffer, offset);
                    uint nameLength = BitConverter.ToUInt32(buffer, offset + 60);
                    if (nameLength == 0 || nameLength % 2 != 0 || nameLength > buffer.Length - offset - 68)
                        throw new InvalidOperationException("Invalid native directory name length.");
                    string name = Encoding.Unicode.GetString(buffer, offset + 68, (int)nameLength);
                    if (name != "." && name != "..")
                    {
                        if (!names.Add(name) || name.IndexOfAny(new char[] { '\\', '/', '\0' }) >= 0)
                            throw new InvalidOperationException("Duplicate or invalid directory name.");
                        if (children.Count >= limit) throw new InvalidOperationException("Directory path limit reached.");
                        children.Add(System.IO.Path.Combine(Path, name));
                    }
                    if (next == 0) break;
                    if (next % 8 != 0 || next < 68 + nameLength || next > buffer.Length - offset - 68)
                        throw new InvalidOperationException("Invalid native next-directory-record offset.");
                    offset += (int)next;
                }
            }
            children.Sort(StringComparer.OrdinalIgnoreCase);
            return children.ToArray();
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            if (handle != null) handle.Dispose();
            for (int i = ancestors.Count - 1; i >= 0; i--) ancestors[i].Dispose();
        }

        private static void ThrowLastError(string operation)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
        }

        public sealed class Snapshot
        {
            public string Path { get; set; }
            public string Kind { get; set; }
            public string Identity { get; set; }
            public string Descriptor { get; set; }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation
        {
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
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
            [Out] byte[] information, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder name, uint size, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumeNameForVolumeMountPointW(string mountPoint, StringBuilder name, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveTypeW(string root);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file, StringBuilder name, uint nameSize,
            out uint serial, out uint maximum, out uint flags, StringBuilder filesystem, uint filesystemSize);
        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityInfo(SafeFileHandle file, int type, uint sections, out IntPtr owner,
            out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll")]
        private static extern uint SetSecurityInfo(SafeFileHandle file, int type, uint sections, IntPtr owner,
            IntPtr group, IntPtr dacl, IntPtr sacl);
        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);
    }
}
