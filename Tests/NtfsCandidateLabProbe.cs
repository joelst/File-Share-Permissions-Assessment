using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace NtfsCandidateLab
{
    public static class Probe
    {
        public const string SourceSHA256 = "__SOURCE_SHA256__";
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint DeleteAccess = 0x00010000;
        private const uint OpenExisting = 3;
        private const uint OpenReparsePoint = 0x00200000;
        private const uint DirectoryAttribute = 0x10;
        private const uint ReparseAttribute = 0x400;

        public static void AppendKnown(string path, string marker)
        {
            ValidateMarker(marker);
            using (SafeFileHandle handle = Open(path, GenericRead | GenericWrite, false))
            using (FileStream stream = new FileStream(handle, FileAccess.ReadWrite))
            {
                AssertContent(stream, path, marker, false);
                stream.Position = stream.Length;
                byte[] suffix = Encoding.UTF8.GetBytes("|modified");
                stream.Write(suffix, 0, suffix.Length);
                stream.Flush(true);
            }
        }

        public static bool RemoveKnown(string path, string marker, bool allowModified, bool missingAllowed)
        {
            ValidateMarker(marker);
            using (SafeFileHandle handle = Open(path, GenericRead | DeleteAccess, missingAllowed))
            {
                if (handle == null) return false;
                using (FileStream stream = new FileStream(handle, FileAccess.Read))
                {
                    AssertContent(stream, path, marker, allowModified);
                    DispositionInfo disposition = new DispositionInfo { DeleteFile = true };
                    if (!SetFileInformationByHandle(handle, 4, ref disposition, (uint)Marshal.SizeOf(disposition)))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 5)
                            throw new UnauthorizedAccessException("Cannot delete generated probe: " + path + " (Windows error 5).");
                        throw new Win32Exception(error, "Cannot delete generated probe: " + path);
                    }
                }
            }
            return true;
        }

        public static bool DeleteByName(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
                throw new ArgumentException("Generated probe path is required.");
            if (!DeleteFileW(path))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 5)
                    throw new UnauthorizedAccessException("Cannot delete generated probe by name: " + path + " (Windows error 5).");
                throw new Win32Exception(error, "Cannot delete generated probe by name: " + path);
            }
            return true;
        }

        private static void ValidateMarker(string marker)
        {
            if (marker == null || !Regex.IsMatch(marker, @"\A[a-f0-9]{32}\z"))
                throw new ArgumentException("Invalid generated probe marker.");
        }

        private static SafeFileHandle Open(string path, uint access, bool missingAllowed)
        {
            SafeFileHandle handle = CreateFileW(path, access, 0, IntPtr.Zero,
                OpenExisting, OpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                if (missingAllowed && error == 2) return null;
                if (error == 5)
                    throw new UnauthorizedAccessException("Cannot access generated probe: " + path + " (Windows error 5).");
                throw new Win32Exception(error, "Cannot open generated probe: " + path);
            }
            try
            {
                FileInformation info;
                if (!GetFileInformationByHandle(handle, out info))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect generated probe: " + path);
                if ((info.Attributes & (DirectoryAttribute | ReparseAttribute)) != 0 || info.NumberOfLinks != 1)
                    throw new InvalidOperationException("Unexpected probe type or link; retained " + path + ".");
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        private static void AssertContent(FileStream stream, string path, string marker, bool allowModified)
        {
            byte[] original = Encoding.UTF8.GetBytes(marker);
            byte[] modified = Encoding.UTF8.GetBytes(marker + "|modified");
            if (stream.Length != original.Length && (!allowModified || stream.Length != modified.Length))
                throw new InvalidOperationException("Probe content changed; retained " + path + ".");
            byte[] actual = new byte[(int)stream.Length];
            int offset = 0;
            while (offset < actual.Length)
            {
                int count = stream.Read(actual, offset, actual.Length - offset);
                if (count == 0) throw new EndOfStreamException("Cannot read generated probe: " + path);
                offset += count;
            }
            if (!Matches(actual, original) && (!allowModified || !Matches(actual, modified)))
                throw new InvalidOperationException("Probe content changed; retained " + path + ".");
        }

        private static bool Matches(byte[] left, byte[] right)
        {
            if (left.Length != right.Length) return false;
            for (int i = 0; i < left.Length; i++)
                if (left[i] != right[i]) return false;
            return true;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DispositionInfo
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool DeleteFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerial;
            public uint SizeHigh;
            public uint SizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
            IntPtr security, uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass,
            ref DispositionInfo information, uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteFileW(string path);
    }
}
