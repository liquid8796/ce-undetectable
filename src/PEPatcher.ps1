# PEPatcher.ps1 - Post-build PE mutation for stealth
# Strips compiler fingerprints, randomizes metadata, renames sections
param(
    [Parameter(Mandatory=$true)][string]$TargetExe,
    [switch]$Force
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;

public class PEPatcher {
    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr hModule, string name);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr hModule);

    const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
    const uint IMAGE_NT_SIGNATURE = 0x00004550;

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        public ushort e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=4)] public ushort[] e_res;
        public ushort e_oemid, e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=10)] public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=8)] public byte[] Name;
        public uint VirtualSize, VirtualAddress;
        public uint SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers;
        public ushort NumberOfRelocations, NumberOfLinenumbers;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DEBUG_DIRECTORY {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion, MinorVersion;
        public uint Type;
        public uint SizeOfData;
        public uint AddressOfRawData;
        public uint PointerToRawData;
    }

    public static void PatchPE(string path) {
        byte[] data = File.ReadAllBytes(path);
        int dosOffset = 0;
        ushort magic = BitConverter.ToUInt16(data, dosOffset);
        if (magic != IMAGE_DOS_SIGNATURE) throw new Exception("Not a valid PE file");

        IMAGE_DOS_HEADER dosHdr = ByteToStruct<IMAGE_DOS_HEADER>(data, dosOffset);
        int peOffset = dosHdr.e_lfanew;

        uint peSig = BitConverter.ToUInt32(data, peOffset);
        if (peSig != IMAGE_NT_SIGNATURE) throw new Exception("Invalid NT signature");

        IMAGE_FILE_HEADER fileHdr = ByteToStruct<IMAGE_FILE_HEADER>(data, peOffset + 4);

        // 1. Randomize PE timestamp
        Random rng = new Random();
        uint newTimestamp = (uint)((DateTime.UtcNow - new DateTime(1970,1,1)).TotalSeconds)
            ^ (uint)rng.Next();
        BitConverter.GetBytes(newTimestamp).CopyTo(data, peOffset + 4 + 4);

        Console.WriteLine("[+] PE Timestamp randomized");

        // 2. Strip Rich Header (compiler fingerprint between DOS stub and PE header)
        int richEnd = peOffset;
        int richStart = dosHdr.e_lfanew;
        for (int i = richStart - 4; i > 0x40; i -= 4) {
            uint val = BitConverter.ToUInt32(data, i);
            if (val == 0x536E6144 || val == 0x68636952) { // "DanS" or "Rich"
                richStart = i;
                break;
            }
        }
        if (richStart < richEnd && richStart > 0x40) {
            int richSize = richEnd - richStart;
            Array.Copy(data, richEnd, data, richStart, data.Length - richEnd);
            Array.Resize(ref data, data.Length - richSize);
            dosHdr.e_lfanew -= richSize;
            byte[] dosBytes = StructToByte(dosHdr);
            Array.Copy(dosBytes, 0, data, dosOffset, dosBytes.Length);
            // Adjust all section pointers
            peOffset = dosHdr.e_lfanew;
            IMAGE_FILE_HEADER fh = ByteToStruct<IMAGE_FILE_HEADER>(data, peOffset + 4);
            int ns = fh.NumberOfSections;
            int optHdrSize = fh.SizeOfOptionalHeader;
            int sectionStart = peOffset + 4 + 20 + optHdrSize;
            for (int s = 0; s < ns; s++) {
                IMAGE_SECTION_HEADER sh = ByteToStruct<IMAGE_SECTION_HEADER>(data, sectionStart + s * 40);
                sh.PointerToRawData = (uint)(sh.PointerToRawData - richSize);
                byte[] shBytes = StructToByte(sh);
                Array.Copy(shBytes, 0, data, sectionStart + s * 40, shBytes.Length);
            }
            // Adjust debug directory pointers
            int optMagic = BitConverter.ToUInt16(data, peOffset + 4 + 20);
            int debugDirRVA = 0, debugDirSize = 0;
            if (optMagic == 0x20b) { // PE64
                debugDirRVA = BitConverter.ToInt32(data, peOffset + 4 + 20 + 112 + 48);
                debugDirSize = BitConverter.ToInt32(data, peOffset + 4 + 20 + 112 + 52);
            } else { // PE32
                debugDirRVA = BitConverter.ToInt32(data, peOffset + 4 + 20 + 96 + 48);
                debugDirSize = BitConverter.ToInt32(data, peOffset + 4 + 20 + 96 + 52);
            }
            Console.WriteLine("[+] Rich Header stripped ({0} bytes, new e_lfanew=0x{1:X})", richSize, dosHdr.e_lfanew);

            // 3. Strip PDB/CodeView debug info
            if (debugDirRVA != 0 && debugDirSize != 0) {
                int debugDirFOA = RvaToFileOffset(data, peOffset, debugDirRVA);
                if (debugDirFOA > 0) {
                    int numEntries = (int)debugDirSize / 28;
                    for (int de = 0; de < numEntries; de++) {
                        IMAGE_DEBUG_DIRECTORY dd = ByteToStruct<IMAGE_DEBUG_DIRECTORY>(data, debugDirFOA + de * 28);
                        if (dd.Type == 2) { // IMAGE_DEBUG_TYPE_CODEVIEW
                            int ddFOA = (int)dd.PointerToRawData;
                            if (ddFOA > 0 && ddFOA < data.Length) {
                                // Zero out the PDB path
                                for (int z = ddFOA + 24; z < Math.Min(ddFOA + (int)dd.SizeOfData, data.Length); z++) {
                                    if (data[z] == 0) break;
                                    data[z] = 0;
                                }
                                Console.WriteLine("[+] PDB path stripped");
                            }
                        }
                    }
                }
            }
        }

        // 4. Keep standard section names (custom names are more suspicious)
        // ponytail: stripping Rich Header + PDB is enough; non-standard names flag as packed malware

        File.WriteAllBytes(path, data);
        Console.WriteLine("[+] PE patching complete: {0}", path);
    }

    static int RvaToFileOffset(byte[] data, int peOffset, int rva) {
        IMAGE_FILE_HEADER fh = ByteToStruct<IMAGE_FILE_HEADER>(data, peOffset + 4);
        int ns = fh.NumberOfSections;
        int ohs = fh.SizeOfOptionalHeader;
        int ss = peOffset + 4 + 20 + ohs;
        for (int s = 0; s < ns; s++) {
            IMAGE_SECTION_HEADER sh = ByteToStruct<IMAGE_SECTION_HEADER>(data, ss + s * 40);
            if (rva >= sh.VirtualAddress && rva < sh.VirtualAddress + sh.VirtualSize) {
                return (int)(rva - sh.VirtualAddress + sh.PointerToRawData);
            }
        }
        return -1;
    }

    static T ByteToStruct<T>(byte[] data, int offset) {
        int size = Marshal.SizeOf(typeof(T));
        IntPtr ptr = Marshal.AllocHGlobal(size);
        Marshal.Copy(data, offset, ptr, size);
        T result = (T)Marshal.PtrToStructure(ptr, typeof(T));
        Marshal.FreeHGlobal(ptr);
        return result;
    }

    static byte[] StructToByte<T>(T obj) {
        int size = Marshal.SizeOf(typeof(T));
        byte[] arr = new byte[size];
        IntPtr ptr = Marshal.AllocHGlobal(size);
        Marshal.StructureToPtr(obj, ptr, false);
        Marshal.Copy(ptr, arr, 0, size);
        Marshal.FreeHGlobal(ptr);
        return arr;
    }
}
"@

try {
    $Target = Resolve-Path $TargetExe -ErrorAction Stop
    [PEPatcher]::PatchPE($Target.Path)
    Write-Host "[OK] PE patched successfully" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
