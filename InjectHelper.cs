using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using static Miljector.InjectHelper.NativeMethods;

namespace Miljector
{
    [SuppressUnmanagedCodeSecurity]
    public static class InjectHelper
    {
        internal static class NativeMethods
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DOS_HEADER
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
                public char[] e_magic;       // Magic number

                public UInt16 e_cblp;    // Bytes on last page of file
                public UInt16 e_cp;      // Pages in file
                public UInt16 e_crlc;    // Relocations
                public UInt16 e_cparhdr;     // Size of header in paragraphs
                public UInt16 e_minalloc;    // Minimum extra paragraphs needed
                public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
                public UInt16 e_ss;      // Initial (relative) SS value
                public UInt16 e_sp;      // Initial SP value
                public UInt16 e_csum;    // Checksum
                public UInt16 e_ip;      // Initial IP value
                public UInt16 e_cs;      // Initial (relative) CS value
                public UInt16 e_lfarlc;      // File address of relocation table
                public UInt16 e_ovno;    // Overlay number

                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                public UInt16[] e_res1;    // Reserved words

                public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
                public UInt16 e_oeminfo;     // OEM information; e_oemid specific

                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
                public UInt16[] e_res2;    // Reserved words

                public Int32 e_lfanew;      // File address of new exe header

                private string _e_magic => new string(e_magic);

                public bool isValid => _e_magic == "MZ";
            }

            public struct IMAGE_IMPORT_BY_NAME
            {
                public short Hint;
                public char Name;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;

                [FieldOffset(8)]
                public UInt32 VirtualSize;

                [FieldOffset(12)]
                public UInt32 VirtualAddress;

                [FieldOffset(16)]
                public UInt32 SizeOfRawData;

                [FieldOffset(20)]
                public UInt32 PointerToRawData;

                [FieldOffset(24)]
                public UInt32 PointerToRelocations;

                [FieldOffset(28)]
                public UInt32 PointerToLinenumbers;

                [FieldOffset(32)]
                public UInt16 NumberOfRelocations;

                [FieldOffset(34)]
                public UInt16 NumberOfLinenumbers;

                [FieldOffset(36)]
                public DataSectionFlags Characteristics;

                public string Section => new string(Name);
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_IMPORT_DESCRIPTOR
            {
                [FieldOffset(0)]
                public uint Characteristics;

                [FieldOffset(0)]
                public uint OriginalFirstThunk;

                [FieldOffset(4)]
                public uint TimeDateStamp;

                [FieldOffset(8)]
                public uint ForwarderChain;

                [FieldOffset(12)]
                public uint Name;

                [FieldOffset(16)]
                public uint FirstThunk;
            }

            [Flags]
            public enum DataSectionFlags : uint
            {
                /// <summary>
                /// Reserved for future use.
                /// </summary>
                TypeReg = 0x00000000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                TypeDsect = 0x00000001,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                TypeNoLoad = 0x00000002,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                TypeGroup = 0x00000004,

                /// <summary>
                /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
                /// </summary>
                TypeNoPadded = 0x00000008,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                TypeCopy = 0x00000010,

                /// <summary>
                /// The section contains executable code.
                /// </summary>
                ContentCode = 0x00000020,

                /// <summary>
                /// The section contains initialized data.
                /// </summary>
                ContentInitializedData = 0x00000040,

                /// <summary>
                /// The section contains uninitialized data.
                /// </summary>
                ContentUninitializedData = 0x00000080,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                LinkOther = 0x00000100,

                /// <summary>
                /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
                /// </summary>
                LinkInfo = 0x00000200,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                TypeOver = 0x00000400,

                /// <summary>
                /// The section will not become part of the image. This is valid only for object files.
                /// </summary>
                LinkRemove = 0x00000800,

                /// <summary>
                /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
                /// </summary>
                LinkComDat = 0x00001000,

                /// <summary>
                /// Reset speculative exceptions handling bits in the TLB entries for this section.
                /// </summary>
                NoDeferSpecExceptions = 0x00004000,

                /// <summary>
                /// The section contains data referenced through the global pointer (GP).
                /// </summary>
                RelativeGP = 0x00008000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                MemPurgeable = 0x00020000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                Memory16Bit = 0x00020000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                MemoryLocked = 0x00040000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                MemoryPreload = 0x00080000,

                /// <summary>
                /// Align data on a 1-byte boundary. Valid only for object files.
                /// </summary>
                Align1Bytes = 0x00100000,

                /// <summary>
                /// Align data on a 2-byte boundary. Valid only for object files.
                /// </summary>
                Align2Bytes = 0x00200000,

                /// <summary>
                /// Align data on a 4-byte boundary. Valid only for object files.
                /// </summary>
                Align4Bytes = 0x00300000,

                /// <summary>
                /// Align data on an 8-byte boundary. Valid only for object files.
                /// </summary>
                Align8Bytes = 0x00400000,

                /// <summary>
                /// Align data on a 16-byte boundary. Valid only for object files.
                /// </summary>
                Align16Bytes = 0x00500000,

                /// <summary>
                /// Align data on a 32-byte boundary. Valid only for object files.
                /// </summary>
                Align32Bytes = 0x00600000,

                /// <summary>
                /// Align data on a 64-byte boundary. Valid only for object files.
                /// </summary>
                Align64Bytes = 0x00700000,

                /// <summary>
                /// Align data on a 128-byte boundary. Valid only for object files.
                /// </summary>
                Align128Bytes = 0x00800000,

                /// <summary>
                /// Align data on a 256-byte boundary. Valid only for object files.
                /// </summary>
                Align256Bytes = 0x00900000,

                /// <summary>
                /// Align data on a 512-byte boundary. Valid only for object files.
                /// </summary>
                Align512Bytes = 0x00A00000,

                /// <summary>
                /// Align data on a 1024-byte boundary. Valid only for object files.
                /// </summary>
                Align1024Bytes = 0x00B00000,

                /// <summary>
                /// Align data on a 2048-byte boundary. Valid only for object files.
                /// </summary>
                Align2048Bytes = 0x00C00000,

                /// <summary>
                /// Align data on a 4096-byte boundary. Valid only for object files.
                /// </summary>
                Align4096Bytes = 0x00D00000,

                /// <summary>
                /// Align data on an 8192-byte boundary. Valid only for object files.
                /// </summary>
                Align8192Bytes = 0x00E00000,

                /// <summary>
                /// The section contains extended relocations.
                /// </summary>
                LinkExtendedRelocationOverflow = 0x01000000,

                /// <summary>
                /// The section can be discarded as needed.
                /// </summary>
                MemoryDiscardable = 0x02000000,

                /// <summary>
                /// The section cannot be cached.
                /// </summary>
                MemoryNotCached = 0x04000000,

                /// <summary>
                /// The section is not pageable.
                /// </summary>
                MemoryNotPaged = 0x08000000,

                /// <summary>
                /// The section can be shared in memory.
                /// </summary>
                MemoryShared = 0x10000000,

                /// <summary>
                /// The section can be executed as code.
                /// </summary>
                MemoryExecute = 0x20000000,

                /// <summary>
                /// The section can be read.
                /// </summary>
                MemoryRead = 0x40000000,

                /// <summary>
                /// The section can be written to.
                /// </summary>
                MemoryWrite = 0x80000000
            }

            [Flags]
            public enum ProcessAccessFlags : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VirtualMemoryOperation = 0x00000008,
                VirtualMemoryRead = 0x00000010,
                VirtualMemoryWrite = 0x00000020,
                DuplicateHandle = 0x00000040,
                CreateProcess = 0x000000080,
                SetQuota = 0x00000100,
                SetInformation = 0x00000200,
                QueryInformation = 0x00000400,
                QueryLimitedInformation = 0x00001000,
                Synchronize = 0x00100000
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {
                public UInt32 VirtualAddress;
                public UInt32 Size;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_FILE_HEADER
            {
                public UInt16 Machine;
                public UInt16 NumberOfSections;
                public UInt32 TimeDateStamp;
                public UInt32 PointerToSymbolTable;
                public UInt32 NumberOfSymbols;
                public UInt16 SizeOfOptionalHeader;
                public UInt16 Characteristics;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_OPTIONAL_HEADER64
            {
                [FieldOffset(0)]
                public MagicType Magic;

                [FieldOffset(2)]
                public byte MajorLinkerVersion;

                [FieldOffset(3)]
                public byte MinorLinkerVersion;

                [FieldOffset(4)]
                public uint SizeOfCode;

                [FieldOffset(8)]
                public uint SizeOfInitializedData;

                [FieldOffset(12)]
                public uint SizeOfUninitializedData;

                [FieldOffset(16)]
                public uint AddressOfEntryPoint;

                [FieldOffset(20)]
                public uint BaseOfCode;

                [FieldOffset(24)]
                public ulong ImageBase;

                [FieldOffset(32)]
                public uint SectionAlignment;

                [FieldOffset(36)]
                public uint FileAlignment;

                [FieldOffset(40)]
                public ushort MajorOperatingSystemVersion;

                [FieldOffset(42)]
                public ushort MinorOperatingSystemVersion;

                [FieldOffset(44)]
                public ushort MajorImageVersion;

                [FieldOffset(46)]
                public ushort MinorImageVersion;

                [FieldOffset(48)]
                public ushort MajorSubsystemVersion;

                [FieldOffset(50)]
                public ushort MinorSubsystemVersion;

                [FieldOffset(52)]
                public uint Win32VersionValue;

                [FieldOffset(56)]
                public uint SizeOfImage;

                [FieldOffset(60)]
                public uint SizeOfHeaders;

                [FieldOffset(64)]
                public uint CheckSum;

                [FieldOffset(68)]
                public SubSystemType Subsystem;

                [FieldOffset(70)]
                public DllCharacteristicsType DllCharacteristics;

                [FieldOffset(72)]
                public ulong SizeOfStackReserve;

                [FieldOffset(80)]
                public ulong SizeOfStackCommit;

                [FieldOffset(88)]
                public ulong SizeOfHeapReserve;

                [FieldOffset(96)]
                public ulong SizeOfHeapCommit;

                [FieldOffset(104)]
                public uint LoaderFlags;

                [FieldOffset(108)]
                public uint NumberOfRvaAndSizes;

                [FieldOffset(112)]
                public IMAGE_DATA_DIRECTORY ExportTable;

                [FieldOffset(120)]
                public IMAGE_DATA_DIRECTORY ImportTable;

                [FieldOffset(128)]
                public IMAGE_DATA_DIRECTORY ResourceTable;

                [FieldOffset(136)]
                public IMAGE_DATA_DIRECTORY ExceptionTable;

                [FieldOffset(144)]
                public IMAGE_DATA_DIRECTORY CertificateTable;

                [FieldOffset(152)]
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;

                [FieldOffset(160)]
                public IMAGE_DATA_DIRECTORY Debug;

                [FieldOffset(168)]
                public IMAGE_DATA_DIRECTORY Architecture;

                [FieldOffset(176)]
                public IMAGE_DATA_DIRECTORY GlobalPtr;

                [FieldOffset(184)]
                public IMAGE_DATA_DIRECTORY TLSTable;

                [FieldOffset(192)]
                public IMAGE_DATA_DIRECTORY LoadConfigTable;

                [FieldOffset(200)]
                public IMAGE_DATA_DIRECTORY BoundImport;

                [FieldOffset(208)]
                public IMAGE_DATA_DIRECTORY IAT;

                [FieldOffset(216)]
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

                [FieldOffset(224)]
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

                [FieldOffset(232)]
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_THUNK_DATA32
            {
                [FieldOffset(0)]
                public uint ForwarderString;

                [FieldOffset(0)]
                public uint Function;

                [FieldOffset(0)]
                public uint Ordinal;

                [FieldOffset(0)]
                public uint AddressOfData;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_THUNK_DATA64
            {
                [FieldOffset(0)]
                public ulong ForwarderString;

                [FieldOffset(0)]
                public ulong Function;

                [FieldOffset(0)]
                public ulong Ordinal;

                [FieldOffset(0)]
                public ulong AddressOfData;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_THUNK_DATA
            {
                [FieldOffset(0)]
                public uint ForwarderString;

                [FieldOffset(0)]
                public uint Function;

                [FieldOffset(0)]
                public uint Ordinal;

                [FieldOffset(0)]
                public uint AddressOfData;
            }

            public struct IMAGE_TLS_DIRECTORY32
            {
                public uint StartAddressOfRawData;
                public uint EndAddressOfRawData;
                public uint AddressOfIndex;
                public uint AddressOfCallBacks;
                public uint SizeOfZeroFill;
                public uint Characteristics;
            }

            public enum MachineType : ushort
            {
                Native = 0,
                I386 = 0x014c,
                Itanium = 0x0200,
                x64 = 0x8664
            }

            public enum MagicType : ushort
            {
                IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
                IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
            }

            public enum SubSystemType : ushort
            {
                IMAGE_SUBSYSTEM_UNKNOWN = 0,
                IMAGE_SUBSYSTEM_NATIVE = 1,
                IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
                IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
                IMAGE_SUBSYSTEM_POSIX_CUI = 7,
                IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
                IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
                IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
                IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
                IMAGE_SUBSYSTEM_EFI_ROM = 13,
                IMAGE_SUBSYSTEM_XBOX = 14
            }

            public enum DllCharacteristicsType : ushort
            {
                RES_0 = 0x0001,
                RES_1 = 0x0002,
                RES_2 = 0x0004,
                RES_3 = 0x0008,
                IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
                IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
                IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
                IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
                IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
                IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
                RES_4 = 0x1000,
                IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
                IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_EXPORT_DIRECTORY
            {
                public UInt32 Characteristics;
                public UInt32 TimeDateStamp;
                public UInt16 MajorVersion;
                public UInt16 MinorVersion;
                public UInt32 Name;
                public UInt32 Base;
                public UInt32 NumberOfFunctions;
                public UInt32 NumberOfNames;
                public UInt32 AddressOfFunctions;     // RVA from base of image
                public UInt32 AddressOfNames;     // RVA from base of image
                public UInt32 AddressOfNameOrdinals;  // RVA from base of image
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_NT_HEADERS32
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                public char[] Signature;

                [FieldOffset(4)]
                public IMAGE_FILE_HEADER FileHeader;

                [FieldOffset(24)]
                public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

                private string _Signature => new string(Signature);

                public bool isValid => _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_OPTIONAL_HEADER32
            {
                [FieldOffset(0)]
                public MagicType Magic;

                [FieldOffset(2)]
                public byte MajorLinkerVersion;

                [FieldOffset(3)]
                public byte MinorLinkerVersion;

                [FieldOffset(4)]
                public uint SizeOfCode;

                [FieldOffset(8)]
                public uint SizeOfInitializedData;

                [FieldOffset(12)]
                public uint SizeOfUninitializedData;

                [FieldOffset(16)]
                public uint AddressOfEntryPoint;

                [FieldOffset(20)]
                public uint BaseOfCode;

                // PE32 contains this additional field
                [FieldOffset(24)]
                public uint BaseOfData;

                [FieldOffset(28)]
                public uint ImageBase;

                [FieldOffset(32)]
                public uint SectionAlignment;

                [FieldOffset(36)]
                public uint FileAlignment;

                [FieldOffset(40)]
                public ushort MajorOperatingSystemVersion;

                [FieldOffset(42)]
                public ushort MinorOperatingSystemVersion;

                [FieldOffset(44)]
                public ushort MajorImageVersion;

                [FieldOffset(46)]
                public ushort MinorImageVersion;

                [FieldOffset(48)]
                public ushort MajorSubsystemVersion;

                [FieldOffset(50)]
                public ushort MinorSubsystemVersion;

                [FieldOffset(52)]
                public uint Win32VersionValue;

                [FieldOffset(56)]
                public uint SizeOfImage;

                [FieldOffset(60)]
                public uint SizeOfHeaders;

                [FieldOffset(64)]
                public uint CheckSum;

                [FieldOffset(68)]
                public SubSystemType Subsystem;

                [FieldOffset(70)]
                public DllCharacteristicsType DllCharacteristics;

                [FieldOffset(72)]
                public uint SizeOfStackReserve;

                [FieldOffset(76)]
                public uint SizeOfStackCommit;

                [FieldOffset(80)]
                public uint SizeOfHeapReserve;

                [FieldOffset(84)]
                public uint SizeOfHeapCommit;

                [FieldOffset(88)]
                public uint LoaderFlags;

                [FieldOffset(92)]
                public uint NumberOfRvaAndSizes;

                [FieldOffset(96)]
                public IMAGE_DATA_DIRECTORY ExportTable;

                [FieldOffset(104)]
                public IMAGE_DATA_DIRECTORY ImportTable;

                [FieldOffset(112)]
                public IMAGE_DATA_DIRECTORY ResourceTable;

                [FieldOffset(120)]
                public IMAGE_DATA_DIRECTORY ExceptionTable;

                [FieldOffset(128)]
                public IMAGE_DATA_DIRECTORY CertificateTable;

                [FieldOffset(136)]
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;

                [FieldOffset(144)]
                public IMAGE_DATA_DIRECTORY Debug;

                [FieldOffset(152)]
                public IMAGE_DATA_DIRECTORY Architecture;

                [FieldOffset(160)]
                public IMAGE_DATA_DIRECTORY GlobalPtr;

                [FieldOffset(168)]
                public IMAGE_DATA_DIRECTORY TLSTable;

                [FieldOffset(176)]
                public IMAGE_DATA_DIRECTORY LoadConfigTable;

                [FieldOffset(184)]
                public IMAGE_DATA_DIRECTORY BoundImport;

                [FieldOffset(192)]
                public IMAGE_DATA_DIRECTORY IAT;

                [FieldOffset(200)]
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

                [FieldOffset(208)]
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

                [FieldOffset(216)]
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_NT_HEADERS64
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                public char[] Signature;

                [FieldOffset(4)]
                public IMAGE_FILE_HEADER FileHeader;

                [FieldOffset(24)]
                public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

                private string _Signature => new string(Signature);

                public bool isValid => _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            }

            public struct FILETIME
            {
                public uint DateTimeLow;
                public uint DateTimeHigh;
            }

            public struct IMAGE_LOAD_CONFIG_DIRECTORY32
            {
                public uint Size;
                public uint TimeDateStamp;
                public ushort MajorVersion;
                public ushort MinorVersion;
                public uint GlobalFlagsClear;
                public uint GlobalFlagsSet;
                public uint CriticalSectionDefaultTimeout;
                public uint DeCommitFreeBlockThreshold;
                public uint DeCommitTotalFreeThreshold;
                public uint LockPrefixTable;
                public uint MaximumAllocationSize;
                public uint VirtualMemoryThreshold;
                public uint ProcessHeapFlags;
                public uint ProcessAffinityMask;
                public ushort CSDVersion;
                public ushort Reserved1;
                public uint EditList;
                public uint SecurityCookie;
                public uint SEHandlerTable;
                public uint SEHandlerCount;
                public uint GuardCFCheckFunctionPointer;
                public uint Reserved2;
                public uint GuardCFFunctionTable;
                public uint GuardCFFunctionCount;
                public uint GuardFlags;
            }

            public struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAddress;
                public uint SizeOfBlock;
            }

            public struct UNICODE_STRING
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;
            }

            public struct PROCESS_BASIC_INFORMATION
            {
                public NtStatus ExitStatus;
                public IntPtr PebBaseAddress;
                public UIntPtr AffinityMask;
                public int BasePriority;
                public UIntPtr UniqueProcessId;
                public UIntPtr InheritedFromUniqueProcessId;
            }

            [Flags]
            public enum FreeType
            {
                Decommit = 0x4000,
                Release = 0x8000,
            }

            public enum NtStatus : uint
            {
                // Success
                Success = 0x00000000,

                Wait0 = 0x00000000,
                Wait1 = 0x00000001,
                Wait2 = 0x00000002,
                Wait3 = 0x00000003,
                Wait63 = 0x0000003f,
                Abandoned = 0x00000080,
                AbandonedWait0 = 0x00000080,
                AbandonedWait1 = 0x00000081,
                AbandonedWait2 = 0x00000082,
                AbandonedWait3 = 0x00000083,
                AbandonedWait63 = 0x000000bf,
                UserApc = 0x000000c0,
                KernelApc = 0x00000100,
                Alerted = 0x00000101,
                Timeout = 0x00000102,
                Pending = 0x00000103,
                Reparse = 0x00000104,
                MoreEntries = 0x00000105,
                NotAllAssigned = 0x00000106,
                SomeNotMapped = 0x00000107,
                OpLockBreakInProgress = 0x00000108,
                VolumeMounted = 0x00000109,
                RxActCommitted = 0x0000010a,
                NotifyCleanup = 0x0000010b,
                NotifyEnumDir = 0x0000010c,
                NoQuotasForAccount = 0x0000010d,
                PrimaryTransportConnectFailed = 0x0000010e,
                PageFaultTransition = 0x00000110,
                PageFaultDemandZero = 0x00000111,
                PageFaultCopyOnWrite = 0x00000112,
                PageFaultGuardPage = 0x00000113,
                PageFaultPagingFile = 0x00000114,
                CrashDump = 0x00000116,
                ReparseObject = 0x00000118,
                NothingToTerminate = 0x00000122,
                ProcessNotInJob = 0x00000123,
                ProcessInJob = 0x00000124,
                ProcessCloned = 0x00000129,
                FileLockedWithOnlyReaders = 0x0000012a,
                FileLockedWithWriters = 0x0000012b,

                // Informational
                Informational = 0x40000000,

                ObjectNameExists = 0x40000000,
                ThreadWasSuspended = 0x40000001,
                WorkingSetLimitRange = 0x40000002,
                ImageNotAtBase = 0x40000003,
                RegistryRecovered = 0x40000009,

                // Warning
                Warning = 0x80000000,

                GuardPageViolation = 0x80000001,
                DatatypeMisalignment = 0x80000002,
                Breakpoint = 0x80000003,
                SingleStep = 0x80000004,
                BufferOverflow = 0x80000005,
                NoMoreFiles = 0x80000006,
                HandlesClosed = 0x8000000a,
                PartialCopy = 0x8000000d,
                DeviceBusy = 0x80000011,
                InvalidEaName = 0x80000013,
                EaListInconsistent = 0x80000014,
                NoMoreEntries = 0x8000001a,
                LongJump = 0x80000026,
                DllMightBeInsecure = 0x8000002b,

                // Error
                Error = 0xc0000000,

                Unsuccessful = 0xc0000001,
                NotImplemented = 0xc0000002,
                InvalidInfoClass = 0xc0000003,
                InfoLengthMismatch = 0xc0000004,
                AccessViolation = 0xc0000005,
                InPageError = 0xc0000006,
                PagefileQuota = 0xc0000007,
                InvalidHandle = 0xc0000008,
                BadInitialStack = 0xc0000009,
                BadInitialPc = 0xc000000a,
                InvalidCid = 0xc000000b,
                TimerNotCanceled = 0xc000000c,
                InvalidParameter = 0xc000000d,
                NoSuchDevice = 0xc000000e,
                NoSuchFile = 0xc000000f,
                InvalidDeviceRequest = 0xc0000010,
                EndOfFile = 0xc0000011,
                WrongVolume = 0xc0000012,
                NoMediaInDevice = 0xc0000013,
                NoMemory = 0xc0000017,
                NotMappedView = 0xc0000019,
                UnableToFreeVm = 0xc000001a,
                UnableToDeleteSection = 0xc000001b,
                IllegalInstruction = 0xc000001d,
                AlreadyCommitted = 0xc0000021,
                AccessDenied = 0xc0000022,
                BufferTooSmall = 0xc0000023,
                ObjectTypeMismatch = 0xc0000024,
                NonContinuableException = 0xc0000025,
                BadStack = 0xc0000028,
                NotLocked = 0xc000002a,
                NotCommitted = 0xc000002d,
                InvalidParameterMix = 0xc0000030,
                ObjectNameInvalid = 0xc0000033,
                ObjectNameNotFound = 0xc0000034,
                ObjectNameCollision = 0xc0000035,
                ObjectPathInvalid = 0xc0000039,
                ObjectPathNotFound = 0xc000003a,
                ObjectPathSyntaxBad = 0xc000003b,
                DataOverrun = 0xc000003c,
                DataLate = 0xc000003d,
                DataError = 0xc000003e,
                CrcError = 0xc000003f,
                SectionTooBig = 0xc0000040,
                PortConnectionRefused = 0xc0000041,
                InvalidPortHandle = 0xc0000042,
                SharingViolation = 0xc0000043,
                QuotaExceeded = 0xc0000044,
                InvalidPageProtection = 0xc0000045,
                MutantNotOwned = 0xc0000046,
                SemaphoreLimitExceeded = 0xc0000047,
                PortAlreadySet = 0xc0000048,
                SectionNotImage = 0xc0000049,
                SuspendCountExceeded = 0xc000004a,
                ThreadIsTerminating = 0xc000004b,
                BadWorkingSetLimit = 0xc000004c,
                IncompatibleFileMap = 0xc000004d,
                SectionProtection = 0xc000004e,
                EasNotSupported = 0xc000004f,
                EaTooLarge = 0xc0000050,
                NonExistentEaEntry = 0xc0000051,
                NoEasOnFile = 0xc0000052,
                EaCorruptError = 0xc0000053,
                FileLockConflict = 0xc0000054,
                LockNotGranted = 0xc0000055,
                DeletePending = 0xc0000056,
                CtlFileNotSupported = 0xc0000057,
                UnknownRevision = 0xc0000058,
                RevisionMismatch = 0xc0000059,
                InvalidOwner = 0xc000005a,
                InvalidPrimaryGroup = 0xc000005b,
                NoImpersonationToken = 0xc000005c,
                CantDisableMandatory = 0xc000005d,
                NoLogonServers = 0xc000005e,
                NoSuchLogonSession = 0xc000005f,
                NoSuchPrivilege = 0xc0000060,
                PrivilegeNotHeld = 0xc0000061,
                InvalidAccountName = 0xc0000062,
                UserExists = 0xc0000063,
                NoSuchUser = 0xc0000064,
                GroupExists = 0xc0000065,
                NoSuchGroup = 0xc0000066,
                MemberInGroup = 0xc0000067,
                MemberNotInGroup = 0xc0000068,
                LastAdmin = 0xc0000069,
                WrongPassword = 0xc000006a,
                IllFormedPassword = 0xc000006b,
                PasswordRestriction = 0xc000006c,
                LogonFailure = 0xc000006d,
                AccountRestriction = 0xc000006e,
                InvalidLogonHours = 0xc000006f,
                InvalidWorkstation = 0xc0000070,
                PasswordExpired = 0xc0000071,
                AccountDisabled = 0xc0000072,
                NoneMapped = 0xc0000073,
                TooManyLuidsRequested = 0xc0000074,
                LuidsExhausted = 0xc0000075,
                InvalidSubAuthority = 0xc0000076,
                InvalidAcl = 0xc0000077,
                InvalidSid = 0xc0000078,
                InvalidSecurityDescr = 0xc0000079,
                ProcedureNotFound = 0xc000007a,
                InvalidImageFormat = 0xc000007b,
                NoToken = 0xc000007c,
                BadInheritanceAcl = 0xc000007d,
                RangeNotLocked = 0xc000007e,
                DiskFull = 0xc000007f,
                ServerDisabled = 0xc0000080,
                ServerNotDisabled = 0xc0000081,
                TooManyGuidsRequested = 0xc0000082,
                GuidsExhausted = 0xc0000083,
                InvalidIdAuthority = 0xc0000084,
                AgentsExhausted = 0xc0000085,
                InvalidVolumeLabel = 0xc0000086,
                SectionNotExtended = 0xc0000087,
                NotMappedData = 0xc0000088,
                ResourceDataNotFound = 0xc0000089,
                ResourceTypeNotFound = 0xc000008a,
                ResourceNameNotFound = 0xc000008b,
                ArrayBoundsExceeded = 0xc000008c,
                FloatDenormalOperand = 0xc000008d,
                FloatDivideByZero = 0xc000008e,
                FloatInexactResult = 0xc000008f,
                FloatInvalidOperation = 0xc0000090,
                FloatOverflow = 0xc0000091,
                FloatStackCheck = 0xc0000092,
                FloatUnderflow = 0xc0000093,
                IntegerDivideByZero = 0xc0000094,
                IntegerOverflow = 0xc0000095,
                PrivilegedInstruction = 0xc0000096,
                TooManyPagingFiles = 0xc0000097,
                FileInvalid = 0xc0000098,
                InstanceNotAvailable = 0xc00000ab,
                PipeNotAvailable = 0xc00000ac,
                InvalidPipeState = 0xc00000ad,
                PipeBusy = 0xc00000ae,
                IllegalFunction = 0xc00000af,
                PipeDisconnected = 0xc00000b0,
                PipeClosing = 0xc00000b1,
                PipeConnected = 0xc00000b2,
                PipeListening = 0xc00000b3,
                InvalidReadMode = 0xc00000b4,
                IoTimeout = 0xc00000b5,
                FileForcedClosed = 0xc00000b6,
                ProfilingNotStarted = 0xc00000b7,
                ProfilingNotStopped = 0xc00000b8,
                NotSameDevice = 0xc00000d4,
                FileRenamed = 0xc00000d5,
                CantWait = 0xc00000d8,
                PipeEmpty = 0xc00000d9,
                CantTerminateSelf = 0xc00000db,
                InternalError = 0xc00000e5,
                InvalidParameter1 = 0xc00000ef,
                InvalidParameter2 = 0xc00000f0,
                InvalidParameter3 = 0xc00000f1,
                InvalidParameter4 = 0xc00000f2,
                InvalidParameter5 = 0xc00000f3,
                InvalidParameter6 = 0xc00000f4,
                InvalidParameter7 = 0xc00000f5,
                InvalidParameter8 = 0xc00000f6,
                InvalidParameter9 = 0xc00000f7,
                InvalidParameter10 = 0xc00000f8,
                InvalidParameter11 = 0xc00000f9,
                InvalidParameter12 = 0xc00000fa,
                MappedFileSizeZero = 0xc000011e,
                TooManyOpenedFiles = 0xc000011f,
                Cancelled = 0xc0000120,
                CannotDelete = 0xc0000121,
                InvalidComputerName = 0xc0000122,
                FileDeleted = 0xc0000123,
                SpecialAccount = 0xc0000124,
                SpecialGroup = 0xc0000125,
                SpecialUser = 0xc0000126,
                MembersPrimaryGroup = 0xc0000127,
                FileClosed = 0xc0000128,
                TooManyThreads = 0xc0000129,
                ThreadNotInProcess = 0xc000012a,
                TokenAlreadyInUse = 0xc000012b,
                PagefileQuotaExceeded = 0xc000012c,
                CommitmentLimit = 0xc000012d,
                InvalidImageLeFormat = 0xc000012e,
                InvalidImageNotMz = 0xc000012f,
                InvalidImageProtect = 0xc0000130,
                InvalidImageWin16 = 0xc0000131,
                LogonServer = 0xc0000132,
                DifferenceAtDc = 0xc0000133,
                SynchronizationRequired = 0xc0000134,
                DllNotFound = 0xc0000135,
                IoPrivilegeFailed = 0xc0000137,
                OrdinalNotFound = 0xc0000138,
                EntryPointNotFound = 0xc0000139,
                ControlCExit = 0xc000013a,
                PortNotSet = 0xc0000353,
                DebuggerInactive = 0xc0000354,
                CallbackBypass = 0xc0000503,
                PortClosed = 0xc0000700,
                MessageLost = 0xc0000701,
                InvalidMessage = 0xc0000702,
                RequestCanceled = 0xc0000703,
                RecursiveDispatch = 0xc0000704,
                LpcReceiveBufferExpected = 0xc0000705,
                LpcInvalidConnectionUsage = 0xc0000706,
                LpcRequestsNotAllowed = 0xc0000707,
                ResourceInUse = 0xc0000708,
                ProcessIsProtected = 0xc0000712,
                VolumeDirty = 0xc0000806,
                FileCheckedOut = 0xc0000901,
                CheckOutRequired = 0xc0000902,
                BadFileType = 0xc0000903,
                FileTooLarge = 0xc0000904,
                FormsAuthRequired = 0xc0000905,
                VirusInfected = 0xc0000906,
                VirusDeleted = 0xc0000907,
                TransactionalConflict = 0xc0190001,
                InvalidTransaction = 0xc0190002,
                TransactionNotActive = 0xc0190003,
                TmInitializationFailed = 0xc0190004,
                RmNotActive = 0xc0190005,
                RmMetadataCorrupt = 0xc0190006,
                TransactionNotJoined = 0xc0190007,
                DirectoryNotRm = 0xc0190008,
                CouldNotResizeLog = 0xc0190009,
                TransactionsUnsupportedRemote = 0xc019000a,
                LogResizeInvalidSize = 0xc019000b,
                RemoteFileVersionMismatch = 0xc019000c,
                CrmProtocolAlreadyExists = 0xc019000f,
                TransactionPropagationFailed = 0xc0190010,
                CrmProtocolNotFound = 0xc0190011,
                TransactionSuperiorExists = 0xc0190012,
                TransactionRequestNotValid = 0xc0190013,
                TransactionNotRequested = 0xc0190014,
                TransactionAlreadyAborted = 0xc0190015,
                TransactionAlreadyCommitted = 0xc0190016,
                TransactionInvalidMarshallBuffer = 0xc0190017,
                CurrentTransactionNotValid = 0xc0190018,
                LogGrowthFailed = 0xc0190019,
                ObjectNoLongerExists = 0xc0190021,
                StreamMiniversionNotFound = 0xc0190022,
                StreamMiniversionNotValid = 0xc0190023,
                MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
                CantOpenMiniversionWithModifyIntent = 0xc0190025,
                CantCreateMoreStreamMiniversions = 0xc0190026,
                HandleNoLongerValid = 0xc0190028,
                NoTxfMetadata = 0xc0190029,
                LogCorruptionDetected = 0xc0190030,
                CantRecoverWithHandleOpen = 0xc0190031,
                RmDisconnected = 0xc0190032,
                EnlistmentNotSuperior = 0xc0190033,
                RecoveryNotNeeded = 0xc0190034,
                RmAlreadyStarted = 0xc0190035,
                FileIdentityNotPersistent = 0xc0190036,
                CantBreakTransactionalDependency = 0xc0190037,
                CantCrossRmBoundary = 0xc0190038,
                TxfDirNotEmpty = 0xc0190039,
                IndoubtTransactionsExist = 0xc019003a,
                TmVolatile = 0xc019003b,
                RollbackTimerExpired = 0xc019003c,
                TxfAttributeCorrupt = 0xc019003d,
                EfsNotAllowedInTransaction = 0xc019003e,
                TransactionalOpenNotAllowed = 0xc019003f,
                TransactedMappingUnsupportedRemote = 0xc0190040,
                TxfMetadataAlreadyPresent = 0xc0190041,
                TransactionScopeCallbacksNotSet = 0xc0190042,
                TransactionRequiredPromotion = 0xc0190043,
                CannotExecuteFileInTransaction = 0xc0190044,
                TransactionsNotFrozen = 0xc0190045,

                MaximumNtStatus = 0xffffffff
            }

            [Flags]
            public enum AllocationType
            {
                Commit = 0x1000,
                Reserve = 0x2000,
                Decommit = 0x4000,
                Release = 0x8000,
                Reset = 0x80000,
                Physical = 0x400000,
                TopDown = 0x100000,
                WriteWatch = 0x200000,
                LargePages = 0x20000000
            }
            [Flags]
            public enum MemoryProtection
            {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                NoAccess = 0x01,
                ReadOnly = 0x02,
                ReadWrite = 0x04,
                WriteCopy = 0x08,
                GuardModifierflag = 0x100,
                NoCacheModifierflag = 0x200,
                WriteCombineModifierflag = 0x400
            }
            public class Pointer<IBuffer> where IBuffer : struct
            {
                private int? IStructSize;
                private GCHandle IGCHandle;
                private bool IShouldFreeHandle;

                public IntPtr IAddress { get; }

                public IBuffer IBufferValue => this[0U];

                public int StructSize
                {
                    get
                    {
                        if (!IStructSize.HasValue)
                        {
                            IStructSize = new int?(Marshal.SizeOf(typeof(IBuffer)));
                        }

                        return IStructSize.Value;
                    }
                }

                private static IBuffer GetStructure(IntPtr iAddressTemp)
                {
                    return (IBuffer)Marshal.PtrToStructure(iAddressTemp, typeof(IBuffer));
                }

                public IBuffer this[uint iIndex] => GetStructure(IAddress + ((int)iIndex * StructSize));

                public static Pointer<IBuffer> operator +(Pointer<IBuffer> iIndex1, int iIndex2)
                {
                    return new Pointer<IBuffer>(iIndex1.IAddress + (iIndex2 * iIndex1.StructSize));
                }

                public static Pointer<IBuffer> operator ++(Pointer<IBuffer> iIncrement)
                {
                    return iIncrement + 1;
                }

                public static Pointer<IBuffer> operator -(Pointer<IBuffer> iIndex1, int iIndex2)
                {
                    return new Pointer<IBuffer>(iIndex1.IAddress - (iIndex2 * iIndex1.StructSize));
                }

                public static Pointer<IBuffer> operator --(Pointer<IBuffer> iIncrement)
                {
                    return iIncrement - 1;
                }

                public static explicit operator Pointer<IBuffer>(IntPtr iPointer)
                {
                    return iPointer != IntPtr.Zero ? new Pointer<IBuffer>(iPointer) : null;
                }

                public static explicit operator IntPtr(Pointer<IBuffer> iPointer)
                {
                    return iPointer.IAddress;
                }

                public Pointer(IntPtr iAddressTemp)
                {
                    IAddress = iAddressTemp;
                }

                public Pointer(object iValue, bool iShouldFreeHandle_tmp = true)
                {
                    if (iValue == null)
                    {
                        throw new Exception("Pointer value is null");
                    }
                    else
                    {
                        try
                        {
                            IGCHandle = GCHandle.Alloc(iValue, GCHandleType.Pinned);
                        }
                        catch (Exception)
                        {
                            throw new Exception("Unable to create a pointer of type " + iValue.GetType().Name);
                        }
                        IShouldFreeHandle = iShouldFreeHandle_tmp;
                        IAddress = IGCHandle.AddrOfPinnedObject();
                    }
                }

                ~Pointer()
                {
                    if (!IGCHandle.IsAllocated || !IShouldFreeHandle)
                    {
                        return;
                    }

                    IGCHandle.Free();
                }
            }
            public class PBYTE : Pointer<byte>
            {
                public PBYTE(IntPtr address)
                  : base(address)
                {
                }

                public PBYTE(object value)
                  : base(value)
                {
                }

                public static PBYTE operator +(PBYTE c1, int c2)
                {
                    return new PBYTE(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PBYTE operator ++(PBYTE a)
                {
                    return a + 1;
                }

                public static explicit operator PBYTE(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PBYTE(ptr) : null;
                }
            }
            public class PCHAR : Pointer<char>
            {
                public PCHAR(IntPtr address)
                  : base(address)
                {
                }

                public PCHAR(object value)
                  : base(value)
                {
                }

                public PCHAR(string value)
                  : base(Encoding.UTF8.GetBytes(value))
                {
                }

                public static PCHAR operator +(PCHAR c1, int c2)
                {
                    return new PCHAR(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PCHAR operator ++(PCHAR a)
                {
                    return a + 1;
                }

                public static explicit operator PCHAR(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PCHAR(ptr) : null;
                }

                public override string ToString()
                {
                    return Marshal.PtrToStringAnsi(IAddress) ?? string.Empty;
                }
            }
            public class PDWORD : Pointer<uint>
            {
                public PDWORD(IntPtr address)
                  : base(address)
                {
                }

                public PDWORD(object value)
                  : base(value)
                {
                }

                public static PDWORD operator +(PDWORD c1, int c2)
                {
                    return new PDWORD(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PDWORD operator ++(PDWORD a)
                {
                    return a + 1;
                }

                public static explicit operator PDWORD(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PDWORD(ptr) : null;
                }
            }
            public class PWORD : Pointer<ushort>
            {
                public PWORD(IntPtr address)
                  : base(address)
                {
                }

                public PWORD(object value)
                  : base(value)
                {
                }

                public static PWORD operator +(PWORD c1, int c2)
                {
                    return new PWORD(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PWORD operator ++(PWORD a)
                {
                    return a + 1;
                }

                public static explicit operator PWORD(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PWORD(ptr) : null;
                }
            }
            public class PSHORT : Pointer<short>
            {
                public PSHORT(IntPtr address)
                  : base(address)
                {
                }

                public PSHORT(object value)
                  : base(value)
                {
                }

                public static PSHORT operator +(PSHORT c1, int c2)
                {
                    return new PSHORT(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PSHORT operator ++(PSHORT a)
                {
                    return a + 1;
                }

                public static explicit operator PSHORT(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PSHORT(ptr) : null;
                }
            }
            public class PPROCESS_BASIC_INFORMATION : Pointer<PROCESS_BASIC_INFORMATION>
            {
                public PPROCESS_BASIC_INFORMATION(IntPtr address)
                  : base(address)
                {
                }

                public PPROCESS_BASIC_INFORMATION(object value)
                  : base(value)
                {
                }

                public static explicit operator PPROCESS_BASIC_INFORMATION(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PPROCESS_BASIC_INFORMATION(ptr) : null;
                }
            }
            public class PIMAGE_TLS_DIRECTORY32 : Pointer<IMAGE_TLS_DIRECTORY32>
            {
                public PIMAGE_TLS_DIRECTORY32(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_TLS_DIRECTORY32(object value)
                  : base(value)
                {
                }

                public static PIMAGE_TLS_DIRECTORY32 operator +(PIMAGE_TLS_DIRECTORY32 c1, int c2)
                {
                    return new PIMAGE_TLS_DIRECTORY32(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PIMAGE_TLS_DIRECTORY32 operator ++(PIMAGE_TLS_DIRECTORY32 a)
                {
                    return a + 1;
                }

                public static explicit operator PIMAGE_TLS_DIRECTORY32(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PIMAGE_TLS_DIRECTORY32(ptr) : null;
                }
            }
            public class PIMAGE_THUNK_DATA : Pointer<IMAGE_THUNK_DATA>
            {
                public PIMAGE_THUNK_DATA(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_THUNK_DATA(object value)
                  : base(value)
                {
                }

                public static PIMAGE_THUNK_DATA operator +(PIMAGE_THUNK_DATA c1, int c2)
                {
                    return new PIMAGE_THUNK_DATA(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PIMAGE_THUNK_DATA operator ++(PIMAGE_THUNK_DATA a)
                {
                    return a + 1;
                }

                public static explicit operator PIMAGE_THUNK_DATA(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PIMAGE_THUNK_DATA(ptr) : null;
                }
            }
            public class PIMAGE_SECTION_HEADER : Pointer<IMAGE_SECTION_HEADER>
            {
                public PIMAGE_SECTION_HEADER(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_SECTION_HEADER(object value)
                  : base(value)
                {
                }

                public static explicit operator PIMAGE_SECTION_HEADER(IntPtr ptr) => ptr != IntPtr.Zero ? new PIMAGE_SECTION_HEADER(ptr) : null;
            }
            public class PIMAGE_NT_HEADERS32 : Pointer<IMAGE_NT_HEADERS32>
            {
                public PIMAGE_NT_HEADERS32(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_NT_HEADERS32(object value)
                  : base(value)
                {
                }

                public static explicit operator PIMAGE_NT_HEADERS32(IntPtr ptr) => ptr == IntPtr.Zero ? (PIMAGE_NT_HEADERS32)null : new PIMAGE_NT_HEADERS32(ptr);
            }
            public class PIMAGE_NT_HEADERS64 : Pointer<IMAGE_NT_HEADERS64>
            {
                public PIMAGE_NT_HEADERS64(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_NT_HEADERS64(object value)
                  : base(value)
                {
                }

                public static explicit operator PIMAGE_NT_HEADERS64(IntPtr ptr) => ptr == IntPtr.Zero ? (PIMAGE_NT_HEADERS64)null : new PIMAGE_NT_HEADERS64(ptr);
            }
            public class PIMAGE_LOAD_CONFIG_DIRECTORY32 : Pointer<IMAGE_LOAD_CONFIG_DIRECTORY32>
            {
                public PIMAGE_LOAD_CONFIG_DIRECTORY32(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_LOAD_CONFIG_DIRECTORY32(object value)
                  : base(value)
                {
                }

                public static PIMAGE_LOAD_CONFIG_DIRECTORY32 operator +(PIMAGE_LOAD_CONFIG_DIRECTORY32 c1, int c2)
                {
                    return new PIMAGE_LOAD_CONFIG_DIRECTORY32(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PIMAGE_LOAD_CONFIG_DIRECTORY32 operator ++(PIMAGE_LOAD_CONFIG_DIRECTORY32 a)
                {
                    return a + 1;
                }

                public static explicit operator PIMAGE_LOAD_CONFIG_DIRECTORY32(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PIMAGE_LOAD_CONFIG_DIRECTORY32(ptr) : null;
                }
            }
            public class PIMAGE_IMPORT_DESCRIPTOR : Pointer<IMAGE_IMPORT_DESCRIPTOR>
            {
                public PIMAGE_IMPORT_DESCRIPTOR(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_IMPORT_DESCRIPTOR(object value)
                  : base(value)
                {
                }

                public static PIMAGE_IMPORT_DESCRIPTOR operator +(PIMAGE_IMPORT_DESCRIPTOR c1, int c2)
                {
                    return new PIMAGE_IMPORT_DESCRIPTOR(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PIMAGE_IMPORT_DESCRIPTOR operator ++(PIMAGE_IMPORT_DESCRIPTOR a)
                {
                    return a + 1;
                }

                public static explicit operator PIMAGE_IMPORT_DESCRIPTOR(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PIMAGE_IMPORT_DESCRIPTOR(ptr) : null;
                }
            }
            public class PIMAGE_IMPORT_BY_NAME : Pointer<IMAGE_IMPORT_BY_NAME>
            {
                public PIMAGE_IMPORT_BY_NAME(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_IMPORT_BY_NAME(object value)
                  : base(value)
                {
                }

                public static PIMAGE_IMPORT_BY_NAME operator +(PIMAGE_IMPORT_BY_NAME c1, int c2)
                {
                    return new PIMAGE_IMPORT_BY_NAME(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PIMAGE_IMPORT_BY_NAME operator ++(PIMAGE_IMPORT_BY_NAME a)
                {
                    return a + 1;
                }

                public static explicit operator PIMAGE_IMPORT_BY_NAME(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PIMAGE_IMPORT_BY_NAME(ptr) : null;
                }
            }
            public class PIMAGE_EXPORT_DIRECTORY : Pointer<IMAGE_EXPORT_DIRECTORY>
            {
                public PIMAGE_EXPORT_DIRECTORY(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_EXPORT_DIRECTORY(object value)
                  : base(value)
                {
                }

                public static PIMAGE_EXPORT_DIRECTORY operator +(PIMAGE_EXPORT_DIRECTORY c1, int c2)
                {
                    return new PIMAGE_EXPORT_DIRECTORY(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PIMAGE_EXPORT_DIRECTORY operator ++(PIMAGE_EXPORT_DIRECTORY a)
                {
                    return a + 1;
                }

                public static explicit operator PIMAGE_EXPORT_DIRECTORY(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PIMAGE_EXPORT_DIRECTORY(ptr) : null;
                }
            }
            public class PIMAGE_DOS_HEADER : Pointer<IMAGE_DOS_HEADER>
            {
                public PIMAGE_DOS_HEADER(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_DOS_HEADER(object value)
                  : base(value)
                {
                }

                public static explicit operator PIMAGE_DOS_HEADER(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PIMAGE_DOS_HEADER(ptr) : null;
                }
            }
            public class PIMAGE_BASE_RELOCATION : Pointer<IMAGE_BASE_RELOCATION>
            {
                public PIMAGE_BASE_RELOCATION(IntPtr address)
                  : base(address)
                {
                }

                public PIMAGE_BASE_RELOCATION(object value)
                  : base(value)
                {
                }

                public static PIMAGE_BASE_RELOCATION operator +(PIMAGE_BASE_RELOCATION c1, int c2)
                {
                    return new PIMAGE_BASE_RELOCATION(c1.IAddress + (c2 * c1.StructSize));
                }

                public static PIMAGE_BASE_RELOCATION operator ++(PIMAGE_BASE_RELOCATION a)
                {
                    return a + 1;
                }

                public static explicit operator PIMAGE_BASE_RELOCATION(IntPtr ptr)
                {
                    return ptr != IntPtr.Zero ? new PIMAGE_BASE_RELOCATION(ptr) : null;
                }
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern int CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesWritten);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, FreeType dwFreeType);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out UIntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress,
                IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern int NtQueryInformationProcess(IntPtr hProcess, int pic, IntPtr pbi, uint cb, out uint pSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, FreeType dwFreeType);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int dwSize, out UIntPtr lpNumberOfBytesRead);

            public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, out UIntPtr lpNumberOfBytesRead)
            {
                GCHandle gcHandle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
                int num = ReadProcessMemory(hProcess, lpBaseAddress, gcHandle.AddrOfPinnedObject(), lpBuffer.Length, out lpNumberOfBytesRead) ? 1 : 0;
                gcHandle.Free();
                return num != 0;
            }

            public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, out uint lpBuffer, out UIntPtr lpNumberOfBytesRead)
            {
                byte[] lpBuffer1 = new byte[4];
                int num = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer1, out lpNumberOfBytesRead) ? 1 : 0;
                lpBuffer = BitConverter.ToUInt32(lpBuffer1, 0);
                return num != 0;
            }

            public static bool ReadProcessMemory<T>(IntPtr hProcess, IntPtr lpBaseAddress, out T lpBuffer, out UIntPtr lpNumberOfBytesRead) where T : struct
            {
                byte[] lpBuffer1 = new byte[Marshal.SizeOf(typeof(T))];
                int num = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer1, out lpNumberOfBytesRead) ? 1 : 0;
                GCHandle gcHandle = GCHandle.Alloc(lpBuffer1, GCHandleType.Pinned);
                lpBuffer = Marshal.PtrToStructure<T>(gcHandle.AddrOfPinnedObject());
                gcHandle.Free();
                return num != 0;
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetProcessHeap();

            [DllImport("Dbghelp.dll")]
            public static extern IntPtr ImageRvaToVa(IntPtr NtHeaders, IntPtr Base, UIntPtr Rva, [Optional] IntPtr LastRvaSection);

            [DllImport("kernel32.dll")]
            public static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

            [DllImport("ntdll.dll")]
            internal static extern string Wine_get_version();
        }

        #region Injection

        public static string AttachProcess(string patch)
        {
            int processId;
            int pid;
            Process[] processes = Process.GetProcessesByName(MainForm.processname);
            if (processes.Length == 0)
            {
                return "Process Not Found (0x1)";
            }
            foreach (Process process in processes)
            {
                if (process.MainWindowHandle == IntPtr.Zero)
                {
                    return "This is background process! (0x2)";
                }
                processId = process.Id;
                pid = processId;
                return InjectUsingID(processId, patch);
            }
            return "Unknown error (0x3)";
        }

        private static IntPtr error_code = IntPtr.Zero;
        private static string error_where = "unknown";

        public static string InjectUsingID(int id, string dllPath)
        {
            if (!File.Exists(dllPath))
            {
                return "DLL Not Found (0x4)";
            }
            uint _proccessId = (uint)id;
            if (_proccessId == 0)
            {
                return "Process Not Found (0x5)";
            }
            if (!InjectLibrary(_proccessId, dllPath))
            {
                if (error_code == IntPtr.Zero && error_where == "OpenProcess")
                {
                    MessageBox.Show("OpenProcess returned 0, something went wrong...\nYou can try again but this time run as administrator the injector!", "Injection Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

                return $"Injection Failed ({error_code} at {error_where})";
            }
            return $"Success ({MainForm.processname})";
        }

        public static bool InjectLibrary(uint process, string dllPath)
        {
            IntPtr hProcess = OpenProcess(0x2 | 0x8 | 0x10 | 0x20 | 0x400, 1, process); // 1082, 0, id
            Debug.WriteLine("OpenProcess: " + hProcess);
            if (hProcess == IntPtr.Zero)
            {
                error_where = "OpenProcess";
                error_code = hProcess;
                return false;
            }
            IntPtr lpLLAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            Debug.WriteLine("GetProcAddress: " + lpLLAddress);
            if (lpLLAddress == IntPtr.Zero)
            {
                error_where = "GetProcAddress";
                error_code = lpLLAddress;
                return false;
            }
            IntPtr lpAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (IntPtr)dllPath.Length, 0x1000 | 0x2000, 0X40); // hProcess, IntPtr.Zero, (IntPtr)(uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), 12288U, 4U);
            Debug.WriteLine("VirtualAllocEx: " + lpAddress);
            if (lpAddress == IntPtr.Zero)
            {
                error_where = "VirtualAllocEx";
                error_code = lpAddress;
                return false;
            }
            int res1 = WriteProcessMemory(hProcess, lpAddress, Encoding.ASCII.GetBytes(dllPath), (uint)(dllPath.Length + 1 * Marshal.SizeOf(typeof(char))), 0);
            Debug.WriteLine("WriteProcessMemory: " + res1);
            if (res1 == 0)
            {
                error_where = "WriteProcessMemory";
                error_code = (IntPtr)res1;
                return false;
            }
            IntPtr res2 = CreateRemoteThread(hProcess, IntPtr.Zero, (IntPtr)0U, lpLLAddress, lpAddress, 0U, IntPtr.Zero);
            Debug.WriteLine("CreateRemoteThread: " + res2);
            if (res2 == IntPtr.Zero)
            {
                error_where = "CreateRemoteThread";
                error_code = res2;
                return false;
            }
            CloseHandle(hProcess);
            return true;
        }

        #endregion Injection

        #region InjectionGen2

        internal class Mapping
        {
            private Process process;
            private IntPtr hProcess;
            private bool AsyncAttach;
            public uint TimedOut = 5000;

            public Mapping(Process process) => this.process = process;

            internal IntPtr Inject(byte[] buffer)
            {
                GCHandle handle = new GCHandle();
                buffer = ((IEnumerable<byte>)buffer).ToArray();
                IntPtr result = IntPtr.Zero;
                if (process == null || process.HasExited)
                {
                    return result;
                }
                try
                {
                    handle = PinBuffer(buffer);
                    IntPtr _hProcess = OpenTarget();
                    if (_hProcess == IntPtr.Zero)
                    {
                        throw new Exception("Failed to open handle.\n" + Marshal.GetLastWin32Error());
                    }
                    else
                    {
                        hProcess = _hProcess;
                    }
                    result = LoadImageToMemory(handle.AddrOfPinnedObject());
                }/*
                catch (Exception)
                {
                    // TODO: handle error
                } */
                finally
                {
                    FreeHandle(handle);
                    CloseTarget();
                }
                return result;
            }

            private bool InjectDependency(string dependency)
            {
                IntPtr procAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                if (procAddress != IntPtr.Zero)
                {
                    IntPtr result = RemoteAllocateMemory((uint)dependency.Length);
                    if (result == IntPtr.Zero)
                    {
                        return false;
                    }

                    byte[] bytes = Encoding.ASCII.GetBytes(dependency);
                    bool flag = WriteProcessMemory(hProcess, result, bytes, (uint)bytes.Length, out UIntPtr _);
                    if (flag && WaitForSingleObject(CreateRemoteThread(hProcess, IntPtr.Zero, (IntPtr)0U, procAddress, result, 0U, IntPtr.Zero), TimedOut) != 0U)
                    {
                        return false;
                    }

                    VirtualFreeEx(hProcess, result, 0, FreeType.Release);
                    return flag;
                }
                return false;
            }

            private void CloseTarget()
            {
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                    hProcess = IntPtr.Zero;
                }
            }

            private void FreeHandle(GCHandle handle)
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }

            private IntPtr LoadImageToMemory(IntPtr baseAddress)
            {
                PIMAGE_NT_HEADERS32 ntHeader = GetNtHeader(baseAddress);
                if (ntHeader != null && ntHeader.IBufferValue.FileHeader.NumberOfSections != 0)
                {
                    uint result1 = uint.MaxValue;
                    uint result2 = 0;
                    PIMAGE_SECTION_HEADER pimageSectionHeader = (PIMAGE_SECTION_HEADER)(ntHeader.IAddress + 24 + ntHeader.IBufferValue.FileHeader.SizeOfOptionalHeader);
                    for (uint i_Index = 0; i_Index < ntHeader.IBufferValue.FileHeader.NumberOfSections; ++i_Index)
                    {
                        if (pimageSectionHeader[i_Index].VirtualSize != 0U)
                        {
                            if (pimageSectionHeader[i_Index].VirtualAddress < result1)
                            {
                                result1 = pimageSectionHeader[i_Index].VirtualAddress;
                            }

                            if (pimageSectionHeader[i_Index].VirtualAddress + pimageSectionHeader[i_Index].VirtualSize > result2)
                            {
                                result2 = pimageSectionHeader[i_Index].VirtualAddress + pimageSectionHeader[i_Index].VirtualSize;
                            }
                        }
                    }
                    uint size = result2 - result1;
                    if (ntHeader.IBufferValue.OptionalHeader.ImageBase % 4096U != 0U || ntHeader.IBufferValue.OptionalHeader.DelayImportDescriptor.Size > 0U)
                    {
                        return IntPtr.Zero;
                    }

                    IntPtr result3 = RemoteAllocateMemory(size);
                    if (result3 == IntPtr.Zero || !ProcessImportTable(baseAddress) || !ProcessDelayedImportTable(baseAddress) || !ProcessRelocations(baseAddress, result3) || !ProcessSections(baseAddress, result3) || !ProcessTlsEntries(baseAddress, result3))
                    {
                        return IntPtr.Zero;
                    }

                    if (ntHeader.IBufferValue.OptionalHeader.AddressOfEntryPoint > 0U)
                    {
                        int result4 = result3.ToInt32() + (int)ntHeader.IBufferValue.OptionalHeader.AddressOfEntryPoint;
                        if (!CallEntryPoint(result3, (uint)result4, AsyncAttach))
                        {
                            return IntPtr.Zero;
                        }
                    }
                    return result3;
                }
                return IntPtr.Zero;
            }

            private bool CallEntryPoint(IntPtr baseAddress, uint entrypoint, bool asyncAttach)
            {
                // TODO: optimize list
                List<byte> byteList = new List<byte>();
                byteList.Add(104);
                byteList.AddRange(BitConverter.GetBytes(baseAddress.ToInt32()));
                byteList.Add(104);
                byteList.AddRange(BitConverter.GetBytes(1));
                byteList.Add(104);
                byteList.AddRange(BitConverter.GetBytes(0));
                byteList.Add(184);
                byteList.AddRange(BitConverter.GetBytes(entrypoint));
                byteList.Add(byte.MaxValue);
                byteList.Add(208);
                byteList.Add(51);
                byteList.Add(192);
                byteList.Add(194);
                byteList.Add(4);
                byteList.Add(0);
                return ExecuteRemoteThreadBuffer(byteList.ToArray(), asyncAttach);
            }

            private bool ExecuteRemoteThreadBuffer(byte[] bufferThreadData, bool asyncAttach)
            {
                // TODO: do something with result code of WaitForSingleObject
                IntPtr lpAddress = RemoteAllocateMemory((uint)bufferThreadData.Length);
                if (lpAddress != IntPtr.Zero)
                {
                    int result = WriteProcessMemory(hProcess, lpAddress, bufferThreadData, (uint)bufferThreadData.Length, out _) ? 1 : 0;
                    if (result != 0)
                    {
                        IntPtr hHandle = CreateRemoteThread(hProcess, IntPtr.Zero, (IntPtr)0U, lpAddress, IntPtr.Zero, 0U, IntPtr.Zero);
                        if (!asyncAttach)
                        {
                            WaitForSingleObject(hHandle, 4000U);
                            VirtualFreeEx(hProcess, lpAddress, 0, FreeType.Release);
                            return result != 0;
                        }
                        new Thread(() =>
                        {
                            WaitForSingleObject(hHandle, 5000U);
                            VirtualFreeEx(hProcess, lpAddress, 0, FreeType.Release);
                        })
                        {
                            IsBackground = true
                        }.Start();
                        return result != 0;
                    }
                    return result != 0;
                }
                return false;
            }

            private bool ProcessTlsEntries(IntPtr baseAddress, IntPtr remoteAddress)
            {
                PIMAGE_NT_HEADERS32 ntHeader = GetNtHeader(baseAddress);
                if (ntHeader != null)
                {
                    if (ntHeader.IBufferValue.OptionalHeader.TLSTable.Size == 0U)
                    {
                        return true;
                    }

                    PIMAGE_TLS_DIRECTORY32 pointer = (PIMAGE_TLS_DIRECTORY32)RvaToPointer(ntHeader.IBufferValue.OptionalHeader.TLSTable.VirtualAddress, baseAddress);
                    if (pointer == null || pointer.IBufferValue.AddressOfCallBacks == 0U)
                    {
                        return true;
                    }

                    byte[] lpBuffer = new byte[1020];
                    if (!ReadProcessMemory(hProcess, new IntPtr(pointer.IBufferValue.AddressOfCallBacks), lpBuffer, out UIntPtr _))
                    {
                        return false;
                    }
                    PDWORD pdword = new PDWORD(lpBuffer);
                    bool flag = true;
                    for (uint i_Index = 0; pdword[i_Index] > 0U; ++i_Index)
                    {
                        flag = CallEntryPoint(remoteAddress, pdword[i_Index], false);
                        if (!flag)
                            break;
                    }
                    return flag;
                }
                return false;
            }

            private IntPtr RvaToPointer(uint rva, IntPtr baseAddress) => GetNtHeader(baseAddress) != null ? ImageRvaToVa(GetNtHeader(baseAddress).IAddress, baseAddress, new UIntPtr(rva), IntPtr.Zero) : IntPtr.Zero;

            private bool ProcessSections(IntPtr baseAddress, IntPtr remoteAddress)
            {
                PIMAGE_NT_HEADERS32 ntHeader = GetNtHeader(baseAddress);
                if (ntHeader != null)
                {
                    PIMAGE_SECTION_HEADER pimageSectionHeader = (PIMAGE_SECTION_HEADER)(ntHeader.IAddress + 24 + ntHeader.IBufferValue.FileHeader.SizeOfOptionalHeader);
                    for (ushort index = 0; index < ntHeader.IBufferValue.FileHeader.NumberOfSections; ++index)
                    {
                        if (!CompareCharArray(".reloc".ToCharArray(), pimageSectionHeader[index].Name))
                        {
                            DataSectionFlags characteristics = pimageSectionHeader[index].Characteristics;
                            if (characteristics.HasFlag(DataSectionFlags.MemoryRead) || characteristics.HasFlag(DataSectionFlags.MemoryWrite) || characteristics.HasFlag(DataSectionFlags.MemoryExecute))
                            {
                                uint sectionProtection = GetSectionProtection(pimageSectionHeader[index].Characteristics);
                                ProcessSection(pimageSectionHeader[index].Name, baseAddress, remoteAddress, pimageSectionHeader[index].PointerToRawData, pimageSectionHeader[index].VirtualAddress, pimageSectionHeader[index].SizeOfRawData, pimageSectionHeader[index].VirtualSize, sectionProtection);
                            }
                        }
                    }
                    return true;
                }
                return false;
            }

            private bool ProcessSection(char[] name, IntPtr baseAddress, IntPtr remoteAddress, ulong rawData, ulong virtualAddress, ulong rawSize, ulong virtualSize, uint protectFlag) => WriteProcessMemory(hProcess, new IntPtr(remoteAddress.ToInt64() + (long)virtualAddress), new IntPtr(baseAddress.ToInt64() + (long)rawData), new IntPtr((long)rawSize), out UIntPtr _) && VirtualProtectEx(hProcess, new IntPtr(remoteAddress.ToInt64() + (long)virtualAddress), new UIntPtr(virtualSize), protectFlag, out uint _);

            private uint GetSectionProtection(DataSectionFlags characteristics)
            {
                uint result = 0;
                if (characteristics.HasFlag(DataSectionFlags.MemoryNotCached))
                {
                    result |= 512U;
                }
                return !characteristics.HasFlag(DataSectionFlags.MemoryExecute) ? (!characteristics.HasFlag(DataSectionFlags.MemoryRead) ? (!characteristics.HasFlag(DataSectionFlags.MemoryWrite) ? result | 1U : result | 8U) : (!characteristics.HasFlag(DataSectionFlags.MemoryWrite) ? result | 2U : result | 4U)) : (!characteristics.HasFlag(DataSectionFlags.MemoryRead) ? (!characteristics.HasFlag(DataSectionFlags.MemoryWrite) ? result | 16U : result | 128U) : (!characteristics.HasFlag(DataSectionFlags.MemoryWrite) ? result | 32U : result | 64U));
            }

            public static bool CompareCharArray(char[] Char1, char[] Char2)
            {
                for (int index = 0; index < Math.Min(Char1.Length, Char2.Length); ++index)
                {
                    if (Char1[index] != Char2[index])
                    {
                        return false;
                    }

                    if (Char1[index] == char.MinValue)
                    {
                        break;
                    }
                }
                return true;
            }

            private bool ProcessRelocations(IntPtr baseAddress, IntPtr remoteAddress)
            {
                PIMAGE_NT_HEADERS32 ntHeader = GetNtHeader(baseAddress);
                if (ntHeader != null)
                {
                    if ((ntHeader.IBufferValue.FileHeader.Characteristics & 1) > 0)
                    {
                        return true;
                    }

                    if (ntHeader.IBufferValue.OptionalHeader.BaseRelocationTable.Size > 0U)
                    {
                        PIMAGE_BASE_RELOCATION pimageBaseRelocation = (PIMAGE_BASE_RELOCATION)RvaToPointer(ntHeader.IBufferValue.OptionalHeader.BaseRelocationTable.VirtualAddress, baseAddress);
                        if (pimageBaseRelocation != null)
                        {
                            PBYTE pbyte = (PBYTE)pimageBaseRelocation.IAddress + (int)ntHeader.IBufferValue.OptionalHeader.BaseRelocationTable.Size;
                            while (true)
                            {
                                IntPtr Address1 = pimageBaseRelocation.IAddress;
                                long address_int_1 = Address1.ToInt64();
                                Address1 = pbyte.IAddress;
                                long address_int_2 = Address1.ToInt64();
                                if (address_int_1 < address_int_2)
                                {
                                    PBYTE pointer = (PBYTE)RvaToPointer(pimageBaseRelocation.IBufferValue.VirtualAddress, baseAddress);
                                    uint result1 = pimageBaseRelocation.IBufferValue.SizeOfBlock - 8U >> 1;
                                    PWORD Address2 = (PWORD)(pimageBaseRelocation + 1).IAddress;
                                    uint result2 = 0;
                                    while (result2 < result1)
                                    {
                                        ProcessRelocation((uint)((ulong)remoteAddress.ToInt32() - ntHeader.IBufferValue.OptionalHeader.ImageBase), Address2.IBufferValue, pointer);
                                        ++result2;
                                        ++Address2;
                                    }
                                    pimageBaseRelocation = (PIMAGE_BASE_RELOCATION)Address2.IAddress;
                                }
                                else
                                    break;
                            }
                        }
                        else
                        {
                            return false;
                        }
                    }
                    return true;
                }
                return false;
            }

            private bool ProcessRelocation(uint imageBaseDelta, ushort bufferValue, PBYTE relocationBase)
            {
                bool flag = true;
                switch ((bufferValue >> 12) & 15)
                {
                    case 0:
                    case 4:
                        return flag;

                    case 1:
                        PSHORT iAddress1 = (PSHORT)(relocationBase + (bufferValue & 4095)).IAddress;
                        Marshal.WriteInt16(iAddress1.IAddress, (short)((long)iAddress1.IBufferValue + (ushort)(imageBaseDelta >> 16 & ushort.MaxValue)));
                        goto case 0;
                    case 2:
                        PSHORT iAddress2 = (PSHORT)(relocationBase + (bufferValue & 4095)).IAddress;
                        Marshal.WriteInt16(iAddress2.IAddress, (short)((long)iAddress2.IBufferValue + (ushort)(imageBaseDelta & ushort.MaxValue)));
                        goto case 0;
                    case 3:
                        PDWORD iAddress3 = (PDWORD)(relocationBase + (bufferValue & 4095)).IAddress;
                        Marshal.WriteInt32(iAddress3.IAddress, (int)iAddress3.IBufferValue + (int)imageBaseDelta);
                        goto case 0;
                    case 10:
                        PDWORD iAddress4 = (PDWORD)(relocationBase + (bufferValue & 4095)).IAddress;
                        Marshal.WriteInt32(iAddress4.IAddress, (int)iAddress4.IBufferValue + (int)imageBaseDelta);
                        goto case 0;
                    default:
                        flag = false;
                        goto case 0;
                }
            }

            private bool ProcessDelayedImportTable(IntPtr baseAddress)
            {
                PIMAGE_NT_HEADERS32 ntHeader = GetNtHeader(baseAddress);
                if (ntHeader != null)
                {
                    if (ntHeader.IBufferValue.OptionalHeader.DelayImportDescriptor.Size <= 0U)
                    {
                        return true;
                    }

                    PIMAGE_IMPORT_DESCRIPTOR pointer1 = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPointer(ntHeader.IBufferValue.OptionalHeader.DelayImportDescriptor.VirtualAddress, baseAddress);
                    if (pointer1 == null)
                    {
                        return false;
                    }

                    while (pointer1.IBufferValue.Name > 0U)
                    {
                        PCHAR pointer2 = (PCHAR)RvaToPointer(pointer1.IBufferValue.Name, baseAddress);
                        PIMAGE_THUNK_DATA pointer3;
                        PIMAGE_THUNK_DATA pointer4;
                        if (pointer2 != null)
                        {
                            IntPtr remoteModuleHandleA = GetRemoteModuleHandleA(pointer2.ToString());
                            if (remoteModuleHandleA == IntPtr.Zero)
                            {
                                InjectDependency(pointer2.ToString());
                                remoteModuleHandleA = GetRemoteModuleHandleA(pointer2.ToString());
                                if (remoteModuleHandleA == IntPtr.Zero)
                                    goto label_16;
                            }
                            if (pointer1.IBufferValue.OriginalFirstThunk > 0U)
                            {
                                pointer3 = (PIMAGE_THUNK_DATA)RvaToPointer(pointer1.IBufferValue.OriginalFirstThunk, baseAddress);
                                pointer4 = (PIMAGE_THUNK_DATA)RvaToPointer(pointer1.IBufferValue.FirstThunk, baseAddress);
                            }
                            else
                            {
                                pointer3 = (PIMAGE_THUNK_DATA)RvaToPointer(pointer1.IBufferValue.FirstThunk, baseAddress);
                                pointer4 = (PIMAGE_THUNK_DATA)RvaToPointer(pointer1.IBufferValue.FirstThunk, baseAddress);
                            }
                            while (pointer3.IBufferValue.AddressOfData > 0U)
                            {
                                IntPtr dependencyProcAddressA;
                                if ((pointer3.IBufferValue.Ordinal & 2147483648U) > 0U)
                                {
                                    short num = (short)((int)pointer3.IBufferValue.Ordinal & ushort.MaxValue);
                                    dependencyProcAddressA = GetDependencyProcAddressA(remoteModuleHandleA, new PCHAR(num));
                                    if (dependencyProcAddressA == IntPtr.Zero)
                                        return false;
                                }
                                else
                                {
                                    PCHAR procName = (PCHAR)((PIMAGE_IMPORT_BY_NAME)RvaToPointer(pointer4.IBufferValue.Ordinal, baseAddress)).IAddress + 2;
                                    dependencyProcAddressA = GetDependencyProcAddressA(remoteModuleHandleA, procName);
                                }
                                Marshal.WriteInt32(pointer4.IAddress, dependencyProcAddressA.ToInt32());
                                ++pointer3;
                                ++pointer4;
                            }
                        }
                    label_16:
                        ++pointer1;
                    }
                    return true;
                }
                return false;
            }

            private IntPtr GetRemoteModuleHandleA(string v)
            {
                IntPtr num1 = IntPtr.Zero;
                IntPtr processHeap = GetProcessHeap();
                uint cb = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
                PPROCESS_BASIC_INFORMATION basicInformation = (PPROCESS_BASIC_INFORMATION)HeapAlloc(processHeap, 8U, new UIntPtr(cb));
                int num2 = NtQueryInformationProcess(hProcess, 0, basicInformation.IAddress, cb, out uint pSize);
                if (num2 >= 0 && cb < pSize)
                {
                    if (basicInformation != null)
                        HeapFree(processHeap, 0U, basicInformation.IAddress);
                    basicInformation = (PPROCESS_BASIC_INFORMATION)HeapAlloc(processHeap, 8U, new UIntPtr(cb));
                    if (basicInformation == null)
                        return IntPtr.Zero;
                    num2 = NtQueryInformationProcess(hProcess, 0, basicInformation.IAddress, pSize, out pSize);
                }
                uint lpBuffer1;
                UIntPtr lpNumberOfBytesRead;
                if (num2 >= 0 && basicInformation.IBufferValue.PebBaseAddress != IntPtr.Zero && ReadProcessMemory(hProcess, basicInformation.IBufferValue.PebBaseAddress + 12, out lpBuffer1, out lpNumberOfBytesRead))
                {
                    uint num3 = lpBuffer1 + 12U;
                    uint num4 = lpBuffer1 + 12U;
                    do
                    {
                        if (!ReadProcessMemory(hProcess, new IntPtr(num4), out uint lpBuffer2, out lpNumberOfBytesRead))
                        {
                            HeapFree(processHeap, 0U, basicInformation.IAddress);
                        }

                        num4 = lpBuffer2;
                        ReadProcessMemory(hProcess, new IntPtr(lpBuffer2) + 44, out UNICODE_STRING lpBuffer3, out lpNumberOfBytesRead);
                        string empty = string.Empty;
                        if (lpBuffer3.Length > 0)
                        {
                            byte[] numArray = new byte[lpBuffer3.Length];
                            ReadProcessMemory(hProcess, lpBuffer3.Buffer, numArray, out lpNumberOfBytesRead);
                            empty = Encoding.Unicode.GetString(numArray);
                        }
                        ReadProcessMemory(hProcess, new IntPtr(lpBuffer2) + 24, out uint lpBuffer4, out lpNumberOfBytesRead);
                        ReadProcessMemory(hProcess, new IntPtr(lpBuffer2) + 32, out uint lpBuffer5, out lpNumberOfBytesRead);
                        if (lpBuffer4 != 0U && lpBuffer5 != 0U && string.Equals(empty, v, StringComparison.OrdinalIgnoreCase))
                        {
                            num1 = new IntPtr(lpBuffer4);
                            break;
                        }
                    }
                    while ((int)num3 != (int)num4);
                }
                if (basicInformation != null)
                    HeapFree(processHeap, 0U, basicInformation.IAddress);
                return num1;
            }

            public static string ToStringAnsi(byte[] Buffers)
            {
                StringBuilder stringBuilder = new StringBuilder();
                foreach (byte iBuffer in Buffers)
                {
                    if (iBuffer == 0)
                        break;
                    else
                    {
                        stringBuilder.Append((char)iBuffer);
                    }
                }
                string str = stringBuilder.ToString();
                stringBuilder.Clear();
                return str;
            }

            private IntPtr AllocateMemory(uint size) => VirtualAlloc(IntPtr.Zero, new UIntPtr(size), AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

            private IntPtr GetDependencyProcAddressA(IntPtr moduleBase, PCHAR procName)
            {
                IntPtr lpBaseAddress = IntPtr.Zero;
                ReadProcessMemory(hProcess, moduleBase, out IMAGE_DOS_HEADER lpBuffer1, out UIntPtr lpNumberOfBytesRead);
                if (lpBuffer1.isValid)
                {
                    ReadProcessMemory(hProcess, moduleBase + lpBuffer1.e_lfanew, out IMAGE_NT_HEADERS32 lpBuffer2, out lpNumberOfBytesRead);
                    if (lpBuffer2.isValid)
                    {
                        uint virtualAddress = lpBuffer2.OptionalHeader.ExportTable.VirtualAddress;
                        if (virtualAddress > 0U)
                        {
                            uint size = lpBuffer2.OptionalHeader.ExportTable.Size;
                            PIMAGE_EXPORT_DIRECTORY pimageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)AllocateMemory(size);
                            ReadProcessMemory(hProcess, moduleBase + (int)virtualAddress, pimageExportDirectory.IAddress, (int)size, out lpNumberOfBytesRead);
                            PWORD pword = (PWORD)(pimageExportDirectory.IAddress + (int)pimageExportDirectory.IBufferValue.AddressOfNameOrdinals - (int)virtualAddress);
                            PDWORD pdword1 = (PDWORD)(pimageExportDirectory.IAddress + (int)pimageExportDirectory.IBufferValue.AddressOfNames - (int)virtualAddress);
                            PDWORD pdword2 = (PDWORD)(pimageExportDirectory.IAddress + (int)pimageExportDirectory.IBufferValue.AddressOfFunctions - (int)virtualAddress);
                            for (uint i_Index = 0; i_Index < pimageExportDirectory.IBufferValue.NumberOfFunctions; ++i_Index)
                            {
                                PCHAR pchar = null;
                                ushort num;
                                if (new PDWORD(procName.IAddress).IBufferValue <= ushort.MaxValue)
                                {
                                    num = (ushort)i_Index;
                                }
                                else
                                {
                                    if (new PDWORD(procName.IAddress).IBufferValue <= ushort.MaxValue || i_Index >= pimageExportDirectory.IBufferValue.NumberOfNames)
                                        return IntPtr.Zero;
                                    pchar = (PCHAR)new IntPtr(pdword1[i_Index] + pimageExportDirectory.IAddress.ToInt32() - virtualAddress);
                                    num = pword[i_Index];
                                }
                                if (new PDWORD(procName.IAddress).IBufferValue <= ushort.MaxValue && (int)new PDWORD(procName.IAddress).IBufferValue == num + (int)pimageExportDirectory.IBufferValue.Base || new PDWORD(procName.IAddress).IBufferValue > ushort.MaxValue && pchar.ToString() == procName.ToString())
                                {
                                    lpBaseAddress = moduleBase + (int)pdword2[num];
                                    if (lpBaseAddress.ToInt64() >= (moduleBase + (int)virtualAddress).ToInt64() && lpBaseAddress.ToInt64() <= (moduleBase + (int)virtualAddress + (int)size).ToInt64())
                                    {
                                        byte[] numArray = new byte[byte.MaxValue];
                                        ReadProcessMemory(hProcess, lpBaseAddress, numArray, out lpNumberOfBytesRead);
                                        string stringAnsi = ToStringAnsi(numArray);
                                        string str1 = stringAnsi.Substring(0, stringAnsi.IndexOf(".")) + ".dll";
                                        string str2 = stringAnsi.Substring(stringAnsi.IndexOf(".") + 1);
                                        IntPtr remoteModuleHandleA = GetRemoteModuleHandleA(str1);
                                        if (remoteModuleHandleA == IntPtr.Zero)
                                            InjectDependency(str1);
                                        lpBaseAddress = !str2.StartsWith("#") ? GetDependencyProcAddressA(remoteModuleHandleA, new PCHAR(str2)) : GetDependencyProcAddressA(remoteModuleHandleA, new PCHAR(str2) + 1);
                                        break;
                                    }
                                    break;
                                }
                            }
                            VirtualFree(pimageExportDirectory.IAddress, 0, FreeType.Release);
                        }
                        return lpBaseAddress;
                    }
                    else
                    {
                        return IntPtr.Zero;
                    }
                }
                return IntPtr.Zero;
            }

            private bool ProcessImportTable(IntPtr baseAddress)
            {
                PIMAGE_NT_HEADERS32 ntHeader = GetNtHeader(baseAddress);
                if (ntHeader == null)
                    return false;
                if (ntHeader.IBufferValue.OptionalHeader.ImportTable.Size <= 0U)
                    return true;
                PIMAGE_IMPORT_DESCRIPTOR pointer1 = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPointer(ntHeader.IBufferValue.OptionalHeader.ImportTable.VirtualAddress, baseAddress);
                if (pointer1 == null)
                    return false;
                while (pointer1.IBufferValue.Name > 0U)
                {
                    PCHAR pchar = (PCHAR)RvaToPointer(pointer1.IBufferValue.Name, baseAddress);
                    if (pchar != null)
                    {
                        if (pchar.ToString().Contains("-ms-win-crt-"))
                        {
                            pchar = new PCHAR("ucrtbase.dll");
                        }

                        IntPtr remoteModuleHandleA = GetRemoteModuleHandleA(pchar.ToString());
                        if (remoteModuleHandleA == IntPtr.Zero)
                        {
                            InjectDependency(pchar.ToString());
                            remoteModuleHandleA = GetRemoteModuleHandleA(pchar.ToString());
                            if (remoteModuleHandleA == IntPtr.Zero)
                                goto label_18;
                        }
                        PIMAGE_THUNK_DATA pointer2;
                        PIMAGE_THUNK_DATA pointer3;
                        if (pointer1.IBufferValue.OriginalFirstThunk > 0U)
                        {
                            pointer2 = (PIMAGE_THUNK_DATA)RvaToPointer(pointer1.IBufferValue.OriginalFirstThunk, baseAddress);
                            pointer3 = (PIMAGE_THUNK_DATA)RvaToPointer(pointer1.IBufferValue.FirstThunk, baseAddress);
                        }
                        else
                        {
                            pointer2 = (PIMAGE_THUNK_DATA)RvaToPointer(pointer1.IBufferValue.FirstThunk, baseAddress);
                            pointer3 = (PIMAGE_THUNK_DATA)RvaToPointer(pointer1.IBufferValue.FirstThunk, baseAddress);
                        }
                        while (pointer2.IBufferValue.AddressOfData > 0U)
                        {
                            IntPtr dependencyProcAddressA;
                            if ((pointer2.IBufferValue.Ordinal & 2147483648U) > 0U)
                            {
                                short num = (short)((int)pointer2.IBufferValue.Ordinal & ushort.MaxValue);
                                dependencyProcAddressA = GetDependencyProcAddressA(remoteModuleHandleA, new PCHAR(num));
                                if (dependencyProcAddressA == IntPtr.Zero)
                                    return false;
                            }
                            else
                            {
                                PCHAR procName = (PCHAR)((PIMAGE_IMPORT_BY_NAME)RvaToPointer(pointer3.IBufferValue.Ordinal, baseAddress)).IAddress + 2;
                                dependencyProcAddressA = GetDependencyProcAddressA(remoteModuleHandleA, procName);
                            }
                            Marshal.WriteInt32(pointer3.IAddress, dependencyProcAddressA.ToInt32());
                            ++pointer2;
                            ++pointer3;
                        }
                    }
                label_18:
                    ++pointer1;
                }
                return true;
            }

            private IntPtr RemoteAllocateMemory(uint size) => VirtualAllocEx(hProcess, IntPtr.Zero, new IntPtr(size), AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

            private PIMAGE_NT_HEADERS32 GetNtHeader(IntPtr baseAddress)
            {
                if (GetDosHeader(baseAddress) != null)
                {
                    PIMAGE_NT_HEADERS32 pimageNtHeaderS32 = (PIMAGE_NT_HEADERS32)(baseAddress + GetDosHeader(baseAddress).IBufferValue.e_lfanew);
                    return pimageNtHeaderS32.IBufferValue.isValid ? pimageNtHeaderS32 : null;
                }
                return null;
            }

            private PIMAGE_DOS_HEADER GetDosHeader(IntPtr baseAddress) => ((PIMAGE_DOS_HEADER)baseAddress).IBufferValue.isValid ? (PIMAGE_DOS_HEADER)baseAddress : null;

            private IntPtr OpenTarget() => OpenProcess((uint)ProcessAccessFlags.All, 0, (uint)process.Id);

            private GCHandle PinBuffer(byte[] buffer) => GCHandle.Alloc(buffer, GCHandleType.Pinned);
        }

        #endregion InjectionGen2

        #region Compatibility

        public static bool IsWine()
        {
            string wine_name;
            try
            {
                wine_name = Wine_get_version();
                Console.WriteLine("---------------------------------------------------------------------------------------------");
                Console.WriteLine($"Running under {wine_name}! Please report any problems that may occur while using it!");
                Console.WriteLine("---------------------------------------------------------------------------------------------");
            }
            catch (Exception) { return false; }
            return true;
        }

        public static bool IsMono()
        {
            return Type.GetType("Mono.Runtime") != null;
        }

        #endregion Compatibility

        #region Detect64Bit

        public static bool IsWin64Emulator(Process process)
        {
            if (IntPtr.Size == 4)
                return false;
            else if (IntPtr.Size == 8)
            {
                if ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
                {
                    return IsWow64Process(process.Handle, out bool retVal) && retVal;
                }
            }
            return false;
        }

        #endregion Detect64Bit

        #region Image

        public static Bitmap ResizeImage(Image image, int width, int height)
        {
            Rectangle destRect = new Rectangle(0, 0, width, height);
            Bitmap destImage = new Bitmap(width, height);
            destImage.SetResolution(image.HorizontalResolution, image.VerticalResolution);
            using (Graphics graphics = Graphics.FromImage(destImage))
            {
                graphics.CompositingMode = CompositingMode.SourceCopy;
                graphics.CompositingQuality = CompositingQuality.HighSpeed;
                graphics.InterpolationMode = InterpolationMode.Low;
                graphics.SmoothingMode = SmoothingMode.HighSpeed;
                graphics.PixelOffsetMode = PixelOffsetMode.HighSpeed;

                using (ImageAttributes wrapMode = new ImageAttributes())
                {
                    wrapMode.SetWrapMode(WrapMode.TileFlipXY);
                    graphics.DrawImage(image, destRect, 0, 0, image.Width, image.Height, GraphicsUnit.Pixel, wrapMode);
                }
            }
            return destImage;
        }

        #endregion Image

        #region Update

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE1006:Naming Styles", Justification = "<Pending>")]
        public class Root
        {
            [JsonProperty("html_url")]
            public string html_url { get; set; }

            [JsonProperty("tag_name")]
            public string tag_name { get; set; }
        }

        #endregion Update
    }
}