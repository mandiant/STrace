#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include "Interface.h"


// Structures
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _OBJECT_HANDLE_INFORMATION
{
    ULONG HandleAttributes;
    ULONG GrantedAccess;
} OBJECT_HANDLE_INFORMATION, * POBJECT_HANDLE_INFORMATION;

typedef struct _OBJECT_TYPE* POBJECT_TYPE;


typedef CCHAR KPROCESSOR_MODE;


#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define STATUS_END_OF_FILE               ((NTSTATUS)0xC0000011L)

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef _Enum_is_bitflag_ enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed = NonPagedPool + 2,
	DontUseThisType,
	NonPagedPoolCacheAligned = NonPagedPool + 4,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
	MaxPoolType,

	//
	// Define base types for NonPaged (versus Paged) pool, for use in cracking
	// the underlying pool type.
	//

	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
	NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
	NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,

	//
	// Note these per session types are carefully chosen so that the appropriate
	// masking still applies as well as MaxPoolType above.
	//

	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,

	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
	NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} _Enum_is_bitflag_ POOL_TYPE;
typedef _Enum_is_bitflag_ enum _POOL_TYPE POOL_TYPE;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55

        //
        //  These are special versions of these operations (defined earlier)
        //  which can be used by kernel mode drivers only to bypass security
        //  access checks for Rename and HardLink operations.  These operations
        //  are only recognized by the IOManager, a file system should never
        //  receive these.
        //

        FileRenameInformationBypassAccessCheck,         // 56
        FileLinkInformationBypassAccessCheck,           // 57

            //
            // End of special information classes reserved for IOManager.
            //

            FileVolumeNameInformation,                      // 58
            FileIdInformation,                              // 59
            FileIdExtdDirectoryInformation,                 // 60
            FileReplaceCompletionInformation,               // 61
            FileHardLinkFullIdInformation,                  // 62
            FileIdExtdBothDirectoryInformation,             // 63
            FileDispositionInformationEx,                   // 64
            FileRenameInformationEx,                        // 65
            FileRenameInformationExBypassAccessCheck,       // 66
            FileDesiredStorageClassInformation,             // 67
            FileStatInformation,                            // 68
            FileMemoryPartitionInformation,                 // 69
            FileStatLxInformation,                          // 70
            FileCaseSensitiveInformation,                   // 71
            FileLinkInformationEx,                          // 72
            FileLinkInformationExBypassAccessCheck,         // 73
            FileStorageReserveIdInformation,                // 74
            FileCaseSensitiveInformationForceAccessCheck,   // 75
            FileKnownFolderInformation,                     // 76

            FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

#define STATUS_PORT_NOT_SET 0xC0000353L
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#define STATUS_UNSUCCESSFUL 0xC0000001L

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING          Name;
    WCHAR*                  NameBuffer;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

extern "C" __declspec(dllimport) PVOID NTAPI ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
extern "C" __declspec(dllimport) void NTAPI ExFreePoolWithTag(PVOID P, ULONG Tag);

extern "C" __declspec(dllimport) NTSTATUS NTAPI RtlAppendUnicodeStringToString(PUNICODE_STRING Destination, PCUNICODE_STRING Source);
extern "C" __declspec(dllimport) NTSTATUS NTAPI RtlAppendUnicodeToString(PUNICODE_STRING Destination, PCWSTR Source);
extern "C" __declspec(dllimport) void NTAPI RtlCopyUnicodeString(PUNICODE_STRING  DestinationString, PCUNICODE_STRING SourceString);
extern "C" __declspec(dllimport) NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW);

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwOpenFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
    );

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength);

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwReadFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID			 ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
    );

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID			 ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
    );

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwClose(HANDLE Handle);

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

extern "C" __declspec(dllimport) NTSTATUS NTAPI ObQueryObjectAuditingByHandle(
    HANDLE   Handle,
    PBOOLEAN GenerateOnClose
);

#define STATUS_HANDLE_NOT_CLOSABLE 0xC0000235L
#define OBJ_PROTECT_CLOSE 0x00000001L

typedef void* PEPROCESS;
extern "C" __declspec(dllimport) PEPROCESS NTAPI PsGetCurrentProcess();

extern "C" __declspec(dllimport) PVOID NTAPI PsGetProcessDebugPort(PEPROCESS Process);

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

extern "C" __declspec(dllimport) NTSTATUS NTAPI NtCreateEvent(
    PHANDLE            EventHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    EVENT_TYPE         EventType,
    BOOLEAN            InitialState
);

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
static const uint64_t DTRACE_IRQL = 15;
typedef UCHAR KIRQL;
extern "C" __declspec(dllimport) KIRQL KfRaiseIrql(KIRQL newIrql);
extern "C" __declspec(dllimport) void KeLowerIrql(KIRQL newIrql);

extern "C" __declspec(dllimport) NTSTATUS NtClose(HANDLE handle);

extern "C" __declspec(dllimport) ULONG NTAPI RtlRandomEx(PULONG Seed);

extern "C" __declspec(dllimport) NTSTATUS NTAPI ObCloseHandle(HANDLE Handle,KPROCESSOR_MODE PreviousMode);

extern "C" __declspec(dllimport) VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

extern "C" __declspec(dllimport) NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwQueryObject(HANDLE Handle,OBJECT_INFORMATION_CLASS ObjectInformationClass,PVOID ObjectInformation,ULONG ObjectInformationLength,PULONG ReturnLength);

extern "C" __declspec(dllimport) int __cdecl _snprintf(char*, size_t, const char*, ...);

extern "C" __declspec(dllimport) NTSTATUS ObReferenceObjectByHandle(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID * Object, POBJECT_HANDLE_INFORMATION HandleInformation);
extern "C" __declspec(dllimport) void ObDereferenceObject(PVOID Object);

extern "C" __declspec(dllimport) KPROCESSOR_MODE ExGetPreviousMode();

extern "C" __declspec(dllimport) ULONG DbgPrint(PCSTR Format);

extern "C" __declspec(dllimport) ULONG RtlGetNtGlobalFlags(VOID);

#define FLG_ENABLE_CLOSE_EXCEPTIONS 0x00400000
enum class LiveKernelDumpFlags : ULONG {
    KernelPages = 0,
    UserAndKernelPages = 1,
    MiniDump = 2,
    HyperVAndKernelPages = 4,
    UserAndHyperVAndKernelPages = 5 // UserAndKernelPages & HyperVAndKernelPages
};

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

// C:\Windows\LiveKernelReports OR path within HKLM\system\currentcontrolset\control\crashcontrol\livekernelreports
// ComponentName: Name of folder created in report directory
// BugCheckCode: Code shown to user in the generated .dmp file when loaded in windbg
// P1 - P4 arbitrary parameters, shown to user as BUGCHECK_P1-... in the generated .dmp file when loaded in windbg
extern "C" __declspec(dllimport) void NTAPI DbgkWerCaptureLiveKernelDump(const wchar_t* ComponentName, ULONG BugCheckCode, ULONG_PTR P1, ULONG_PTR P2, ULONG_PTR P3, ULONG_PTR P4, LiveKernelDumpFlags flags);