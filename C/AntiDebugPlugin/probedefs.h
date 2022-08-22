#pragma once
#include "utils.h"
#include "phantom_type.h"
#include "magic_enum.hpp"

#include <string_view>

enum PROBE_IDS : ULONG64 {
    IdLockProductActivationKeys = 0,
    IdWaitHighEventPair = 1,
    IdRegisterThreadTerminatePort = 2,
    IdAssociateWaitCompletionPacket = 3,
    IdQueryPerformanceCounter = 4,
    IdCompactKeys = 5,
    IdQuerySystemInformationEx = 6,
    IdResetEvent = 7,
    IdGetContextThread = 8,
    IdQueryInformationThread = 9,
    IdWaitForSingleObject = 10,
    IdFlushBuffersFileEx = 11,
    IdUnloadKey2 = 12,
    IdReadOnlyEnlistment = 13,
    IdDeleteFile = 14,
    IdDeleteAtom = 15,
    IdQueryDirectoryFile = 16,
    IdSetEventBoostPriority = 17,
    IdAllocateUserPhysicalPagesEx = 18,
    IdWriteFile = 19,
    IdQueryInformationFile = 20,
    IdAlpcCancelMessage = 21,
    IdOpenMutant = 22,
    IdCreatePartition = 23,
    IdQueryTimer = 24,
    IdOpenEvent = 25,
    IdOpenObjectAuditAlarm = 26,
    IdMakePermanentObject = 27,
    IdCommitTransaction = 28,
    IdSetSystemTime = 29,
    IdGetDevicePowerState = 30,
    IdSetSystemPowerState = 31,
    IdAlpcCreateResourceReserve = 32,
    IdUnlockFile = 33,
    IdAlpcDeletePortSection = 34,
    IdSetInformationResourceManager = 35,
    IdFreeUserPhysicalPages = 36,
    IdLoadKeyEx = 37,
    IdPropagationComplete = 38,
    IdAccessCheckByTypeResultListAndAuditAlarm = 39,
    IdQueryInformationToken = 40,
    IdRegisterProtocolAddressInformation = 41,
    IdProtectVirtualMemory = 42,
    IdCreateKey = 43,
    IdAlpcSendWaitReceivePort = 44,
    IdOpenRegistryTransaction = 45,
    IdTerminateProcess = 46,
    IdPowerInformation = 47,
    IdotifyChangeDirectoryFile = 48,
    IdCreateTransaction = 49,
    IdCreateProfileEx = 50,
    IdQueryLicenseValue = 51,
    IdCreateProfile = 52,
    IdInitializeRegistry = 53,
    IdFreezeTransactions = 54,
    IdOpenJobObject = 55,
    IdSubscribeWnfStateChange = 56,
    IdGetWriteWatch = 57,
    IdGetCachedSigningLevel = 58,
    IdSetSecurityObject = 59,
    IdQueryIntervalProfile = 60,
    IdPropagationFailed = 61,
    IdCreateSectionEx = 62,
    IdRaiseException = 63,
    IdSetCachedSigningLevel2 = 64,
    IdCommitEnlistment = 65,
    IdQueryInformationByName = 66,
    IdCreateThread = 67,
    IdOpenResourceManager = 68,
    IdReadRequestData = 69,
    IdClearEvent = 70,
    IdTestAlert = 71,
    IdSetInformationThread = 72,
    IdSetTimer2 = 73,
    IdSetDefaultUILanguage = 74,
    IdEnumerateValueKey = 75,
    IdOpenEnlistment = 76,
    IdSetIntervalProfile = 77,
    IdQueryPortInformationProcess = 78,
    IdQueryInformationTransactionManager = 79,
    IdSetInformationTransactionManager = 80,
    IdInitializeEnclave = 81,
    IdPrepareComplete = 82,
    IdQueueApcThread = 83,
    IdWorkerFactoryWorkerReady = 84,
    IdGetCompleteWnfStateSubscription = 85,
    IdAlertThreadByThreadId = 86,
    IdLockVirtualMemory = 87,
    IdDeviceIoControlFile = 88,
    IdCreateUserProcess = 89,
    IdQuerySection = 90,
    IdSaveKeyEx = 91,
    IdRollbackTransaction = 92,
    IdTraceEvent = 93,
    IdOpenSection = 94,
    IdRequestPort = 95,
    IdUnsubscribeWnfStateChange = 96,
    IdThawRegistry = 97,
    IdCreateJobObject = 98,
    IdOpenKeyTransactedEx = 99,
    IdWaitForMultipleObjects = 100,
    IdDuplicateToken = 101,
    IdAlpcOpenSenderThread = 102,
    IdAlpcImpersonateClientContainerOfPort = 103,
    IdDrawText = 104,
    IdReleaseSemaphore = 105,
    IdSetQuotaInformationFile = 106,
    IdQueryInformationAtom = 107,
    IdEnumerateBootEntries = 108,
    IdThawTransactions = 109,
    IdAccessCheck = 110,
    IdFlushProcessWriteBuffers = 111,
    IdQuerySemaphore = 112,
    IdCreateNamedPipeFile = 113,
    IdAlpcDeleteResourceReserve = 114,
    IdQuerySystemEnvironmentValueEx = 115,
    IdReadFileScatter = 116,
    IdOpenKeyEx = 117,
    IdSignalAndWaitForSingleObject = 118,
    IdReleaseMutant = 119,
    IdTerminateJobObject = 120,
    IdSetSystemEnvironmentValue = 121,
    IdClose = 122,
    IdQueueApcThreadEx = 123,
    IdQueryMultipleValueKey = 124,
    IdAlpcQueryInformation = 125,
    IdUpdateWnfStateData = 126,
    IdListenPort = 127,
    IdFlushInstructionCache = 128,
    IdGetNotificationResourceManager = 129,
    IdQueryFullAttributesFile = 130,
    IdSuspendThread = 131,
    IdCompareTokens = 132,
    IdCancelWaitCompletionPacket = 133,
    IdAlpcAcceptConnectPort = 134,
    IdOpenTransaction = 135,
    IdImpersonateAnonymousToken = 136,
    IdQuerySecurityObject = 137,
    IdRollbackEnlistment = 138,
    IdReplacePartitionUnit = 139,
    IdCreateKeyTransacted = 140,
    IdConvertBetweenAuxiliaryCounterAndPerformanceCounter = 141,
    IdCreateKeyedEvent = 142,
    IdCreateEventPair = 143,
    IdAddAtom = 144,
    IdQueryOpenSubKeys = 145,
    IdQuerySystemTime = 146,
    IdSetEaFile = 147,
    IdSetInformationProcess = 148,
    IdSetValueKey = 149,
    IdQuerySymbolicLinkObject = 150,
    IdQueryOpenSubKeysEx = 151,
    IdotifyChangeKey = 152,
    IdIsProcessInJob = 153,
    IdCommitComplete = 154,
    IdEnumerateDriverEntries = 155,
    IdAccessCheckByTypeResultList = 156,
    IdLoadEnclaveData = 157,
    IdAllocateVirtualMemoryEx = 158,
    IdWaitForWorkViaWorkerFactory = 159,
    IdQueryInformationResourceManager = 160,
    IdEnumerateKey = 161,
    IdGetMUIRegistryInfo = 162,
    IdAcceptConnectPort = 163,
    IdRecoverTransactionManager = 164,
    IdWriteVirtualMemory = 165,
    IdQueryBootOptions = 166,
    IdRollbackComplete = 167,
    IdQueryAuxiliaryCounterFrequency = 168,
    IdAlpcCreatePortSection = 169,
    IdQueryObject = 170,
    IdQueryWnfStateData = 171,
    IdInitiatePowerAction = 172,
    IdDirectGraphicsCall = 173,
    IdAcquireCrossVmMutant = 174,
    IdRollbackRegistryTransaction = 175,
    IdAlertResumeThread = 176,
    IdPssCaptureVaSpaceBulk = 177,
    IdCreateToken = 178,
    IdPrepareEnlistment = 179,
    IdFlushWriteBuffer = 180,
    IdCommitRegistryTransaction = 181,
    IdAccessCheckByType = 182,
    IdOpenThread = 183,
    IdAccessCheckAndAuditAlarm = 184,
    IdOpenThreadTokenEx = 185,
    IdWriteRequestData = 186,
    IdCreateWorkerFactory = 187,
    IdOpenPartition = 188,
    IdSetSystemInformation = 189,
    IdEnumerateSystemEnvironmentValuesEx = 190,
    IdCreateWnfStateName = 191,
    IdQueryInformationJobObject = 192,
    IdPrivilegedServiceAuditAlarm = 193,
    IdEnableLastKnownGood = 194,
    IdotifyChangeDirectoryFileEx = 195,
    IdCreateWaitablePort = 196,
    IdWaitForAlertByThreadId = 197,
    IdGetNextProcess = 198,
    IdOpenKeyedEvent = 199,
    IdDeleteBootEntry = 200,
    IdFilterToken = 201,
    IdCompressKey = 202,
    IdModifyBootEntry = 203,
    IdSetInformationTransaction = 204,
    IdPlugPlayControl = 205,
    IdOpenDirectoryObject = 206,
    IdContinue = 207,
    IdPrivilegeObjectAuditAlarm = 208,
    IdQueryKey = 209,
    IdFilterBootOption = 210,
    IdYieldExecution = 211,
    IdResumeThread = 212,
    IdAddBootEntry = 213,
    IdGetCurrentProcessorNumberEx = 214,
    IdCreateLowBoxToken = 215,
    IdFlushBuffersFile = 216,
    IdDelayExecution = 217,
    IdOpenKey = 218,
    IdStopProfile = 219,
    IdSetEvent = 220,
    IdRestoreKey = 221,
    IdExtendSection = 222,
    IdInitializeNlsFiles = 223,
    IdFindAtom = 224,
    IdDisplayString = 225,
    IdLoadDriver = 226,
    IdQueryWnfStateNameInformation = 227,
    IdCreateMutant = 228,
    IdFlushKey = 229,
    IdDuplicateObject = 230,
    IdCancelTimer2 = 231,
    IdQueryAttributesFile = 232,
    IdCompareSigningLevels = 233,
    IdAccessCheckByTypeResultListAndAuditAlarmByHandle = 234,
    IdDeleteValueKey = 235,
    IdSetDebugFilterState = 236,
    IdPulseEvent = 237,
    IdAllocateReserveObject = 238,
    IdAlpcDisconnectPort = 239,
    IdQueryTimerResolution = 240,
    IdDeleteKey = 241,
    IdCreateFile = 242,
    IdReplyPort = 243,
    IdGetNlsSectionPtr = 244,
    IdQueryInformationProcess = 245,
    IdReplyWaitReceivePortEx = 246,
    IdUmsThreadYield = 247,
    IdManagePartition = 248,
    IdAdjustPrivilegesToken = 249,
    IdCreateCrossVmMutant = 250,
    IdCreateDirectoryObject = 251,
    IdOpenFile = 252,
    IdSetInformationVirtualMemory = 253,
    IdTerminateEnclave = 254,
    IdSuspendProcess = 255,
    IdReplyWaitReplyPort = 256,
    IdOpenTransactionManager = 257,
    IdCreateSemaphore = 258,
    IdUnmapViewOfSectionEx = 259,
    IdMapViewOfSection = 260,
    IdDisableLastKnownGood = 261,
    IdGetNextThread = 262,
    IdMakeTemporaryObject = 263,
    IdSetInformationFile = 264,
    IdCreateTransactionManager = 265,
    IdWriteFileGather = 266,
    IdQueryInformationTransaction = 267,
    IdFlushVirtualMemory = 268,
    IdQueryQuotaInformationFile = 269,
    IdSetVolumeInformationFile = 270,
    IdQueryInformationEnlistment = 271,
    IdCreateIoCompletion = 272,
    IdUnloadKeyEx = 273,
    IdQueryEaFile = 274,
    IdQueryDirectoryObject = 275,
    IdAddAtomEx = 276,
    IdSinglePhaseReject = 277,
    IdDeleteWnfStateName = 278,
    IdSetSystemEnvironmentValueEx = 279,
    IdContinueEx = 280,
    IdUnloadDriver = 281,
    IdCallEnclave = 282,
    IdCancelIoFileEx = 283,
    IdSetTimer = 284,
    IdQuerySystemEnvironmentValue = 285,
    IdOpenThreadToken = 286,
    IdMapUserPhysicalPagesScatter = 287,
    IdCreateResourceManager = 288,
    IdUnlockVirtualMemory = 289,
    IdQueryInformationPort = 290,
    IdSetLowEventPair = 291,
    IdSetInformationKey = 292,
    IdQuerySecurityPolicy = 293,
    IdOpenProcessToken = 294,
    IdQueryVolumeInformationFile = 295,
    IdOpenTimer = 296,
    IdMapUserPhysicalPages = 297,
    IdLoadKey = 298,
    IdCreateWaitCompletionPacket = 299,
    IdReleaseWorkerFactoryWorker = 300,
    IdPrePrepareComplete = 301,
    IdReadVirtualMemory = 302,
    IdFreeVirtualMemory = 303,
    IdSetDriverEntryOrder = 304,
    IdReadFile = 305,
    IdTraceControl = 306,
    IdOpenProcessTokenEx = 307,
    IdSecureConnectPort = 308,
    IdSaveKey = 309,
    IdSetDefaultHardErrorPort = 310,
    IdCreateEnclave = 311,
    IdOpenPrivateNamespace = 312,
    IdSetLdtEntries = 313,
    IdResetWriteWatch = 314,
    IdRenameKey = 315,
    IdRevertContainerImpersonation = 316,
    IdAlpcCreateSectionView = 317,
    IdCreateCrossVmEvent = 318,
    IdImpersonateThread = 319,
    IdSetIRTimer = 320,
    IdCreateDirectoryObjectEx = 321,
    IdAcquireProcessActivityReference = 322,
    IdReplaceKey = 323,
    IdStartProfile = 324,
    IdQueryBootEntryOrder = 325,
    IdLockRegistryKey = 326,
    IdImpersonateClientOfPort = 327,
    IdQueryEvent = 328,
    IdFsControlFile = 329,
    IdOpenProcess = 330,
    IdSetIoCompletion = 331,
    IdConnectPort = 332,
    IdCloseObjectAuditAlarm = 333,
    IdRequestWaitReplyPort = 334,
    IdSetInformationObject = 335,
    IdPrivilegeCheck = 336,
    IdCallbackReturn = 337,
    IdSetInformationToken = 338,
    IdSetUuidSeed = 339,
    IdOpenKeyTransacted = 340,
    IdAlpcDeleteSecurityContext = 341,
    IdSetBootOptions = 342,
    IdManageHotPatch = 343,
    IdEnumerateTransactionObject = 344,
    IdSetThreadExecutionState = 345,
    IdWaitLowEventPair = 346,
    IdSetHighWaitLowEventPair = 347,
    IdQueryInformationWorkerFactory = 348,
    IdSetWnfProcessNotificationEvent = 349,
    IdAlpcDeleteSectionView = 350,
    IdCreateMailslotFile = 351,
    IdCreateProcess = 352,
    IdQueryIoCompletion = 353,
    IdCreateTimer = 354,
    IdFlushInstallUILanguage = 355,
    IdCompleteConnectPort = 356,
    IdAlpcConnectPort = 357,
    IdFreezeRegistry = 358,
    IdMapCMFModule = 359,
    IdAllocateUserPhysicalPages = 360,
    IdSetInformationEnlistment = 361,
    IdRaiseHardError = 362,
    IdCreateSection = 363,
    IdOpenIoCompletion = 364,
    IdSystemDebugControl = 365,
    IdTranslateFilePath = 366,
    IdCreateIRTimer = 367,
    IdCreateRegistryTransaction = 368,
    IdLoadKey2 = 369,
    IdAlpcCreatePort = 370,
    IdDeleteWnfStateData = 371,
    IdSetTimerEx = 372,
    IdSetLowWaitHighEventPair = 373,
    IdAlpcCreateSecurityContext = 374,
    IdSetCachedSigningLevel = 375,
    IdSetHighEventPair = 376,
    IdShutdownWorkerFactory = 377,
    IdSetInformationJobObject = 378,
    IdAdjustGroupsToken = 379,
    IdAreMappedFilesTheSame = 380,
    IdSetBootEntryOrder = 381,
    IdQueryMutant = 382,
    IdotifyChangeSession = 383,
    IdQueryDefaultLocale = 384,
    IdCreateThreadEx = 385,
    IdQueryDriverEntryOrder = 386,
    IdSetTimerResolution = 387,
    IdPrePrepareEnlistment = 388,
    IdCancelSynchronousIoFile = 389,
    IdQueryDirectoryFileEx = 390,
    IdAddDriverEntry = 391,
    IdUnloadKey = 392,
    IdCreateEvent = 393,
    IdOpenSession = 394,
    IdQueryValueKey = 395,
    IdCreatePrivateNamespace = 396,
    IdIsUILanguageComitted = 397,
    IdAlertThread = 398,
    IdQueryInstallUILanguage = 399,
    IdCreateSymbolicLinkObject = 400,
    IdAllocateUuids = 401,
    IdShutdownSystem = 402,
    IdCreateTokenEx = 403,
    IdQueryVirtualMemory = 404,
    IdAlpcOpenSenderProcess = 405,
    IdAssignProcessToJobObject = 406,
    IdRemoveIoCompletion = 407,
    IdCreateTimer2 = 408,
    IdCreateEnlistment = 409,
    IdRecoverEnlistment = 410,
    IdCreateJobSet = 411,
    IdSetIoCompletionEx = 412,
    IdCreateProcessEx = 413,
    IdAlpcConnectPortEx = 414,
    IdWaitForMultipleObjects32 = 415,
    IdRecoverResourceManager = 416,
    IdAlpcSetInformation = 417,
    IdAlpcRevokeSecurityContext = 418,
    IdAlpcImpersonateClientOfPort = 419,
    IdReleaseKeyedEvent = 420,
    IdTerminateThread = 421,
    IdSetInformationSymbolicLink = 422,
    IdDeleteObjectAuditAlarm = 423,
    IdWaitForKeyedEvent = 424,
    IdCreatePort = 425,
    IdDeletePrivateNamespace = 426,
    IdotifyChangeMultipleKeys = 427,
    IdLockFile = 428,
    IdQueryDefaultUILanguage = 429,
    IdOpenEventPair = 430,
    IdRollforwardTransactionManager = 431,
    IdAlpcQueryInformationMessage = 432,
    IdUnmapViewOfSection = 433,
    IdCancelIoFile = 434,
    IdCreatePagingFile = 435,
    IdCancelTimer = 436,
    IdReplyWaitReceivePort = 437,
    IdCompareObjects = 438,
    IdSetDefaultLocale = 439,
    IdAllocateLocallyUniqueId = 440,
    IdAccessCheckByTypeAndAuditAlarm = 441,
    IdQueryDebugFilterState = 442,
    IdOpenSemaphore = 443,
    IdAllocateVirtualMemory = 444,
    IdResumeProcess = 445,
    IdSetContextThread = 446,
    IdOpenSymbolicLinkObject = 447,
    IdModifyDriverEntry = 448,
    IdSerializeBoot = 449,
    IdRenameTransactionManager = 450,
    IdRemoveIoCompletionEx = 451,
    IdMapViewOfSectionEx = 452,
    IdFilterTokenEx = 453,
    IdDeleteDriverEntry = 454,
    IdQuerySystemInformation = 455,
    IdSetInformationWorkerFactory = 456,
    IdAdjustTokenClaimsAndDeviceGroups = 457,
    IdSaveMergedKeys = 458
};

// To print types that alias to other types (via say c++ typedef), we have to define 'stronger' typedefs.
// In C++ typedefs alias to other types, and this makes it so that TYPE1 === TYPE2 in a template. We don't want this.
// For TYPE1 !== TYPE2 to occur, a 'strong typedef' must be created. This is done below for types printed in the log, the struct mimics the underlying type.
// Don't actually use these types, instead use them in combination with get_type_id - etc only
strong_typedef(DWORD, MY_ACCESS_MASK);
strong_typedef(PVOID, MY_HANDLE);
strong_typedef(MY_HANDLE*, MY_PHANDLE);
strong_typedef(BYTE, MY_BOOLEAN);
strong_typedef(MY_BOOLEAN*, MY_PBOOLEAN);

typedef struct _MEMORY_RANGE_ENTRY {
    PVOID VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

strong_typedef(PVOID, MY_PIO_APC_ROUTINE);
strong_typedef(UINT32, MY_KPROFILE_SOURCE);
strong_typedef(PVOID, MY_PCWNF_STATE_NAME);
strong_typedef(PVOID, MY_PCLIENT_ID);
strong_typedef(UINT32, MY_THREADINFOCLASS);
strong_typedef(UINT32, MY_KEY_VALUE_INFORMATION_CLASS);
strong_typedef(PVOID, MY_PWNF_STATE_NAME);
strong_typedef(UINT32, MY_WAIT_TYPE);
strong_typedef(PVOID, MY_PKEY_VALUE_ENTRY);
strong_typedef(UINT32, MY_LOGICAL);
strong_typedef(PVOID, MY_PFILE_NETWORK_OPEN_INFORMATION);
strong_typedef(UINT32, MY_PROCESSINFOCLASS);
strong_typedef(UINT32, MY_KEY_INFORMATION_CLASS);
strong_typedef(UINT32, MY_DIRECTORY_NOTIFY_INFORMATION_CLASS);
strong_typedef(PVOID, MY_PFILE_BASIC_INFORMATION);
strong_typedef(UINT32, MY_VIRTUAL_MEMORY_INFORMATION_CLASS);
strong_typedef(PMEMORY_RANGE_ENTRY, MY_PMEMORY_RANGE_ENTRY);
strong_typedef(UINT32, MY_SECTION_INHERIT);
strong_typedef(UINT32, MY_FS_INFORMATION_CLASS);
strong_typedef(PVOID, MY_PTIMER_APC_ROUTINE);
strong_typedef(UINT32, MY_KEY_SET_INFORMATION_CLASS);
strong_typedef(UINT32, MY_TIMER_TYPE);
strong_typedef(UINT32, MY_TIMER_SET_INFORMATION_CLASS);
strong_typedef(UINT32, MY_IO_SESSION_EVENT);
strong_typedef(UINT32, MY_IO_SESSION_STATE);
strong_typedef(UINT32, MY_EVENT_TYPE);
strong_typedef(UINT32, MY_MEMORY_INFORMATION_CLASS);
strong_typedef(UINT32, MY_TOKENINFOCLASS);

// Literally magic here. Enum value to const char* string at compile time w/o lookup table.
// Always null terminated. This compiles as a lookup table in the data section.
template<typename ENUM_TYPE>
const char* get_enum_value_name(auto enum_val) {
    // allow integers as input, cast here
    auto name = magic_enum::enum_name((ENUM_TYPE)enum_val);
    if (name.length() == 0) {
        return "UNKNOWN_ENUM_VAL";
    }
    return name.data(); // safe, returns pointer view holds
}

enum class VIRTUAL_MEMORY_INFORMATION_CLASS
{
    VmPrefetchInformation, // ULONG
    VmPagePriorityInformation, // OFFER_PRIORITY
    VmCfgCallTargetInformation, // CFG_CALL_TARGET_LIST_INFORMATION // REDSTONE2
    VmPageDirtyStateInformation, // REDSTONE3
    VmImageHotPatchInformation, // 19H1
    VmPhysicalContiguityInformation, // 20H1
    VmVirtualMachinePrepopulateInformation,
    VmRemoveFromWorkingSetInformation,
    MaxVmInfoClass
};

enum class PROCESSINFOCLASS : UINT32
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // qs: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement 
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // 80
    ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures,
    ProcessAltPrefetchParam, // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx,
    ProcessMembershipInformation,
    ProcessEffectiveIoPriority,
    ProcessEffectivePagePriority,
    MaxProcessInfoClass
};

enum class TOKEN_INFO_CLASS : UINT32
{
    TokenNULL,
    TokenUser, // q: TOKEN_USER
    TokenGroups, // q: TOKEN_GROUPS
    TokenPrivileges, // q: TOKEN_PRIVILEGES
    TokenOwner, // q; s: TOKEN_OWNER
    TokenPrimaryGroup, // q; s: TOKEN_PRIMARY_GROUP
    TokenDefaultDacl, // q; s: TOKEN_DEFAULT_DACL
    TokenSource, // q: TOKEN_SOURCE
    TokenType, // q: TOKEN_TYPE
    TokenImpersonationLevel, // q: SECURITY_IMPERSONATION_LEVEL
    TokenStatistics, // q: TOKEN_STATISTICS // 10
    TokenRestrictedSids, // q: TOKEN_GROUPS
    TokenSessionId, // q; s: ULONG (requires SeTcbPrivilege)
    TokenGroupsAndPrivileges, // q: TOKEN_GROUPS_AND_PRIVILEGES
    TokenSessionReference, // s: ULONG (requires SeTcbPrivilege)
    TokenSandBoxInert, // q: ULONG
    TokenAuditPolicy, // q; s: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
    TokenOrigin, // q; s: TOKEN_ORIGIN (requires SeTcbPrivilege)
    TokenElevationType, // q: TOKEN_ELEVATION_TYPE
    TokenLinkedToken, // q; s: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
    TokenElevation, // q: TOKEN_ELEVATION // 20
    TokenHasRestrictions, // q: ULONG
    TokenAccessInformation, // q: TOKEN_ACCESS_INFORMATION
    TokenVirtualizationAllowed, // q; s: ULONG (requires SeCreateTokenPrivilege)
    TokenVirtualizationEnabled, // q; s: ULONG
    TokenIntegrityLevel, // q; s: TOKEN_MANDATORY_LABEL
    TokenUIAccess, // q; s: ULONG
    TokenMandatoryPolicy, // q; s: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
    TokenLogonSid, // q: TOKEN_GROUPS
    TokenIsAppContainer, // q: ULONG
    TokenCapabilities, // q: TOKEN_GROUPS // 30
    TokenAppContainerSid, // q: TOKEN_APPCONTAINER_INFORMATION
    TokenAppContainerNumber, // q: ULONG
    TokenUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenRestrictedUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenDeviceGroups, // q: TOKEN_GROUPS
    TokenRestrictedDeviceGroups, // q: TOKEN_GROUPS
    TokenSecurityAttributes, // q; s: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION
    TokenIsRestricted, // q: ULONG // 40
    TokenProcessTrustLevel, // q: TOKEN_PROCESS_TRUST_LEVEL
    TokenPrivateNameSpace, // q; s: ULONG
    TokenSingletonAttributes, // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION
    TokenBnoIsolation, // q: TOKEN_BNO_ISOLATION_INFORMATION
    TokenChildProcessFlags, // s: ULONG
    TokenIsLessPrivilegedAppContainer, // q: ULONG
    TokenIsSandboxed, // q: ULONG
    TokenIsAppSilo, // TokenOriginatingProcessTrustLevel // q: TOKEN_PROCESS_TRUST_LEVEL
    MaxTokenInfoClass,
};

enum class THREADINFOCLASS : UINT32
{
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority, // s: KPRIORITY
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
    ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress, // s: ULONG_PTR 
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // q: BOOLEAN; s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated, // q: ULONG // 20
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority, // q: ULONG
    ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context, // qs: WOW64_CONTEXT
    ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
    ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
    ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount, // q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, // q: GUID
    ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
    ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
    ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE
    ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange, // since WIN11
    ThreadApplyStateChange,
    ThreadStrongerBadHandleChecks, // since 22H1
    ThreadEffectiveIoPriority,
    ThreadEffectivePagePriority,
    MaxThreadInfoClass
};

typedef NTSTATUS(NTAPI* tLockProductActivationKeys) (UINT32*, UINT32*);
typedef NTSTATUS(NTAPI* tWaitHighEventPair) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tRegisterThreadTerminatePort) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tAssociateWaitCompletionPacket) (MY_HANDLE, MY_HANDLE, MY_HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tQueryPerformanceCounter) (PLARGE_INTEGER, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tCompactKeys) (ULONG, void**);
typedef NTSTATUS(NTAPI* tQuerySystemInformationEx) (UINT32, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tResetEvent) (MY_HANDLE, PLONG);
typedef NTSTATUS(NTAPI* tGetContextThread) (MY_HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* tQueryInformationThread) (MY_HANDLE, UINT32, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tWaitForSingleObject) (MY_HANDLE, MY_BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tFlushBuffersFileEx) (MY_HANDLE, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK);
typedef NTSTATUS(NTAPI* tUnloadKey2) (POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI* tReadOnlyEnlistment) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tDeleteFile) (POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tDeleteAtom) (UINT32);
typedef NTSTATUS(NTAPI* tQueryDirectoryFile) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, MY_BOOLEAN, PUNICODE_STRING, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tSetEventBoostPriority) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tAllocateUserPhysicalPagesEx) (MY_HANDLE, PULONG_PTR, PULONG_PTR,/*Unknown*/ void*, ULONG);
typedef NTSTATUS(NTAPI* tWriteFile) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* tQueryInformationFile) (MY_HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* tAlpcCancelMessage) (MY_HANDLE, ULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tOpenMutant) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tCreatePartition) (MY_HANDLE, MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tQueryTimer) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tOpenEvent) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tOpenObjectAuditAlarm) (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, MY_HANDLE, MY_ACCESS_MASK, MY_ACCESS_MASK, PPRIVILEGE_SET, MY_BOOLEAN, MY_BOOLEAN, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tMakePermanentObject) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tCommitTransaction) (MY_HANDLE, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tSetSystemTime) (PLARGE_INTEGER, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tGetDevicePowerState) (MY_HANDLE, PDEVICE_POWER_STATE);
typedef NTSTATUS(NTAPI* tSetSystemPowerState) (UINT32, SYSTEM_POWER_STATE, ULONG);
typedef NTSTATUS(NTAPI* tAlpcCreateResourceReserve) (MY_HANDLE, ULONG, SIZE_T, PULONG);
typedef NTSTATUS(NTAPI* tUnlockFile) (MY_HANDLE, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG);
typedef NTSTATUS(NTAPI* tAlpcDeletePortSection) (MY_HANDLE, ULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tSetInformationResourceManager) (MY_HANDLE, RESOURCEMANAGER_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tFreeUserPhysicalPages) (MY_HANDLE, PULONG_PTR, PULONG_PTR);
typedef NTSTATUS(NTAPI* tLoadKeyEx) (POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, MY_HANDLE, MY_HANDLE, MY_ACCESS_MASK, MY_PHANDLE, PIO_STATUS_BLOCK);
typedef NTSTATUS(NTAPI* tPropagationComplete) (MY_HANDLE, ULONG, ULONG, PVOID);
typedef NTSTATUS(NTAPI* tAccessCheckByTypeResultListAndAuditAlarm) (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, MY_ACCESS_MASK, AUDIT_EVENT_TYPE, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, MY_BOOLEAN, PACCESS_MASK, PNTSTATUS, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tQueryInformationToken) (MY_HANDLE, MY_TOKENINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tRegisterProtocolAddressInformation) (MY_HANDLE, PCRM_PROTOCOL_ID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tProtectVirtualMemory) (MY_HANDLE, void**, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tCreateKey) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tAlpcSendWaitReceivePort) (MY_HANDLE, ULONG,/*Unknown*/ void*,/*Unknown*/ void*,/*Unknown*/ void*, PSIZE_T,/*Unknown*/ void*, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tOpenRegistryTransaction) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tTerminateProcess) (MY_HANDLE, NTSTATUS);
typedef NTSTATUS(NTAPI* tPowerInformation) (UINT32, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* totifyChangeDirectoryFile) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tCreateTransaction) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, MY_HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tCreateProfileEx) (MY_PHANDLE, MY_HANDLE, PVOID, SIZE_T, ULONG, PULONG, ULONG, MY_KPROFILE_SOURCE, USHORT, PGROUP_AFFINITY);
typedef NTSTATUS(NTAPI* tQueryLicenseValue) (PUNICODE_STRING, PULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tCreateProfile) (MY_PHANDLE, MY_HANDLE, PVOID, SIZE_T, ULONG, PULONG, ULONG, MY_KPROFILE_SOURCE, KAFFINITY);
typedef NTSTATUS(NTAPI* tInitializeRegistry) (USHORT);
typedef NTSTATUS(NTAPI* tFreezeTransactions) (PLARGE_INTEGER, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tOpenJobObject) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tSubscribeWnfStateChange) (MY_PCWNF_STATE_NAME,/*Unknown*/ void*, ULONG, PULONG64);
typedef NTSTATUS(NTAPI* tGetWriteWatch) (MY_HANDLE, ULONG, PVOID, SIZE_T, void**, PULONG_PTR, PULONG);
typedef NTSTATUS(NTAPI* tGetCachedSigningLevel) (MY_HANDLE, PULONG, PSE_SIGNING_LEVEL, PUCHAR, PULONG, PULONG);
typedef NTSTATUS(NTAPI* tSetSecurityObject) (MY_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
typedef NTSTATUS(NTAPI* tQueryIntervalProfile) (MY_KPROFILE_SOURCE, PULONG);
typedef NTSTATUS(NTAPI* tPropagationFailed) (MY_HANDLE, ULONG, NTSTATUS);
typedef NTSTATUS(NTAPI* tCreateSectionEx) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, MY_HANDLE,/*Unknown*/ void*, ULONG);
typedef NTSTATUS(NTAPI* tRaiseException) (PEXCEPTION_RECORD, PCONTEXT, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tSetCachedSigningLevel2) (ULONG, SE_SIGNING_LEVEL, MY_PHANDLE, ULONG, MY_HANDLE,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tCommitEnlistment) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tQueryInformationByName) (POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* tCreateThread) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_HANDLE, MY_PCLIENT_ID, PCONTEXT,/*Unknown*/ void*, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tOpenResourceManager) (MY_PHANDLE, MY_ACCESS_MASK, MY_HANDLE, LPGUID, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tReadRequestData) (MY_HANDLE,/*Unknown*/ void*, ULONG, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tClearEvent)(MY_HANDLE);
typedef NTSTATUS(NTAPI* tTestAlert)();
typedef NTSTATUS(NTAPI* tSetInformationThread) (MY_HANDLE, MY_THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tSetTimer2) (MY_HANDLE, PLARGE_INTEGER, PLARGE_INTEGER,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tSetDefaultUILanguage) (LANGID);
typedef NTSTATUS(NTAPI* tEnumerateValueKey) (MY_HANDLE, ULONG, MY_KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tOpenEnlistment) (MY_PHANDLE, MY_ACCESS_MASK, MY_HANDLE, LPGUID, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tSetIntervalProfile) (ULONG, MY_KPROFILE_SOURCE);
typedef NTSTATUS(NTAPI* tQueryPortInformationProcess)();
typedef NTSTATUS(NTAPI* tQueryInformationTransactionManager) (MY_HANDLE, TRANSACTIONMANAGER_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tSetInformationTransactionManager) (MY_HANDLE, TRANSACTIONMANAGER_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tInitializeEnclave) (MY_HANDLE, PVOID,/*Unknown*/ void*, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tPrepareComplete) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tQueueApcThread) (MY_HANDLE,/*Unknown*/ void*, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* tWorkerFactoryWorkerReady) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tGetCompleteWnfStateSubscription) (MY_PWNF_STATE_NAME, UINT64*, ULONG, ULONG,/*Unknown*/ void*, ULONG);
typedef NTSTATUS(NTAPI* tAlertThreadByThreadId) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tLockVirtualMemory) (MY_HANDLE, void**, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* tDeviceIoControlFile) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tCreateUserProcess) (MY_PHANDLE, MY_PHANDLE, MY_ACCESS_MASK, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID,/*Unknown*/ void*,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tQuerySection) (MY_HANDLE,/*Unknown*/ void*, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tSaveKeyEx) (MY_HANDLE, MY_HANDLE, ULONG);
typedef NTSTATUS(NTAPI* tRollbackTransaction) (MY_HANDLE, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tTraceEvent) (MY_HANDLE, ULONG, ULONG, PVOID);
typedef NTSTATUS(NTAPI* tOpenSection) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tRequestPort) (MY_HANDLE,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tUnsubscribeWnfStateChange) (MY_PCWNF_STATE_NAME);
typedef NTSTATUS(NTAPI* tThawRegistry)();
typedef NTSTATUS(NTAPI* tCreateJobObject) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tOpenKeyTransactedEx) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, MY_HANDLE);
typedef NTSTATUS(NTAPI* tWaitForMultipleObjects) (ULONG, void**, MY_WAIT_TYPE, MY_BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tDuplicateToken) (MY_HANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_BOOLEAN, TOKEN_TYPE, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tAlpcOpenSenderThread) (MY_PHANDLE, MY_HANDLE,/*Unknown*/ void*, ULONG, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tAlpcImpersonateClientContainerOfPort) (MY_HANDLE,/*Unknown*/ void*, ULONG);
typedef NTSTATUS(NTAPI* tDrawText) (PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tReleaseSemaphore) (MY_HANDLE, LONG, PLONG);
typedef NTSTATUS(NTAPI* tSetQuotaInformationFile) (MY_HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tQueryInformationAtom) (UINT32, UINT32, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tEnumerateBootEntries) (PVOID, PULONG);
typedef NTSTATUS(NTAPI* tThawTransactions)();
typedef NTSTATUS(NTAPI* tAccessCheck) (PSECURITY_DESCRIPTOR, MY_HANDLE, MY_ACCESS_MASK, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS);
typedef NTSTATUS(NTAPI* tFlushProcessWriteBuffers)();
typedef NTSTATUS(NTAPI* tQuerySemaphore) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tCreateNamedPipeFile) (MY_PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tAlpcDeleteResourceReserve) (MY_HANDLE, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tQuerySystemEnvironmentValueEx) (PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG);
typedef NTSTATUS(NTAPI* tReadFileScatter) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PFILE_SEGMENT_ELEMENT, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* tOpenKeyEx) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI* tSignalAndWaitForSingleObject) (MY_HANDLE, MY_HANDLE, MY_BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tReleaseMutant) (MY_HANDLE, PLONG);
typedef NTSTATUS(NTAPI* tTerminateJobObject) (MY_HANDLE, NTSTATUS);
typedef NTSTATUS(NTAPI* tSetSystemEnvironmentValue) (PUNICODE_STRING, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tClose) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tQueueApcThreadEx) (MY_HANDLE, MY_HANDLE,/*Unknown*/ void*, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* tQueryMultipleValueKey) (MY_HANDLE, MY_PKEY_VALUE_ENTRY, ULONG, PVOID, PULONG, PULONG);
typedef NTSTATUS(NTAPI* tAlpcQueryInformation) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tUpdateWnfStateData) (MY_PCWNF_STATE_NAME,/*Unknown*/ void*, ULONG,/*Unknown*/ void*, PVOID,/*Unknown*/ void*, MY_LOGICAL);
typedef NTSTATUS(NTAPI* tListenPort) (MY_HANDLE,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tFlushInstructionCache) (MY_HANDLE, PVOID, SIZE_T);
typedef NTSTATUS(NTAPI* tGetNotificationResourceManager) (MY_HANDLE, PTRANSACTION_NOTIFICATION, ULONG, PLARGE_INTEGER, PULONG, ULONG, ULONG_PTR);
typedef NTSTATUS(NTAPI* tQueryFullAttributesFile) (POBJECT_ATTRIBUTES, MY_PFILE_NETWORK_OPEN_INFORMATION);
typedef NTSTATUS(NTAPI* tSuspendThread) (MY_HANDLE, PULONG);
typedef NTSTATUS(NTAPI* tCompareTokens) (MY_HANDLE, MY_HANDLE, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tCancelWaitCompletionPacket) (MY_HANDLE, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tAlpcAcceptConnectPort) (MY_PHANDLE, MY_HANDLE, ULONG, POBJECT_ATTRIBUTES,/*Unknown*/ void*, PVOID,/*Unknown*/ void*,/*Unknown*/ void*, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tOpenTransaction) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, MY_HANDLE);
typedef NTSTATUS(NTAPI* tImpersonateAnonymousToken) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tQuerySecurityObject) (MY_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tRollbackEnlistment) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tReplacePartitionUnit) (PUNICODE_STRING, PUNICODE_STRING, ULONG);
typedef NTSTATUS(NTAPI* tCreateKeyTransacted) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, MY_HANDLE, PULONG);
typedef NTSTATUS(NTAPI* tConvertBetweenAuxiliaryCounterAndPerformanceCounter) (MY_BOOLEAN, PULONG64, PULONG64, PULONG64);
typedef NTSTATUS(NTAPI* tCreateKeyedEvent) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI* tCreateEventPair) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tAddAtom) (PWSTR, ULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tQueryOpenSubKeys) (POBJECT_ATTRIBUTES, PULONG);
typedef NTSTATUS(NTAPI* tQuerySystemTime) (PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tSetEaFile) (MY_HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tSetInformationProcess) (MY_HANDLE, MY_PROCESSINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tSetValueKey) (MY_HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tQuerySymbolicLinkObject) (MY_HANDLE, PUNICODE_STRING, PULONG);
typedef NTSTATUS(NTAPI* tQueryOpenSubKeysEx) (POBJECT_ATTRIBUTES, ULONG, PVOID, PULONG);
typedef NTSTATUS(NTAPI* totifyChangeKey) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, MY_BOOLEAN, PVOID, ULONG, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tIsProcessInJob) (MY_HANDLE, MY_HANDLE);
typedef NTSTATUS(NTAPI* tCommitComplete) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tEnumerateDriverEntries) (PVOID, PULONG);
typedef NTSTATUS(NTAPI* tAccessCheckByTypeResultList) (PSECURITY_DESCRIPTOR, PSID, MY_HANDLE, MY_ACCESS_MASK, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS);
typedef NTSTATUS(NTAPI* tLoadEnclaveData) (MY_HANDLE, PVOID,/*Unknown*/ void*, SIZE_T, ULONG,/*Unknown*/ void*, ULONG, PSIZE_T, PULONG);
typedef NTSTATUS(NTAPI* tAllocateVirtualMemoryEx) (MY_HANDLE, void**, PSIZE_T, ULONG, ULONG,/*Unknown*/ void*, ULONG);
typedef NTSTATUS(NTAPI* tWaitForWorkViaWorkerFactory) (MY_HANDLE,/*Unknown*/ void*, ULONG, PULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tQueryInformationResourceManager) (MY_HANDLE, RESOURCEMANAGER_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tEnumerateKey) (MY_HANDLE, ULONG, MY_KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tGetMUIRegistryInfo) (ULONG, UINT32*, PVOID);
typedef NTSTATUS(NTAPI* tAcceptConnectPort) (MY_PHANDLE, PVOID,/*Unknown*/ void*, MY_BOOLEAN,/*Unknown*/ void*,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tRecoverTransactionManager) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tWriteVirtualMemory) (MY_HANDLE, PVOID,/*Unknown*/ void*, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tQueryBootOptions) (UINT32, PULONG);
typedef NTSTATUS(NTAPI* tRollbackComplete) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tQueryAuxiliaryCounterFrequency) (PULONG64);
typedef NTSTATUS(NTAPI* tAlpcCreatePortSection) (MY_HANDLE, ULONG, MY_HANDLE, SIZE_T,/*Unknown*/ void*, PSIZE_T);
typedef NTSTATUS(NTAPI* tQueryObject) (MY_HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tQueryWnfStateData) (MY_PCWNF_STATE_NAME,/*Unknown*/ void*,/*Unknown*/ void*,/*Unknown*/ void*, PVOID, PULONG);
typedef NTSTATUS(NTAPI* tInitiatePowerAction) (UINT32, SYSTEM_POWER_STATE, ULONG, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tDirectGraphicsCall) (ULONG, PVOID, ULONG, PVOID, PULONG);
typedef NTSTATUS(NTAPI* tAcquireCrossVmMutant) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tRollbackRegistryTransaction) (MY_HANDLE, ULONG);
typedef NTSTATUS(NTAPI* tAlertResumeThread) (MY_HANDLE, PULONG);
typedef NTSTATUS(NTAPI* tPssCaptureVaSpaceBulk) (MY_HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tCreateToken) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, TOKEN_TYPE, PLUID, PLARGE_INTEGER, PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_OWNER, PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PTOKEN_SOURCE);
typedef NTSTATUS(NTAPI* tPrepareEnlistment) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tFlushWriteBuffer)();
typedef NTSTATUS(NTAPI* tCommitRegistryTransaction) (MY_HANDLE, ULONG);
typedef NTSTATUS(NTAPI* tAccessCheckByType) (PSECURITY_DESCRIPTOR, PSID, MY_HANDLE, MY_ACCESS_MASK, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS);
typedef NTSTATUS(NTAPI* tOpenThread) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_PCLIENT_ID);
typedef NTSTATUS(NTAPI* tAccessCheckAndAuditAlarm) (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, MY_ACCESS_MASK, PGENERIC_MAPPING, MY_BOOLEAN, PACCESS_MASK, PNTSTATUS, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tOpenThreadTokenEx) (MY_HANDLE, MY_ACCESS_MASK, MY_BOOLEAN, ULONG, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tWriteRequestData) (MY_HANDLE,/*Unknown*/ void*, ULONG, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tCreateWorkerFactory) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_HANDLE, MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, SIZE_T, SIZE_T);
typedef NTSTATUS(NTAPI* tOpenPartition) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tSetSystemInformation) (UINT32, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tEnumerateSystemEnvironmentValuesEx) (ULONG, PVOID, PULONG);
typedef NTSTATUS(NTAPI* tCreateWnfStateName) (MY_PWNF_STATE_NAME,/*Unknown*/ void*,/*Unknown*/ void*, MY_BOOLEAN,/*Unknown*/ void*, ULONG, PSECURITY_DESCRIPTOR);
typedef NTSTATUS(NTAPI* tQueryInformationJobObject) (MY_HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tPrivilegedServiceAuditAlarm) (PUNICODE_STRING, PUNICODE_STRING, MY_HANDLE, PPRIVILEGE_SET, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tEnableLastKnownGood)();
typedef NTSTATUS(NTAPI* totifyChangeDirectoryFileEx) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, MY_BOOLEAN, MY_DIRECTORY_NOTIFY_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* tCreateWaitablePort) (MY_PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tWaitForAlertByThreadId) (PVOID, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tGetNextProcess) (MY_HANDLE, MY_ACCESS_MASK, ULONG, ULONG, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tOpenKeyedEvent) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tDeleteBootEntry) (ULONG);
typedef NTSTATUS(NTAPI* tFilterToken) (MY_HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tCompressKey) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tModifyBootEntry) (UINT32);
typedef NTSTATUS(NTAPI* tSetInformationTransaction) (MY_HANDLE, TRANSACTION_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tPlugPlayControl) (UINT32, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tOpenDirectoryObject) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tContinue) (PCONTEXT, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tPrivilegeObjectAuditAlarm) (PUNICODE_STRING, PVOID, MY_HANDLE, MY_ACCESS_MASK, PPRIVILEGE_SET, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tQueryKey) (MY_HANDLE, MY_KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tFilterBootOption) (UINT32, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tYieldExecution)();
typedef NTSTATUS(NTAPI* tResumeThread) (MY_HANDLE, PULONG);
typedef NTSTATUS(NTAPI* tAddBootEntry) (UINT32, PULONG);
typedef NTSTATUS(NTAPI* tGetCurrentProcessorNumberEx) (PPROCESSOR_NUMBER);
typedef NTSTATUS(NTAPI* tCreateLowBoxToken) (MY_PHANDLE, MY_HANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PSID, ULONG, PSID_AND_ATTRIBUTES, ULONG, void**);
typedef NTSTATUS(NTAPI* tFlushBuffersFile) (MY_HANDLE, PIO_STATUS_BLOCK);
typedef NTSTATUS(NTAPI* tDelayExecution) (MY_BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tOpenKey) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tStopProfile) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tSetEvent) (MY_HANDLE, PLONG);
typedef NTSTATUS(NTAPI* tRestoreKey) (MY_HANDLE, MY_HANDLE, ULONG);
typedef NTSTATUS(NTAPI* tExtendSection) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tInitializeNlsFiles) (void**, PLCID, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tFindAtom) (PWSTR, ULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tDisplayString) (PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tLoadDriver) (PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tQueryWnfStateNameInformation) (MY_PCWNF_STATE_NAME,/*Unknown*/ void*, PVOID, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tCreateMutant) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tFlushKey) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tDuplicateObject) (MY_HANDLE, MY_HANDLE, MY_HANDLE, MY_PHANDLE, MY_ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tCancelTimer2) (MY_HANDLE,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tQueryAttributesFile) (POBJECT_ATTRIBUTES, MY_PFILE_BASIC_INFORMATION);
typedef NTSTATUS(NTAPI* tCompareSigningLevels) (SE_SIGNING_LEVEL, SE_SIGNING_LEVEL);
typedef NTSTATUS(NTAPI* tAccessCheckByTypeResultListAndAuditAlarmByHandle) (PUNICODE_STRING, PVOID, MY_HANDLE, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, MY_ACCESS_MASK, AUDIT_EVENT_TYPE, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, MY_BOOLEAN, PACCESS_MASK, PNTSTATUS, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tDeleteValueKey) (MY_HANDLE, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tSetDebugFilterState) (ULONG, ULONG, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tPulseEvent) (MY_HANDLE, PLONG);
typedef NTSTATUS(NTAPI* tAllocateReserveObject) (MY_PHANDLE, POBJECT_ATTRIBUTES,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tAlpcDisconnectPort) (MY_HANDLE, ULONG);
typedef NTSTATUS(NTAPI* tQueryTimerResolution) (PULONG, PULONG, PULONG);
typedef NTSTATUS(NTAPI* tDeleteKey) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tCreateFile) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tReplyPort) (MY_HANDLE,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tGetNlsSectionPtr) (ULONG, ULONG, PVOID, void**, PSIZE_T);
typedef NTSTATUS(NTAPI* tQueryInformationProcess) (MY_HANDLE, MY_PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tReplyWaitReceivePortEx) (MY_HANDLE, void**,/*Unknown*/ void*,/*Unknown*/ void*, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tUmsThreadYield) (PVOID);
typedef NTSTATUS(NTAPI* tManagePartition) (MY_HANDLE, MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tAdjustPrivilegesToken) (MY_HANDLE, MY_BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
typedef NTSTATUS(NTAPI* tCreateCrossVmMutant) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, LPCGUID, LPCGUID);
typedef NTSTATUS(NTAPI* tCreateDirectoryObject) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tOpenFile) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tSetInformationVirtualMemory) (MY_HANDLE, MY_VIRTUAL_MEMORY_INFORMATION_CLASS, ULONG_PTR, MY_PMEMORY_RANGE_ENTRY, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tTerminateEnclave) (PVOID, ULONG);
typedef NTSTATUS(NTAPI* tSuspendProcess) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tReplyWaitReplyPort) (MY_HANDLE,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tOpenTransactionManager) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, LPGUID, ULONG);
typedef NTSTATUS(NTAPI* tCreateSemaphore) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
typedef NTSTATUS(NTAPI* tUnmapViewOfSectionEx) (MY_HANDLE, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tMapViewOfSection) (MY_HANDLE, MY_HANDLE, void**, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, MY_SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tDisableLastKnownGood)();
typedef NTSTATUS(NTAPI* tGetNextThread) (MY_HANDLE, MY_HANDLE, MY_ACCESS_MASK, ULONG, ULONG, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tMakeTemporaryObject) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tSetInformationFile) (MY_HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* tCreateTransactionManager) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tWriteFileGather) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PFILE_SEGMENT_ELEMENT, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* tQueryInformationTransaction) (MY_HANDLE, TRANSACTION_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tFlushVirtualMemory) (MY_HANDLE, void**, PSIZE_T, PIO_STATUS_BLOCK);
typedef NTSTATUS(NTAPI* tQueryQuotaInformationFile) (MY_HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, MY_BOOLEAN, PVOID, ULONG, PSID, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tSetVolumeInformationFile) (MY_HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, MY_FS_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* tQueryInformationEnlistment) (MY_HANDLE, ENLISTMENT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tCreateIoCompletion) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI* tUnloadKeyEx) (POBJECT_ATTRIBUTES, MY_HANDLE);
typedef NTSTATUS(NTAPI* tQueryEaFile) (MY_HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, MY_BOOLEAN, PVOID, ULONG, PULONG, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tQueryDirectoryObject) (MY_HANDLE, PVOID, ULONG, MY_BOOLEAN, MY_BOOLEAN, PULONG, PULONG);
typedef NTSTATUS(NTAPI* tAddAtomEx) (PWSTR, ULONG,/*Unknown*/ void*, ULONG);
typedef NTSTATUS(NTAPI* tSinglePhaseReject) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tDeleteWnfStateName) (MY_PCWNF_STATE_NAME);
typedef NTSTATUS(NTAPI* tSetSystemEnvironmentValueEx) (PUNICODE_STRING, LPGUID, PVOID, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tContinueEx) (PCONTEXT,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tUnloadDriver) (PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tCallEnclave) (PVOID, ULONG_PTR, ULONG, PULONG_PTR);
typedef NTSTATUS(NTAPI* tCancelIoFileEx) (MY_HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
typedef NTSTATUS(NTAPI* tSetTimer) (MY_HANDLE, PLARGE_INTEGER, MY_PTIMER_APC_ROUTINE, PVOID, MY_BOOLEAN, LONG, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tQuerySystemEnvironmentValue) (PUNICODE_STRING, PWSTR, USHORT, PUSHORT);
typedef NTSTATUS(NTAPI* tOpenThreadToken) (MY_HANDLE, MY_ACCESS_MASK, MY_BOOLEAN, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tMapUserPhysicalPagesScatter) (void**, ULONG_PTR, PULONG_PTR);
typedef NTSTATUS(NTAPI* tCreateResourceManager) (MY_PHANDLE, MY_ACCESS_MASK, MY_HANDLE, LPGUID, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tUnlockVirtualMemory) (MY_HANDLE, void**, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* tQueryInformationPort) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tSetLowEventPair) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tSetInformationKey) (MY_HANDLE, MY_KEY_SET_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tQuerySecurityPolicy) (PCUNICODE_STRING, PCUNICODE_STRING, PCUNICODE_STRING,/*Unknown*/ void*, PVOID, PULONG);
typedef NTSTATUS(NTAPI* tOpenProcessToken) (MY_HANDLE, MY_ACCESS_MASK, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tQueryVolumeInformationFile) (MY_HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, MY_FS_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* tOpenTimer) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tMapUserPhysicalPages) (PVOID, ULONG_PTR, PULONG_PTR);
typedef NTSTATUS(NTAPI* tLoadKey) (POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tCreateWaitCompletionPacket) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tReleaseWorkerFactoryWorker) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tPrePrepareComplete) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tReadVirtualMemory) (MY_HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tFreeVirtualMemory) (MY_HANDLE, void**, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* tSetDriverEntryOrder) (PULONG, ULONG);
typedef NTSTATUS(NTAPI* tReadFile) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* tTraceControl) (ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tOpenProcessTokenEx) (MY_HANDLE, MY_ACCESS_MASK, ULONG, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tSecureConnectPort) (MY_PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE,/*Unknown*/ void*, PSID,/*Unknown*/ void*, PULONG, PVOID, PULONG);
typedef NTSTATUS(NTAPI* tSaveKey) (MY_HANDLE, MY_HANDLE);
typedef NTSTATUS(NTAPI* tSetDefaultHardErrorPort) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tCreateEnclave) (MY_HANDLE, void**, ULONG_PTR, SIZE_T, SIZE_T, ULONG,/*Unknown*/ void*, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tOpenPrivateNamespace) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID);
typedef NTSTATUS(NTAPI* tSetLdtEntries) (ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tResetWriteWatch) (MY_HANDLE, PVOID, SIZE_T);
typedef NTSTATUS(NTAPI* tRenameKey) (MY_HANDLE, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tRevertContainerImpersonation)();
typedef NTSTATUS(NTAPI* tAlpcCreateSectionView) (MY_HANDLE, ULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tCreateCrossVmEvent) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, LPCGUID, LPCGUID);
typedef NTSTATUS(NTAPI* tImpersonateThread) (MY_HANDLE, MY_HANDLE, PSECURITY_QUALITY_OF_SERVICE);
typedef NTSTATUS(NTAPI* tSetIRTimer) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tCreateDirectoryObjectEx) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_HANDLE, ULONG);
typedef NTSTATUS(NTAPI* tAcquireProcessActivityReference) (MY_PHANDLE, MY_HANDLE,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tReplaceKey) (POBJECT_ATTRIBUTES, MY_HANDLE, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tStartProfile) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tQueryBootEntryOrder) (PULONG, PULONG);
typedef NTSTATUS(NTAPI* tLockRegistryKey) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tImpersonateClientOfPort) (MY_HANDLE,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tQueryEvent) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tFsControlFile) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tOpenProcess) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_PCLIENT_ID);
typedef NTSTATUS(NTAPI* tSetIoCompletion) (MY_HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
typedef NTSTATUS(NTAPI* tConnectPort) (MY_PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE,/*Unknown*/ void*,/*Unknown*/ void*, PULONG, PVOID, PULONG);
typedef NTSTATUS(NTAPI* tCloseObjectAuditAlarm) (PUNICODE_STRING, PVOID, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tRequestWaitReplyPort) (MY_HANDLE,/*Unknown*/ void*,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tSetInformationObject) (MY_HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tPrivilegeCheck) (MY_HANDLE, PPRIVILEGE_SET, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tCallbackReturn) (PVOID, ULONG, NTSTATUS);
typedef NTSTATUS(NTAPI* tSetInformationToken) (MY_HANDLE, MY_TOKENINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tSetUuidSeed) (PCHAR);
typedef NTSTATUS(NTAPI* tOpenKeyTransacted) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_HANDLE);
typedef NTSTATUS(NTAPI* tAlpcDeleteSecurityContext) (MY_HANDLE, ULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tSetBootOptions) (UINT32, ULONG);
typedef NTSTATUS(NTAPI* tManageHotPatch) (UINT32, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tEnumerateTransactionObject) (MY_HANDLE, KTMOBJECT_TYPE, PKTMOBJECT_CURSOR, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tSetThreadExecutionState) (EXECUTION_STATE, PEXECUTION_STATE);
typedef NTSTATUS(NTAPI* tWaitLowEventPair) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tSetHighWaitLowEventPair) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tQueryInformationWorkerFactory) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tSetWnfProcessNotificationEvent) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tAlpcDeleteSectionView) (MY_HANDLE, ULONG, PVOID);
typedef NTSTATUS(NTAPI* tCreateMailslotFile) (MY_PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tCreateProcess) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_HANDLE, MY_BOOLEAN, MY_HANDLE, MY_HANDLE, MY_HANDLE);
typedef NTSTATUS(NTAPI* tQueryIoCompletion) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tCreateTimer) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_TIMER_TYPE);
typedef NTSTATUS(NTAPI* tFlushInstallUILanguage) (ULONG, ULONG);
typedef NTSTATUS(NTAPI* tCompleteConnectPort) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tAlpcConnectPort) (MY_PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES,/*Unknown*/ void*, ULONG, PSID,/*Unknown*/ void*, PSIZE_T,/*Unknown*/ void*,/*Unknown*/ void*, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tFreezeRegistry) (ULONG);
typedef NTSTATUS(NTAPI* tMapCMFModule) (ULONG, ULONG, UINT32*, UINT32*, UINT32*, void**);
typedef NTSTATUS(NTAPI* tAllocateUserPhysicalPages) (MY_HANDLE, PULONG_PTR, PULONG_PTR);
typedef NTSTATUS(NTAPI* tSetInformationEnlistment) (MY_HANDLE, ENLISTMENT_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tRaiseHardError) (NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tCreateSection) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, MY_HANDLE);
typedef NTSTATUS(NTAPI* tOpenIoCompletion) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tSystemDebugControl) (UINT32, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tTranslateFilePath) (UINT32, ULONG,/*Unknown*/ void*, PULONG);
typedef NTSTATUS(NTAPI* tCreateIRTimer) (MY_PHANDLE,/*Unknown*/ void*, MY_ACCESS_MASK);
typedef NTSTATUS(NTAPI* tCreateRegistryTransaction) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI* tLoadKey2) (POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI* tAlpcCreatePort) (MY_PHANDLE, POBJECT_ATTRIBUTES,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tDeleteWnfStateData) (MY_PCWNF_STATE_NAME, PVOID);
typedef NTSTATUS(NTAPI* tSetTimerEx) (MY_HANDLE, MY_TIMER_SET_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tSetLowWaitHighEventPair) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tAlpcCreateSecurityContext) (MY_HANDLE, ULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tSetCachedSigningLevel) (ULONG, SE_SIGNING_LEVEL, MY_PHANDLE, ULONG, MY_HANDLE);
typedef NTSTATUS(NTAPI* tSetHighEventPair) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tShutdownWorkerFactory) (MY_HANDLE, UINT32*);
typedef NTSTATUS(NTAPI* tSetInformationJobObject) (MY_HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tAdjustGroupsToken) (MY_HANDLE, MY_BOOLEAN, PTOKEN_GROUPS, ULONG, PTOKEN_GROUPS, PULONG);
typedef NTSTATUS(NTAPI* tAreMappedFilesTheSame) (PVOID, PVOID);
typedef NTSTATUS(NTAPI* tSetBootEntryOrder) (PULONG, ULONG);
typedef NTSTATUS(NTAPI* tQueryMutant) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* totifyChangeSession) (MY_HANDLE, ULONG, PLARGE_INTEGER, MY_IO_SESSION_EVENT, MY_IO_SESSION_STATE, MY_IO_SESSION_STATE, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tQueryDefaultLocale) (MY_BOOLEAN, PLCID);
typedef NTSTATUS(NTAPI* tCreateThreadEx) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tQueryDriverEntryOrder) (PULONG, PULONG);
typedef NTSTATUS(NTAPI* tSetTimerResolution) (ULONG, MY_BOOLEAN, PULONG);
typedef NTSTATUS(NTAPI* tPrePrepareEnlistment) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tCancelSynchronousIoFile) (MY_HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
typedef NTSTATUS(NTAPI* tQueryDirectoryFileEx) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, ULONG, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tAddDriverEntry) (UINT32, PULONG);
typedef NTSTATUS(NTAPI* tUnloadKey) (POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tCreateEvent) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_EVENT_TYPE, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tOpenSession) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tQueryValueKey) (MY_HANDLE, PUNICODE_STRING, MY_KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tCreatePrivateNamespace) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID);
typedef NTSTATUS(NTAPI* tIsUILanguageComitted)();
typedef NTSTATUS(NTAPI* tAlertThread) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tQueryInstallUILanguage) (UINT16*);
typedef NTSTATUS(NTAPI* tCreateSymbolicLinkObject) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* tAllocateUuids) (PULARGE_INTEGER, PULONG, PULONG, PCHAR);
typedef NTSTATUS(NTAPI* tShutdownSystem) (UINT32);
typedef NTSTATUS(NTAPI* tCreateTokenEx) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, TOKEN_TYPE, PLUID, PLARGE_INTEGER, PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES,/*Unknown*/ void*,/*Unknown*/ void*, PTOKEN_GROUPS, PTOKEN_MANDATORY_POLICY, PTOKEN_OWNER, PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PTOKEN_SOURCE);
typedef NTSTATUS(NTAPI* tQueryVirtualMemory) (MY_HANDLE, PVOID, MY_MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tAlpcOpenSenderProcess) (MY_PHANDLE, MY_HANDLE,/*Unknown*/ void*, ULONG, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tAssignProcessToJobObject) (MY_HANDLE, MY_HANDLE);
typedef NTSTATUS(NTAPI* tRemoveIoCompletion) (MY_HANDLE, void**, void**, PIO_STATUS_BLOCK, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tCreateTimer2) (MY_PHANDLE, PVOID, PVOID, ULONG, MY_ACCESS_MASK);
typedef NTSTATUS(NTAPI* tCreateEnlistment) (MY_PHANDLE, MY_ACCESS_MASK, MY_HANDLE, MY_HANDLE, POBJECT_ATTRIBUTES, ULONG, NOTIFICATION_MASK, PVOID);
typedef NTSTATUS(NTAPI* tRecoverEnlistment) (MY_HANDLE, PVOID);
typedef NTSTATUS(NTAPI* tCreateJobSet) (ULONG, PJOB_SET_ARRAY, ULONG);
typedef NTSTATUS(NTAPI* tSetIoCompletionEx) (MY_HANDLE, MY_HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
typedef NTSTATUS(NTAPI* tCreateProcessEx) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES, MY_HANDLE, ULONG, MY_HANDLE, MY_HANDLE, MY_HANDLE, ULONG);
typedef NTSTATUS(NTAPI* tAlpcConnectPortEx) (MY_PHANDLE, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,/*Unknown*/ void*, ULONG, PSECURITY_DESCRIPTOR,/*Unknown*/ void*, PSIZE_T,/*Unknown*/ void*,/*Unknown*/ void*, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tWaitForMultipleObjects32) (ULONG, INT32*, MY_WAIT_TYPE, MY_BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tRecoverResourceManager) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tAlpcSetInformation) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tAlpcRevokeSecurityContext) (MY_HANDLE, ULONG,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tAlpcImpersonateClientOfPort) (MY_HANDLE,/*Unknown*/ void*, PVOID);
typedef NTSTATUS(NTAPI* tReleaseKeyedEvent) (MY_HANDLE, PVOID, MY_BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tTerminateThread) (MY_HANDLE, NTSTATUS);
typedef NTSTATUS(NTAPI* tSetInformationSymbolicLink) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tDeleteObjectAuditAlarm) (PUNICODE_STRING, PVOID, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tWaitForKeyedEvent) (MY_HANDLE, PVOID, MY_BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tCreatePort) (MY_PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tDeletePrivateNamespace) (MY_HANDLE);
typedef NTSTATUS(NTAPI* totifyChangeMultipleKeys) (MY_HANDLE, ULONG, struct _OBJECT_ATTRIBUTES*, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, MY_BOOLEAN, PVOID, ULONG, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tLockFile) (MY_HANDLE, MY_HANDLE, MY_PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG, MY_BOOLEAN, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tQueryDefaultUILanguage) (UINT16*);
typedef NTSTATUS(NTAPI* tOpenEventPair) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tRollforwardTransactionManager) (MY_HANDLE, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* tAlpcQueryInformationMessage) (MY_HANDLE,/*Unknown*/ void*,/*Unknown*/ void*, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tUnmapViewOfSection) (MY_HANDLE, PVOID);
typedef NTSTATUS(NTAPI* tCancelIoFile) (MY_HANDLE, PIO_STATUS_BLOCK);
typedef NTSTATUS(NTAPI* tCreatePagingFile) (PUNICODE_STRING, PLARGE_INTEGER, PLARGE_INTEGER, ULONG);
typedef NTSTATUS(NTAPI* tCancelTimer) (MY_HANDLE, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tReplyWaitReceivePort) (MY_HANDLE, void**,/*Unknown*/ void*,/*Unknown*/ void*);
typedef NTSTATUS(NTAPI* tCompareObjects) (MY_HANDLE, MY_HANDLE);
typedef NTSTATUS(NTAPI* tSetDefaultLocale) (MY_BOOLEAN, LCID);
typedef NTSTATUS(NTAPI* tAllocateLocallyUniqueId) (PLUID);
typedef NTSTATUS(NTAPI* tAccessCheckByTypeAndAuditAlarm) (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, MY_ACCESS_MASK, AUDIT_EVENT_TYPE, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, MY_BOOLEAN, PACCESS_MASK, PNTSTATUS, MY_PBOOLEAN);
typedef NTSTATUS(NTAPI* tQueryDebugFilterState) (ULONG, ULONG);
typedef NTSTATUS(NTAPI* tOpenSemaphore) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tAllocateVirtualMemory) (MY_HANDLE, void**, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tResumeProcess) (MY_HANDLE);
typedef NTSTATUS(NTAPI* tSetContextThread) (MY_HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* tOpenSymbolicLinkObject) (MY_PHANDLE, MY_ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* tModifyDriverEntry) (UINT32);
typedef NTSTATUS(NTAPI* tSerializeBoot)();
typedef NTSTATUS(NTAPI* tRenameTransactionManager) (PUNICODE_STRING, LPGUID);
typedef NTSTATUS(NTAPI* tRemoveIoCompletionEx) (MY_HANDLE,/*Unknown*/ void*, ULONG, PULONG, PLARGE_INTEGER, MY_BOOLEAN);
typedef NTSTATUS(NTAPI* tMapViewOfSectionEx) (MY_HANDLE, MY_HANDLE, void**, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG,/*Unknown*/ void*, ULONG);
typedef NTSTATUS(NTAPI* tFilterTokenEx) (MY_HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, ULONG, PUNICODE_STRING, ULONG, PUNICODE_STRING, PTOKEN_GROUPS,/*Unknown*/ void*,/*Unknown*/ void*, PTOKEN_GROUPS, MY_PHANDLE);
typedef NTSTATUS(NTAPI* tDeleteDriverEntry) (ULONG);
typedef NTSTATUS(NTAPI* tQuerySystemInformation) (UINT32, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tSetInformationWorkerFactory) (MY_HANDLE,/*Unknown*/ void*, PVOID, ULONG);
typedef NTSTATUS(NTAPI* tAdjustTokenClaimsAndDeviceGroups) (MY_HANDLE, MY_BOOLEAN, MY_BOOLEAN, MY_BOOLEAN,void*,void*, PTOKEN_GROUPS, ULONG,void*, ULONG, void*, ULONG, PTOKEN_GROUPS, PULONG, PULONG, PULONG);
typedef NTSTATUS(NTAPI* tSaveMergedKeys)(MY_HANDLE, MY_HANDLE, MY_HANDLE);

const char* get_probe_name(PROBE_IDS probeId) {
    switch (probeId) {
    case PROBE_IDS::IdLockProductActivationKeys: return "NtLockProductActivationKeys";
    case PROBE_IDS::IdWaitHighEventPair: return "NtWaitHighEventPair";
    case PROBE_IDS::IdRegisterThreadTerminatePort: return "NtRegisterThreadTerminatePort";
    case PROBE_IDS::IdAssociateWaitCompletionPacket: return "NtAssociateWaitCompletionPacket";
    case PROBE_IDS::IdQueryPerformanceCounter: return "NtQueryPerformanceCounter";
    case PROBE_IDS::IdCompactKeys: return "NtCompactKeys";
    case PROBE_IDS::IdQuerySystemInformationEx: return "NtQuerySystemInformationEx";
    case PROBE_IDS::IdResetEvent: return "NtResetEvent";
    case PROBE_IDS::IdGetContextThread: return "NtGetContextThread";
    case PROBE_IDS::IdQueryInformationThread: return "NtQueryInformationThread";
    case PROBE_IDS::IdWaitForSingleObject: return "NtWaitForSingleObject";
    case PROBE_IDS::IdFlushBuffersFileEx: return "NtFlushBuffersFileEx";
    case PROBE_IDS::IdUnloadKey2: return "NtUnloadKey2";
    case PROBE_IDS::IdReadOnlyEnlistment: return "NtReadOnlyEnlistment";
    case PROBE_IDS::IdDeleteFile: return "NtDeleteFile";
    case PROBE_IDS::IdDeleteAtom: return "NtDeleteAtom";
    case PROBE_IDS::IdQueryDirectoryFile: return "NtQueryDirectoryFile";
    case PROBE_IDS::IdSetEventBoostPriority: return "NtSetEventBoostPriority";
    case PROBE_IDS::IdAllocateUserPhysicalPagesEx: return "NtAllocateUserPhysicalPagesEx";
    case PROBE_IDS::IdWriteFile: return "NtWriteFile";
    case PROBE_IDS::IdQueryInformationFile: return "NtQueryInformationFile";
    case PROBE_IDS::IdAlpcCancelMessage: return "NtAlpcCancelMessage";
    case PROBE_IDS::IdOpenMutant: return "NtOpenMutant";
    case PROBE_IDS::IdCreatePartition: return "NtCreatePartition";
    case PROBE_IDS::IdQueryTimer: return "NtQueryTimer";
    case PROBE_IDS::IdOpenEvent: return "NtOpenEvent";
    case PROBE_IDS::IdOpenObjectAuditAlarm: return "NtOpenObjectAuditAlarm";
    case PROBE_IDS::IdMakePermanentObject: return "NtMakePermanentObject";
    case PROBE_IDS::IdCommitTransaction: return "NtCommitTransaction";
    case PROBE_IDS::IdSetSystemTime: return "NtSetSystemTime";
    case PROBE_IDS::IdGetDevicePowerState: return "NtGetDevicePowerState";
    case PROBE_IDS::IdSetSystemPowerState: return "NtSetSystemPowerState";
    case PROBE_IDS::IdAlpcCreateResourceReserve: return "NtAlpcCreateResourceReserve";
    case PROBE_IDS::IdUnlockFile: return "NtUnlockFile";
    case PROBE_IDS::IdAlpcDeletePortSection: return "NtAlpcDeletePortSection";
    case PROBE_IDS::IdSetInformationResourceManager: return "NtSetInformationResourceManager";
    case PROBE_IDS::IdFreeUserPhysicalPages: return "NtFreeUserPhysicalPages";
    case PROBE_IDS::IdLoadKeyEx: return "NtLoadKeyEx";
    case PROBE_IDS::IdPropagationComplete: return "NtPropagationComplete";
    case PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarm: return "NtAccessCheckByTypeResultListAndAuditAlarm";
    case PROBE_IDS::IdQueryInformationToken: return "NtQueryInformationToken";
    case PROBE_IDS::IdRegisterProtocolAddressInformation: return "NtRegisterProtocolAddressInformation";
    case PROBE_IDS::IdProtectVirtualMemory: return "NtProtectVirtualMemory";
    case PROBE_IDS::IdCreateKey: return "NtCreateKey";
    case PROBE_IDS::IdAlpcSendWaitReceivePort: return "NtAlpcSendWaitReceivePort";
    case PROBE_IDS::IdOpenRegistryTransaction: return "NtOpenRegistryTransaction";
    case PROBE_IDS::IdTerminateProcess: return "NtTerminateProcess";
    case PROBE_IDS::IdPowerInformation: return "NtPowerInformation";
    case PROBE_IDS::IdotifyChangeDirectoryFile: return "NtNotifyChangeDirectoryFile";
    case PROBE_IDS::IdCreateTransaction: return "NtCreateTransaction";
    case PROBE_IDS::IdCreateProfileEx: return "NtCreateProfileEx";
    case PROBE_IDS::IdQueryLicenseValue: return "NtQueryLicenseValue";
    case PROBE_IDS::IdCreateProfile: return "NtCreateProfile";
    case PROBE_IDS::IdInitializeRegistry: return "NtInitializeRegistry";
    case PROBE_IDS::IdFreezeTransactions: return "NtFreezeTransactions";
    case PROBE_IDS::IdOpenJobObject: return "NtOpenJobObject";
    case PROBE_IDS::IdSubscribeWnfStateChange: return "NtSubscribeWnfStateChange";
    case PROBE_IDS::IdGetWriteWatch: return "NtGetWriteWatch";
    case PROBE_IDS::IdGetCachedSigningLevel: return "NtGetCachedSigningLevel";
    case PROBE_IDS::IdSetSecurityObject: return "NtSetSecurityObject";
    case PROBE_IDS::IdQueryIntervalProfile: return "NtQueryIntervalProfile";
    case PROBE_IDS::IdPropagationFailed: return "NtPropagationFailed";
    case PROBE_IDS::IdCreateSectionEx: return "NtCreateSectionEx";
    case PROBE_IDS::IdRaiseException: return "NtRaiseException";
    case PROBE_IDS::IdSetCachedSigningLevel2: return "NtSetCachedSigningLevel2";
    case PROBE_IDS::IdCommitEnlistment: return "NtCommitEnlistment";
    case PROBE_IDS::IdQueryInformationByName: return "NtQueryInformationByName";
    case PROBE_IDS::IdCreateThread: return "NtCreateThread";
    case PROBE_IDS::IdOpenResourceManager: return "NtOpenResourceManager";
    case PROBE_IDS::IdReadRequestData: return "NtReadRequestData";
    case PROBE_IDS::IdClearEvent: return "NtClearEvent";
    case PROBE_IDS::IdTestAlert: return "NtTestAlert";
    case PROBE_IDS::IdSetInformationThread: return "NtSetInformationThread";
    case PROBE_IDS::IdSetTimer2: return "NtSetTimer2";
    case PROBE_IDS::IdSetDefaultUILanguage: return "NtSetDefaultUILanguage";
    case PROBE_IDS::IdEnumerateValueKey: return "NtEnumerateValueKey";
    case PROBE_IDS::IdOpenEnlistment: return "NtOpenEnlistment";
    case PROBE_IDS::IdSetIntervalProfile: return "NtSetIntervalProfile";
    case PROBE_IDS::IdQueryPortInformationProcess: return "NtQueryPortInformationProcess";
    case PROBE_IDS::IdQueryInformationTransactionManager: return "NtQueryInformationTransactionManager";
    case PROBE_IDS::IdSetInformationTransactionManager: return "NtSetInformationTransactionManager";
    case PROBE_IDS::IdInitializeEnclave: return "NtInitializeEnclave";
    case PROBE_IDS::IdPrepareComplete: return "NtPrepareComplete";
    case PROBE_IDS::IdQueueApcThread: return "NtQueueApcThread";
    case PROBE_IDS::IdWorkerFactoryWorkerReady: return "NtWorkerFactoryWorkerReady";
    case PROBE_IDS::IdGetCompleteWnfStateSubscription: return "NtGetCompleteWnfStateSubscription";
    case PROBE_IDS::IdAlertThreadByThreadId: return "NtAlertThreadByThreadId";
    case PROBE_IDS::IdLockVirtualMemory: return "NtLockVirtualMemory";
    case PROBE_IDS::IdDeviceIoControlFile: return "NtDeviceIoControlFile";
    case PROBE_IDS::IdCreateUserProcess: return "NtCreateUserProcess";
    case PROBE_IDS::IdQuerySection: return "NtQuerySection";
    case PROBE_IDS::IdSaveKeyEx: return "NtSaveKeyEx";
    case PROBE_IDS::IdRollbackTransaction: return "NtRollbackTransaction";
    case PROBE_IDS::IdTraceEvent: return "NtTraceEvent";
    case PROBE_IDS::IdOpenSection: return "NtOpenSection";
    case PROBE_IDS::IdRequestPort: return "NtRequestPort";
    case PROBE_IDS::IdUnsubscribeWnfStateChange: return "NtUnsubscribeWnfStateChange";
    case PROBE_IDS::IdThawRegistry: return "NtThawRegistry";
    case PROBE_IDS::IdCreateJobObject: return "NtCreateJobObject";
    case PROBE_IDS::IdOpenKeyTransactedEx: return "NtOpenKeyTransactedEx";
    case PROBE_IDS::IdWaitForMultipleObjects: return "NtWaitForMultipleObjects";
    case PROBE_IDS::IdDuplicateToken: return "NtDuplicateToken";
    case PROBE_IDS::IdAlpcOpenSenderThread: return "NtAlpcOpenSenderThread";
    case PROBE_IDS::IdAlpcImpersonateClientContainerOfPort: return "NtAlpcImpersonateClientContainerOfPort";
    case PROBE_IDS::IdDrawText: return "NtDrawText";
    case PROBE_IDS::IdReleaseSemaphore: return "NtReleaseSemaphore";
    case PROBE_IDS::IdSetQuotaInformationFile: return "NtSetQuotaInformationFile";
    case PROBE_IDS::IdQueryInformationAtom: return "NtQueryInformationAtom";
    case PROBE_IDS::IdEnumerateBootEntries: return "NtEnumerateBootEntries";
    case PROBE_IDS::IdThawTransactions: return "NtThawTransactions";
    case PROBE_IDS::IdAccessCheck: return "NtAccessCheck";
    case PROBE_IDS::IdFlushProcessWriteBuffers: return "NtFlushProcessWriteBuffers";
    case PROBE_IDS::IdQuerySemaphore: return "NtQuerySemaphore";
    case PROBE_IDS::IdCreateNamedPipeFile: return "NtCreateNamedPipeFile";
    case PROBE_IDS::IdAlpcDeleteResourceReserve: return "NtAlpcDeleteResourceReserve";
    case PROBE_IDS::IdQuerySystemEnvironmentValueEx: return "NtQuerySystemEnvironmentValueEx";
    case PROBE_IDS::IdReadFileScatter: return "NtReadFileScatter";
    case PROBE_IDS::IdOpenKeyEx: return "NtOpenKeyEx";
    case PROBE_IDS::IdSignalAndWaitForSingleObject: return "NtSignalAndWaitForSingleObject";
    case PROBE_IDS::IdReleaseMutant: return "NtReleaseMutant";
    case PROBE_IDS::IdTerminateJobObject: return "NtTerminateJobObject";
    case PROBE_IDS::IdSetSystemEnvironmentValue: return "NtSetSystemEnvironmentValue";
    case PROBE_IDS::IdClose: return "NtClose";
    case PROBE_IDS::IdQueueApcThreadEx: return "NtQueueApcThreadEx";
    case PROBE_IDS::IdQueryMultipleValueKey: return "NtQueryMultipleValueKey";
    case PROBE_IDS::IdAlpcQueryInformation: return "NtAlpcQueryInformation";
    case PROBE_IDS::IdUpdateWnfStateData: return "NtUpdateWnfStateData";
    case PROBE_IDS::IdListenPort: return "NtListenPort";
    case PROBE_IDS::IdFlushInstructionCache: return "NtFlushInstructionCache";
    case PROBE_IDS::IdGetNotificationResourceManager: return "NtGetNotificationResourceManager";
    case PROBE_IDS::IdQueryFullAttributesFile: return "NtQueryFullAttributesFile";
    case PROBE_IDS::IdSuspendThread: return "NtSuspendThread";
    case PROBE_IDS::IdCompareTokens: return "NtCompareTokens";
    case PROBE_IDS::IdCancelWaitCompletionPacket: return "NtCancelWaitCompletionPacket";
    case PROBE_IDS::IdAlpcAcceptConnectPort: return "NtAlpcAcceptConnectPort";
    case PROBE_IDS::IdOpenTransaction: return "NtOpenTransaction";
    case PROBE_IDS::IdImpersonateAnonymousToken: return "NtImpersonateAnonymousToken";
    case PROBE_IDS::IdQuerySecurityObject: return "NtQuerySecurityObject";
    case PROBE_IDS::IdRollbackEnlistment: return "NtRollbackEnlistment";
    case PROBE_IDS::IdReplacePartitionUnit: return "NtReplacePartitionUnit";
    case PROBE_IDS::IdCreateKeyTransacted: return "NtCreateKeyTransacted";
    case PROBE_IDS::IdConvertBetweenAuxiliaryCounterAndPerformanceCounter: return "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter";
    case PROBE_IDS::IdCreateKeyedEvent: return "NtCreateKeyedEvent";
    case PROBE_IDS::IdCreateEventPair: return "NtCreateEventPair";
    case PROBE_IDS::IdAddAtom: return "NtAddAtom";
    case PROBE_IDS::IdQueryOpenSubKeys: return "NtQueryOpenSubKeys";
    case PROBE_IDS::IdQuerySystemTime: return "NtQuerySystemTime";
    case PROBE_IDS::IdSetEaFile: return "NtSetEaFile";
    case PROBE_IDS::IdSetInformationProcess: return "NtSetInformationProcess";
    case PROBE_IDS::IdSetValueKey: return "NtSetValueKey";
    case PROBE_IDS::IdQuerySymbolicLinkObject: return "NtQuerySymbolicLinkObject";
    case PROBE_IDS::IdQueryOpenSubKeysEx: return "NtQueryOpenSubKeysEx";
    case PROBE_IDS::IdotifyChangeKey: return "NtNotifyChangeKey";
    case PROBE_IDS::IdIsProcessInJob: return "NtIsProcessInJob";
    case PROBE_IDS::IdCommitComplete: return "NtCommitComplete";
    case PROBE_IDS::IdEnumerateDriverEntries: return "NtEnumerateDriverEntries";
    case PROBE_IDS::IdAccessCheckByTypeResultList: return "NtAccessCheckByTypeResultList";
    case PROBE_IDS::IdLoadEnclaveData: return "NtLoadEnclaveData";
    case PROBE_IDS::IdAllocateVirtualMemoryEx: return "NtAllocateVirtualMemoryEx";
    case PROBE_IDS::IdWaitForWorkViaWorkerFactory: return "NtWaitForWorkViaWorkerFactory";
    case PROBE_IDS::IdQueryInformationResourceManager: return "NtQueryInformationResourceManager";
    case PROBE_IDS::IdEnumerateKey: return "NtEnumerateKey";
    case PROBE_IDS::IdGetMUIRegistryInfo: return "NtGetMUIRegistryInfo";
    case PROBE_IDS::IdAcceptConnectPort: return "NtAcceptConnectPort";
    case PROBE_IDS::IdRecoverTransactionManager: return "NtRecoverTransactionManager";
    case PROBE_IDS::IdWriteVirtualMemory: return "NtWriteVirtualMemory";
    case PROBE_IDS::IdQueryBootOptions: return "NtQueryBootOptions";
    case PROBE_IDS::IdRollbackComplete: return "NtRollbackComplete";
    case PROBE_IDS::IdQueryAuxiliaryCounterFrequency: return "NtQueryAuxiliaryCounterFrequency";
    case PROBE_IDS::IdAlpcCreatePortSection: return "NtAlpcCreatePortSection";
    case PROBE_IDS::IdQueryObject: return "NtQueryObject";
    case PROBE_IDS::IdQueryWnfStateData: return "NtQueryWnfStateData";
    case PROBE_IDS::IdInitiatePowerAction: return "NtInitiatePowerAction";
    case PROBE_IDS::IdDirectGraphicsCall: return "NtDirectGraphicsCall";
    case PROBE_IDS::IdAcquireCrossVmMutant: return "NtAcquireCrossVmMutant";
    case PROBE_IDS::IdRollbackRegistryTransaction: return "NtRollbackRegistryTransaction";
    case PROBE_IDS::IdAlertResumeThread: return "NtAlertResumeThread";
    case PROBE_IDS::IdPssCaptureVaSpaceBulk: return "NtPssCaptureVaSpaceBulk";
    case PROBE_IDS::IdCreateToken: return "NtCreateToken";
    case PROBE_IDS::IdPrepareEnlistment: return "NtPrepareEnlistment";
    case PROBE_IDS::IdFlushWriteBuffer: return "NtFlushWriteBuffer";
    case PROBE_IDS::IdCommitRegistryTransaction: return "NtCommitRegistryTransaction";
    case PROBE_IDS::IdAccessCheckByType: return "NtAccessCheckByType";
    case PROBE_IDS::IdOpenThread: return "NtOpenThread";
    case PROBE_IDS::IdAccessCheckAndAuditAlarm: return "NtAccessCheckAndAuditAlarm";
    case PROBE_IDS::IdOpenThreadTokenEx: return "NtOpenThreadTokenEx";
    case PROBE_IDS::IdWriteRequestData: return "NtWriteRequestData";
    case PROBE_IDS::IdCreateWorkerFactory: return "NtCreateWorkerFactory";
    case PROBE_IDS::IdOpenPartition: return "NtOpenPartition";
    case PROBE_IDS::IdSetSystemInformation: return "NtSetSystemInformation";
    case PROBE_IDS::IdEnumerateSystemEnvironmentValuesEx: return "NtEnumerateSystemEnvironmentValuesEx";
    case PROBE_IDS::IdCreateWnfStateName: return "NtCreateWnfStateName";
    case PROBE_IDS::IdQueryInformationJobObject: return "NtQueryInformationJobObject";
    case PROBE_IDS::IdPrivilegedServiceAuditAlarm: return "NtPrivilegedServiceAuditAlarm";
    case PROBE_IDS::IdEnableLastKnownGood: return "NtEnableLastKnownGood";
    case PROBE_IDS::IdotifyChangeDirectoryFileEx: return "NtNotifyChangeDirectoryFileEx";
    case PROBE_IDS::IdCreateWaitablePort: return "NtCreateWaitablePort";
    case PROBE_IDS::IdWaitForAlertByThreadId: return "NtWaitForAlertByThreadId";
    case PROBE_IDS::IdGetNextProcess: return "NtGetNextProcess";
    case PROBE_IDS::IdOpenKeyedEvent: return "NtOpenKeyedEvent";
    case PROBE_IDS::IdDeleteBootEntry: return "NtDeleteBootEntry";
    case PROBE_IDS::IdFilterToken: return "NtFilterToken";
    case PROBE_IDS::IdCompressKey: return "NtCompressKey";
    case PROBE_IDS::IdModifyBootEntry: return "NtModifyBootEntry";
    case PROBE_IDS::IdSetInformationTransaction: return "NtSetInformationTransaction";
    case PROBE_IDS::IdPlugPlayControl: return "NtPlugPlayControl";
    case PROBE_IDS::IdOpenDirectoryObject: return "NtOpenDirectoryObject";
    case PROBE_IDS::IdContinue: return "NtContinue";
    case PROBE_IDS::IdPrivilegeObjectAuditAlarm: return "NtPrivilegeObjectAuditAlarm";
    case PROBE_IDS::IdQueryKey: return "NtQueryKey";
    case PROBE_IDS::IdFilterBootOption: return "NtFilterBootOption";
    case PROBE_IDS::IdYieldExecution: return "NtYieldExecution";
    case PROBE_IDS::IdResumeThread: return "NtResumeThread";
    case PROBE_IDS::IdAddBootEntry: return "NtAddBootEntry";
    case PROBE_IDS::IdGetCurrentProcessorNumberEx: return "NtGetCurrentProcessorNumberEx";
    case PROBE_IDS::IdCreateLowBoxToken: return "NtCreateLowBoxToken";
    case PROBE_IDS::IdFlushBuffersFile: return "NtFlushBuffersFile";
    case PROBE_IDS::IdDelayExecution: return "NtDelayExecution";
    case PROBE_IDS::IdOpenKey: return "NtOpenKey";
    case PROBE_IDS::IdStopProfile: return "NtStopProfile";
    case PROBE_IDS::IdSetEvent: return "NtSetEvent";
    case PROBE_IDS::IdRestoreKey: return "NtRestoreKey";
    case PROBE_IDS::IdExtendSection: return "NtExtendSection";
    case PROBE_IDS::IdInitializeNlsFiles: return "NtInitializeNlsFiles";
    case PROBE_IDS::IdFindAtom: return "NtFindAtom";
    case PROBE_IDS::IdDisplayString: return "NtDisplayString";
    case PROBE_IDS::IdLoadDriver: return "NtLoadDriver";
    case PROBE_IDS::IdQueryWnfStateNameInformation: return "NtQueryWnfStateNameInformation";
    case PROBE_IDS::IdCreateMutant: return "NtCreateMutant";
    case PROBE_IDS::IdFlushKey: return "NtFlushKey";
    case PROBE_IDS::IdDuplicateObject: return "NtDuplicateObject";
    case PROBE_IDS::IdCancelTimer2: return "NtCancelTimer2";
    case PROBE_IDS::IdQueryAttributesFile: return "NtQueryAttributesFile";
    case PROBE_IDS::IdCompareSigningLevels: return "NtCompareSigningLevels";
    case PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarmByHandle: return "NtAccessCheckByTypeResultListAndAuditAlarmByHandle";
    case PROBE_IDS::IdDeleteValueKey: return "NtDeleteValueKey";
    case PROBE_IDS::IdSetDebugFilterState: return "NtSetDebugFilterState";
    case PROBE_IDS::IdPulseEvent: return "NtPulseEvent";
    case PROBE_IDS::IdAllocateReserveObject: return "NtAllocateReserveObject";
    case PROBE_IDS::IdAlpcDisconnectPort: return "NtAlpcDisconnectPort";
    case PROBE_IDS::IdQueryTimerResolution: return "NtQueryTimerResolution";
    case PROBE_IDS::IdDeleteKey: return "NtDeleteKey";
    case PROBE_IDS::IdCreateFile: return "NtCreateFile";
    case PROBE_IDS::IdReplyPort: return "NtReplyPort";
    case PROBE_IDS::IdGetNlsSectionPtr: return "NtGetNlsSectionPtr";
    case PROBE_IDS::IdQueryInformationProcess: return "NtQueryInformationProcess";
    case PROBE_IDS::IdReplyWaitReceivePortEx: return "NtReplyWaitReceivePortEx";
    case PROBE_IDS::IdUmsThreadYield: return "NtUmsThreadYield";
    case PROBE_IDS::IdManagePartition: return "NtManagePartition";
    case PROBE_IDS::IdAdjustPrivilegesToken: return "NtAdjustPrivilegesToken";
    case PROBE_IDS::IdCreateCrossVmMutant: return "NtCreateCrossVmMutant";
    case PROBE_IDS::IdCreateDirectoryObject: return "NtCreateDirectoryObject";
    case PROBE_IDS::IdOpenFile: return "NtOpenFile";
    case PROBE_IDS::IdSetInformationVirtualMemory: return "NtSetInformationVirtualMemory";
    case PROBE_IDS::IdTerminateEnclave: return "NtTerminateEnclave";
    case PROBE_IDS::IdSuspendProcess: return "NtSuspendProcess";
    case PROBE_IDS::IdReplyWaitReplyPort: return "NtReplyWaitReplyPort";
    case PROBE_IDS::IdOpenTransactionManager: return "NtOpenTransactionManager";
    case PROBE_IDS::IdCreateSemaphore: return "NtCreateSemaphore";
    case PROBE_IDS::IdUnmapViewOfSectionEx: return "NtUnmapViewOfSectionEx";
    case PROBE_IDS::IdMapViewOfSection: return "NtMapViewOfSection";
    case PROBE_IDS::IdDisableLastKnownGood: return "NtDisableLastKnownGood";
    case PROBE_IDS::IdGetNextThread: return "NtGetNextThread";
    case PROBE_IDS::IdMakeTemporaryObject: return "NtMakeTemporaryObject";
    case PROBE_IDS::IdSetInformationFile: return "NtSetInformationFile";
    case PROBE_IDS::IdCreateTransactionManager: return "NtCreateTransactionManager";
    case PROBE_IDS::IdWriteFileGather: return "NtWriteFileGather";
    case PROBE_IDS::IdQueryInformationTransaction: return "NtQueryInformationTransaction";
    case PROBE_IDS::IdFlushVirtualMemory: return "NtFlushVirtualMemory";
    case PROBE_IDS::IdQueryQuotaInformationFile: return "NtQueryQuotaInformationFile";
    case PROBE_IDS::IdSetVolumeInformationFile: return "NtSetVolumeInformationFile";
    case PROBE_IDS::IdQueryInformationEnlistment: return "NtQueryInformationEnlistment";
    case PROBE_IDS::IdCreateIoCompletion: return "NtCreateIoCompletion";
    case PROBE_IDS::IdUnloadKeyEx: return "NtUnloadKeyEx";
    case PROBE_IDS::IdQueryEaFile: return "NtQueryEaFile";
    case PROBE_IDS::IdQueryDirectoryObject: return "NtQueryDirectoryObject";
    case PROBE_IDS::IdAddAtomEx: return "NtAddAtomEx";
    case PROBE_IDS::IdSinglePhaseReject: return "NtSinglePhaseReject";
    case PROBE_IDS::IdDeleteWnfStateName: return "NtDeleteWnfStateName";
    case PROBE_IDS::IdSetSystemEnvironmentValueEx: return "NtSetSystemEnvironmentValueEx";
    case PROBE_IDS::IdContinueEx: return "NtContinueEx";
    case PROBE_IDS::IdUnloadDriver: return "NtUnloadDriver";
    case PROBE_IDS::IdCallEnclave: return "NtCallEnclave";
    case PROBE_IDS::IdCancelIoFileEx: return "NtCancelIoFileEx";
    case PROBE_IDS::IdSetTimer: return "NtSetTimer";
    case PROBE_IDS::IdQuerySystemEnvironmentValue: return "NtQuerySystemEnvironmentValue";
    case PROBE_IDS::IdOpenThreadToken: return "NtOpenThreadToken";
    case PROBE_IDS::IdMapUserPhysicalPagesScatter: return "NtMapUserPhysicalPagesScatter";
    case PROBE_IDS::IdCreateResourceManager: return "NtCreateResourceManager";
    case PROBE_IDS::IdUnlockVirtualMemory: return "NtUnlockVirtualMemory";
    case PROBE_IDS::IdQueryInformationPort: return "NtQueryInformationPort";
    case PROBE_IDS::IdSetLowEventPair: return "NtSetLowEventPair";
    case PROBE_IDS::IdSetInformationKey: return "NtSetInformationKey";
    case PROBE_IDS::IdQuerySecurityPolicy: return "NtQuerySecurityPolicy";
    case PROBE_IDS::IdOpenProcessToken: return "NtOpenProcessToken";
    case PROBE_IDS::IdQueryVolumeInformationFile: return "NtQueryVolumeInformationFile";
    case PROBE_IDS::IdOpenTimer: return "NtOpenTimer";
    case PROBE_IDS::IdMapUserPhysicalPages: return "NtMapUserPhysicalPages";
    case PROBE_IDS::IdLoadKey: return "NtLoadKey";
    case PROBE_IDS::IdCreateWaitCompletionPacket: return "NtCreateWaitCompletionPacket";
    case PROBE_IDS::IdReleaseWorkerFactoryWorker: return "NtReleaseWorkerFactoryWorker";
    case PROBE_IDS::IdPrePrepareComplete: return "NtPrePrepareComplete";
    case PROBE_IDS::IdReadVirtualMemory: return "NtReadVirtualMemory";
    case PROBE_IDS::IdFreeVirtualMemory: return "NtFreeVirtualMemory";
    case PROBE_IDS::IdSetDriverEntryOrder: return "NtSetDriverEntryOrder";
    case PROBE_IDS::IdReadFile: return "NtReadFile";
    case PROBE_IDS::IdTraceControl: return "NtTraceControl";
    case PROBE_IDS::IdOpenProcessTokenEx: return "NtOpenProcessTokenEx";
    case PROBE_IDS::IdSecureConnectPort: return "NtSecureConnectPort";
    case PROBE_IDS::IdSaveKey: return "NtSaveKey";
    case PROBE_IDS::IdSetDefaultHardErrorPort: return "NtSetDefaultHardErrorPort";
    case PROBE_IDS::IdCreateEnclave: return "NtCreateEnclave";
    case PROBE_IDS::IdOpenPrivateNamespace: return "NtOpenPrivateNamespace";
    case PROBE_IDS::IdSetLdtEntries: return "NtSetLdtEntries";
    case PROBE_IDS::IdResetWriteWatch: return "NtResetWriteWatch";
    case PROBE_IDS::IdRenameKey: return "NtRenameKey";
    case PROBE_IDS::IdRevertContainerImpersonation: return "NtRevertContainerImpersonation";
    case PROBE_IDS::IdAlpcCreateSectionView: return "NtAlpcCreateSectionView";
    case PROBE_IDS::IdCreateCrossVmEvent: return "NtCreateCrossVmEvent";
    case PROBE_IDS::IdImpersonateThread: return "NtImpersonateThread";
    case PROBE_IDS::IdSetIRTimer: return "NtSetIRTimer";
    case PROBE_IDS::IdCreateDirectoryObjectEx: return "NtCreateDirectoryObjectEx";
    case PROBE_IDS::IdAcquireProcessActivityReference: return "NtAcquireProcessActivityReference";
    case PROBE_IDS::IdReplaceKey: return "NtReplaceKey";
    case PROBE_IDS::IdStartProfile: return "NtStartProfile";
    case PROBE_IDS::IdQueryBootEntryOrder: return "NtQueryBootEntryOrder";
    case PROBE_IDS::IdLockRegistryKey: return "NtLockRegistryKey";
    case PROBE_IDS::IdImpersonateClientOfPort: return "NtImpersonateClientOfPort";
    case PROBE_IDS::IdQueryEvent: return "NtQueryEvent";
    case PROBE_IDS::IdFsControlFile: return "NtFsControlFile";
    case PROBE_IDS::IdOpenProcess: return "NtOpenProcess";
    case PROBE_IDS::IdSetIoCompletion: return "NtSetIoCompletion";
    case PROBE_IDS::IdConnectPort: return "NtConnectPort";
    case PROBE_IDS::IdCloseObjectAuditAlarm: return "NtCloseObjectAuditAlarm";
    case PROBE_IDS::IdRequestWaitReplyPort: return "NtRequestWaitReplyPort";
    case PROBE_IDS::IdSetInformationObject: return "NtSetInformationObject";
    case PROBE_IDS::IdPrivilegeCheck: return "NtPrivilegeCheck";
    case PROBE_IDS::IdCallbackReturn: return "NtCallbackReturn";
    case PROBE_IDS::IdSetInformationToken: return "NtSetInformationToken";
    case PROBE_IDS::IdSetUuidSeed: return "NtSetUuidSeed";
    case PROBE_IDS::IdOpenKeyTransacted: return "NtOpenKeyTransacted";
    case PROBE_IDS::IdAlpcDeleteSecurityContext: return "NtAlpcDeleteSecurityContext";
    case PROBE_IDS::IdSetBootOptions: return "NtSetBootOptions";
    case PROBE_IDS::IdManageHotPatch: return "NtManageHotPatch";
    case PROBE_IDS::IdEnumerateTransactionObject: return "NtEnumerateTransactionObject";
    case PROBE_IDS::IdSetThreadExecutionState: return "NtSetThreadExecutionState";
    case PROBE_IDS::IdWaitLowEventPair: return "NtWaitLowEventPair";
    case PROBE_IDS::IdSetHighWaitLowEventPair: return "NtSetHighWaitLowEventPair";
    case PROBE_IDS::IdQueryInformationWorkerFactory: return "NtQueryInformationWorkerFactory";
    case PROBE_IDS::IdSetWnfProcessNotificationEvent: return "NtSetWnfProcessNotificationEvent";
    case PROBE_IDS::IdAlpcDeleteSectionView: return "NtAlpcDeleteSectionView";
    case PROBE_IDS::IdCreateMailslotFile: return "NtCreateMailslotFile";
    case PROBE_IDS::IdCreateProcess: return "NtCreateProcess";
    case PROBE_IDS::IdQueryIoCompletion: return "NtQueryIoCompletion";
    case PROBE_IDS::IdCreateTimer: return "NtCreateTimer";
    case PROBE_IDS::IdFlushInstallUILanguage: return "NtFlushInstallUILanguage";
    case PROBE_IDS::IdCompleteConnectPort: return "NtCompleteConnectPort";
    case PROBE_IDS::IdAlpcConnectPort: return "NtAlpcConnectPort";
    case PROBE_IDS::IdFreezeRegistry: return "NtFreezeRegistry";
    case PROBE_IDS::IdMapCMFModule: return "NtMapCMFModule";
    case PROBE_IDS::IdAllocateUserPhysicalPages: return "NtAllocateUserPhysicalPages";
    case PROBE_IDS::IdSetInformationEnlistment: return "NtSetInformationEnlistment";
    case PROBE_IDS::IdRaiseHardError: return "NtRaiseHardError";
    case PROBE_IDS::IdCreateSection: return "NtCreateSection";
    case PROBE_IDS::IdOpenIoCompletion: return "NtOpenIoCompletion";
    case PROBE_IDS::IdSystemDebugControl: return "NtSystemDebugControl";
    case PROBE_IDS::IdTranslateFilePath: return "NtTranslateFilePath";
    case PROBE_IDS::IdCreateIRTimer: return "NtCreateIRTimer";
    case PROBE_IDS::IdCreateRegistryTransaction: return "NtCreateRegistryTransaction";
    case PROBE_IDS::IdLoadKey2: return "NtLoadKey2";
    case PROBE_IDS::IdAlpcCreatePort: return "NtAlpcCreatePort";
    case PROBE_IDS::IdDeleteWnfStateData: return "NtDeleteWnfStateData";
    case PROBE_IDS::IdSetTimerEx: return "NtSetTimerEx";
    case PROBE_IDS::IdSetLowWaitHighEventPair: return "NtSetLowWaitHighEventPair";
    case PROBE_IDS::IdAlpcCreateSecurityContext: return "NtAlpcCreateSecurityContext";
    case PROBE_IDS::IdSetCachedSigningLevel: return "NtSetCachedSigningLevel";
    case PROBE_IDS::IdSetHighEventPair: return "NtSetHighEventPair";
    case PROBE_IDS::IdShutdownWorkerFactory: return "NtShutdownWorkerFactory";
    case PROBE_IDS::IdSetInformationJobObject: return "NtSetInformationJobObject";
    case PROBE_IDS::IdAdjustGroupsToken: return "NtAdjustGroupsToken";
    case PROBE_IDS::IdAreMappedFilesTheSame: return "NtAreMappedFilesTheSame";
    case PROBE_IDS::IdSetBootEntryOrder: return "NtSetBootEntryOrder";
    case PROBE_IDS::IdQueryMutant: return "NtQueryMutant";
    case PROBE_IDS::IdotifyChangeSession: return "NtNotifyChangeSession";
    case PROBE_IDS::IdQueryDefaultLocale: return "NtQueryDefaultLocale";
    case PROBE_IDS::IdCreateThreadEx: return "NtCreateThreadEx";
    case PROBE_IDS::IdQueryDriverEntryOrder: return "NtQueryDriverEntryOrder";
    case PROBE_IDS::IdSetTimerResolution: return "NtSetTimerResolution";
    case PROBE_IDS::IdPrePrepareEnlistment: return "NtPrePrepareEnlistment";
    case PROBE_IDS::IdCancelSynchronousIoFile: return "NtCancelSynchronousIoFile";
    case PROBE_IDS::IdQueryDirectoryFileEx: return "NtQueryDirectoryFileEx";
    case PROBE_IDS::IdAddDriverEntry: return "NtAddDriverEntry";
    case PROBE_IDS::IdUnloadKey: return "NtUnloadKey";
    case PROBE_IDS::IdCreateEvent: return "NtCreateEvent";
    case PROBE_IDS::IdOpenSession: return "NtOpenSession";
    case PROBE_IDS::IdQueryValueKey: return "NtQueryValueKey";
    case PROBE_IDS::IdCreatePrivateNamespace: return "NtCreatePrivateNamespace";
    case PROBE_IDS::IdIsUILanguageComitted: return "NtIsUILanguageComitted";
    case PROBE_IDS::IdAlertThread: return "NtAlertThread";
    case PROBE_IDS::IdQueryInstallUILanguage: return "NtQueryInstallUILanguage";
    case PROBE_IDS::IdCreateSymbolicLinkObject: return "NtCreateSymbolicLinkObject";
    case PROBE_IDS::IdAllocateUuids: return "NtAllocateUuids";
    case PROBE_IDS::IdShutdownSystem: return "NtShutdownSystem";
    case PROBE_IDS::IdCreateTokenEx: return "NtCreateTokenEx";
    case PROBE_IDS::IdQueryVirtualMemory: return "NtQueryVirtualMemory";
    case PROBE_IDS::IdAlpcOpenSenderProcess: return "NtAlpcOpenSenderProcess";
    case PROBE_IDS::IdAssignProcessToJobObject: return "NtAssignProcessToJobObject";
    case PROBE_IDS::IdRemoveIoCompletion: return "NtRemoveIoCompletion";
    case PROBE_IDS::IdCreateTimer2: return "NtCreateTimer2";
    case PROBE_IDS::IdCreateEnlistment: return "NtCreateEnlistment";
    case PROBE_IDS::IdRecoverEnlistment: return "NtRecoverEnlistment";
    case PROBE_IDS::IdCreateJobSet: return "NtCreateJobSet";
    case PROBE_IDS::IdSetIoCompletionEx: return "NtSetIoCompletionEx";
    case PROBE_IDS::IdCreateProcessEx: return "NtCreateProcessEx";
    case PROBE_IDS::IdAlpcConnectPortEx: return "NtAlpcConnectPortEx";
    case PROBE_IDS::IdWaitForMultipleObjects32: return "NtWaitForMultipleObjects32";
    case PROBE_IDS::IdRecoverResourceManager: return "NtRecoverResourceManager";
    case PROBE_IDS::IdAlpcSetInformation: return "NtAlpcSetInformation";
    case PROBE_IDS::IdAlpcRevokeSecurityContext: return "NtAlpcRevokeSecurityContext";
    case PROBE_IDS::IdAlpcImpersonateClientOfPort: return "NtAlpcImpersonateClientOfPort";
    case PROBE_IDS::IdReleaseKeyedEvent: return "NtReleaseKeyedEvent";
    case PROBE_IDS::IdTerminateThread: return "NtTerminateThread";
    case PROBE_IDS::IdSetInformationSymbolicLink: return "NtSetInformationSymbolicLink";
    case PROBE_IDS::IdDeleteObjectAuditAlarm: return "NtDeleteObjectAuditAlarm";
    case PROBE_IDS::IdWaitForKeyedEvent: return "NtWaitForKeyedEvent";
    case PROBE_IDS::IdCreatePort: return "NtCreatePort";
    case PROBE_IDS::IdDeletePrivateNamespace: return "NtDeletePrivateNamespace";
    case PROBE_IDS::IdotifyChangeMultipleKeys: return "NtNotifyChangeMultipleKeys";
    case PROBE_IDS::IdLockFile: return "NtLockFile";
    case PROBE_IDS::IdQueryDefaultUILanguage: return "NtQueryDefaultUILanguage";
    case PROBE_IDS::IdOpenEventPair: return "NtOpenEventPair";
    case PROBE_IDS::IdRollforwardTransactionManager: return "NtRollforwardTransactionManager";
    case PROBE_IDS::IdAlpcQueryInformationMessage: return "NtAlpcQueryInformationMessage";
    case PROBE_IDS::IdUnmapViewOfSection: return "NtUnmapViewOfSection";
    case PROBE_IDS::IdCancelIoFile: return "NtCancelIoFile";
    case PROBE_IDS::IdCreatePagingFile: return "NtCreatePagingFile";
    case PROBE_IDS::IdCancelTimer: return "NtCancelTimer";
    case PROBE_IDS::IdReplyWaitReceivePort: return "NtReplyWaitReceivePort";
    case PROBE_IDS::IdCompareObjects: return "NtCompareObjects";
    case PROBE_IDS::IdSetDefaultLocale: return "NtSetDefaultLocale";
    case PROBE_IDS::IdAllocateLocallyUniqueId: return "NtAllocateLocallyUniqueId";
    case PROBE_IDS::IdAccessCheckByTypeAndAuditAlarm: return "NtAccessCheckByTypeAndAuditAlarm";
    case PROBE_IDS::IdQueryDebugFilterState: return "NtQueryDebugFilterState";
    case PROBE_IDS::IdOpenSemaphore: return "NtOpenSemaphore";
    case PROBE_IDS::IdAllocateVirtualMemory: return "NtAllocateVirtualMemory";
    case PROBE_IDS::IdResumeProcess: return "NtResumeProcess";
    case PROBE_IDS::IdSetContextThread: return "NtSetContextThread";
    case PROBE_IDS::IdOpenSymbolicLinkObject: return "NtOpenSymbolicLinkObject";
    case PROBE_IDS::IdModifyDriverEntry: return "NtModifyDriverEntry";
    case PROBE_IDS::IdSerializeBoot: return "NtSerializeBoot";
    case PROBE_IDS::IdRenameTransactionManager: return "NtRenameTransactionManager";
    case PROBE_IDS::IdRemoveIoCompletionEx: return "NtRemoveIoCompletionEx";
    case PROBE_IDS::IdMapViewOfSectionEx: return "NtMapViewOfSectionEx";
    case PROBE_IDS::IdFilterTokenEx: return "NtFilterTokenEx";
    case PROBE_IDS::IdDeleteDriverEntry: return "NtDeleteDriverEntry";
    case PROBE_IDS::IdQuerySystemInformation: return "NtQuerySystemInformation";
    case PROBE_IDS::IdSetInformationWorkerFactory: return "NtSetInformationWorkerFactory";
    case PROBE_IDS::IdAdjustTokenClaimsAndDeviceGroups: return "NtAdjustTokenClaimsAndDeviceGroups";
    case PROBE_IDS::IdSaveMergedKeys: return "NtSaveMergedKeys";
    default: return "UNKNOWN";
    }
}

auto get_probe_argtypes(PROBE_IDS probeId) {
    switch (probeId) {
    case PROBE_IDS::IdLockProductActivationKeys: return make_span(arg_types<tLockProductActivationKeys>::value.begin(), arg_types<tLockProductActivationKeys>::value.end());
    case PROBE_IDS::IdWaitHighEventPair: return make_span(arg_types<tWaitHighEventPair>::value.begin(), arg_types<tWaitHighEventPair>::value.end());
    case PROBE_IDS::IdRegisterThreadTerminatePort: return make_span(arg_types<tRegisterThreadTerminatePort>::value.begin(), arg_types<tRegisterThreadTerminatePort>::value.end());
    case PROBE_IDS::IdAssociateWaitCompletionPacket: return make_span(arg_types<tAssociateWaitCompletionPacket>::value.begin(), arg_types<tAssociateWaitCompletionPacket>::value.end());
    case PROBE_IDS::IdQueryPerformanceCounter: return make_span(arg_types<tQueryPerformanceCounter>::value.begin(), arg_types<tQueryPerformanceCounter>::value.end());
    case PROBE_IDS::IdCompactKeys: return make_span(arg_types<tCompactKeys>::value.begin(), arg_types<tCompactKeys>::value.end());
    case PROBE_IDS::IdQuerySystemInformationEx: return make_span(arg_types<tQuerySystemInformationEx>::value.begin(), arg_types<tQuerySystemInformationEx>::value.end());
    case PROBE_IDS::IdResetEvent: return make_span(arg_types<tResetEvent>::value.begin(), arg_types<tResetEvent>::value.end());
    case PROBE_IDS::IdGetContextThread: return make_span(arg_types<tGetContextThread>::value.begin(), arg_types<tGetContextThread>::value.end());
    case PROBE_IDS::IdQueryInformationThread: return make_span(arg_types<tQueryInformationThread>::value.begin(), arg_types<tQueryInformationThread>::value.end());
    case PROBE_IDS::IdWaitForSingleObject: return make_span(arg_types<tWaitForSingleObject>::value.begin(), arg_types<tWaitForSingleObject>::value.end());
    case PROBE_IDS::IdFlushBuffersFileEx: return make_span(arg_types<tFlushBuffersFileEx>::value.begin(), arg_types<tFlushBuffersFileEx>::value.end());
    case PROBE_IDS::IdUnloadKey2: return make_span(arg_types<tUnloadKey2>::value.begin(), arg_types<tUnloadKey2>::value.end());
    case PROBE_IDS::IdReadOnlyEnlistment: return make_span(arg_types<tReadOnlyEnlistment>::value.begin(), arg_types<tReadOnlyEnlistment>::value.end());
    case PROBE_IDS::IdDeleteFile: return make_span(arg_types<tDeleteFile>::value.begin(), arg_types<tDeleteFile>::value.end());
    case PROBE_IDS::IdDeleteAtom: return make_span(arg_types<tDeleteAtom>::value.begin(), arg_types<tDeleteAtom>::value.end());
    case PROBE_IDS::IdQueryDirectoryFile: return make_span(arg_types<tQueryDirectoryFile>::value.begin(), arg_types<tQueryDirectoryFile>::value.end());
    case PROBE_IDS::IdSetEventBoostPriority: return make_span(arg_types<tSetEventBoostPriority>::value.begin(), arg_types<tSetEventBoostPriority>::value.end());
    case PROBE_IDS::IdAllocateUserPhysicalPagesEx: return make_span(arg_types<tAllocateUserPhysicalPagesEx>::value.begin(), arg_types<tAllocateUserPhysicalPagesEx>::value.end());
    case PROBE_IDS::IdWriteFile: return make_span(arg_types<tWriteFile>::value.begin(), arg_types<tWriteFile>::value.end());
    case PROBE_IDS::IdQueryInformationFile: return make_span(arg_types<tQueryInformationFile>::value.begin(), arg_types<tQueryInformationFile>::value.end());
    case PROBE_IDS::IdAlpcCancelMessage: return make_span(arg_types<tAlpcCancelMessage>::value.begin(), arg_types<tAlpcCancelMessage>::value.end());
    case PROBE_IDS::IdOpenMutant: return make_span(arg_types<tOpenMutant>::value.begin(), arg_types<tOpenMutant>::value.end());
    case PROBE_IDS::IdCreatePartition: return make_span(arg_types<tCreatePartition>::value.begin(), arg_types<tCreatePartition>::value.end());
    case PROBE_IDS::IdQueryTimer: return make_span(arg_types<tQueryTimer>::value.begin(), arg_types<tQueryTimer>::value.end());
    case PROBE_IDS::IdOpenEvent: return make_span(arg_types<tOpenEvent>::value.begin(), arg_types<tOpenEvent>::value.end());
    case PROBE_IDS::IdOpenObjectAuditAlarm: return make_span(arg_types<tOpenObjectAuditAlarm>::value.begin(), arg_types<tOpenObjectAuditAlarm>::value.end());
    case PROBE_IDS::IdMakePermanentObject: return make_span(arg_types<tMakePermanentObject>::value.begin(), arg_types<tMakePermanentObject>::value.end());
    case PROBE_IDS::IdCommitTransaction: return make_span(arg_types<tCommitTransaction>::value.begin(), arg_types<tCommitTransaction>::value.end());
    case PROBE_IDS::IdSetSystemTime: return make_span(arg_types<tSetSystemTime>::value.begin(), arg_types<tSetSystemTime>::value.end());
    case PROBE_IDS::IdGetDevicePowerState: return make_span(arg_types<tGetDevicePowerState>::value.begin(), arg_types<tGetDevicePowerState>::value.end());
    case PROBE_IDS::IdSetSystemPowerState: return make_span(arg_types<tSetSystemPowerState>::value.begin(), arg_types<tSetSystemPowerState>::value.end());
    case PROBE_IDS::IdAlpcCreateResourceReserve: return make_span(arg_types<tAlpcCreateResourceReserve>::value.begin(), arg_types<tAlpcCreateResourceReserve>::value.end());
    case PROBE_IDS::IdUnlockFile: return make_span(arg_types<tUnlockFile>::value.begin(), arg_types<tUnlockFile>::value.end());
    case PROBE_IDS::IdAlpcDeletePortSection: return make_span(arg_types<tAlpcDeletePortSection>::value.begin(), arg_types<tAlpcDeletePortSection>::value.end());
    case PROBE_IDS::IdSetInformationResourceManager: return make_span(arg_types<tSetInformationResourceManager>::value.begin(), arg_types<tSetInformationResourceManager>::value.end());
    case PROBE_IDS::IdFreeUserPhysicalPages: return make_span(arg_types<tFreeUserPhysicalPages>::value.begin(), arg_types<tFreeUserPhysicalPages>::value.end());
    case PROBE_IDS::IdLoadKeyEx: return make_span(arg_types<tLoadKeyEx>::value.begin(), arg_types<tLoadKeyEx>::value.end());
    case PROBE_IDS::IdPropagationComplete: return make_span(arg_types<tPropagationComplete>::value.begin(), arg_types<tPropagationComplete>::value.end());
    case PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarm: return make_span(arg_types<tAccessCheckByTypeResultListAndAuditAlarm>::value.begin(), arg_types<tAccessCheckByTypeResultListAndAuditAlarm>::value.end());
    case PROBE_IDS::IdQueryInformationToken: return make_span(arg_types<tQueryInformationToken>::value.begin(), arg_types<tQueryInformationToken>::value.end());
    case PROBE_IDS::IdRegisterProtocolAddressInformation: return make_span(arg_types<tRegisterProtocolAddressInformation>::value.begin(), arg_types<tRegisterProtocolAddressInformation>::value.end());
    case PROBE_IDS::IdProtectVirtualMemory: return make_span(arg_types<tProtectVirtualMemory>::value.begin(), arg_types<tProtectVirtualMemory>::value.end());
    case PROBE_IDS::IdCreateKey: return make_span(arg_types<tCreateKey>::value.begin(), arg_types<tCreateKey>::value.end());
    case PROBE_IDS::IdAlpcSendWaitReceivePort: return make_span(arg_types<tAlpcSendWaitReceivePort>::value.begin(), arg_types<tAlpcSendWaitReceivePort>::value.end());
    case PROBE_IDS::IdOpenRegistryTransaction: return make_span(arg_types<tOpenRegistryTransaction>::value.begin(), arg_types<tOpenRegistryTransaction>::value.end());
    case PROBE_IDS::IdTerminateProcess: return make_span(arg_types<tTerminateProcess>::value.begin(), arg_types<tTerminateProcess>::value.end());
    case PROBE_IDS::IdPowerInformation: return make_span(arg_types<tPowerInformation>::value.begin(), arg_types<tPowerInformation>::value.end());
    case PROBE_IDS::IdotifyChangeDirectoryFile: return make_span(arg_types<totifyChangeDirectoryFile>::value.begin(), arg_types<totifyChangeDirectoryFile>::value.end());
    case PROBE_IDS::IdCreateTransaction: return make_span(arg_types<tCreateTransaction>::value.begin(), arg_types<tCreateTransaction>::value.end());
    case PROBE_IDS::IdCreateProfileEx: return make_span(arg_types<tCreateProfileEx>::value.begin(), arg_types<tCreateProfileEx>::value.end());
    case PROBE_IDS::IdQueryLicenseValue: return make_span(arg_types<tQueryLicenseValue>::value.begin(), arg_types<tQueryLicenseValue>::value.end());
    case PROBE_IDS::IdCreateProfile: return make_span(arg_types<tCreateProfile>::value.begin(), arg_types<tCreateProfile>::value.end());
    case PROBE_IDS::IdInitializeRegistry: return make_span(arg_types<tInitializeRegistry>::value.begin(), arg_types<tInitializeRegistry>::value.end());
    case PROBE_IDS::IdFreezeTransactions: return make_span(arg_types<tFreezeTransactions>::value.begin(), arg_types<tFreezeTransactions>::value.end());
    case PROBE_IDS::IdOpenJobObject: return make_span(arg_types<tOpenJobObject>::value.begin(), arg_types<tOpenJobObject>::value.end());
    case PROBE_IDS::IdSubscribeWnfStateChange: return make_span(arg_types<tSubscribeWnfStateChange>::value.begin(), arg_types<tSubscribeWnfStateChange>::value.end());
    case PROBE_IDS::IdGetWriteWatch: return make_span(arg_types<tGetWriteWatch>::value.begin(), arg_types<tGetWriteWatch>::value.end());
    case PROBE_IDS::IdGetCachedSigningLevel: return make_span(arg_types<tGetCachedSigningLevel>::value.begin(), arg_types<tGetCachedSigningLevel>::value.end());
    case PROBE_IDS::IdSetSecurityObject: return make_span(arg_types<tSetSecurityObject>::value.begin(), arg_types<tSetSecurityObject>::value.end());
    case PROBE_IDS::IdQueryIntervalProfile: return make_span(arg_types<tQueryIntervalProfile>::value.begin(), arg_types<tQueryIntervalProfile>::value.end());
    case PROBE_IDS::IdPropagationFailed: return make_span(arg_types<tPropagationFailed>::value.begin(), arg_types<tPropagationFailed>::value.end());
    case PROBE_IDS::IdCreateSectionEx: return make_span(arg_types<tCreateSectionEx>::value.begin(), arg_types<tCreateSectionEx>::value.end());
    case PROBE_IDS::IdRaiseException: return make_span(arg_types<tRaiseException>::value.begin(), arg_types<tRaiseException>::value.end());
    case PROBE_IDS::IdSetCachedSigningLevel2: return make_span(arg_types<tSetCachedSigningLevel2>::value.begin(), arg_types<tSetCachedSigningLevel2>::value.end());
    case PROBE_IDS::IdCommitEnlistment: return make_span(arg_types<tCommitEnlistment>::value.begin(), arg_types<tCommitEnlistment>::value.end());
    case PROBE_IDS::IdQueryInformationByName: return make_span(arg_types<tQueryInformationByName>::value.begin(), arg_types<tQueryInformationByName>::value.end());
    case PROBE_IDS::IdCreateThread: return make_span(arg_types<tCreateThread>::value.begin(), arg_types<tCreateThread>::value.end());
    case PROBE_IDS::IdOpenResourceManager: return make_span(arg_types<tOpenResourceManager>::value.begin(), arg_types<tOpenResourceManager>::value.end());
    case PROBE_IDS::IdReadRequestData: return make_span(arg_types<tReadRequestData>::value.begin(), arg_types<tReadRequestData>::value.end());
    case PROBE_IDS::IdClearEvent: return make_span(arg_types<tClearEvent>::value.begin(), arg_types<tClearEvent>::value.end());
    case PROBE_IDS::IdTestAlert: return make_span(arg_types<tTestAlert>::value.begin(), arg_types<tTestAlert>::value.end());
    case PROBE_IDS::IdSetInformationThread: return make_span(arg_types<tSetInformationThread>::value.begin(), arg_types<tSetInformationThread>::value.end());
    case PROBE_IDS::IdSetTimer2: return make_span(arg_types<tSetTimer2>::value.begin(), arg_types<tSetTimer2>::value.end());
    case PROBE_IDS::IdSetDefaultUILanguage: return make_span(arg_types<tSetDefaultUILanguage>::value.begin(), arg_types<tSetDefaultUILanguage>::value.end());
    case PROBE_IDS::IdEnumerateValueKey: return make_span(arg_types<tEnumerateValueKey>::value.begin(), arg_types<tEnumerateValueKey>::value.end());
    case PROBE_IDS::IdOpenEnlistment: return make_span(arg_types<tOpenEnlistment>::value.begin(), arg_types<tOpenEnlistment>::value.end());
    case PROBE_IDS::IdSetIntervalProfile: return make_span(arg_types<tSetIntervalProfile>::value.begin(), arg_types<tSetIntervalProfile>::value.end());
    case PROBE_IDS::IdQueryPortInformationProcess: return make_span(arg_types<tQueryPortInformationProcess>::value.begin(), arg_types<tQueryPortInformationProcess>::value.end());
    case PROBE_IDS::IdQueryInformationTransactionManager: return make_span(arg_types<tQueryInformationTransactionManager>::value.begin(), arg_types<tQueryInformationTransactionManager>::value.end());
    case PROBE_IDS::IdSetInformationTransactionManager: return make_span(arg_types<tSetInformationTransactionManager>::value.begin(), arg_types<tSetInformationTransactionManager>::value.end());
    case PROBE_IDS::IdInitializeEnclave: return make_span(arg_types<tInitializeEnclave>::value.begin(), arg_types<tInitializeEnclave>::value.end());
    case PROBE_IDS::IdPrepareComplete: return make_span(arg_types<tPrepareComplete>::value.begin(), arg_types<tPrepareComplete>::value.end());
    case PROBE_IDS::IdQueueApcThread: return make_span(arg_types<tQueueApcThread>::value.begin(), arg_types<tQueueApcThread>::value.end());
    case PROBE_IDS::IdWorkerFactoryWorkerReady: return make_span(arg_types<tWorkerFactoryWorkerReady>::value.begin(), arg_types<tWorkerFactoryWorkerReady>::value.end());
    case PROBE_IDS::IdGetCompleteWnfStateSubscription: return make_span(arg_types<tGetCompleteWnfStateSubscription>::value.begin(), arg_types<tGetCompleteWnfStateSubscription>::value.end());
    case PROBE_IDS::IdAlertThreadByThreadId: return make_span(arg_types<tAlertThreadByThreadId>::value.begin(), arg_types<tAlertThreadByThreadId>::value.end());
    case PROBE_IDS::IdLockVirtualMemory: return make_span(arg_types<tLockVirtualMemory>::value.begin(), arg_types<tLockVirtualMemory>::value.end());
    case PROBE_IDS::IdDeviceIoControlFile: return make_span(arg_types<tDeviceIoControlFile>::value.begin(), arg_types<tDeviceIoControlFile>::value.end());
    case PROBE_IDS::IdCreateUserProcess: return make_span(arg_types<tCreateUserProcess>::value.begin(), arg_types<tCreateUserProcess>::value.end());
    case PROBE_IDS::IdQuerySection: return make_span(arg_types<tQuerySection>::value.begin(), arg_types<tQuerySection>::value.end());
    case PROBE_IDS::IdSaveKeyEx: return make_span(arg_types<tSaveKeyEx>::value.begin(), arg_types<tSaveKeyEx>::value.end());
    case PROBE_IDS::IdRollbackTransaction: return make_span(arg_types<tRollbackTransaction>::value.begin(), arg_types<tRollbackTransaction>::value.end());
    case PROBE_IDS::IdTraceEvent: return make_span(arg_types<tTraceEvent>::value.begin(), arg_types<tTraceEvent>::value.end());
    case PROBE_IDS::IdOpenSection: return make_span(arg_types<tOpenSection>::value.begin(), arg_types<tOpenSection>::value.end());
    case PROBE_IDS::IdRequestPort: return make_span(arg_types<tRequestPort>::value.begin(), arg_types<tRequestPort>::value.end());
    case PROBE_IDS::IdUnsubscribeWnfStateChange: return make_span(arg_types<tUnsubscribeWnfStateChange>::value.begin(), arg_types<tUnsubscribeWnfStateChange>::value.end());
    case PROBE_IDS::IdThawRegistry: return make_span(arg_types<tThawRegistry>::value.begin(), arg_types<tThawRegistry>::value.end());
    case PROBE_IDS::IdCreateJobObject: return make_span(arg_types<tCreateJobObject>::value.begin(), arg_types<tCreateJobObject>::value.end());
    case PROBE_IDS::IdOpenKeyTransactedEx: return make_span(arg_types<tOpenKeyTransactedEx>::value.begin(), arg_types<tOpenKeyTransactedEx>::value.end());
    case PROBE_IDS::IdWaitForMultipleObjects: return make_span(arg_types<tWaitForMultipleObjects>::value.begin(), arg_types<tWaitForMultipleObjects>::value.end());
    case PROBE_IDS::IdDuplicateToken: return make_span(arg_types<tDuplicateToken>::value.begin(), arg_types<tDuplicateToken>::value.end());
    case PROBE_IDS::IdAlpcOpenSenderThread: return make_span(arg_types<tAlpcOpenSenderThread>::value.begin(), arg_types<tAlpcOpenSenderThread>::value.end());
    case PROBE_IDS::IdAlpcImpersonateClientContainerOfPort: return make_span(arg_types<tAlpcImpersonateClientContainerOfPort>::value.begin(), arg_types<tAlpcImpersonateClientContainerOfPort>::value.end());
    case PROBE_IDS::IdDrawText: return make_span(arg_types<tDrawText>::value.begin(), arg_types<tDrawText>::value.end());
    case PROBE_IDS::IdReleaseSemaphore: return make_span(arg_types<tReleaseSemaphore>::value.begin(), arg_types<tReleaseSemaphore>::value.end());
    case PROBE_IDS::IdSetQuotaInformationFile: return make_span(arg_types<tSetQuotaInformationFile>::value.begin(), arg_types<tSetQuotaInformationFile>::value.end());
    case PROBE_IDS::IdQueryInformationAtom: return make_span(arg_types<tQueryInformationAtom>::value.begin(), arg_types<tQueryInformationAtom>::value.end());
    case PROBE_IDS::IdEnumerateBootEntries: return make_span(arg_types<tEnumerateBootEntries>::value.begin(), arg_types<tEnumerateBootEntries>::value.end());
    case PROBE_IDS::IdThawTransactions: return make_span(arg_types<tThawTransactions>::value.begin(), arg_types<tThawTransactions>::value.end());
    case PROBE_IDS::IdAccessCheck: return make_span(arg_types<tAccessCheck>::value.begin(), arg_types<tAccessCheck>::value.end());
    case PROBE_IDS::IdFlushProcessWriteBuffers: return make_span(arg_types<tFlushProcessWriteBuffers>::value.begin(), arg_types<tFlushProcessWriteBuffers>::value.end());
    case PROBE_IDS::IdQuerySemaphore: return make_span(arg_types<tQuerySemaphore>::value.begin(), arg_types<tQuerySemaphore>::value.end());
    case PROBE_IDS::IdCreateNamedPipeFile: return make_span(arg_types<tCreateNamedPipeFile>::value.begin(), arg_types<tCreateNamedPipeFile>::value.end());
    case PROBE_IDS::IdAlpcDeleteResourceReserve: return make_span(arg_types<tAlpcDeleteResourceReserve>::value.begin(), arg_types<tAlpcDeleteResourceReserve>::value.end());
    case PROBE_IDS::IdQuerySystemEnvironmentValueEx: return make_span(arg_types<tQuerySystemEnvironmentValueEx>::value.begin(), arg_types<tQuerySystemEnvironmentValueEx>::value.end());
    case PROBE_IDS::IdReadFileScatter: return make_span(arg_types<tReadFileScatter>::value.begin(), arg_types<tReadFileScatter>::value.end());
    case PROBE_IDS::IdOpenKeyEx: return make_span(arg_types<tOpenKeyEx>::value.begin(), arg_types<tOpenKeyEx>::value.end());
    case PROBE_IDS::IdSignalAndWaitForSingleObject: return make_span(arg_types<tSignalAndWaitForSingleObject>::value.begin(), arg_types<tSignalAndWaitForSingleObject>::value.end());
    case PROBE_IDS::IdReleaseMutant: return make_span(arg_types<tReleaseMutant>::value.begin(), arg_types<tReleaseMutant>::value.end());
    case PROBE_IDS::IdTerminateJobObject: return make_span(arg_types<tTerminateJobObject>::value.begin(), arg_types<tTerminateJobObject>::value.end());
    case PROBE_IDS::IdSetSystemEnvironmentValue: return make_span(arg_types<tSetSystemEnvironmentValue>::value.begin(), arg_types<tSetSystemEnvironmentValue>::value.end());
    case PROBE_IDS::IdClose: return make_span(arg_types<tClose>::value.begin(), arg_types<tClose>::value.end());
    case PROBE_IDS::IdQueueApcThreadEx: return make_span(arg_types<tQueueApcThreadEx>::value.begin(), arg_types<tQueueApcThreadEx>::value.end());
    case PROBE_IDS::IdQueryMultipleValueKey: return make_span(arg_types<tQueryMultipleValueKey>::value.begin(), arg_types<tQueryMultipleValueKey>::value.end());
    case PROBE_IDS::IdAlpcQueryInformation: return make_span(arg_types<tAlpcQueryInformation>::value.begin(), arg_types<tAlpcQueryInformation>::value.end());
    case PROBE_IDS::IdUpdateWnfStateData: return make_span(arg_types<tUpdateWnfStateData>::value.begin(), arg_types<tUpdateWnfStateData>::value.end());
    case PROBE_IDS::IdListenPort: return make_span(arg_types<tListenPort>::value.begin(), arg_types<tListenPort>::value.end());
    case PROBE_IDS::IdFlushInstructionCache: return make_span(arg_types<tFlushInstructionCache>::value.begin(), arg_types<tFlushInstructionCache>::value.end());
    case PROBE_IDS::IdGetNotificationResourceManager: return make_span(arg_types<tGetNotificationResourceManager>::value.begin(), arg_types<tGetNotificationResourceManager>::value.end());
    case PROBE_IDS::IdQueryFullAttributesFile: return make_span(arg_types<tQueryFullAttributesFile>::value.begin(), arg_types<tQueryFullAttributesFile>::value.end());
    case PROBE_IDS::IdSuspendThread: return make_span(arg_types<tSuspendThread>::value.begin(), arg_types<tSuspendThread>::value.end());
    case PROBE_IDS::IdCompareTokens: return make_span(arg_types<tCompareTokens>::value.begin(), arg_types<tCompareTokens>::value.end());
    case PROBE_IDS::IdCancelWaitCompletionPacket: return make_span(arg_types<tCancelWaitCompletionPacket>::value.begin(), arg_types<tCancelWaitCompletionPacket>::value.end());
    case PROBE_IDS::IdAlpcAcceptConnectPort: return make_span(arg_types<tAlpcAcceptConnectPort>::value.begin(), arg_types<tAlpcAcceptConnectPort>::value.end());
    case PROBE_IDS::IdOpenTransaction: return make_span(arg_types<tOpenTransaction>::value.begin(), arg_types<tOpenTransaction>::value.end());
    case PROBE_IDS::IdImpersonateAnonymousToken: return make_span(arg_types<tImpersonateAnonymousToken>::value.begin(), arg_types<tImpersonateAnonymousToken>::value.end());
    case PROBE_IDS::IdQuerySecurityObject: return make_span(arg_types<tQuerySecurityObject>::value.begin(), arg_types<tQuerySecurityObject>::value.end());
    case PROBE_IDS::IdRollbackEnlistment: return make_span(arg_types<tRollbackEnlistment>::value.begin(), arg_types<tRollbackEnlistment>::value.end());
    case PROBE_IDS::IdReplacePartitionUnit: return make_span(arg_types<tReplacePartitionUnit>::value.begin(), arg_types<tReplacePartitionUnit>::value.end());
    case PROBE_IDS::IdCreateKeyTransacted: return make_span(arg_types<tCreateKeyTransacted>::value.begin(), arg_types<tCreateKeyTransacted>::value.end());
    case PROBE_IDS::IdConvertBetweenAuxiliaryCounterAndPerformanceCounter: return make_span(arg_types<tConvertBetweenAuxiliaryCounterAndPerformanceCounter>::value.begin(), arg_types<tConvertBetweenAuxiliaryCounterAndPerformanceCounter>::value.end());
    case PROBE_IDS::IdCreateKeyedEvent: return make_span(arg_types<tCreateKeyedEvent>::value.begin(), arg_types<tCreateKeyedEvent>::value.end());
    case PROBE_IDS::IdCreateEventPair: return make_span(arg_types<tCreateEventPair>::value.begin(), arg_types<tCreateEventPair>::value.end());
    case PROBE_IDS::IdAddAtom: return make_span(arg_types<tAddAtom>::value.begin(), arg_types<tAddAtom>::value.end());
    case PROBE_IDS::IdQueryOpenSubKeys: return make_span(arg_types<tQueryOpenSubKeys>::value.begin(), arg_types<tQueryOpenSubKeys>::value.end());
    case PROBE_IDS::IdQuerySystemTime: return make_span(arg_types<tQuerySystemTime>::value.begin(), arg_types<tQuerySystemTime>::value.end());
    case PROBE_IDS::IdSetEaFile: return make_span(arg_types<tSetEaFile>::value.begin(), arg_types<tSetEaFile>::value.end());
    case PROBE_IDS::IdSetInformationProcess: return make_span(arg_types<tSetInformationProcess>::value.begin(), arg_types<tSetInformationProcess>::value.end());
    case PROBE_IDS::IdSetValueKey: return make_span(arg_types<tSetValueKey>::value.begin(), arg_types<tSetValueKey>::value.end());
    case PROBE_IDS::IdQuerySymbolicLinkObject: return make_span(arg_types<tQuerySymbolicLinkObject>::value.begin(), arg_types<tQuerySymbolicLinkObject>::value.end());
    case PROBE_IDS::IdQueryOpenSubKeysEx: return make_span(arg_types<tQueryOpenSubKeysEx>::value.begin(), arg_types<tQueryOpenSubKeysEx>::value.end());
    case PROBE_IDS::IdotifyChangeKey: return make_span(arg_types<totifyChangeKey>::value.begin(), arg_types<totifyChangeKey>::value.end());
    case PROBE_IDS::IdIsProcessInJob: return make_span(arg_types<tIsProcessInJob>::value.begin(), arg_types<tIsProcessInJob>::value.end());
    case PROBE_IDS::IdCommitComplete: return make_span(arg_types<tCommitComplete>::value.begin(), arg_types<tCommitComplete>::value.end());
    case PROBE_IDS::IdEnumerateDriverEntries: return make_span(arg_types<tEnumerateDriverEntries>::value.begin(), arg_types<tEnumerateDriverEntries>::value.end());
    case PROBE_IDS::IdAccessCheckByTypeResultList: return make_span(arg_types<tAccessCheckByTypeResultList>::value.begin(), arg_types<tAccessCheckByTypeResultList>::value.end());
    case PROBE_IDS::IdLoadEnclaveData: return make_span(arg_types<tLoadEnclaveData>::value.begin(), arg_types<tLoadEnclaveData>::value.end());
    case PROBE_IDS::IdAllocateVirtualMemoryEx: return make_span(arg_types<tAllocateVirtualMemoryEx>::value.begin(), arg_types<tAllocateVirtualMemoryEx>::value.end());
    case PROBE_IDS::IdWaitForWorkViaWorkerFactory: return make_span(arg_types<tWaitForWorkViaWorkerFactory>::value.begin(), arg_types<tWaitForWorkViaWorkerFactory>::value.end());
    case PROBE_IDS::IdQueryInformationResourceManager: return make_span(arg_types<tQueryInformationResourceManager>::value.begin(), arg_types<tQueryInformationResourceManager>::value.end());
    case PROBE_IDS::IdEnumerateKey: return make_span(arg_types<tEnumerateKey>::value.begin(), arg_types<tEnumerateKey>::value.end());
    case PROBE_IDS::IdGetMUIRegistryInfo: return make_span(arg_types<tGetMUIRegistryInfo>::value.begin(), arg_types<tGetMUIRegistryInfo>::value.end());
    case PROBE_IDS::IdAcceptConnectPort: return make_span(arg_types<tAcceptConnectPort>::value.begin(), arg_types<tAcceptConnectPort>::value.end());
    case PROBE_IDS::IdRecoverTransactionManager: return make_span(arg_types<tRecoverTransactionManager>::value.begin(), arg_types<tRecoverTransactionManager>::value.end());
    case PROBE_IDS::IdWriteVirtualMemory: return make_span(arg_types<tWriteVirtualMemory>::value.begin(), arg_types<tWriteVirtualMemory>::value.end());
    case PROBE_IDS::IdQueryBootOptions: return make_span(arg_types<tQueryBootOptions>::value.begin(), arg_types<tQueryBootOptions>::value.end());
    case PROBE_IDS::IdRollbackComplete: return make_span(arg_types<tRollbackComplete>::value.begin(), arg_types<tRollbackComplete>::value.end());
    case PROBE_IDS::IdQueryAuxiliaryCounterFrequency: return make_span(arg_types<tQueryAuxiliaryCounterFrequency>::value.begin(), arg_types<tQueryAuxiliaryCounterFrequency>::value.end());
    case PROBE_IDS::IdAlpcCreatePortSection: return make_span(arg_types<tAlpcCreatePortSection>::value.begin(), arg_types<tAlpcCreatePortSection>::value.end());
    case PROBE_IDS::IdQueryObject: return make_span(arg_types<tQueryObject>::value.begin(), arg_types<tQueryObject>::value.end());
    case PROBE_IDS::IdQueryWnfStateData: return make_span(arg_types<tQueryWnfStateData>::value.begin(), arg_types<tQueryWnfStateData>::value.end());
    case PROBE_IDS::IdInitiatePowerAction: return make_span(arg_types<tInitiatePowerAction>::value.begin(), arg_types<tInitiatePowerAction>::value.end());
    case PROBE_IDS::IdDirectGraphicsCall: return make_span(arg_types<tDirectGraphicsCall>::value.begin(), arg_types<tDirectGraphicsCall>::value.end());
    case PROBE_IDS::IdAcquireCrossVmMutant: return make_span(arg_types<tAcquireCrossVmMutant>::value.begin(), arg_types<tAcquireCrossVmMutant>::value.end());
    case PROBE_IDS::IdRollbackRegistryTransaction: return make_span(arg_types<tRollbackRegistryTransaction>::value.begin(), arg_types<tRollbackRegistryTransaction>::value.end());
    case PROBE_IDS::IdAlertResumeThread: return make_span(arg_types<tAlertResumeThread>::value.begin(), arg_types<tAlertResumeThread>::value.end());
    case PROBE_IDS::IdPssCaptureVaSpaceBulk: return make_span(arg_types<tPssCaptureVaSpaceBulk>::value.begin(), arg_types<tPssCaptureVaSpaceBulk>::value.end());
    case PROBE_IDS::IdCreateToken: return make_span(arg_types<tCreateToken>::value.begin(), arg_types<tCreateToken>::value.end());
    case PROBE_IDS::IdPrepareEnlistment: return make_span(arg_types<tPrepareEnlistment>::value.begin(), arg_types<tPrepareEnlistment>::value.end());
    case PROBE_IDS::IdFlushWriteBuffer: return make_span(arg_types<tFlushWriteBuffer>::value.begin(), arg_types<tFlushWriteBuffer>::value.end());
    case PROBE_IDS::IdCommitRegistryTransaction: return make_span(arg_types<tCommitRegistryTransaction>::value.begin(), arg_types<tCommitRegistryTransaction>::value.end());
    case PROBE_IDS::IdAccessCheckByType: return make_span(arg_types<tAccessCheckByType>::value.begin(), arg_types<tAccessCheckByType>::value.end());
    case PROBE_IDS::IdOpenThread: return make_span(arg_types<tOpenThread>::value.begin(), arg_types<tOpenThread>::value.end());
    case PROBE_IDS::IdAccessCheckAndAuditAlarm: return make_span(arg_types<tAccessCheckAndAuditAlarm>::value.begin(), arg_types<tAccessCheckAndAuditAlarm>::value.end());
    case PROBE_IDS::IdOpenThreadTokenEx: return make_span(arg_types<tOpenThreadTokenEx>::value.begin(), arg_types<tOpenThreadTokenEx>::value.end());
    case PROBE_IDS::IdWriteRequestData: return make_span(arg_types<tWriteRequestData>::value.begin(), arg_types<tWriteRequestData>::value.end());
    case PROBE_IDS::IdCreateWorkerFactory: return make_span(arg_types<tCreateWorkerFactory>::value.begin(), arg_types<tCreateWorkerFactory>::value.end());
    case PROBE_IDS::IdOpenPartition: return make_span(arg_types<tOpenPartition>::value.begin(), arg_types<tOpenPartition>::value.end());
    case PROBE_IDS::IdSetSystemInformation: return make_span(arg_types<tSetSystemInformation>::value.begin(), arg_types<tSetSystemInformation>::value.end());
    case PROBE_IDS::IdEnumerateSystemEnvironmentValuesEx: return make_span(arg_types<tEnumerateSystemEnvironmentValuesEx>::value.begin(), arg_types<tEnumerateSystemEnvironmentValuesEx>::value.end());
    case PROBE_IDS::IdCreateWnfStateName: return make_span(arg_types<tCreateWnfStateName>::value.begin(), arg_types<tCreateWnfStateName>::value.end());
    case PROBE_IDS::IdQueryInformationJobObject: return make_span(arg_types<tQueryInformationJobObject>::value.begin(), arg_types<tQueryInformationJobObject>::value.end());
    case PROBE_IDS::IdPrivilegedServiceAuditAlarm: return make_span(arg_types<tPrivilegedServiceAuditAlarm>::value.begin(), arg_types<tPrivilegedServiceAuditAlarm>::value.end());
    case PROBE_IDS::IdEnableLastKnownGood: return make_span(arg_types<tEnableLastKnownGood>::value.begin(), arg_types<tEnableLastKnownGood>::value.end());
    case PROBE_IDS::IdotifyChangeDirectoryFileEx: return make_span(arg_types<totifyChangeDirectoryFileEx>::value.begin(), arg_types<totifyChangeDirectoryFileEx>::value.end());
    case PROBE_IDS::IdCreateWaitablePort: return make_span(arg_types<tCreateWaitablePort>::value.begin(), arg_types<tCreateWaitablePort>::value.end());
    case PROBE_IDS::IdWaitForAlertByThreadId: return make_span(arg_types<tWaitForAlertByThreadId>::value.begin(), arg_types<tWaitForAlertByThreadId>::value.end());
    case PROBE_IDS::IdGetNextProcess: return make_span(arg_types<tGetNextProcess>::value.begin(), arg_types<tGetNextProcess>::value.end());
    case PROBE_IDS::IdOpenKeyedEvent: return make_span(arg_types<tOpenKeyedEvent>::value.begin(), arg_types<tOpenKeyedEvent>::value.end());
    case PROBE_IDS::IdDeleteBootEntry: return make_span(arg_types<tDeleteBootEntry>::value.begin(), arg_types<tDeleteBootEntry>::value.end());
    case PROBE_IDS::IdFilterToken: return make_span(arg_types<tFilterToken>::value.begin(), arg_types<tFilterToken>::value.end());
    case PROBE_IDS::IdCompressKey: return make_span(arg_types<tCompressKey>::value.begin(), arg_types<tCompressKey>::value.end());
    case PROBE_IDS::IdModifyBootEntry: return make_span(arg_types<tModifyBootEntry>::value.begin(), arg_types<tModifyBootEntry>::value.end());
    case PROBE_IDS::IdSetInformationTransaction: return make_span(arg_types<tSetInformationTransaction>::value.begin(), arg_types<tSetInformationTransaction>::value.end());
    case PROBE_IDS::IdPlugPlayControl: return make_span(arg_types<tPlugPlayControl>::value.begin(), arg_types<tPlugPlayControl>::value.end());
    case PROBE_IDS::IdOpenDirectoryObject: return make_span(arg_types<tOpenDirectoryObject>::value.begin(), arg_types<tOpenDirectoryObject>::value.end());
    case PROBE_IDS::IdContinue: return make_span(arg_types<tContinue>::value.begin(), arg_types<tContinue>::value.end());
    case PROBE_IDS::IdPrivilegeObjectAuditAlarm: return make_span(arg_types<tPrivilegeObjectAuditAlarm>::value.begin(), arg_types<tPrivilegeObjectAuditAlarm>::value.end());
    case PROBE_IDS::IdQueryKey: return make_span(arg_types<tQueryKey>::value.begin(), arg_types<tQueryKey>::value.end());
    case PROBE_IDS::IdFilterBootOption: return make_span(arg_types<tFilterBootOption>::value.begin(), arg_types<tFilterBootOption>::value.end());
    case PROBE_IDS::IdYieldExecution: return make_span(arg_types<tYieldExecution>::value.begin(), arg_types<tYieldExecution>::value.end());
    case PROBE_IDS::IdResumeThread: return make_span(arg_types<tResumeThread>::value.begin(), arg_types<tResumeThread>::value.end());
    case PROBE_IDS::IdAddBootEntry: return make_span(arg_types<tAddBootEntry>::value.begin(), arg_types<tAddBootEntry>::value.end());
    case PROBE_IDS::IdGetCurrentProcessorNumberEx: return make_span(arg_types<tGetCurrentProcessorNumberEx>::value.begin(), arg_types<tGetCurrentProcessorNumberEx>::value.end());
    case PROBE_IDS::IdCreateLowBoxToken: return make_span(arg_types<tCreateLowBoxToken>::value.begin(), arg_types<tCreateLowBoxToken>::value.end());
    case PROBE_IDS::IdFlushBuffersFile: return make_span(arg_types<tFlushBuffersFile>::value.begin(), arg_types<tFlushBuffersFile>::value.end());
    case PROBE_IDS::IdDelayExecution: return make_span(arg_types<tDelayExecution>::value.begin(), arg_types<tDelayExecution>::value.end());
    case PROBE_IDS::IdOpenKey: return make_span(arg_types<tOpenKey>::value.begin(), arg_types<tOpenKey>::value.end());
    case PROBE_IDS::IdStopProfile: return make_span(arg_types<tStopProfile>::value.begin(), arg_types<tStopProfile>::value.end());
    case PROBE_IDS::IdSetEvent: return make_span(arg_types<tSetEvent>::value.begin(), arg_types<tSetEvent>::value.end());
    case PROBE_IDS::IdRestoreKey: return make_span(arg_types<tRestoreKey>::value.begin(), arg_types<tRestoreKey>::value.end());
    case PROBE_IDS::IdExtendSection: return make_span(arg_types<tExtendSection>::value.begin(), arg_types<tExtendSection>::value.end());
    case PROBE_IDS::IdInitializeNlsFiles: return make_span(arg_types<tInitializeNlsFiles>::value.begin(), arg_types<tInitializeNlsFiles>::value.end());
    case PROBE_IDS::IdFindAtom: return make_span(arg_types<tFindAtom>::value.begin(), arg_types<tFindAtom>::value.end());
    case PROBE_IDS::IdDisplayString: return make_span(arg_types<tDisplayString>::value.begin(), arg_types<tDisplayString>::value.end());
    case PROBE_IDS::IdLoadDriver: return make_span(arg_types<tLoadDriver>::value.begin(), arg_types<tLoadDriver>::value.end());
    case PROBE_IDS::IdQueryWnfStateNameInformation: return make_span(arg_types<tQueryWnfStateNameInformation>::value.begin(), arg_types<tQueryWnfStateNameInformation>::value.end());
    case PROBE_IDS::IdCreateMutant: return make_span(arg_types<tCreateMutant>::value.begin(), arg_types<tCreateMutant>::value.end());
    case PROBE_IDS::IdFlushKey: return make_span(arg_types<tFlushKey>::value.begin(), arg_types<tFlushKey>::value.end());
    case PROBE_IDS::IdDuplicateObject: return make_span(arg_types<tDuplicateObject>::value.begin(), arg_types<tDuplicateObject>::value.end());
    case PROBE_IDS::IdCancelTimer2: return make_span(arg_types<tCancelTimer2>::value.begin(), arg_types<tCancelTimer2>::value.end());
    case PROBE_IDS::IdQueryAttributesFile: return make_span(arg_types<tQueryAttributesFile>::value.begin(), arg_types<tQueryAttributesFile>::value.end());
    case PROBE_IDS::IdCompareSigningLevels: return make_span(arg_types<tCompareSigningLevels>::value.begin(), arg_types<tCompareSigningLevels>::value.end());
    case PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarmByHandle: return make_span(arg_types<tAccessCheckByTypeResultListAndAuditAlarmByHandle>::value.begin(), arg_types<tAccessCheckByTypeResultListAndAuditAlarmByHandle>::value.end());
    case PROBE_IDS::IdDeleteValueKey: return make_span(arg_types<tDeleteValueKey>::value.begin(), arg_types<tDeleteValueKey>::value.end());
    case PROBE_IDS::IdSetDebugFilterState: return make_span(arg_types<tSetDebugFilterState>::value.begin(), arg_types<tSetDebugFilterState>::value.end());
    case PROBE_IDS::IdPulseEvent: return make_span(arg_types<tPulseEvent>::value.begin(), arg_types<tPulseEvent>::value.end());
    case PROBE_IDS::IdAllocateReserveObject: return make_span(arg_types<tAllocateReserveObject>::value.begin(), arg_types<tAllocateReserveObject>::value.end());
    case PROBE_IDS::IdAlpcDisconnectPort: return make_span(arg_types<tAlpcDisconnectPort>::value.begin(), arg_types<tAlpcDisconnectPort>::value.end());
    case PROBE_IDS::IdQueryTimerResolution: return make_span(arg_types<tQueryTimerResolution>::value.begin(), arg_types<tQueryTimerResolution>::value.end());
    case PROBE_IDS::IdDeleteKey: return make_span(arg_types<tDeleteKey>::value.begin(), arg_types<tDeleteKey>::value.end());
    case PROBE_IDS::IdCreateFile: return make_span(arg_types<tCreateFile>::value.begin(), arg_types<tCreateFile>::value.end());
    case PROBE_IDS::IdReplyPort: return make_span(arg_types<tReplyPort>::value.begin(), arg_types<tReplyPort>::value.end());
    case PROBE_IDS::IdGetNlsSectionPtr: return make_span(arg_types<tGetNlsSectionPtr>::value.begin(), arg_types<tGetNlsSectionPtr>::value.end());
    case PROBE_IDS::IdQueryInformationProcess: return make_span(arg_types<tQueryInformationProcess>::value.begin(), arg_types<tQueryInformationProcess>::value.end());
    case PROBE_IDS::IdReplyWaitReceivePortEx: return make_span(arg_types<tReplyWaitReceivePortEx>::value.begin(), arg_types<tReplyWaitReceivePortEx>::value.end());
    case PROBE_IDS::IdUmsThreadYield: return make_span(arg_types<tUmsThreadYield>::value.begin(), arg_types<tUmsThreadYield>::value.end());
    case PROBE_IDS::IdManagePartition: return make_span(arg_types<tManagePartition>::value.begin(), arg_types<tManagePartition>::value.end());
    case PROBE_IDS::IdAdjustPrivilegesToken: return make_span(arg_types<tAdjustPrivilegesToken>::value.begin(), arg_types<tAdjustPrivilegesToken>::value.end());
    case PROBE_IDS::IdCreateCrossVmMutant: return make_span(arg_types<tCreateCrossVmMutant>::value.begin(), arg_types<tCreateCrossVmMutant>::value.end());
    case PROBE_IDS::IdCreateDirectoryObject: return make_span(arg_types<tCreateDirectoryObject>::value.begin(), arg_types<tCreateDirectoryObject>::value.end());
    case PROBE_IDS::IdOpenFile: return make_span(arg_types<tOpenFile>::value.begin(), arg_types<tOpenFile>::value.end());
    case PROBE_IDS::IdSetInformationVirtualMemory: return make_span(arg_types<tSetInformationVirtualMemory>::value.begin(), arg_types<tSetInformationVirtualMemory>::value.end());
    case PROBE_IDS::IdTerminateEnclave: return make_span(arg_types<tTerminateEnclave>::value.begin(), arg_types<tTerminateEnclave>::value.end());
    case PROBE_IDS::IdSuspendProcess: return make_span(arg_types<tSuspendProcess>::value.begin(), arg_types<tSuspendProcess>::value.end());
    case PROBE_IDS::IdReplyWaitReplyPort: return make_span(arg_types<tReplyWaitReplyPort>::value.begin(), arg_types<tReplyWaitReplyPort>::value.end());
    case PROBE_IDS::IdOpenTransactionManager: return make_span(arg_types<tOpenTransactionManager>::value.begin(), arg_types<tOpenTransactionManager>::value.end());
    case PROBE_IDS::IdCreateSemaphore: return make_span(arg_types<tCreateSemaphore>::value.begin(), arg_types<tCreateSemaphore>::value.end());
    case PROBE_IDS::IdUnmapViewOfSectionEx: return make_span(arg_types<tUnmapViewOfSectionEx>::value.begin(), arg_types<tUnmapViewOfSectionEx>::value.end());
    case PROBE_IDS::IdMapViewOfSection: return make_span(arg_types<tMapViewOfSection>::value.begin(), arg_types<tMapViewOfSection>::value.end());
    case PROBE_IDS::IdDisableLastKnownGood: return make_span(arg_types<tDisableLastKnownGood>::value.begin(), arg_types<tDisableLastKnownGood>::value.end());
    case PROBE_IDS::IdGetNextThread: return make_span(arg_types<tGetNextThread>::value.begin(), arg_types<tGetNextThread>::value.end());
    case PROBE_IDS::IdMakeTemporaryObject: return make_span(arg_types<tMakeTemporaryObject>::value.begin(), arg_types<tMakeTemporaryObject>::value.end());
    case PROBE_IDS::IdSetInformationFile: return make_span(arg_types<tSetInformationFile>::value.begin(), arg_types<tSetInformationFile>::value.end());
    case PROBE_IDS::IdCreateTransactionManager: return make_span(arg_types<tCreateTransactionManager>::value.begin(), arg_types<tCreateTransactionManager>::value.end());
    case PROBE_IDS::IdWriteFileGather: return make_span(arg_types<tWriteFileGather>::value.begin(), arg_types<tWriteFileGather>::value.end());
    case PROBE_IDS::IdQueryInformationTransaction: return make_span(arg_types<tQueryInformationTransaction>::value.begin(), arg_types<tQueryInformationTransaction>::value.end());
    case PROBE_IDS::IdFlushVirtualMemory: return make_span(arg_types<tFlushVirtualMemory>::value.begin(), arg_types<tFlushVirtualMemory>::value.end());
    case PROBE_IDS::IdQueryQuotaInformationFile: return make_span(arg_types<tQueryQuotaInformationFile>::value.begin(), arg_types<tQueryQuotaInformationFile>::value.end());
    case PROBE_IDS::IdSetVolumeInformationFile: return make_span(arg_types<tSetVolumeInformationFile>::value.begin(), arg_types<tSetVolumeInformationFile>::value.end());
    case PROBE_IDS::IdQueryInformationEnlistment: return make_span(arg_types<tQueryInformationEnlistment>::value.begin(), arg_types<tQueryInformationEnlistment>::value.end());
    case PROBE_IDS::IdCreateIoCompletion: return make_span(arg_types<tCreateIoCompletion>::value.begin(), arg_types<tCreateIoCompletion>::value.end());
    case PROBE_IDS::IdUnloadKeyEx: return make_span(arg_types<tUnloadKeyEx>::value.begin(), arg_types<tUnloadKeyEx>::value.end());
    case PROBE_IDS::IdQueryEaFile: return make_span(arg_types<tQueryEaFile>::value.begin(), arg_types<tQueryEaFile>::value.end());
    case PROBE_IDS::IdQueryDirectoryObject: return make_span(arg_types<tQueryDirectoryObject>::value.begin(), arg_types<tQueryDirectoryObject>::value.end());
    case PROBE_IDS::IdAddAtomEx: return make_span(arg_types<tAddAtomEx>::value.begin(), arg_types<tAddAtomEx>::value.end());
    case PROBE_IDS::IdSinglePhaseReject: return make_span(arg_types<tSinglePhaseReject>::value.begin(), arg_types<tSinglePhaseReject>::value.end());
    case PROBE_IDS::IdDeleteWnfStateName: return make_span(arg_types<tDeleteWnfStateName>::value.begin(), arg_types<tDeleteWnfStateName>::value.end());
    case PROBE_IDS::IdSetSystemEnvironmentValueEx: return make_span(arg_types<tSetSystemEnvironmentValueEx>::value.begin(), arg_types<tSetSystemEnvironmentValueEx>::value.end());
    case PROBE_IDS::IdContinueEx: return make_span(arg_types<tContinueEx>::value.begin(), arg_types<tContinueEx>::value.end());
    case PROBE_IDS::IdUnloadDriver: return make_span(arg_types<tUnloadDriver>::value.begin(), arg_types<tUnloadDriver>::value.end());
    case PROBE_IDS::IdCallEnclave: return make_span(arg_types<tCallEnclave>::value.begin(), arg_types<tCallEnclave>::value.end());
    case PROBE_IDS::IdCancelIoFileEx: return make_span(arg_types<tCancelIoFileEx>::value.begin(), arg_types<tCancelIoFileEx>::value.end());
    case PROBE_IDS::IdSetTimer: return make_span(arg_types<tSetTimer>::value.begin(), arg_types<tSetTimer>::value.end());
    case PROBE_IDS::IdQuerySystemEnvironmentValue: return make_span(arg_types<tQuerySystemEnvironmentValue>::value.begin(), arg_types<tQuerySystemEnvironmentValue>::value.end());
    case PROBE_IDS::IdOpenThreadToken: return make_span(arg_types<tOpenThreadToken>::value.begin(), arg_types<tOpenThreadToken>::value.end());
    case PROBE_IDS::IdMapUserPhysicalPagesScatter: return make_span(arg_types<tMapUserPhysicalPagesScatter>::value.begin(), arg_types<tMapUserPhysicalPagesScatter>::value.end());
    case PROBE_IDS::IdCreateResourceManager: return make_span(arg_types<tCreateResourceManager>::value.begin(), arg_types<tCreateResourceManager>::value.end());
    case PROBE_IDS::IdUnlockVirtualMemory: return make_span(arg_types<tUnlockVirtualMemory>::value.begin(), arg_types<tUnlockVirtualMemory>::value.end());
    case PROBE_IDS::IdQueryInformationPort: return make_span(arg_types<tQueryInformationPort>::value.begin(), arg_types<tQueryInformationPort>::value.end());
    case PROBE_IDS::IdSetLowEventPair: return make_span(arg_types<tSetLowEventPair>::value.begin(), arg_types<tSetLowEventPair>::value.end());
    case PROBE_IDS::IdSetInformationKey: return make_span(arg_types<tSetInformationKey>::value.begin(), arg_types<tSetInformationKey>::value.end());
    case PROBE_IDS::IdQuerySecurityPolicy: return make_span(arg_types<tQuerySecurityPolicy>::value.begin(), arg_types<tQuerySecurityPolicy>::value.end());
    case PROBE_IDS::IdOpenProcessToken: return make_span(arg_types<tOpenProcessToken>::value.begin(), arg_types<tOpenProcessToken>::value.end());
    case PROBE_IDS::IdQueryVolumeInformationFile: return make_span(arg_types<tQueryVolumeInformationFile>::value.begin(), arg_types<tQueryVolumeInformationFile>::value.end());
    case PROBE_IDS::IdOpenTimer: return make_span(arg_types<tOpenTimer>::value.begin(), arg_types<tOpenTimer>::value.end());
    case PROBE_IDS::IdMapUserPhysicalPages: return make_span(arg_types<tMapUserPhysicalPages>::value.begin(), arg_types<tMapUserPhysicalPages>::value.end());
    case PROBE_IDS::IdLoadKey: return make_span(arg_types<tLoadKey>::value.begin(), arg_types<tLoadKey>::value.end());
    case PROBE_IDS::IdCreateWaitCompletionPacket: return make_span(arg_types<tCreateWaitCompletionPacket>::value.begin(), arg_types<tCreateWaitCompletionPacket>::value.end());
    case PROBE_IDS::IdReleaseWorkerFactoryWorker: return make_span(arg_types<tReleaseWorkerFactoryWorker>::value.begin(), arg_types<tReleaseWorkerFactoryWorker>::value.end());
    case PROBE_IDS::IdPrePrepareComplete: return make_span(arg_types<tPrePrepareComplete>::value.begin(), arg_types<tPrePrepareComplete>::value.end());
    case PROBE_IDS::IdReadVirtualMemory: return make_span(arg_types<tReadVirtualMemory>::value.begin(), arg_types<tReadVirtualMemory>::value.end());
    case PROBE_IDS::IdFreeVirtualMemory: return make_span(arg_types<tFreeVirtualMemory>::value.begin(), arg_types<tFreeVirtualMemory>::value.end());
    case PROBE_IDS::IdSetDriverEntryOrder: return make_span(arg_types<tSetDriverEntryOrder>::value.begin(), arg_types<tSetDriverEntryOrder>::value.end());
    case PROBE_IDS::IdReadFile: return make_span(arg_types<tReadFile>::value.begin(), arg_types<tReadFile>::value.end());
    case PROBE_IDS::IdTraceControl: return make_span(arg_types<tTraceControl>::value.begin(), arg_types<tTraceControl>::value.end());
    case PROBE_IDS::IdOpenProcessTokenEx: return make_span(arg_types<tOpenProcessTokenEx>::value.begin(), arg_types<tOpenProcessTokenEx>::value.end());
    case PROBE_IDS::IdSecureConnectPort: return make_span(arg_types<tSecureConnectPort>::value.begin(), arg_types<tSecureConnectPort>::value.end());
    case PROBE_IDS::IdSaveKey: return make_span(arg_types<tSaveKey>::value.begin(), arg_types<tSaveKey>::value.end());
    case PROBE_IDS::IdSetDefaultHardErrorPort: return make_span(arg_types<tSetDefaultHardErrorPort>::value.begin(), arg_types<tSetDefaultHardErrorPort>::value.end());
    case PROBE_IDS::IdCreateEnclave: return make_span(arg_types<tCreateEnclave>::value.begin(), arg_types<tCreateEnclave>::value.end());
    case PROBE_IDS::IdOpenPrivateNamespace: return make_span(arg_types<tOpenPrivateNamespace>::value.begin(), arg_types<tOpenPrivateNamespace>::value.end());
    case PROBE_IDS::IdSetLdtEntries: return make_span(arg_types<tSetLdtEntries>::value.begin(), arg_types<tSetLdtEntries>::value.end());
    case PROBE_IDS::IdResetWriteWatch: return make_span(arg_types<tResetWriteWatch>::value.begin(), arg_types<tResetWriteWatch>::value.end());
    case PROBE_IDS::IdRenameKey: return make_span(arg_types<tRenameKey>::value.begin(), arg_types<tRenameKey>::value.end());
    case PROBE_IDS::IdRevertContainerImpersonation: return make_span(arg_types<tRevertContainerImpersonation>::value.begin(), arg_types<tRevertContainerImpersonation>::value.end());
    case PROBE_IDS::IdAlpcCreateSectionView: return make_span(arg_types<tAlpcCreateSectionView>::value.begin(), arg_types<tAlpcCreateSectionView>::value.end());
    case PROBE_IDS::IdCreateCrossVmEvent: return make_span(arg_types<tCreateCrossVmEvent>::value.begin(), arg_types<tCreateCrossVmEvent>::value.end());
    case PROBE_IDS::IdImpersonateThread: return make_span(arg_types<tImpersonateThread>::value.begin(), arg_types<tImpersonateThread>::value.end());
    case PROBE_IDS::IdSetIRTimer: return make_span(arg_types<tSetIRTimer>::value.begin(), arg_types<tSetIRTimer>::value.end());
    case PROBE_IDS::IdCreateDirectoryObjectEx: return make_span(arg_types<tCreateDirectoryObjectEx>::value.begin(), arg_types<tCreateDirectoryObjectEx>::value.end());
    case PROBE_IDS::IdAcquireProcessActivityReference: return make_span(arg_types<tAcquireProcessActivityReference>::value.begin(), arg_types<tAcquireProcessActivityReference>::value.end());
    case PROBE_IDS::IdReplaceKey: return make_span(arg_types<tReplaceKey>::value.begin(), arg_types<tReplaceKey>::value.end());
    case PROBE_IDS::IdStartProfile: return make_span(arg_types<tStartProfile>::value.begin(), arg_types<tStartProfile>::value.end());
    case PROBE_IDS::IdQueryBootEntryOrder: return make_span(arg_types<tQueryBootEntryOrder>::value.begin(), arg_types<tQueryBootEntryOrder>::value.end());
    case PROBE_IDS::IdLockRegistryKey: return make_span(arg_types<tLockRegistryKey>::value.begin(), arg_types<tLockRegistryKey>::value.end());
    case PROBE_IDS::IdImpersonateClientOfPort: return make_span(arg_types<tImpersonateClientOfPort>::value.begin(), arg_types<tImpersonateClientOfPort>::value.end());
    case PROBE_IDS::IdQueryEvent: return make_span(arg_types<tQueryEvent>::value.begin(), arg_types<tQueryEvent>::value.end());
    case PROBE_IDS::IdFsControlFile: return make_span(arg_types<tFsControlFile>::value.begin(), arg_types<tFsControlFile>::value.end());
    case PROBE_IDS::IdOpenProcess: return make_span(arg_types<tOpenProcess>::value.begin(), arg_types<tOpenProcess>::value.end());
    case PROBE_IDS::IdSetIoCompletion: return make_span(arg_types<tSetIoCompletion>::value.begin(), arg_types<tSetIoCompletion>::value.end());
    case PROBE_IDS::IdConnectPort: return make_span(arg_types<tConnectPort>::value.begin(), arg_types<tConnectPort>::value.end());
    case PROBE_IDS::IdCloseObjectAuditAlarm: return make_span(arg_types<tCloseObjectAuditAlarm>::value.begin(), arg_types<tCloseObjectAuditAlarm>::value.end());
    case PROBE_IDS::IdRequestWaitReplyPort: return make_span(arg_types<tRequestWaitReplyPort>::value.begin(), arg_types<tRequestWaitReplyPort>::value.end());
    case PROBE_IDS::IdSetInformationObject: return make_span(arg_types<tSetInformationObject>::value.begin(), arg_types<tSetInformationObject>::value.end());
    case PROBE_IDS::IdPrivilegeCheck: return make_span(arg_types<tPrivilegeCheck>::value.begin(), arg_types<tPrivilegeCheck>::value.end());
    case PROBE_IDS::IdCallbackReturn: return make_span(arg_types<tCallbackReturn>::value.begin(), arg_types<tCallbackReturn>::value.end());
    case PROBE_IDS::IdSetInformationToken: return make_span(arg_types<tSetInformationToken>::value.begin(), arg_types<tSetInformationToken>::value.end());
    case PROBE_IDS::IdSetUuidSeed: return make_span(arg_types<tSetUuidSeed>::value.begin(), arg_types<tSetUuidSeed>::value.end());
    case PROBE_IDS::IdOpenKeyTransacted: return make_span(arg_types<tOpenKeyTransacted>::value.begin(), arg_types<tOpenKeyTransacted>::value.end());
    case PROBE_IDS::IdAlpcDeleteSecurityContext: return make_span(arg_types<tAlpcDeleteSecurityContext>::value.begin(), arg_types<tAlpcDeleteSecurityContext>::value.end());
    case PROBE_IDS::IdSetBootOptions: return make_span(arg_types<tSetBootOptions>::value.begin(), arg_types<tSetBootOptions>::value.end());
    case PROBE_IDS::IdManageHotPatch: return make_span(arg_types<tManageHotPatch>::value.begin(), arg_types<tManageHotPatch>::value.end());
    case PROBE_IDS::IdEnumerateTransactionObject: return make_span(arg_types<tEnumerateTransactionObject>::value.begin(), arg_types<tEnumerateTransactionObject>::value.end());
    case PROBE_IDS::IdSetThreadExecutionState: return make_span(arg_types<tSetThreadExecutionState>::value.begin(), arg_types<tSetThreadExecutionState>::value.end());
    case PROBE_IDS::IdWaitLowEventPair: return make_span(arg_types<tWaitLowEventPair>::value.begin(), arg_types<tWaitLowEventPair>::value.end());
    case PROBE_IDS::IdSetHighWaitLowEventPair: return make_span(arg_types<tSetHighWaitLowEventPair>::value.begin(), arg_types<tSetHighWaitLowEventPair>::value.end());
    case PROBE_IDS::IdQueryInformationWorkerFactory: return make_span(arg_types<tQueryInformationWorkerFactory>::value.begin(), arg_types<tQueryInformationWorkerFactory>::value.end());
    case PROBE_IDS::IdSetWnfProcessNotificationEvent: return make_span(arg_types<tSetWnfProcessNotificationEvent>::value.begin(), arg_types<tSetWnfProcessNotificationEvent>::value.end());
    case PROBE_IDS::IdAlpcDeleteSectionView: return make_span(arg_types<tAlpcDeleteSectionView>::value.begin(), arg_types<tAlpcDeleteSectionView>::value.end());
    case PROBE_IDS::IdCreateMailslotFile: return make_span(arg_types<tCreateMailslotFile>::value.begin(), arg_types<tCreateMailslotFile>::value.end());
    case PROBE_IDS::IdCreateProcess: return make_span(arg_types<tCreateProcess>::value.begin(), arg_types<tCreateProcess>::value.end());
    case PROBE_IDS::IdQueryIoCompletion: return make_span(arg_types<tQueryIoCompletion>::value.begin(), arg_types<tQueryIoCompletion>::value.end());
    case PROBE_IDS::IdCreateTimer: return make_span(arg_types<tCreateTimer>::value.begin(), arg_types<tCreateTimer>::value.end());
    case PROBE_IDS::IdFlushInstallUILanguage: return make_span(arg_types<tFlushInstallUILanguage>::value.begin(), arg_types<tFlushInstallUILanguage>::value.end());
    case PROBE_IDS::IdCompleteConnectPort: return make_span(arg_types<tCompleteConnectPort>::value.begin(), arg_types<tCompleteConnectPort>::value.end());
    case PROBE_IDS::IdAlpcConnectPort: return make_span(arg_types<tAlpcConnectPort>::value.begin(), arg_types<tAlpcConnectPort>::value.end());
    case PROBE_IDS::IdFreezeRegistry: return make_span(arg_types<tFreezeRegistry>::value.begin(), arg_types<tFreezeRegistry>::value.end());
    case PROBE_IDS::IdMapCMFModule: return make_span(arg_types<tMapCMFModule>::value.begin(), arg_types<tMapCMFModule>::value.end());
    case PROBE_IDS::IdAllocateUserPhysicalPages: return make_span(arg_types<tAllocateUserPhysicalPages>::value.begin(), arg_types<tAllocateUserPhysicalPages>::value.end());
    case PROBE_IDS::IdSetInformationEnlistment: return make_span(arg_types<tSetInformationEnlistment>::value.begin(), arg_types<tSetInformationEnlistment>::value.end());
    case PROBE_IDS::IdRaiseHardError: return make_span(arg_types<tRaiseHardError>::value.begin(), arg_types<tRaiseHardError>::value.end());
    case PROBE_IDS::IdCreateSection: return make_span(arg_types<tCreateSection>::value.begin(), arg_types<tCreateSection>::value.end());
    case PROBE_IDS::IdOpenIoCompletion: return make_span(arg_types<tOpenIoCompletion>::value.begin(), arg_types<tOpenIoCompletion>::value.end());
    case PROBE_IDS::IdSystemDebugControl: return make_span(arg_types<tSystemDebugControl>::value.begin(), arg_types<tSystemDebugControl>::value.end());
    case PROBE_IDS::IdTranslateFilePath: return make_span(arg_types<tTranslateFilePath>::value.begin(), arg_types<tTranslateFilePath>::value.end());
    case PROBE_IDS::IdCreateIRTimer: return make_span(arg_types<tCreateIRTimer>::value.begin(), arg_types<tCreateIRTimer>::value.end());
    case PROBE_IDS::IdCreateRegistryTransaction: return make_span(arg_types<tCreateRegistryTransaction>::value.begin(), arg_types<tCreateRegistryTransaction>::value.end());
    case PROBE_IDS::IdLoadKey2: return make_span(arg_types<tLoadKey2>::value.begin(), arg_types<tLoadKey2>::value.end());
    case PROBE_IDS::IdAlpcCreatePort: return make_span(arg_types<tAlpcCreatePort>::value.begin(), arg_types<tAlpcCreatePort>::value.end());
    case PROBE_IDS::IdDeleteWnfStateData: return make_span(arg_types<tDeleteWnfStateData>::value.begin(), arg_types<tDeleteWnfStateData>::value.end());
    case PROBE_IDS::IdSetTimerEx: return make_span(arg_types<tSetTimerEx>::value.begin(), arg_types<tSetTimerEx>::value.end());
    case PROBE_IDS::IdSetLowWaitHighEventPair: return make_span(arg_types<tSetLowWaitHighEventPair>::value.begin(), arg_types<tSetLowWaitHighEventPair>::value.end());
    case PROBE_IDS::IdAlpcCreateSecurityContext: return make_span(arg_types<tAlpcCreateSecurityContext>::value.begin(), arg_types<tAlpcCreateSecurityContext>::value.end());
    case PROBE_IDS::IdSetCachedSigningLevel: return make_span(arg_types<tSetCachedSigningLevel>::value.begin(), arg_types<tSetCachedSigningLevel>::value.end());
    case PROBE_IDS::IdSetHighEventPair: return make_span(arg_types<tSetHighEventPair>::value.begin(), arg_types<tSetHighEventPair>::value.end());
    case PROBE_IDS::IdShutdownWorkerFactory: return make_span(arg_types<tShutdownWorkerFactory>::value.begin(), arg_types<tShutdownWorkerFactory>::value.end());
    case PROBE_IDS::IdSetInformationJobObject: return make_span(arg_types<tSetInformationJobObject>::value.begin(), arg_types<tSetInformationJobObject>::value.end());
    case PROBE_IDS::IdAdjustGroupsToken: return make_span(arg_types<tAdjustGroupsToken>::value.begin(), arg_types<tAdjustGroupsToken>::value.end());
    case PROBE_IDS::IdAreMappedFilesTheSame: return make_span(arg_types<tAreMappedFilesTheSame>::value.begin(), arg_types<tAreMappedFilesTheSame>::value.end());
    case PROBE_IDS::IdSetBootEntryOrder: return make_span(arg_types<tSetBootEntryOrder>::value.begin(), arg_types<tSetBootEntryOrder>::value.end());
    case PROBE_IDS::IdQueryMutant: return make_span(arg_types<tQueryMutant>::value.begin(), arg_types<tQueryMutant>::value.end());
    case PROBE_IDS::IdotifyChangeSession: return make_span(arg_types<totifyChangeSession>::value.begin(), arg_types<totifyChangeSession>::value.end());
    case PROBE_IDS::IdQueryDefaultLocale: return make_span(arg_types<tQueryDefaultLocale>::value.begin(), arg_types<tQueryDefaultLocale>::value.end());
    case PROBE_IDS::IdCreateThreadEx: return make_span(arg_types<tCreateThreadEx>::value.begin(), arg_types<tCreateThreadEx>::value.end());
    case PROBE_IDS::IdQueryDriverEntryOrder: return make_span(arg_types<tQueryDriverEntryOrder>::value.begin(), arg_types<tQueryDriverEntryOrder>::value.end());
    case PROBE_IDS::IdSetTimerResolution: return make_span(arg_types<tSetTimerResolution>::value.begin(), arg_types<tSetTimerResolution>::value.end());
    case PROBE_IDS::IdPrePrepareEnlistment: return make_span(arg_types<tPrePrepareEnlistment>::value.begin(), arg_types<tPrePrepareEnlistment>::value.end());
    case PROBE_IDS::IdCancelSynchronousIoFile: return make_span(arg_types<tCancelSynchronousIoFile>::value.begin(), arg_types<tCancelSynchronousIoFile>::value.end());
    case PROBE_IDS::IdQueryDirectoryFileEx: return make_span(arg_types<tQueryDirectoryFileEx>::value.begin(), arg_types<tQueryDirectoryFileEx>::value.end());
    case PROBE_IDS::IdAddDriverEntry: return make_span(arg_types<tAddDriverEntry>::value.begin(), arg_types<tAddDriverEntry>::value.end());
    case PROBE_IDS::IdUnloadKey: return make_span(arg_types<tUnloadKey>::value.begin(), arg_types<tUnloadKey>::value.end());
    case PROBE_IDS::IdCreateEvent: return make_span(arg_types<tCreateEvent>::value.begin(), arg_types<tCreateEvent>::value.end());
    case PROBE_IDS::IdOpenSession: return make_span(arg_types<tOpenSession>::value.begin(), arg_types<tOpenSession>::value.end());
    case PROBE_IDS::IdQueryValueKey: return make_span(arg_types<tQueryValueKey>::value.begin(), arg_types<tQueryValueKey>::value.end());
    case PROBE_IDS::IdCreatePrivateNamespace: return make_span(arg_types<tCreatePrivateNamespace>::value.begin(), arg_types<tCreatePrivateNamespace>::value.end());
    case PROBE_IDS::IdIsUILanguageComitted: return make_span(arg_types<tIsUILanguageComitted>::value.begin(), arg_types<tIsUILanguageComitted>::value.end());
    case PROBE_IDS::IdAlertThread: return make_span(arg_types<tAlertThread>::value.begin(), arg_types<tAlertThread>::value.end());
    case PROBE_IDS::IdQueryInstallUILanguage: return make_span(arg_types<tQueryInstallUILanguage>::value.begin(), arg_types<tQueryInstallUILanguage>::value.end());
    case PROBE_IDS::IdCreateSymbolicLinkObject: return make_span(arg_types<tCreateSymbolicLinkObject>::value.begin(), arg_types<tCreateSymbolicLinkObject>::value.end());
    case PROBE_IDS::IdAllocateUuids: return make_span(arg_types<tAllocateUuids>::value.begin(), arg_types<tAllocateUuids>::value.end());
    case PROBE_IDS::IdShutdownSystem: return make_span(arg_types<tShutdownSystem>::value.begin(), arg_types<tShutdownSystem>::value.end());
    case PROBE_IDS::IdCreateTokenEx: return make_span(arg_types<tCreateTokenEx>::value.begin(), arg_types<tCreateTokenEx>::value.end());
    case PROBE_IDS::IdQueryVirtualMemory: return make_span(arg_types<tQueryVirtualMemory>::value.begin(), arg_types<tQueryVirtualMemory>::value.end());
    case PROBE_IDS::IdAlpcOpenSenderProcess: return make_span(arg_types<tAlpcOpenSenderProcess>::value.begin(), arg_types<tAlpcOpenSenderProcess>::value.end());
    case PROBE_IDS::IdAssignProcessToJobObject: return make_span(arg_types<tAssignProcessToJobObject>::value.begin(), arg_types<tAssignProcessToJobObject>::value.end());
    case PROBE_IDS::IdRemoveIoCompletion: return make_span(arg_types<tRemoveIoCompletion>::value.begin(), arg_types<tRemoveIoCompletion>::value.end());
    case PROBE_IDS::IdCreateTimer2: return make_span(arg_types<tCreateTimer2>::value.begin(), arg_types<tCreateTimer2>::value.end());
    case PROBE_IDS::IdCreateEnlistment: return make_span(arg_types<tCreateEnlistment>::value.begin(), arg_types<tCreateEnlistment>::value.end());
    case PROBE_IDS::IdRecoverEnlistment: return make_span(arg_types<tRecoverEnlistment>::value.begin(), arg_types<tRecoverEnlistment>::value.end());
    case PROBE_IDS::IdCreateJobSet: return make_span(arg_types<tCreateJobSet>::value.begin(), arg_types<tCreateJobSet>::value.end());
    case PROBE_IDS::IdSetIoCompletionEx: return make_span(arg_types<tSetIoCompletionEx>::value.begin(), arg_types<tSetIoCompletionEx>::value.end());
    case PROBE_IDS::IdCreateProcessEx: return make_span(arg_types<tCreateProcessEx>::value.begin(), arg_types<tCreateProcessEx>::value.end());
    case PROBE_IDS::IdAlpcConnectPortEx: return make_span(arg_types<tAlpcConnectPortEx>::value.begin(), arg_types<tAlpcConnectPortEx>::value.end());
    case PROBE_IDS::IdWaitForMultipleObjects32: return make_span(arg_types<tWaitForMultipleObjects32>::value.begin(), arg_types<tWaitForMultipleObjects32>::value.end());
    case PROBE_IDS::IdRecoverResourceManager: return make_span(arg_types<tRecoverResourceManager>::value.begin(), arg_types<tRecoverResourceManager>::value.end());
    case PROBE_IDS::IdAlpcSetInformation: return make_span(arg_types<tAlpcSetInformation>::value.begin(), arg_types<tAlpcSetInformation>::value.end());
    case PROBE_IDS::IdAlpcRevokeSecurityContext: return make_span(arg_types<tAlpcRevokeSecurityContext>::value.begin(), arg_types<tAlpcRevokeSecurityContext>::value.end());
    case PROBE_IDS::IdAlpcImpersonateClientOfPort: return make_span(arg_types<tAlpcImpersonateClientOfPort>::value.begin(), arg_types<tAlpcImpersonateClientOfPort>::value.end());
    case PROBE_IDS::IdReleaseKeyedEvent: return make_span(arg_types<tReleaseKeyedEvent>::value.begin(), arg_types<tReleaseKeyedEvent>::value.end());
    case PROBE_IDS::IdTerminateThread: return make_span(arg_types<tTerminateThread>::value.begin(), arg_types<tTerminateThread>::value.end());
    case PROBE_IDS::IdSetInformationSymbolicLink: return make_span(arg_types<tSetInformationSymbolicLink>::value.begin(), arg_types<tSetInformationSymbolicLink>::value.end());
    case PROBE_IDS::IdDeleteObjectAuditAlarm: return make_span(arg_types<tDeleteObjectAuditAlarm>::value.begin(), arg_types<tDeleteObjectAuditAlarm>::value.end());
    case PROBE_IDS::IdWaitForKeyedEvent: return make_span(arg_types<tWaitForKeyedEvent>::value.begin(), arg_types<tWaitForKeyedEvent>::value.end());
    case PROBE_IDS::IdCreatePort: return make_span(arg_types<tCreatePort>::value.begin(), arg_types<tCreatePort>::value.end());
    case PROBE_IDS::IdDeletePrivateNamespace: return make_span(arg_types<tDeletePrivateNamespace>::value.begin(), arg_types<tDeletePrivateNamespace>::value.end());
    case PROBE_IDS::IdotifyChangeMultipleKeys: return make_span(arg_types<totifyChangeMultipleKeys>::value.begin(), arg_types<totifyChangeMultipleKeys>::value.end());
    case PROBE_IDS::IdLockFile: return make_span(arg_types<tLockFile>::value.begin(), arg_types<tLockFile>::value.end());
    case PROBE_IDS::IdQueryDefaultUILanguage: return make_span(arg_types<tQueryDefaultUILanguage>::value.begin(), arg_types<tQueryDefaultUILanguage>::value.end());
    case PROBE_IDS::IdOpenEventPair: return make_span(arg_types<tOpenEventPair>::value.begin(), arg_types<tOpenEventPair>::value.end());
    case PROBE_IDS::IdRollforwardTransactionManager: return make_span(arg_types<tRollforwardTransactionManager>::value.begin(), arg_types<tRollforwardTransactionManager>::value.end());
    case PROBE_IDS::IdAlpcQueryInformationMessage: return make_span(arg_types<tAlpcQueryInformationMessage>::value.begin(), arg_types<tAlpcQueryInformationMessage>::value.end());
    case PROBE_IDS::IdUnmapViewOfSection: return make_span(arg_types<tUnmapViewOfSection>::value.begin(), arg_types<tUnmapViewOfSection>::value.end());
    case PROBE_IDS::IdCancelIoFile: return make_span(arg_types<tCancelIoFile>::value.begin(), arg_types<tCancelIoFile>::value.end());
    case PROBE_IDS::IdCreatePagingFile: return make_span(arg_types<tCreatePagingFile>::value.begin(), arg_types<tCreatePagingFile>::value.end());
    case PROBE_IDS::IdCancelTimer: return make_span(arg_types<tCancelTimer>::value.begin(), arg_types<tCancelTimer>::value.end());
    case PROBE_IDS::IdReplyWaitReceivePort: return make_span(arg_types<tReplyWaitReceivePort>::value.begin(), arg_types<tReplyWaitReceivePort>::value.end());
    case PROBE_IDS::IdCompareObjects: return make_span(arg_types<tCompareObjects>::value.begin(), arg_types<tCompareObjects>::value.end());
    case PROBE_IDS::IdSetDefaultLocale: return make_span(arg_types<tSetDefaultLocale>::value.begin(), arg_types<tSetDefaultLocale>::value.end());
    case PROBE_IDS::IdAllocateLocallyUniqueId: return make_span(arg_types<tAllocateLocallyUniqueId>::value.begin(), arg_types<tAllocateLocallyUniqueId>::value.end());
    case PROBE_IDS::IdAccessCheckByTypeAndAuditAlarm: return make_span(arg_types<tAccessCheckByTypeAndAuditAlarm>::value.begin(), arg_types<tAccessCheckByTypeAndAuditAlarm>::value.end());
    case PROBE_IDS::IdQueryDebugFilterState: return make_span(arg_types<tQueryDebugFilterState>::value.begin(), arg_types<tQueryDebugFilterState>::value.end());
    case PROBE_IDS::IdOpenSemaphore: return make_span(arg_types<tOpenSemaphore>::value.begin(), arg_types<tOpenSemaphore>::value.end());
    case PROBE_IDS::IdAllocateVirtualMemory: return make_span(arg_types<tAllocateVirtualMemory>::value.begin(), arg_types<tAllocateVirtualMemory>::value.end());
    case PROBE_IDS::IdResumeProcess: return make_span(arg_types<tResumeProcess>::value.begin(), arg_types<tResumeProcess>::value.end());
    case PROBE_IDS::IdSetContextThread: return make_span(arg_types<tSetContextThread>::value.begin(), arg_types<tSetContextThread>::value.end());
    case PROBE_IDS::IdOpenSymbolicLinkObject: return make_span(arg_types<tOpenSymbolicLinkObject>::value.begin(), arg_types<tOpenSymbolicLinkObject>::value.end());
    case PROBE_IDS::IdModifyDriverEntry: return make_span(arg_types<tModifyDriverEntry>::value.begin(), arg_types<tModifyDriverEntry>::value.end());
    case PROBE_IDS::IdSerializeBoot: return make_span(arg_types<tSerializeBoot>::value.begin(), arg_types<tSerializeBoot>::value.end());
    case PROBE_IDS::IdRenameTransactionManager: return make_span(arg_types<tRenameTransactionManager>::value.begin(), arg_types<tRenameTransactionManager>::value.end());
    case PROBE_IDS::IdRemoveIoCompletionEx: return make_span(arg_types<tRemoveIoCompletionEx>::value.begin(), arg_types<tRemoveIoCompletionEx>::value.end());
    case PROBE_IDS::IdMapViewOfSectionEx: return make_span(arg_types<tMapViewOfSectionEx>::value.begin(), arg_types<tMapViewOfSectionEx>::value.end());
    case PROBE_IDS::IdFilterTokenEx: return make_span(arg_types<tFilterTokenEx>::value.begin(), arg_types<tFilterTokenEx>::value.end());
    case PROBE_IDS::IdDeleteDriverEntry: return make_span(arg_types<tDeleteDriverEntry>::value.begin(), arg_types<tDeleteDriverEntry>::value.end());
    case PROBE_IDS::IdQuerySystemInformation: return make_span(arg_types<tQuerySystemInformation>::value.begin(), arg_types<tQuerySystemInformation>::value.end());
    case PROBE_IDS::IdSetInformationWorkerFactory: return make_span(arg_types<tSetInformationWorkerFactory>::value.begin(), arg_types<tSetInformationWorkerFactory>::value.end());
    case PROBE_IDS::IdAdjustTokenClaimsAndDeviceGroups: return make_span(arg_types<tAdjustTokenClaimsAndDeviceGroups>::value.begin(), arg_types<tAdjustTokenClaimsAndDeviceGroups>::value.end());
    case PROBE_IDS::IdSaveMergedKeys: return make_span(arg_types<tSaveMergedKeys>::value.begin(), arg_types<tSaveMergedKeys>::value.end());
    default:
        return make_span(arg_types<void(*)()>::value.begin(), arg_types<void(*)()>::value.end());
    }
}