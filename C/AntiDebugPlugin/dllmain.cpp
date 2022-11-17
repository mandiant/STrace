#include <stdint.h>
#include <intrin.h>

#include "Interface.h"
#include "crt.h"
#include "utils.h"
#include "config.h"
#include "probedefs.h"
#include "string.h"
#include "magic_enum.hpp"


#pragma warning(disable: 6011)
PluginApis g_Apis;
HANDLE g_hGlobalPollThrd = 0;
BOOLEAN g_GlobalThreadShouldDie = FALSE;
LONGLONG g_ThreadWaitInterval = 10000000;  // 1 second (unit of 100 nanoseconds each)
void* g_GlobalPollThrdObject = nullptr;

const wchar_t targetProcW[] = L"BasicHello.exe";
const char targetProcA[] = "BasicHello.exe";

#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt,   __VA_ARGS__)

VOID GlobalPollThread(PVOID Context) {
    // must do this here since this call requires PASSIVE_LEVEL
    if (!g_GlobalPollThrdObject) {
        if(!NT_SUCCESS(ObReferenceObjectByHandle(g_hGlobalPollThrd, THREAD_ALL_ACCESS, NULL, KernelMode, &g_GlobalPollThrdObject, NULL))) {
            g_GlobalPollThrdObject = nullptr;
        }
    }

    while (!g_GlobalThreadShouldDie) {
        ULONG bufferSize = 0;
        if (ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize) == STATUS_INFO_LENGTH_MISMATCH) {
            char* pBuf = (char*)ExAllocatePoolWithTag(NonPagedPool, bufferSize, POOL_TAG);
            if (!pBuf) {
                continue;
            }

            if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, pBuf, bufferSize, &bufferSize))) {
                PSYSTEM_PROCESSES process = (PSYSTEM_PROCESSES)pBuf;
                do {
                    if (process->ProcessName.Length && process->ProcessName.Buffer && wcscmp(process->ProcessName.Buffer, targetProcW) == 0) {
                        void* eprocess = nullptr;
                        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)process->ProcessId, &eprocess);
                        if (NT_SUCCESS(status)) {
                            // PEB is in user process address space
                            KAPC_STATE state = {0};
                            KeStackAttachProcess(eprocess, &state);
    
                            PEB32* pPEB32 = (PEB32*)PsGetProcessWow64Process(eprocess);
                            PEB* pPeb = PsGetProcessPeb(eprocess);

                            auto CleanHeap = [](char* processHeap, const uint32_t FlagsOffset, const uint32_t ForceFlagsOffset) {
                                int32_t flags = 0;
                                int32_t forceFlags = 0;
                                if (g_Apis.pTraceAccessMemory(&flags, (ULONG_PTR)(processHeap + FlagsOffset), sizeof(flags), 1, true) && g_Apis.pTraceAccessMemory(&forceFlags, (ULONG_PTR)(processHeap + ForceFlagsOffset), sizeof(forceFlags), 1, true)) {
                                    flags &= ~HEAP_CLEARABLE_FLAGS;
                                    forceFlags &= ~HEAP_CLEARABLE_FORCE_FLAGS;

                                    g_Apis.pTraceAccessMemory(&flags, (ULONG_PTR)(processHeap + FlagsOffset), sizeof(flags), 1, false);
                                    g_Apis.pTraceAccessMemory(&forceFlags, (ULONG_PTR)(processHeap + ForceFlagsOffset), sizeof(forceFlags), 1, false);
                                }
                            };

                            auto CleanPEB = []<typename T>(char* pPeb, uint64_t& processHeap) {
                                uint64_t newValue = 0;
                                g_Apis.pTraceAccessMemory(&newValue, (ULONG_PTR)(pPeb + offsetof(T, BeingDebugged)), sizeof(T::BeingDebugged), 1, false);
                                g_Apis.pTraceAccessMemory(&newValue, (ULONG_PTR)(pPeb + offsetof(T, NtGlobalFlag)), sizeof(T::NtGlobalFlag), 1, false);

                                if (!g_Apis.pTraceAccessMemory(&processHeap, (ULONG_PTR)(pPeb + offsetof(T, ProcessHeap)), sizeof(T::ProcessHeap), 1, true)) {
                                    processHeap = 0;
                                }
                            };

                            uint64_t newValue = 0;
                            if (pPEB32) {
                                uint64_t processHeap = 0;
                                CleanPEB.template operator()<PEB32>((char*)pPEB32, processHeap);

                                if (processHeap) {
                                    const uint32_t FlagsOffset = 0x40; // Win10+
                                    const uint32_t ForceFlagsOffset = 0x44; // Win10+
                                    CleanHeap((char*)processHeap, FlagsOffset, ForceFlagsOffset);
                                }
                            } else {
                                uint64_t processHeap = 0;
                                CleanPEB.template operator()<PEB>((char*)pPeb, processHeap);

                                if (processHeap) {
                                    const uint32_t FlagsOffset = 0x70; // Win10+
                                    const uint32_t ForceFlagsOffset = 0x74; // Win10+
                                    CleanHeap((char*)processHeap, FlagsOffset, ForceFlagsOffset);
                                }
                            }
                            KeUnstackDetachProcess(&state);
                        }
                    }
                    process = (PSYSTEM_PROCESSES)((char*)process + process->NextEntryDelta);
                }while(process->NextEntryDelta);
            }

            ExFreePoolWithTag(pBuf, POOL_TAG);
        }
        
        LARGE_INTEGER sleep = {0};
        sleep.QuadPart = -g_ThreadWaitInterval;
        KeDelayExecutionThread(KernelMode, FALSE, &sleep);
    }
}

extern "C" __declspec(dllexport) void StpInitialize(PluginApis& pApis) {
    g_Apis = pApis;
    LOG_INFO("Plugin Initializing...\r\n");

    g_Apis.pSetCallback("QueryInformationProcess", PROBE_IDS::IdQueryInformationProcess);
    g_Apis.pSetCallback("QueryInformationThread", PROBE_IDS::IdQueryInformationThread);
    g_Apis.pSetCallback("GetContextThread", PROBE_IDS::IdGetContextThread);
    g_Apis.pSetCallback("SetInformationThread", PROBE_IDS::IdSetInformationThread);
    g_Apis.pSetCallback("Close", PROBE_IDS::IdClose);
    g_Apis.pSetCallback("CreateThreadEx", PROBE_IDS::IdCreateThreadEx);
    g_Apis.pSetCallback("QueryObject", PROBE_IDS::IdQueryObject);
    g_Apis.pSetCallback("QuerySystemInformation", PROBE_IDS::IdQuerySystemInformation);
    g_Apis.pSetCallback("OpenProcess", PROBE_IDS::IdOpenProcess);
    g_Apis.pSetCallback("SystemDebugControl", PROBE_IDS::IdSystemDebugControl);

    NTSTATUS status = PsCreateSystemThread(&g_hGlobalPollThrd,(ACCESS_MASK)0,NULL,(HANDLE)0,NULL,GlobalPollThread,NULL);

    LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
    LOG_INFO("Plugin DeInitializing...\r\n");

    // Wait for thread to die (timeout necessary at dispatch level)
    if(g_GlobalPollThrdObject) {
        g_GlobalThreadShouldDie = TRUE;
        LARGE_INTEGER sleep = { 0 };
        sleep.QuadPart = -(g_ThreadWaitInterval * 3); // max of 3x what the thread sleeps for should be fine
        KeWaitForSingleObject(g_GlobalPollThrdObject, KWAIT_REASON::Executive, KernelMode, FALSE, &sleep);
        g_hGlobalPollThrd = 0;
    }

    g_Apis.pUnsetCallback("QueryInformationProcess");
    g_Apis.pUnsetCallback("QueryInformationThread");
    g_Apis.pUnsetCallback("GetContextThread");
    g_Apis.pUnsetCallback("SetInformationThread");
    g_Apis.pUnsetCallback("Close");
    g_Apis.pUnsetCallback("CreateThreadEx");
    g_Apis.pUnsetCallback("QueryObject");
    g_Apis.pUnsetCallback("QuerySystemInformation");
    g_Apis.pUnsetCallback("OpenProcess");
    g_Apis.pUnsetCallback("SystemDebugControl");

    LOG_INFO("Plugin DeInitialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpDeInitialize, tStpDeInitialize, "StpDeInitialize does not match the interface type");

void PrintStackTrace(CallerInfo& callerinfo) {
    for (int i = 0; i < callerinfo.frameDepth; i++) {
        if ((callerinfo.frames)[i].frameaddress) {
            const auto modulePathLen = (callerinfo.frames)[i].modulePath ? strlen((callerinfo.frames)[i].modulePath) : 0;

            // add brackets around module dynamically
            if (modulePathLen) {
                char moduleName[sizeof(CallerInfo::StackFrame::modulePath) + 2] = { 0 };
                moduleName[0] = '[';
                strcpy(&moduleName[1], (callerinfo.frames)[i].modulePath);
                moduleName[modulePathLen + 1] = ']';

                LOG_INFO("  %-18s +0x%08llx\r\n", moduleName, (callerinfo.frames)[i].frameaddress - (callerinfo.frames)[i].modulebase);
            }
            else {
                LOG_INFO("  %-18s 0x%016llx\r\n", "[UNKNOWN MODULE]", (callerinfo.frames)[i].frameaddress);
            }
        }
        else {
            LOG_INFO("  Frame Missing\r\n");
        }
    }
}

void LiveKernelDump(LiveKernelDumpFlags flags)
{
    const auto MANUALLY_INITIATED_CRASH = 0xE2;
    DbgkWerCaptureLiveKernelDump(L"STRACE", MANUALLY_INITIATED_CRASH, 1, 3, 3, 7, flags);
}

extern "C" __declspec(dllexport) bool StpIsTarget(CallerInfo & callerinfo) {
    if (strcmp(callerinfo.processName, targetProcA) == 0) {
        return true;
    }
    return false;
}
ASSERT_INTERFACE_IMPLEMENTED(StpIsTarget, tStpIsTarget, "StpIsTarget does not match the interface type");

enum TLS_SLOTS : uint8_t {
    PROCESS_INFO_CLASS = 0,
    PROCESS_INFO_DATA = 1,
    PROCESS_INFO_RET_LEN = 2,

    CONTEXT_THREAD_DATA = 3,

    THREAD_INFO_HANDLE = 4,
    THREAD_INFO_CLASS = 5,
    THREAD_INFO_DATA = 6,
    THREAD_INFO_RET_LEN = 7,

    CLOSE_RETVAL = 8,
    CLOSE_OVERWRITE_RETVAL = 9,

    OBJECT_INFO_CLASS = 10,
    OBJECT_INFO_DATA = 11,
    OBJECT_INFO_RET_LEN = 12,

    SYS_INFO_CLASS = 13,
    SYS_INFO_DATA = 14,
    SYS_INFO_RET_LEN = 15
};

/*
This is a funny little trick. In a switch case, if you define a new scope with locals they all
get lifted to the parent scope which can allocate lots of stack space even if that case isn't
always taken. The fix for that is to not define locals in a switch case, and call a function instead.
But that's annoying and breaks cleanly putting the code in the switch body. Instead, we can define a lambda.

The lambda acts like we made a function, which we ensure is true by forcing noinline. This way stack space is only
allocated if the case is taken. This basically is a technique to declare a global function, while within a function.
*/
#define NEW_SCOPE(code) [&]() DECLSPEC_NOINLINE { code }()

// no change to retval
DECLSPEC_NOINLINE void noop() {
    volatile uint64_t noop = 0x1337;
}

// Do same checks as original, but otherwise nothing except say ok
DECLSPEC_NOINLINE NTSTATUS NoopNtSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
) {
    auto PreviousMode = ExGetPreviousMode();
    ULONG ProbeAlignment = 0;

    if (PreviousMode != KernelMode) {
        switch (ThreadInformationClass) {
        case THREADINFOCLASS::ThreadHideFromDebugger:
            ProbeAlignment = sizeof(ULONG);
        }

        // mimick ProbeForRead
        if (ThreadInformationLength) {
            KIRQL oldIrql = KfRaiseIrql(DTRACE_IRQL);
            uint64_t tmp = 0;
            if (!g_Apis.pTraceAccessMemory(&tmp, (ULONG_PTR)ThreadInformation, 1, 1, true)) {
                KeLowerIrql(oldIrql);
                return STATUS_ACCESS_VIOLATION;
            }
            KeLowerIrql(oldIrql);
        }
    }

    switch (ThreadInformationClass) {
    case THREADINFOCLASS::ThreadHideFromDebugger:
        if (ThreadInformationLength != 0) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        // check if handle is valid
        HANDLE Thread = 0;
        auto status = ObReferenceObjectByHandle(ThreadHandle,
            THREAD_SET_INFORMATION,
            NULL,
            PreviousMode,
            &Thread,
            NULL);

        if (!NT_SUCCESS(status)) {
            return status;
        }
        break;
    }

    return STATUS_SUCCESS;
}

DECLSPEC_NOINLINE NTSTATUS noop_openprocess_accessdenied(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    if (ProcessHandle) {
        HANDLE newValue = 0;
        g_Apis.pTraceAccessMemory(&newValue, (ULONG_PTR)ProcessHandle, sizeof(newValue), 1, false);
    }
    return STATUS_ACCESS_DENIED; 
}

DECLSPEC_NOINLINE NTSTATUS NTAPI NoopNtSystemDebugControl(
    IN SYSDBG_COMMAND Command,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnLength) {
    if (((Command - SysDbgGetTriageDump) & 0xFFFFFFF7) != 0) {
        return STATUS_DEBUGGER_INACTIVE;
    } 

    // SeSinglePrivilegeCheck(SeDebugPrivilege, PreviousMode). Force this to always look like it failed.
    return STATUS_ACCESS_DENIED;
}

void LogAntiDbg(const char* Msg, CallerInfo& callerinfo) {
    LOG_INFO("[ANTI-DBG]%s\n", Msg);
    PrintStackTrace(callerinfo);
}

/**
pService: Pointer to system service from SSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses
pArgs: Argument array, usually x64 fastcall registers rcx, rdx, r8, r9
pArgSize: Length of argument array, usually hard coded to 4
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo)
{
    // Ported from: https://github.com/mrexodia/TitanHide
    // Credits: Duncan Ogilvie (mrexodia), Matthijs Lavrijsen (Matti)
    switch ((PROBE_IDS)probeId) {
    case PROBE_IDS::IdQueryInformationProcess:
        NEW_SCOPE(
            auto processInfoClass = ctx.read_argument(1);
            auto processInfoData = ctx.read_argument(2);
            auto processInfoRetLen = ctx.read_argument(4);

            g_Apis.pSetTlsData(processInfoClass, TLS_SLOTS::PROCESS_INFO_CLASS);
            g_Apis.pSetTlsData(processInfoData, TLS_SLOTS::PROCESS_INFO_DATA);
            g_Apis.pSetTlsData(processInfoRetLen, TLS_SLOTS::PROCESS_INFO_RET_LEN);
        );
        break;
    case PROBE_IDS::IdGetContextThread:
        NEW_SCOPE(
            auto pContextThreadData = ctx.read_argument(1);
            g_Apis.pSetTlsData(pContextThreadData, TLS_SLOTS::CONTEXT_THREAD_DATA);
        );
        break;
    case PROBE_IDS::IdQueryInformationThread:
        NEW_SCOPE(
            auto threadInfoClass = ctx.read_argument(1);
            auto threadInfoData = ctx.read_argument(2);
            auto threadInfoRetLen = ctx.read_argument(4);

            g_Apis.pSetTlsData(threadInfoClass, TLS_SLOTS::THREAD_INFO_CLASS);
            g_Apis.pSetTlsData(threadInfoData, TLS_SLOTS::THREAD_INFO_DATA);
            g_Apis.pSetTlsData(threadInfoRetLen, TLS_SLOTS::THREAD_INFO_RET_LEN);
        );
        break;
    case PROBE_IDS::IdSetInformationThread:
        NEW_SCOPE(
            auto threadInfoClass = ctx.read_argument(1);

            switch (threadInfoClass) {
            case (uint64_t)THREADINFOCLASS::ThreadHideFromDebugger:
                LogAntiDbg("NtSetInformationThread ThreadHideFromDebugger", callerinfo);
                // just do nothing, pretend the call happened ok
                ctx.redirect_syscall((uint64_t)&NoopNtSetInformationThread);
                break;
            }
        );
        break;
    case PROBE_IDS::IdClose:
        /*When under a debugger, NtClose generates an exception for usermode apps if an invalid OR pseudohandle is closed.
        We have to replace the logic of this syscall entire. This mirrors the functionality an inline hook provides, but simpler. */
        NEW_SCOPE(
            HANDLE Handle = (HANDLE)ctx.read_argument(0);
            auto PreviousMode = ExGetPreviousMode();

            BOOLEAN AuditOnClose;
            NTSTATUS ObStatus = ObQueryObjectAuditingByHandle(Handle, &AuditOnClose);

            if (ObStatus != STATUS_INVALID_HANDLE) {
                // handle isn't invalid, check some additional properties
                BOOLEAN BeingDebugged = PsGetProcessDebugPort(PsGetCurrentProcess()) != nullptr;
                BOOLEAN GlobalFlgExceptions = RtlGetNtGlobalFlags() & FLG_ENABLE_CLOSE_EXCEPTIONS;
                OBJECT_HANDLE_INFORMATION HandleInfo = { 0 };

                // exceptions are raised if debugger attached OR global flag set
                if (BeingDebugged || GlobalFlgExceptions)
                {
                    // Get handle info so we can check if the handle has the ProtectFromClose bit set
                    PVOID Object = nullptr;
                    ObStatus = ObReferenceObjectByHandle(Handle,
                        0,
                        nullptr,
                        PreviousMode,
                        &Object,
                        &HandleInfo);

                    if (Object != nullptr) {
                        ObDereferenceObject(Object);
                    }
                }

                // If debugged, or handle not closeable, avoid exception and give noncloseable back
                if ((BeingDebugged || GlobalFlgExceptions) && NT_SUCCESS(ObStatus) && (HandleInfo.HandleAttributes & OBJ_PROTECT_CLOSE))
                {
                    LogAntiDbg("NtClose on a handle that would RaiseException", callerinfo);

                    ctx.redirect_syscall((uint64_t)&noop);
                    g_Apis.pSetTlsData(STATUS_HANDLE_NOT_CLOSABLE, CLOSE_RETVAL);
                    g_Apis.pSetTlsData(TRUE, CLOSE_OVERWRITE_RETVAL);
                } else {
                    // Normal Path. Actually do the close (ourselves), it's ok won't raise. Cancel the original close since we did it (could let this occur as normal if we wanted).
                    ctx.redirect_syscall((uint64_t)&noop);
                    g_Apis.pSetTlsData(ObCloseHandle(Handle, PreviousMode), CLOSE_RETVAL);
                    g_Apis.pSetTlsData(TRUE, CLOSE_OVERWRITE_RETVAL);
                }
            } else {
                LogAntiDbg("NtClose on an Invalid Handle", callerinfo);

                // the handle is invalid, would raise so cancel that, just set status
                ctx.redirect_syscall((uint64_t)&noop);
                g_Apis.pSetTlsData(STATUS_INVALID_HANDLE, CLOSE_RETVAL);
                g_Apis.pSetTlsData(TRUE, CLOSE_OVERWRITE_RETVAL);
            }
        );
        break;
    case PROBE_IDS::IdCreateThreadEx:
        NEW_SCOPE(
            ULONG createFlags = ctx.read_argument(6);
            if (createFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER != 0) {
                LogAntiDbg("NtCreateThreadEx THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER", callerinfo);
                createFlags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
                ctx.write_argument(6, createFlags);
            }
        );
        break;
    case PROBE_IDS::IdQueryObject:
        NEW_SCOPE(
            auto objectInfoClass = ctx.read_argument(1);
            auto objectInfoData = ctx.read_argument(2);
            auto objectInfoRetLen = ctx.read_argument(4);

            g_Apis.pSetTlsData(objectInfoClass, TLS_SLOTS::OBJECT_INFO_CLASS);
            g_Apis.pSetTlsData(objectInfoData, TLS_SLOTS::OBJECT_INFO_DATA);
            g_Apis.pSetTlsData(objectInfoRetLen, TLS_SLOTS::OBJECT_INFO_RET_LEN);
        );
        break;
    case PROBE_IDS::IdQuerySystemInformation:
        NEW_SCOPE(
            auto sysInfoClass = ctx.read_argument(0);
            auto sysInfoData = ctx.read_argument(1);
            auto sysInfoRetLen = ctx.read_argument(3);

            g_Apis.pSetTlsData(sysInfoClass, TLS_SLOTS::SYS_INFO_CLASS);
            g_Apis.pSetTlsData(sysInfoData, TLS_SLOTS::SYS_INFO_DATA);
            g_Apis.pSetTlsData(sysInfoRetLen, TLS_SLOTS::SYS_INFO_RET_LEN);
        );
        break;
    case PROBE_IDS::IdOpenProcess:
        NEW_SCOPE(
            uint64_t pClientId = ctx.read_argument(3);
            CLIENT_ID clientId = {0};
            if (pClientId && g_Apis.pTraceAccessMemory(&clientId, (ULONG_PTR)pClientId, sizeof(clientId), 1, true)) {
                void* eprocess = nullptr;
                PsLookupProcessByProcessId((HANDLE)clientId.UniqueProcess, &eprocess);
                if (eprocess) {
                    // Deny opening this to hide SeDebugPriviledge (TODO: there's other valid targets we should block, but do they actually get used IRL?)
                    if (strcmp(PsGetProcessImageFileName(eprocess), "csrss.exe") == 0) {
                        LogAntiDbg("OpenProcess on csrss.exe to check for SeDebugPrivilege", callerinfo);
                        ctx.redirect_syscall((uint64_t)&noop_openprocess_accessdenied);
                    }
                }
            }
        );
        break;
    case PROBE_IDS::IdSystemDebugControl:
        LogAntiDbg("NtSystemDebugControl", callerinfo);
        ctx.redirect_syscall((uint64_t)&NoopNtSystemDebugControl);
        break;
    default:
        break;
    }
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackEntry, tStpCallbackEntryPlugin, "StpCallbackEntry does not match the interface type");

/**
pService: Pointer to system service from SSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses, usually hard coded to 1
pArgs: Argument array, usually a single entry that holds return value
pArgSize: Length of argument array, usually hard coded to 1
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo & callerinfo) {
    switch ((PROBE_IDS)probeId) {
    case PROBE_IDS::IdQueryInformationProcess:
        // Internally, the kernel sets ProcessInfo first THEN sets ProcessInfoLength. We have to mirror this. So we bypass processInfo values first, then set length.
        // The anti-debug technique used sets both ProcessInfo and ProcessInfo length to be teh same pointer, so if you JUST bypass ProcessInfo then the Length value gets 
        // overwritten too since they're the same buffer. Fixing the Length value means, we have to write it too, which is why we bother backing it up.
        NEW_SCOPE(
            uint64_t processInfoClass = 0;
            uint64_t processInfoData = 0;
            uint64_t processInfoLen = 0;

            if (g_Apis.pGetTlsData(processInfoClass, TLS_SLOTS::PROCESS_INFO_CLASS) && g_Apis.pGetTlsData(processInfoLen, TLS_SLOTS::PROCESS_INFO_RET_LEN) && g_Apis.pGetTlsData(processInfoData, TLS_SLOTS::PROCESS_INFO_DATA) && processInfoData) {
                // backup length (it can be null, in which case, don't read it)
                uint32_t origProcessInfoLen = 0;
                if (processInfoLen) {
                    g_Apis.pTraceAccessMemory(&origProcessInfoLen, processInfoLen, sizeof(origProcessInfoLen), 1, true);
                }

                switch (processInfoClass) {
                case (uint64_t)PROCESSINFOCLASS::ProcessDebugPort:
                    NEW_SCOPE(
                        LogAntiDbg("NtQueryInformationProcess ProcessDebugPort", callerinfo);

                        DWORD64 newValue = 0;
                        g_Apis.pTraceAccessMemory(&newValue, processInfoData, sizeof(newValue), 1, false);
                    );
                    break;
                case (uint64_t)PROCESSINFOCLASS::ProcessDebugFlags:
                    NEW_SCOPE(
                        LogAntiDbg("NtQueryInformationProcess ProcessDebugFlags", callerinfo);

                        DWORD newValue = 1;
                        g_Apis.pTraceAccessMemory(&newValue, processInfoData, sizeof(newValue), 1, false);
                    );
                    break;
                case (uint64_t)PROCESSINFOCLASS::ProcessDebugObjectHandle:
                    NEW_SCOPE(
                        LogAntiDbg("NtQueryInformationProcess ProcessDebugObjectHandle", callerinfo);
                        if (ctx.read_return_value() == STATUS_SUCCESS) {
                            HANDLE newValue = 0;
                            g_Apis.pTraceAccessMemory(&newValue, processInfoData, sizeof(newValue), 1, false);
                            ctx.write_return_value(STATUS_PORT_NOT_SET);
                        }
                    );
                    break;
                }

                // reset length
                if (processInfoLen) {
                    g_Apis.pTraceAccessMemory(&origProcessInfoLen, processInfoLen, sizeof(origProcessInfoLen), 1, false);
                }
            }
        );
        break;
    case PROBE_IDS::IdQueryInformationThread:
        NEW_SCOPE(
            uint64_t threadInfoClass = 0;
            uint64_t threadInfoData = 0;
            uint64_t threadInfoRetLen = 0;

            if (g_Apis.pGetTlsData(threadInfoClass, TLS_SLOTS::THREAD_INFO_CLASS) && g_Apis.pGetTlsData(threadInfoRetLen, TLS_SLOTS::THREAD_INFO_RET_LEN) && g_Apis.pGetTlsData(threadInfoData, TLS_SLOTS::THREAD_INFO_DATA) && threadInfoData) {
                // backup length (it can be null, in which case, don't read it)
                uint32_t origThreadInfoLen = 0;
                if (threadInfoRetLen) {
                    g_Apis.pTraceAccessMemory(&origThreadInfoLen, threadInfoRetLen, sizeof(origThreadInfoLen), 1, true);
                }

                switch (threadInfoClass) {
                case (uint64_t)THREADINFOCLASS::ThreadWow64Context:
                    NEW_SCOPE(
                        LogAntiDbg("NtQueryInformationThread ThreadWow64Context, potentially checking DBG registers", callerinfo);

                        uint64_t newValue = 0;
                        g_Apis.pTraceAccessMemory(&newValue, threadInfoData + offsetof(WOW64_CONTEXT, Dr0), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, threadInfoData + offsetof(WOW64_CONTEXT, Dr1), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, threadInfoData + offsetof(WOW64_CONTEXT, Dr2), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, threadInfoData + offsetof(WOW64_CONTEXT, Dr3), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, threadInfoData + offsetof(WOW64_CONTEXT, Dr6), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, threadInfoData + offsetof(WOW64_CONTEXT, Dr7), sizeof(newValue), 1, false);
                    );
                    break;
                case (uint64_t)THREADINFOCLASS::ThreadHideFromDebugger:
                    NEW_SCOPE(
                        LogAntiDbg("NtQueryInformationThread ThreadHideFromDebugger, verifying was set and not previously bypassed (anti-anti-anti-dbg)", callerinfo);

                        // Assume they expect YES back (i.e. someone bothers to check if their SetThreadInfo call worked).
                        BOOLEAN newValue = TRUE;
                        g_Apis.pTraceAccessMemory(&newValue, threadInfoData, sizeof(newValue), 1, false);
                    );
                    break;
                }

                // reset length
                if (threadInfoRetLen) {
                    g_Apis.pTraceAccessMemory(&origThreadInfoLen, threadInfoRetLen, sizeof(origThreadInfoLen), 1, false);
                }
            }
        );
        break;
    case PROBE_IDS::IdGetContextThread:
        NEW_SCOPE(
            uint64_t pContextThreadData = { 0 };
            if (g_Apis.pGetTlsData(pContextThreadData, TLS_SLOTS::CONTEXT_THREAD_DATA)) {
                LogAntiDbg("NtGetContextThread, potentially checking DBG registers", callerinfo);

                uint64_t newValue = 0;
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, Dr0), sizeof(newValue), 1, false);
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, Dr1), sizeof(newValue), 1, false);
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, Dr2), sizeof(newValue), 1, false);
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, Dr3), sizeof(newValue), 1, false);
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, Dr6), sizeof(newValue), 1, false);
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, Dr7), sizeof(newValue), 1, false);

                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, LastBranchToRip), sizeof(newValue), 1, false);
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, LastBranchFromRip), sizeof(newValue), 1, false);
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, LastExceptionToRip), sizeof(newValue), 1, false);
                g_Apis.pTraceAccessMemory(&newValue, pContextThreadData + offsetof(CONTEXT, LastExceptionFromRip), sizeof(newValue), 1, false);
            }
        );
        break;
    case PROBE_IDS::IdClose:
        NEW_SCOPE(
            uint64_t ovrwRetVal = { 0 };
            uint64_t newRetVal = { 0 };
            if (g_Apis.pGetTlsData(ovrwRetVal, TLS_SLOTS::CLOSE_OVERWRITE_RETVAL) && g_Apis.pGetTlsData(newRetVal, TLS_SLOTS::CLOSE_RETVAL) && ovrwRetVal) {
                ctx.write_return_value(newRetVal);
            }
        );
        break;
    case PROBE_IDS::IdQueryObject:
        NEW_SCOPE(
            uint64_t objectInfoClass = 0;
            uint64_t objectInfoData = 0;
            uint64_t objectInfoRetLen = 0;

            // return: true if debugobject zeroed
            auto ZeroDbgObject = [&](uint64_t pObjInfo, OBJECT_TYPE_INFORMATION& typeInfo) {
                if (g_Apis.pTraceAccessMemory(&typeInfo, (ULONG_PTR)pObjInfo, sizeof(typeInfo), 1, true)) {
                    wchar_t typeName[20] = { 0 };
                    uint32_t typeNameByteSize = typeInfo.TypeName.Length > sizeof(typeName) ? sizeof(typeName) : typeInfo.TypeName.Length;
                    if (g_Apis.pTraceAccessMemory(&typeName, (ULONG_PTR)typeInfo.TypeName.Buffer, typeNameByteSize, 1, true)) {
                        if (wcscmp(typeName, L"DebugObject") == 0) {
                            typeInfo.TotalNumberOfObjects = 0;
                            typeInfo.TotalNumberOfHandles = 0;
                            return (bool)g_Apis.pTraceAccessMemory(&typeInfo, pObjInfo, sizeof(typeInfo), 1, false);
                        }
                        return false;
                    }
                }
                return false;
            };

            NTSTATUS status = ctx.read_return_value();
            if (NT_SUCCESS(status) && g_Apis.pGetTlsData(objectInfoClass, TLS_SLOTS::OBJECT_INFO_CLASS) && g_Apis.pGetTlsData(objectInfoData, TLS_SLOTS::OBJECT_INFO_DATA) && g_Apis.pGetTlsData(objectInfoRetLen, TLS_SLOTS::OBJECT_INFO_RET_LEN) && objectInfoData) {
                /*
                This isn't perfect. DebugObjects are always present in the output, so we can't remove them, but we can zero their counts.
                Some things purposely create a debug object, then check if the count is zero, which detects anti-anti-dbg like this.
                Need to hook NtCreateDebugObject, and increment by 1 for each call to that, before the handle is closed via NtClose.
                TODO: fix this (it's hard), it's an anti-anti-anti-dbg technique (not common?)
                */
                uint32_t origObjectInfoLen = 0;
                if (objectInfoRetLen) {
                    g_Apis.pTraceAccessMemory(&origObjectInfoLen, objectInfoRetLen, sizeof(origObjectInfoLen), 1, true);
                }

                switch (objectInfoClass) {
                case ObjectTypeInformation: {
                    LogAntiDbg("NtQueryObject ObjectTypeInformation, count DebugObjects", callerinfo);
                    OBJECT_TYPE_INFORMATION typeInfo = { 0 };
                    ZeroDbgObject(objectInfoData, typeInfo);
                    break;
                }
                case ObjectTypesInformation: {
                    OBJECT_ALL_INFORMATION objectAllInfo = { 0 };
                    if (g_Apis.pTraceAccessMemory(&objectAllInfo, objectInfoData, sizeof(objectAllInfo), 1, true)) {
                        uint32_t numberOfObjects = objectAllInfo.NumberOfObjects;
                        char* pObjInfoLocation = (char*)objectAllInfo.ObjectTypeInformation;
                        for (uint32_t i = 0; i < numberOfObjects; i++) {
                            OBJECT_TYPE_INFORMATION typeInfo = { 0 };
                            if (ZeroDbgObject((uint64_t)pObjInfoLocation, typeInfo)) {
                                LogAntiDbg("NtQueryObject ObjectTypesInformation, count DebugObjects", callerinfo);
                                break;
                            }

                            pObjInfoLocation = ((char*)typeInfo.TypeName.Buffer) + typeInfo.TypeName.MaximumLength;

                            // alignment (next info is next aligned pointer after end of where UNICODE_STRING.Buffer data is)
                            // MS: what the heck is this structure layout???
                            ULONG_PTR tmp = ((ULONG_PTR)pObjInfoLocation) & -(LONG_PTR)sizeof(void*);
                            if ((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
                                tmp += sizeof(void*);

                            pObjInfoLocation = (char*)tmp;
                        }
                    }
                    break;
                }
                }

                // reset length
                if (objectInfoRetLen) {
                    g_Apis.pTraceAccessMemory(&origObjectInfoLen, objectInfoRetLen, sizeof(origObjectInfoLen), 1, false);
                }
            }
        );
        break;
    case IdQuerySystemInformation:
        NEW_SCOPE(
            uint64_t sysInfoClass = 0;
            uint64_t sysInfoData = 0;
            uint64_t sysInfoRetLen = 0;

            NTSTATUS status = ctx.read_return_value();
            if (NT_SUCCESS(status) && g_Apis.pGetTlsData(sysInfoClass, TLS_SLOTS::SYS_INFO_CLASS) && g_Apis.pGetTlsData(sysInfoData, TLS_SLOTS::SYS_INFO_DATA) && g_Apis.pGetTlsData(sysInfoRetLen, TLS_SLOTS::SYS_INFO_RET_LEN) && sysInfoData) {
                uint32_t origSysInfoLen = 0;
                if (sysInfoRetLen) {
                    g_Apis.pTraceAccessMemory(&origSysInfoLen, sysInfoRetLen, sizeof(origSysInfoLen), 1, true);
                }

                switch (sysInfoClass) {
                case SystemKernelDebuggerInformation: {
                    LogAntiDbg("NtQuerySystemInformation SystemKernelDebuggerInformation", callerinfo);
                    SYSTEM_KERNEL_DEBUGGER_INFORMATION debugInfo = { 0 };
                    if (g_Apis.pTraceAccessMemory(&debugInfo, sysInfoData, sizeof(debugInfo), 1, true)) {
                        debugInfo.DebuggerEnabled = false;
                        debugInfo.DebuggerNotPresent = true;
                        g_Apis.pTraceAccessMemory(&debugInfo, sysInfoData, sizeof(debugInfo), 1, false);
                    }
                    break;
                }
                case SystemKernelDebuggerInformationEx: {
                    LogAntiDbg("NtQuerySystemInformation SystemKernelDebuggerInformationEx", callerinfo);
                    SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX debugInfoEx = { 0 };
                    if (g_Apis.pTraceAccessMemory(&debugInfoEx, sysInfoData, sizeof(debugInfoEx), 1, true)) {
                        debugInfoEx.DebuggerAllowed = false;
                        debugInfoEx.DebuggerEnabled = false;
                        debugInfoEx.DebuggerPresent = false;
                        g_Apis.pTraceAccessMemory(&debugInfoEx, sysInfoData, sizeof(debugInfoEx), 1, false);
                    }
                    break;
                }
                }

                // reset length
                if (sysInfoRetLen) {
                    g_Apis.pTraceAccessMemory(&origSysInfoLen, sysInfoRetLen, sizeof(origSysInfoLen), 1, false);
                }
            }
        );
        break;
    default:
        break;
    }
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackReturn, tStpCallbackReturnPlugin, "StpCallbackEntry does not match the interface type");

BOOL APIENTRY Main(HMODULE hModule, DWORD  reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

