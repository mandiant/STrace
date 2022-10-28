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

#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt,   __VA_ARGS__)

extern "C" __declspec(dllexport) void StpInitialize(PluginApis& pApis) {
    g_Apis = pApis;
    LOG_INFO("Plugin Initializing...\r\n");

    g_Apis.pSetCallback("QueryInformationProcess", PROBE_IDS::IdQueryInformationProcess);
    g_Apis.pSetCallback("QueryInformationThread", PROBE_IDS::IdQueryInformationThread);
    g_Apis.pSetCallback("GetContextThread", PROBE_IDS::IdGetContextThread);
    g_Apis.pSetCallback("SetInformationThread", PROBE_IDS::IdSetInformationThread);
    g_Apis.pSetCallback("Close", PROBE_IDS::IdClose);


    LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
    LOG_INFO("Plugin DeInitializing...\r\n");

    g_Apis.pUnsetCallback("QueryInformationProcess");
    g_Apis.pUnsetCallback("QueryInformationThread");
    g_Apis.pUnsetCallback("GetContextThread");
    g_Apis.pUnsetCallback("SetInformationThread");
    g_Apis.pUnsetCallback("Close");

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

/*
 Receives the offset to CrossThreadFlags bitmask (https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/ethread/crossthreadflags.htm) 
 within ETHREAD (https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/ethread/index.htm), which varies between Windows versions. 
 That said, since STrace is supported only as of Windows 10 19041, effectively we'll have to use only one of the offsets.
 This function serves for future updates, in case the offset to the CrossThreadFlags field in ETHREAD changes. 
*/
int GetCrossThreadFlagsOffset()
{
    RTL_OSVERSIONINFOW verInfo; 

    if (RtlGetVersion(&verInfo) == STATUS_SUCCESS)
    {
        switch (verInfo.dwBuildNumber)
        {
            case 10240: // NT10.0
            case 10586: // 1511
                return 0x6BC;
            case 14393: // 1607
                return 0x6C0;
            case 15063: // 1703
                return 0x6C0;                
            case 16299: // 1709
            case 17134: // 1803
            case 17763: // 1809
                return 0x6D0;
            case 18362: // 1903 
                return 0x6E0;
            case 18663: // 1909
            case 19041: // 2004
            case 19042: // 20H2
            case 19043: // 21H1
            case 19044: // 21H2
            case 19045: // 22H2
            case 22000: 
            case 22621:
            default:
                return 0x510; // this is what's usually chosen
        }
    }

    return -1;
}

extern "C" __declspec(dllexport) bool StpIsTarget(CallerInfo & callerinfo) {
    if (strcmp(callerinfo.processName, "al-khaser.exe") == 0) {
        return true;
    }
    return false;
}
ASSERT_INTERFACE_IMPLEMENTED(StpIsTarget, tStpIsTarget, "StpIsTarget does not match the interface type");

enum TLS_SLOTS : uint8_t {
    PROCESS_INFO_CLASS = 0,
    PROCESS_INFO_DATA = 1,
    PROCESS_INFO_DATA_LEN = 2,

    CONTEXT_THREAD_DATA = 3,

    THREAD_INFO_HANDLE = 4,
    THREAD_INFO_CLASS = 5,
    THREAD_INFO_DATA = 6,
    THREAD_INFO_DATA_LEN = 7,

    CLOSE_NEW_RETVAL = 8,
    CLOSE_SHOULD_WRITE_RETVAL = 9
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
            auto pProcessInfo = ctx.read_argument(2);
            auto pProcessInfoLen = ctx.read_argument(4);

            g_Apis.pSetTlsData(processInfoClass, TLS_SLOTS::PROCESS_INFO_CLASS);
            g_Apis.pSetTlsData(pProcessInfo, TLS_SLOTS::PROCESS_INFO_DATA);
            g_Apis.pSetTlsData(pProcessInfoLen, TLS_SLOTS::PROCESS_INFO_DATA_LEN);
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
            auto pThreadInfo = ctx.read_argument(2);
            auto pThreadInfoLen = ctx.read_argument(3);

            g_Apis.pSetTlsData(threadInfoClass, TLS_SLOTS::THREAD_INFO_CLASS);
            g_Apis.pSetTlsData(pThreadInfo, TLS_SLOTS::THREAD_INFO_DATA);
            g_Apis.pSetTlsData(pThreadInfoLen, TLS_SLOTS::THREAD_INFO_DATA_LEN);
        );
        break;
    case PROBE_IDS::IdSetInformationThread:
        NEW_SCOPE(
            auto threadHandle = ctx.read_argument(0);
            auto threadInfoClass = ctx.read_argument(1);
            auto pThreadInfo = ctx.read_argument(2);
            auto ThreadInfoLen = ctx.read_argument(3);

            g_Apis.pSetTlsData(threadHandle, TLS_SLOTS::THREAD_INFO_HANDLE);
            g_Apis.pSetTlsData(threadInfoClass, TLS_SLOTS::THREAD_INFO_CLASS);
            g_Apis.pSetTlsData(pThreadInfo, TLS_SLOTS::THREAD_INFO_DATA);
            g_Apis.pSetTlsData(ThreadInfoLen, TLS_SLOTS::THREAD_INFO_DATA_LEN);
        );
        break;
    case PROBE_IDS::IdClose:
        /*When under a debugger, NtClose generates an exception for usermode apps if an invalid OR pseudohandle is closed.
        We cannot cancel calls in the way inline hooks can, so we replace the handle with a valid one in these cases instead.*/
        NEW_SCOPE(
            HANDLE Handle = (HANDLE)ctx.read_argument(0);
            auto PreviousMode = ExGetPreviousMode();

            BOOLEAN AuditOnClose;
            NTSTATUS ObStatus = ObQueryObjectAuditingByHandle(Handle, &AuditOnClose);

            // only invalid handles must we replace
            if (ObStatus == STATUS_INVALID_HANDLE) {
                BOOLEAN BeingDebugged = PsGetProcessDebugPort(PsGetCurrentProcess()) != nullptr;

                OBJECT_HANDLE_INFORMATION HandleInfo = { 0 };
                if (BeingDebugged)
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

                // Set new status appropriately
                if (BeingDebugged && NT_SUCCESS(ObStatus) &&
                    (HandleInfo.HandleAttributes & OBJ_PROTECT_CLOSE))
                {
                    g_Apis.pSetTlsData(STATUS_HANDLE_NOT_CLOSABLE, TLS_SLOTS::CLOSE_NEW_RETVAL);
                }
                else {
                    g_Apis.pSetTlsData(ObCloseHandle(Handle, PreviousMode), TLS_SLOTS::CLOSE_NEW_RETVAL);
                }
                g_Apis.pSetTlsData(true, TLS_SLOTS::CLOSE_SHOULD_WRITE_RETVAL);

                // build a random event name
                wchar_t alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
                uint64_t alphabetSize = ARRAYSIZE(alphabet) - 1;

                wchar_t eventBaseName[] = L"\\BaseNamedObjects\\STrace_FK_CLOSE";
                uint64_t eventBaseNameSize = wcslen(eventBaseName);

                SIZE_T strMemSize = sizeof(UNICODE_STRING) + eventBaseNameSize + 20;
                char* pUserMemStr = NULL;
                if (NT_SUCCESS(ZwAllocateVirtualMemory((HANDLE)-1, (PVOID*)&pUserMemStr, NULL, &strMemSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                    //g_Apis.pTraceAccessMemory(&attrs, (ULONG_PTR)pUserMemAttrs, sizeof(OBJECT_ATTRIBUTES), 1, false);

                    ULONG seed = callerinfo.processId;
                    wchar_t eventName[ARRAYSIZE(eventBaseName) + 20] = { 0 };
                    memcpy(eventName, eventBaseName, eventBaseNameSize * sizeof(wchar_t));

                    wchar_t* pRawString = (wchar_t*)(pUserMemStr + sizeof(UNICODE_STRING));
                    g_Apis.pTraceAccessMemory(eventBaseName, (ULONG_PTR)pRawString, eventBaseNameSize * sizeof(wchar_t), 1, false);

                    pRawString[eventBaseNameSize] = alphabet[RtlRandomEx(&seed) % alphabetSize];
                    pRawString[eventBaseNameSize + 1] = alphabet[RtlRandomEx(&seed) % alphabetSize];
                    pRawString[eventBaseNameSize + 2] = alphabet[RtlRandomEx(&seed) % alphabetSize];
                    pRawString[eventBaseNameSize + 3] = alphabet[RtlRandomEx(&seed) % alphabetSize];
                    pRawString[eventBaseNameSize + 4] = alphabet[RtlRandomEx(&seed) % alphabetSize];
                    pRawString[eventBaseNameSize + 5] = alphabet[RtlRandomEx(&seed) % alphabetSize];
                    pRawString[eventBaseNameSize + 6] = alphabet[RtlRandomEx(&seed) % alphabetSize];
                    pRawString[eventBaseNameSize + 7] = alphabet[RtlRandomEx(&seed) % alphabetSize];

                    USHORT len = wcslen(pRawString) * sizeof(wchar_t);
                    g_Apis.pTraceAccessMemory(&len, (ULONG_PTR)pUserMemStr + offsetof(UNICODE_STRING, Length), sizeof(USHORT), 1, false);

                    USHORT maxLen = len + 2;
                    g_Apis.pTraceAccessMemory(&maxLen, (ULONG_PTR)pUserMemStr + offsetof(UNICODE_STRING, MaximumLength), sizeof(USHORT), 1, false);

                    uint64_t RawStrAddr = (uint64_t)pRawString;
                    g_Apis.pTraceAccessMemory(&RawStrAddr, (ULONG_PTR)pUserMemStr + offsetof(UNICODE_STRING, Buffer), sizeof(void*), 1, false);
                }

                OBJECT_ATTRIBUTES attrs = { 0 };
                InitializeObjectAttributes(&attrs, (UNICODE_STRING*)pUserMemStr, OBJ_INHERIT, NULL, NULL);

                SIZE_T attrMemSize = sizeof(OBJECT_ATTRIBUTES);
                char* pUserMemAttrs = NULL;
                if (NT_SUCCESS(ZwAllocateVirtualMemory((HANDLE)-1, (PVOID*)&pUserMemAttrs, NULL, &attrMemSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                    g_Apis.pTraceAccessMemory(&attrs, (ULONG_PTR)pUserMemAttrs, sizeof(OBJECT_ATTRIBUTES), 1, false);
                }

                // handle must point at usermode memory for the usermode previousmode
                SIZE_T handleMemSize = sizeof(HANDLE);
                char* pUserMem = NULL;
                if (NT_SUCCESS(ZwAllocateVirtualMemory((HANDLE)-1, (PVOID*)&pUserMem, NULL, &handleMemSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                    // open new event to replace it, will be immediately closed
                    // Use NT so that PreviousMode is read and a usermode handle is created
                    if (NT_SUCCESS(NtCreateEvent((PHANDLE)pUserMem, EVENT_ALL_ACCESS, (OBJECT_ATTRIBUTES*)pUserMemAttrs, EVENT_TYPE::NotificationEvent, FALSE))) {
                        HANDLE fakeHandle = 0;
                        if (g_Apis.pTraceAccessMemory(&fakeHandle, (ULONG_PTR)pUserMem, sizeof(fakeHandle), 1, true)) {
                            if (Handle == (HANDLE)0x99999999ULL) {
                                __debugbreak();
                            }
                            ctx.write_argument(0, (uint64_t)fakeHandle);
                        }
                    }
                }
            }
        );
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
            uint64_t pProcessInfo = 0;
            uint64_t pProcessInfoLen = 0;

            if (g_Apis.pGetTlsData(processInfoClass, TLS_SLOTS::PROCESS_INFO_CLASS) && g_Apis.pGetTlsData(pProcessInfoLen, TLS_SLOTS::PROCESS_INFO_DATA_LEN) && g_Apis.pGetTlsData(pProcessInfo, TLS_SLOTS::PROCESS_INFO_DATA) && pProcessInfo) {
                // backup length (it can be null, in which case, don't read it)
                uint32_t origProcessInfoLen = 0;
                if (pProcessInfoLen) {
                    g_Apis.pTraceAccessMemory(&origProcessInfoLen, pProcessInfoLen, sizeof(origProcessInfoLen), 1, true);
                }

                switch (processInfoClass) {
                case (uint64_t)PROCESSINFOCLASS::ProcessDebugPort:
                    NEW_SCOPE(
                        DWORD64 newValue = 0;
                        g_Apis.pTraceAccessMemory(&newValue, pProcessInfo, sizeof(newValue), 1, false);
                    );
                    break;
                case (uint64_t)PROCESSINFOCLASS::ProcessDebugFlags:
                    NEW_SCOPE(
                        DWORD newValue = 1;
                        g_Apis.pTraceAccessMemory(&newValue, pProcessInfo, sizeof(newValue), 1, false);
                    );
                    break;
                case (uint64_t)PROCESSINFOCLASS::ProcessDebugObjectHandle:
                    if (ctx.read_return_value() == STATUS_SUCCESS) {
                        HANDLE newValue = 0;
                        g_Apis.pTraceAccessMemory(&newValue, pProcessInfo, sizeof(newValue), 1, false);
                        ctx.write_return_value(STATUS_PORT_NOT_SET);
                    }
                    break;
                }

                // reset length
                if (pProcessInfoLen) {
                    g_Apis.pTraceAccessMemory(&origProcessInfoLen, pProcessInfoLen, sizeof(origProcessInfoLen), 1, false);
                }
            }
        );
        break;
    case PROBE_IDS::IdQueryInformationThread:
        NEW_SCOPE(
            uint64_t threadInfoClass = 0;
            uint64_t pThreadInfo = 0;
            uint64_t pThreadInfoLen = 0;

            if (g_Apis.pGetTlsData(threadInfoClass, TLS_SLOTS::THREAD_INFO_CLASS) && g_Apis.pGetTlsData(pThreadInfoLen, TLS_SLOTS::THREAD_INFO_DATA_LEN) && g_Apis.pGetTlsData(pThreadInfo, TLS_SLOTS::THREAD_INFO_DATA) && pThreadInfo) {
                // backup length (it can be null, in which case, don't read it)
                uint32_t origThreadInfoLen = 0;
                if (pThreadInfoLen) {
                    g_Apis.pTraceAccessMemory(&origThreadInfoLen, pThreadInfoLen, sizeof(origThreadInfoLen), 1, true);
                }

                switch (threadInfoClass) {
                case (uint64_t)THREADINFOCLASS::ThreadWow64Context:
                    NEW_SCOPE(
                        uint64_t newValue = 0;
                        g_Apis.pTraceAccessMemory(&newValue, pThreadInfo + offsetof(WOW64_CONTEXT, Dr0), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, pThreadInfo + offsetof(WOW64_CONTEXT, Dr1), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, pThreadInfo + offsetof(WOW64_CONTEXT, Dr2), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, pThreadInfo + offsetof(WOW64_CONTEXT, Dr3), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, pThreadInfo + offsetof(WOW64_CONTEXT, Dr6), sizeof(newValue), 1, false);
                        g_Apis.pTraceAccessMemory(&newValue, pThreadInfo + offsetof(WOW64_CONTEXT, Dr7), sizeof(newValue), 1, false);
                    );
                    break;
                case (uint64_t)THREADINFOCLASS::ThreadHideFromDebugger:
                    NEW_SCOPE(
                        // Assume they expect YES back (i.e. someone bothers to check if their SetThreadInfo call worked).
                        BOOLEAN newValue = TRUE;
                        g_Apis.pTraceAccessMemory(&newValue, pThreadInfo, sizeof(newValue), 1, false);
                    );
                    break;
                }

                // reset length
                if (pThreadInfoLen) {
                    g_Apis.pTraceAccessMemory(&origThreadInfoLen, pThreadInfoLen, sizeof(origThreadInfoLen), 1, false);
                }
            }
        );
        break;
    case PROBE_IDS::IdSetInformationThread:
        NEW_SCOPE(
            uint64_t threadInfoClass = 0;
           
            if (g_Apis.pGetTlsData(threadInfoClass, TLS_SLOTS::THREAD_INFO_CLASS)) {
                switch (threadInfoClass) {
                case (uint64_t)THREADINFOCLASS::ThreadHideFromDebugger:
                    NEW_SCOPE(
                        ULONG crossThreadFlagsOffset = 0;
                        PVOID pETHREAD = { 0 };
                        ULONG crossThreadFlags = 0;
                        uint64_t threadHandle = 0;

                        if (g_Apis.pGetTlsData(threadHandle, TLS_SLOTS::THREAD_INFO_HANDLE) && threadHandle)
                        {
                            // get Ethread of thread info being set and reset the value
                            crossThreadFlagsOffset = GetCrossThreadFlagsOffset();
                            ObReferenceObjectByHandle((HANDLE)threadHandle, THREAD_ALL_ACCESS, NULL, ExGetPreviousMode(), (PVOID*)&pETHREAD, NULL);
                            if (pETHREAD)
                            {
                                g_Apis.pTraceAccessMemory(&crossThreadFlags, (ULONG_PTR)pETHREAD + crossThreadFlagsOffset, sizeof(crossThreadFlags), 1, true);

                                if (crossThreadFlags & 0x4)
                                {
                                    _InterlockedAnd((volatile unsigned long long*)(&crossThreadFlags), (unsigned long long)(0xFFFFFFFF - 4));
                                    g_Apis.pTraceAccessMemory(&crossThreadFlags, (ULONG_PTR)pETHREAD + crossThreadFlagsOffset, sizeof(crossThreadFlags), 1, false);
                                    ObDereferenceObject(pETHREAD);
                                }
                            }
                        }
                    );
                    break;
                }
            }
        );
        break;
    case PROBE_IDS::IdGetContextThread:
        NEW_SCOPE(
            uint64_t pContextThreadData = {0};
            if (g_Apis.pGetTlsData(pContextThreadData, TLS_SLOTS::CONTEXT_THREAD_DATA)) {
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
            uint64_t newRetVal = 0;
            uint64_t shouldWriteRetVal = 0;
            if (g_Apis.pGetTlsData(newRetVal, TLS_SLOTS::CLOSE_NEW_RETVAL) && g_Apis.pGetTlsData(shouldWriteRetVal, TLS_SLOTS::CLOSE_SHOULD_WRITE_RETVAL) && shouldWriteRetVal) {
                ctx.write_return_value(newRetVal);
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

