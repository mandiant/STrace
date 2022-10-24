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
bool g_isHideFromDebugger;


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


    LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
    LOG_INFO("Plugin DeInitializing...\r\n");

    g_Apis.pUnsetCallback("QueryInformationProcess");
    g_Apis.pUnsetCallback("QueryInformationThread");
    g_Apis.pUnsetCallback("GetContextThread");
    g_Apis.pUnsetCallback("SetInformationThread");

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
 That said, since STrace is supported only as of Windows 10 19041, effectively we'll have to use only one of two offsets (depending on if the CPU is a 
 32 bit or 64 bit one). This function serves for future updates, in case the offset to the CrossThreadFlags field in ETHREAD changes. 
*/
int GetCrossThreadFlagsOffset()
{
    RTL_OSVERSIONINFOW verInfo; 

    if (RtlGetVersion(&verInfo) == STATUS_SUCCESS)
    {
#if _WIN64
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
                return 0x510;
        }

#else
        switch (verInfo.dwBuildNumber)
        {
        case 10240: // NT10.0
        case 10586: // 1511
            return 0x3C8;
        case 14393: // 1607
            return 0x3C4;
        case 15063: // 1703
        case 16299: // 1709
        case 17134: // 1803
        case 17763: // 1809
            return 0x3CC;
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
            return 0x2FC;
        }
        
#endif
    
    }
    else
        return -1;
    
}


extern "C" __declspec(dllexport) bool StpIsTarget(CallerInfo & callerinfo) {
    if (strcmp(callerinfo.processName, "test.exe") == 0) {
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
    WOW64_CONTEXT_THREAD_DATA = 4,
    THREAD_HANDLE = 5,
    QUERY_THREAD_HIDE_FROM_DEBUGGER = 6,
    THREAD_HIDE_FROM_DEBUGGER_DATA = 7
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
            auto pContextThreadData = (PCONTEXT)ctx.read_argument(1);

            g_Apis.pSetTlsData((uint64_t)pContextThreadData, TLS_SLOTS::CONTEXT_THREAD_DATA);
        );
        break;
    case PROBE_IDS::IdQueryInformationThread:
        NEW_SCOPE(
            auto threadInfoClass = ctx.read_argument(1);
            auto pThreadInfoData = ctx.read_argument(2);
            auto threadInfoLen = ctx.read_argument(3);

            if (threadInfoClass == (uint64_t)THREADINFOCLASS::ThreadWow64Context && threadInfoLen == sizeof(WOW64_CONTEXT)) {
                g_Apis.pSetTlsData((uint64_t)pThreadInfoData, TLS_SLOTS::WOW64_CONTEXT_THREAD_DATA);
            }
            else if (threadInfoClass == (uint64_t)THREADINFOCLASS::ThreadHideFromDebugger)
            {
                g_Apis.pSetTlsData(true, TLS_SLOTS::QUERY_THREAD_HIDE_FROM_DEBUGGER);
                g_Apis.pSetTlsData((uint64_t)pThreadInfoData, TLS_SLOTS::THREAD_HIDE_FROM_DEBUGGER_DATA);
            }
            else
            {
                g_Apis.pSetTlsData(false, TLS_SLOTS::QUERY_THREAD_HIDE_FROM_DEBUGGER);
            }
        );
        break;
    case PROBE_IDS::IdSetInformationThread:
        NEW_SCOPE(
            auto threadHandle = ctx.read_argument(0);
            auto threadInfoClass = ctx.read_argument(1);
            auto pThreadInfoData = ctx.read_argument(2);
            auto threadInfoLen = ctx.read_argument(3);


            if (threadInfoClass == (uint64_t)THREADINFOCLASS::ThreadHideFromDebugger && !threadInfoLen && threadHandle)
            {
                g_Apis.pSetTlsData(threadHandle, TLS_SLOTS::THREAD_HANDLE);
            }
            /*
            else if (threadInfoClass == (uint64_t)THREADINFOCLASS::ThreadWow64Context && threadInfoLen == sizeof(WOW64_CONTEXT))
            {
            // TODO
            }*/
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
                        ULONG newValue = 0;
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
    case PROBE_IDS::IdGetContextThread:
        NEW_SCOPE(
            uint64_t pContextThreadData = {0};
            
            if (g_Apis.pGetTlsData(pContextThreadData, TLS_SLOTS::CONTEXT_THREAD_DATA)) {
                uint64_t contextBase = 0;
                if (g_Apis.pTraceAccessMemory(&contextBase, pContextThreadData, sizeof(contextBase), 1, true)) {
                    uint64_t newValue = 0;
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, Dr0), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, Dr1), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, Dr2), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, Dr3), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, Dr6), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, Dr7), sizeof(newValue), 1, false);

                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, LastBranchToRip), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, LastBranchFromRip), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, LastExceptionToRip), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(CONTEXT, LastExceptionFromRip), sizeof(newValue), 1, false);
                }
            }
        );
        break;
    case PROBE_IDS::IdQueryInformationThread:
        NEW_SCOPE(
            uint64_t pWow64ContextThreadData = { 0 };
            uint64_t isRequestThreadHideFromDebugger;

            if (g_Apis.pGetTlsData(pWow64ContextThreadData, TLS_SLOTS::WOW64_CONTEXT_THREAD_DATA)) {
                uint64_t contextBase = 0;
                if (g_Apis.pTraceAccessMemory(&contextBase, pWow64ContextThreadData, sizeof(contextBase), 1, true)) {
                    uint64_t newValue = 0;
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(WOW64_CONTEXT, Dr0), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(WOW64_CONTEXT, Dr1), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(WOW64_CONTEXT, Dr2), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(WOW64_CONTEXT, Dr3), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(WOW64_CONTEXT, Dr6), sizeof(newValue), 1, false);
                    g_Apis.pTraceAccessMemory(&newValue, contextBase + offsetof(WOW64_CONTEXT, Dr7), sizeof(newValue), 1, false);
                }
            }
            else if (g_Apis.pGetTlsData(isRequestThreadHideFromDebugger, TLS_SLOTS::QUERY_THREAD_HIDE_FROM_DEBUGGER) && isRequestThreadHideFromDebugger && g_isHideFromDebugger)
            {
                uint64_t threadInfo; 
                bool newValue = true;

                g_Apis.pGetTlsData(threadInfo, TLS_SLOTS::THREAD_HIDE_FROM_DEBUGGER_DATA);
                g_Apis.pTraceAccessMemory(&newValue, threadInfo, sizeof(newValue), 1, false);
            }
        );
        break;
    case PROBE_IDS::IdSetInformationThread:
        NEW_SCOPE(
            ULONG crossThreadFlagsOffset = 0; 
            PVOID pETHREAD = { 0 };
            ULONG crossThreadFlags = 0;
            uint64_t threadHandle = 0;

            if (g_Apis.pGetTlsData(threadHandle, TLS_SLOTS::THREAD_HANDLE) && threadHandle)
            {
                crossThreadFlagsOffset = GetCrossThreadFlagsOffset();
                ObReferenceObjectByHandle((HANDLE)threadHandle, THREAD_ALL_ACCESS, NULL, ExGetPreviousMode(), (PVOID*)&pETHREAD, NULL);
                if (pETHREAD)
                {
                    g_Apis.pTraceAccessMemory(&crossThreadFlags, (ULONG_PTR)pETHREAD + crossThreadFlagsOffset, sizeof(crossThreadFlags), 1, true);

                    if (crossThreadFlags & 0x4)
                    {
                        g_isHideFromDebugger = true;
                        _InterlockedAnd((volatile unsigned long long*)(&crossThreadFlags), (unsigned long long)(0xFFFFFFFF - 4));
                        g_Apis.pTraceAccessMemory(&crossThreadFlags, (ULONG_PTR)pETHREAD + crossThreadFlagsOffset, sizeof(crossThreadFlags), 1, false);
                        ObDereferenceObject(pETHREAD);
                    }
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

