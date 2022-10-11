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

    LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
    LOG_INFO("Plugin DeInitializing...\r\n");

    g_Apis.pUnsetCallback("QueryInformationProcess");
   
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
    return true;
}
ASSERT_INTERFACE_IMPLEMENTED(StpIsTarget, tStpIsTarget, "StpIsTarget does not match the interface type");

enum TLS_SLOTS : uint8_t {
    PROCESS_INFO_CLASS = 0,
    PROCESS_INFO_DATA = 1
};

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
    // !!BEWARE OF HOW MUCH STACK SPACE IS USED!!
    char sprintf_tmp_buf[256] = { 0 };

    switch ((PROBE_IDS)probeId) {
    case PROBE_IDS::IdQueryInformationProcess: {
        auto processInfoClass = ctx.read_argument(1);
        auto processInfo = ctx.read_argument(2);

        g_Apis.pSetTlsData(processInfoClass, TLS_SLOTS::PROCESS_INFO_CLASS);
        g_Apis.pSetTlsData(processInfo, TLS_SLOTS::PROCESS_INFO_DATA);

        if (processInfoClass == (uint64_t)PROCESSINFOCLASS::ProcessDebugPort) {
            LOG_INFO("[!] %s ANTI_DBG QueryInformationProcess ProcessDebugPort\r\n", callerinfo.processName);
            PrintStackTrace(callerinfo);
        }
        break;
    }
    default:
        break;
    }
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackEntry, tStpCallbackEntryPlugin, "StpCallbackEntry does not match the interface type");

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
paramCount: Number of arguments this system service uses, usually hard coded to 1
pArgs: Argument array, usually a single entry that holds return value
pArgSize: Length of argument array, usually hard coded to 1
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo & callerinfo) {
    switch ((PROBE_IDS)probeId) {
    case PROBE_IDS::IdQueryInformationProcess: {
        uint64_t processInfoClass = 0;
        uint64_t processInfo = 0;
        if (g_Apis.pGetTlsData(processInfoClass, TLS_SLOTS::PROCESS_INFO_CLASS) && g_Apis.pGetTlsData(processInfo, TLS_SLOTS::PROCESS_INFO_DATA) && processInfo) {
            switch (processInfoClass) {
            case (uint64_t)PROCESSINFOCLASS::ProcessDebugPort:
                NEW_SCOPE(
                    ULONG newValue = 0;
                    g_Apis.pTraceAccessMemory(&newValue, processInfo, sizeof(newValue), 1, false);
                );
                break;
            case (uint64_t)PROCESSINFOCLASS::ProcessDebugFlags:
                NEW_SCOPE(
                    DWORD newValue = 1;
                    g_Apis.pTraceAccessMemory(&newValue, processInfo, sizeof(newValue), 1, false);
                );
                break;
            case (uint64_t)PROCESSINFOCLASS::ProcessDebugObjectHandle:
                NEW_SCOPE(
                    HANDLE old = 0;
                    g_Apis.pTraceAccessMemory(&old, processInfo, sizeof(old), 1, true);

                    if (ctx.read_return_value() == STATUS_SUCCESS && old) {
                        HANDLE newValue = 0;
                        g_Apis.pTraceAccessMemory(&newValue, processInfo, sizeof(newValue), 1, false);
                        ctx.write_return_value(STATUS_PORT_NOT_SET);
                    }
                );
                break;
            }
            
        }
        break;
    }
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

