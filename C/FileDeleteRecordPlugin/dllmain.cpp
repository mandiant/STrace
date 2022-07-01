#include <stdint.h>
#include <intrin.h>

#include "Interface.h"
#include "crt.h"
#include "utils.h"
#include "config.h"
#include "string.h"

#pragma warning(disable: 6011)
PluginApis g_Apis;

#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt,   __VA_ARGS__)

enum PROBE_IDS : ULONG64 {
    IdSetInformationFile = 0,
};

extern "C" __declspec(dllexport) void StpInitialize(PluginApis& pApis) {
    g_Apis = pApis;
    LOG_INFO("Plugin Initializing...\r\n");

    g_Apis.pSetCallback("SetInformationFile", true, PROBE_IDS::IdSetInformationFile);
    LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
    LOG_INFO("Plugin DeInitializing...\r\n");

    g_Apis.pUnsetCallback("SetInformationFile", true);

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

/**
pService: Pointer to system service from SSDT/SSSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses
pArgs: Argument array, usually x64 fastcall registers rcx, rdx, r8, r9
pArgSize: Length of argument array, usually hard coded to 4
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo)
{
    //LOG_INFO("[ENTRY] %s[0x%x](%d) Id: %d Parameters: [%d]\r\n", callerinfo.processName, callerinfo.processId, callerinfo.isWow64 ? 32 : 64, pService, probeId, ctx.paramCount);
    
    switch (probeId) {
        case PROBE_IDS::IdSetInformationFile: {
            auto hFile = (HANDLE)ctx.read_argument(0);
            auto InformationClass = ctx.read_argument(4);
            if (InformationClass == 13) { // FileDispositionInformation
                auto pInformation = (char*)ctx.read_argument(2); // 1 == DeleteFile
                if (*pInformation == 1) {
                    auto pFilePath = getFilePathFromHandle(hFile);

                    if(pFilePath) {
                        LOG_INFO("File %wZ deleted\r\n", pFilePath);
                        backupFile((wchar_t*)backup_directory, pFilePath->Name, hFile);
                        ExFreePoolWithTag(pFilePath, POOL_TAG);
                        pFilePath = nullptr;
                        LOG_INFO("File Backup Complete\r\n");
                    }else {
                        LOG_INFO("File [unknown] deleted\r\n");
                    }

                    PrintStackTrace(callerinfo);
                }
            }
            break;
        }
    }
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackEntry, tStpCallbackEntryPlugin, "StpCallbackEntry does not match the interface type");

/**
pService: Pointer to system service from SSDT/SSSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses, usually hard coded to 1
pArgs: Argument array, usually a single entry that holds return value
pArgSize: Length of argument array, usually hard coded to 1
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo & callerinfo) {
    //LOG_INFO("[RETURN] %s[%x](%d) %016llx Id: %d\r\n", callerinfo.processName, callerinfo.processId, callerinfo.isWow64 ? 32 : 64, pService, probeId);
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

