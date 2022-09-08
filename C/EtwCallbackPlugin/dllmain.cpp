#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <evntcons.h>

#include "Interface.h"

#pragma warning(disable: 6011)
PluginApis g_Apis;

#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt,   __VA_ARGS__)

extern "C" __declspec(dllexport) void StpInitialize(PluginApis & pApis) {
    g_Apis = pApis;
    LOG_INFO("Plugin Initializing...\r\n");

    GUID providerGuid;
    providerGuid.Data1 = 0xd1d93ef7;
    providerGuid.Data2 = 0xe1f2;
    providerGuid.Data3 = 0x4f45;
    providerGuid.Data4[0] = 0x99;
    providerGuid.Data4[1] = 0x43;
    providerGuid.Data4[2] = 0x03;
    providerGuid.Data4[3] = 0xd2;
    providerGuid.Data4[4] = 0x45;
    providerGuid.Data4[5] = 0xfe;
    providerGuid.Data4[6] = 0x6c;
    providerGuid.Data4[7] = 0x00;

    NTSTATUS ret = g_Apis.pEtwSetCallback(providerGuid);
    LOG_INFO("Plugin Initialise returned 0x%08X\r\n", ret);

    LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
    LOG_INFO("Plugin DeInitializing...\r\n");

    NTSTATUS ret = g_Apis.pEtwUnSetCallback();
    LOG_INFO("Plugin DeInitialise returned 0x%08X\r\n", ret);

    LOG_INFO("Plugin DeInitialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpDeInitialize, tStpDeInitialize, "StpDeInitialize does not match the interface type");

extern "C" __declspec(dllexport) void DtEtwpEventCallback(PEVENT_HEADER EventHeader, ULONG32 a, GUID* ProviderGuid, ULONG32 b)
{
    LOG_INFO("Received event ID %d\r\n", EventHeader->EventDescriptor.Id);
}
ASSERT_INTERFACE_IMPLEMENTED(DtEtwpEventCallback, tDtEtwpEventCallback, "DtEtwpEventCallback does not match the interface type");

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
