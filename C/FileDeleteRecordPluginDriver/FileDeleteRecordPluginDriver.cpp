#pragma warning(disable: 4996) //exallocatepoolwithtag
#include <ntifs.h>

#include "interface.h"

#include "utils.h"

const unsigned long PLUGIN_POOL_TAG = 'LEDS';

#pragma warning(disable: 6011)
PluginApis g_Apis;

#if defined(ENABLE_LOG)
#if defined(__GNUC__) || defined(__clang__)

// On GCC and Clang __VA_ARGS__ must be used differently.
#define DBGPRINT(format, ...)  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[STRACE] " format "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt, ##__VA_ARGS__)
#else

#define DBGPRINT(format, ...)  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[STRACE] " format "\n", __VA_ARGS__)
#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt,   __VA_ARGS__)
#endif // __GNUC__ || __clang__

#else

#define DBGPRINT(format, ...)   ((void)format)

#endif // _DEBUG

enum PROBE_IDS : ULONG64 {
    IdSetInformationFile = 0,
};

extern "C" __declspec(dllexport) void StpInitialize(PluginApis & pApis) {
    g_Apis = pApis;
    LOG_INFO("Plugin Initializing...\r\n");
    
    g_Apis.pSetCallback("SetInformationFile", PROBE_IDS::IdSetInformationFile);
    LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
    LOG_INFO("Plugin DeInitializing...\r\n");

    g_Apis.pUnsetCallback("SetInformationFile");

    LOG_INFO("Plugin DeInitialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpDeInitialize, tStpDeInitialize, "StpDeInitialize does not match the interface type");

extern "C" __declspec(dllexport) bool StpIsTarget(CallerInfo & callerinfo) {
    UNREFERENCED_PARAMETER(callerinfo);
    return true;
}
ASSERT_INTERFACE_IMPLEMENTED(StpIsTarget, tStpIsTarget, "StpIsTarget does not match the interface type");

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



OBJECT_NAME_INFORMATION* getFilePathFromHandle(HANDLE hFile) {
    ULONG dwSize = 0;
    OBJECT_NAME_INFORMATION* pObjectName = nullptr;
    NTSTATUS status = ZwQueryObject(hFile, (OBJECT_INFORMATION_CLASS)1 /*ObjectNameInformation*/, pObjectName, 0, &dwSize);
    if (dwSize)
    {
        pObjectName = (OBJECT_NAME_INFORMATION*)ExAllocatePoolWithTag(NonPagedPoolNx, dwSize, PLUGIN_POOL_TAG);
        if (pObjectName) {
            status = ZwQueryObject(hFile, (OBJECT_INFORMATION_CLASS)1 /*ObjectNameInformation*/, pObjectName, dwSize, &dwSize);
        }
    }

    if (status == STATUS_SUCCESS && pObjectName) {
        return pObjectName;
    }

    if (pObjectName) {
        ExFreePoolWithTag(pObjectName, PLUGIN_POOL_TAG);
        pObjectName = nullptr;
    }
    return nullptr;
}

extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, MachineState & ctx, CallerInfo & callerinfo)
{
    //LOG_INFO("[ENTRY] %s[0x%x](%d) Id: %d Parameters: [%d]\r\n", callerinfo.processName, callerinfo.processId, callerinfo.isWow64 ? 32 : 64, pService, probeId, ctx.paramCount);
    UNREFERENCED_PARAMETER(pService);
    UNREFERENCED_PARAMETER(probeId);
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(callerinfo);
    switch (probeId) {
        case PROBE_IDS::IdSetInformationFile: {
            auto hFile = (HANDLE)ctx.read_argument(0);
            auto InformationClass = ctx.read_argument(4);
            if (InformationClass == 13) { // FileDispositionInformation
                auto pInformation = (char*)ctx.read_argument(2); // 1 == DeleteFile
                if (*pInformation == 1) {
                    auto pFilePath = getFilePathFromHandle(hFile);
                    
                    if (pFilePath) {
                        LOG_INFO("File %wZ deleted\r\n", pFilePath->Name);
                        //backupFile((wchar_t*)backup_directory, pFilePath->Name, hFile);
                        //ExFreePoolWithTag(pFilePath, PLUGIN_POOL_TAG);
                        //pFilePath = nullptr;
                        LOG_INFO("File Backup Complete\r\n");
                    }
                    else {
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

extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, MachineState & ctx, CallerInfo & callerinfo) {
    UNREFERENCED_PARAMETER(pService);
    UNREFERENCED_PARAMETER(probeId);
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(callerinfo);
    //LOG_INFO("[RETURN] %s[%x](%d) %016llx Id: %d\r\n", callerinfo.processName, callerinfo.processId, callerinfo.isWow64 ? 32 : 64, pService, probeId);
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackReturn, tStpCallbackReturnPlugin, "StpCallbackEntry does not match the interface type");


NTSTATUS DeviceCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID DeviceUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DBGPRINT("FileDeleteRecord::DeviceUnload");
}


/* 
*   /GS- must be set to disable stack cookies and have DriverEntry
*   be the entrypoint. GsDriverEntry sets up stack cookie and calls
*   Driver Entry normally.
*/
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DBGPRINT("FileDeleteRecord::DriverEntry()");

    
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    DriverObject->DriverUnload = DeviceUnload;

    return STATUS_SUCCESS;
}
