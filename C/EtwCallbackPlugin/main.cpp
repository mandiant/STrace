#pragma warning(disable: 4996) //exallocatepoolwithtag
#pragma warning(disable: 4244) // conversion from uint64_t to base, possible loss of data
#pragma warning(disable: 4100) // unreferenced param
#include <ntifs.h>

#include "interface.h"
#include "utils.h"
#include "probedefs.h"

const unsigned long PLUGIN_POOL_TAG = ' xtS';

#pragma warning(disable: 6011)
PluginApis g_Apis;

// Microsoft-Windows-Kernel-Memory
constexpr GUID g_ProviderGuid = { 0xd1d93ef7, 0xe1f2, 0x4f45, { 0x99, 0x43, 0x03, 0xd2, 0x45, 0xfe, 0x6c, 0x00 } };

#ifdef DBG
#define DBGPRINT(format, ...)  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[STRACE] " format "\n", __VA_ARGS__)
#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt,   __VA_ARGS__)
#else
#define DBGPRINT(format, ...)
#define LOG_DEBUG(fmt,...)
#define LOG_INFO(fmt,...)
#define LOG_WARN(fmt,...)
#define LOG_ERROR(fmt,...)
#endif


extern "C" __declspec(dllexport) void StpInitialize(PluginApis & pApis) {
	g_Apis.pEtwSetCallback(g_ProviderGuid);
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
	g_Apis.pEtwUnSetCallback();
}
ASSERT_INTERFACE_IMPLEMENTED(StpDeInitialize, tStpDeInitialize, "StpDeInitialize does not match the interface type");

extern "C" __declspec(dllexport) void DtEtwpEventCallback(PEVENT_HEADER EventHeader, ULONG32 a, GUID * ProviderGuid, ULONG32 b)
{
	LOG_INFO("Received event ID %d\r\n", EventHeader->EventDescriptor.Id);
}
ASSERT_INTERFACE_IMPLEMENTED(DtEtwpEventCallback, tDtEtwpEventCallback, "DtEtwpEventCallback does not match the interface type");

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
    DBGPRINT("EtwCallbackPlugin::DeviceUnload");
}

/*
*   /GS- must be set to disable stack cookies and have DriverEntry
*   be the entrypoint. GsDriverEntry sets up stack cookie and calls
*   Driver Entry normally.
*/
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DBGPRINT("EtwCallbackPlugin::DriverEntry()");
	
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    DriverObject->DriverUnload = DeviceUnload;

    return STATUS_SUCCESS;
}
