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

// {d7827ef0-cc9e-4b7c-a322-be5280ff3622}
constexpr GUID ProviderGuid = { 0xd7827ef0, 0xcc9e, 0x4b7c, { 0xa3, 0x22, 0xbe, 0x52, 0x80, 0xff, 0x36, 0x22 } };

extern "C" __declspec(dllexport) void StpInitialize(PluginApis & pApis) {
	g_Apis = pApis;
	g_Apis.pSetCallback("OpenFile", PROBE_IDS::IdOpenFile);
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
	g_Apis.pUnsetCallback("OpenFile");
}
ASSERT_INTERFACE_IMPLEMENTED(StpDeInitialize, tStpDeInitialize, "StpDeInitialize does not match the interface type");

extern "C" __declspec(dllexport) bool StpIsTarget(CallerInfo & callerinfo) {
	return true;
}
ASSERT_INTERFACE_IMPLEMENTED(StpIsTarget, tStpIsTarget, "StpIsTarget does not match the interface type");

extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, MachineState & ctx, CallerInfo & callerinfo)
{
	g_Apis.pEtwTrace(
		"Tools.DTrace.Platform", /* Provider Name */
		&ProviderGuid, /* Provider GUID */
		"SysCallEntry", /* Event Name */
		1, /* Event Level (0 - 5) */
		11, /* Event channel */
		0x0000000000000020, /* Flag */
		3, /* Number of fields */
		"PID", /* Field_1 Name */
		EtwFieldPid, /* Field_1 Type */
		(int32_t)callerinfo.processId, /* Field_1 Value */
		"Execname", /* Field_2 Name */
		EtwFieldString, /* Field_2 Type */
		(const char*)callerinfo.processName, /* Field_2 Value */
		"SysCall", /* Field_3 Name */
		EtwFieldString, /* Field_3 Type */
		get_probe_name((PROBE_IDS)probeId) /* Field_3 Value */
	);
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackEntry, tStpCallbackEntryPlugin, "StpCallbackEntry does not match the interface type");

extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, MachineState & ctx, CallerInfo & callerinfo) {
	g_Apis.pEtwTrace(
		"Tools.DTrace.Platform", /* Provider Name */
		&ProviderGuid, /* Provider GUID */
		"SysCallReturn", /* Event Name */
		1, /* Event Level (0 - 5) */
		11, /* Event channel */
		0x0000000000000020, /* Flag */
		4, /* Number of fields */
		"PID", /* Field_1 Name */
		EtwFieldPid, /* Field_1 Type */
		(int32_t)callerinfo.processId, /* Field_1 Value */
		"Execname", /* Field_2 Name */
		EtwFieldString, /* Field_2 Type */
		(const char*)callerinfo.processName, /* Field_2 Value */
		"SysCall", /* Field_3 Name */
		EtwFieldString, /* Field_3 Type */
		get_probe_name((PROBE_IDS)probeId) /* Field_3 Value */,
		"Ret",
		EtwFieldInt64,
		ctx.read_return_value()
	);
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
}

/*
*   /GS- must be set to disable stack cookies and have DriverEntry
*   be the entrypoint. GsDriverEntry sets up stack cookie and calls
*   Driver Entry normally.
*/
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DBGPRINT("AddNewEtwEventPlugin::DriverEntry()");
	
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    DriverObject->DriverUnload = DeviceUnload;

    return STATUS_SUCCESS;
}
