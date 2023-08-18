/**
 * Recreation of the file 'AddNewEtwEvent.d' from the DTrace-for-Windows project.
 *
 * Generates an ETW event when a syscall routine returns  0xc0000001 - STATUS_UNSUCCESSFUL.
 *
 * This demonstrates the ability of STrace to log to ETW events.
 */

#include "Interface.h"
#include "probedefs.h"

#pragma warning(disable: 6011)
PluginApis g_Apis;

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

