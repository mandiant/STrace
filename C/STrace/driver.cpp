#pragma warning(disable: 4996) //exallocatepoolwithtag
#include <ntifs.h>
#include <ntstatus.h>

#include "Etw.h"
#include "EtwLogger.h"
#include "DynamicTrace.h"
#include "PluginData.h"
#include "Logger.h"
#include "Interface.h"

// forward declare
extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs);
extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs);
extern "C" __declspec(dllexport) void DtEtwpEventCallback(PEVENT_HEADER pEventHeader, ULONG32 a, PGUID pProviderGuid, ULONG32 b);

NTSTATUS SetCallbackApi(const char* syscallName, ULONG64 probeId) 
{
    if (!TraceSystemApi || !TraceSystemApi->KeSetSystemServiceCallback) {
        return STATUS_UNSUCCESSFUL;
    }

    // set both entry and exit callbacks. This is because this driver requires both due to how TLS data is managed in this design.
    NTSTATUS status = TraceSystemApi->KeSetSystemServiceCallback(syscallName, true, (ULONG64)&StpCallbackEntry, probeId);
    if (NT_SUCCESS(status)) {
        status = TraceSystemApi->KeSetSystemServiceCallback(syscallName, false, (ULONG64)&StpCallbackReturn, probeId);
    }
    return status;
}

NTSTATUS UnSetCallbackApi(const char* syscallName) {
    if (!TraceSystemApi || !TraceSystemApi->KeSetSystemServiceCallback) {
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS status = TraceSystemApi->KeSetSystemServiceCallback(syscallName, true, 0, 0);
    if (NT_SUCCESS(status)) {
        status = TraceSystemApi->KeSetSystemServiceCallback(syscallName, false, 0, 0);
    }
    return status;
}

NTSTATUS SetEtwCallback(GUID providerGuid)
{
    if (!TraceSystemApi || !TraceSystemApi->EtwRegisterEventCallback) {
        return STATUS_UNSUCCESSFUL;
    }

    TRACEHANDLE traceHandle = 0;
    NTSTATUS status = EtwStartTracingSession(OUT &traceHandle);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    status = EtwAddProviderToTracingSession(traceHandle, providerGuid);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    return TraceSystemApi->EtwRegisterEventCallback((UINT32)traceHandle, (ULONG64)&DtEtwpEventCallback, 0);
}

NTSTATUS UnSetEtwCallback()
{
    return EtwStopTracingSession();
}

bool LogInitialized = false;
PluginData pluginData;

NTSTATUS NotImplementedRoutine()
{
	return STATUS_NOT_IMPLEMENTED;
}

/**
pService: Pointer to system service from SSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses
pArgs: Argument array, usually x64 fastcall registers rcx, rdx, r8, r9
pArgSize: Length of argument array, usually hard coded to 4
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs)
{
    // this is because TLS routines can allocate, could be changed. But this is simplest.
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return;
    }

    bool calledChildren = TraceSystemApi->EnterProbe();
    if (!TraceSystemApi->isCallFromInsideProbe()) {
        TLSData* ptlsData = TraceSystemApi->getRawTLSData();

        if (pluginData.isLoaded() && pluginData.pCallbackEntry && pluginData.pIsTarget && pluginData.pIsTarget(ptlsData->getCallerInfo())) {
            ptlsData->getCallerInfo().CaptureStackTrace(calledChildren ? 1 : 0);
    
            MachineState ctx = { 0 };
            ctx.pRegArgs = pArgs;
            ctx.regArgsSize = pArgSize;
            ctx.pStackArgs = (uint64_t*)pStackArgs;
            ctx.paramCount = paramCount;

            pluginData.pCallbackEntry(pService, probeId, ctx, ptlsData->getCallerInfo());
        }
    }
    TraceSystemApi->ExitProbe();
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackEntry, tStpCallbackEntry, "StpCallbackEntry does not match the interface type");

/**
pService: Pointer to system service from SSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses, usually hard coded to 1
pArgs: Argument array, usually a single entry that holds return value
pArgSize: Length of argument array, usually hard coded to 1
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64 *pArgs, ULONG32 pArgSize, void* pStackArgs)
{
    // this is because TLS routines can allocate, could be changed. But this is simplest.
    // stack walk also requires <= dispatch
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return;
    }
    
    TraceSystemApi->EnterProbe();
    if (!TraceSystemApi->isCallFromInsideProbe()) {
        TLSData* ptlsData = TraceSystemApi->getRawTLSData();

        if (pluginData.isLoaded() && pluginData.pCallbackReturn && pluginData.pIsTarget && pluginData.pIsTarget(ptlsData->getCallerInfo())) {
            MachineState ctx = { 0 };
            ctx.pRegArgs = pArgs;
            ctx.regArgsSize = pArgSize;
            ctx.pStackArgs = (uint64_t*)pStackArgs;
            ctx.paramCount = paramCount;

            pluginData.pCallbackReturn(pService, probeId, ctx, ptlsData->getCallerInfo());
        }
    }

    // return probes should de-allocate TLS data if the call depth is at zero for this thread (TLS data lives from Entry-Exit)
    TraceSystemApi->ExitProbe(true);
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackReturn, tStpCallbackReturn, "StpCallbackReturn does not match the interface type");

/**
pEventHeader: Information about the received event.
a: TODO: what is a
pProviderGuid: GUID of the ETW provider that created the event.
b: TODO: what is b
**/
extern "C" __declspec(dllexport) void DtEtwpEventCallback(PEVENT_HEADER pEventHeader, ULONG32 a, PGUID pProviderGuid, ULONG32 b)
{
    // this is because TLS routines can allocate, could be changed. But this is simplest.
    // stack walk also requires <= dispatch
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return;
    }
    
    TraceSystemApi->EnterProbe();
    if (!TraceSystemApi->isCallFromInsideProbe() && pluginData.isLoaded() && pluginData.pDtEtwpEventCallback) {
        pluginData.pDtEtwpEventCallback(pEventHeader, a, pProviderGuid, b);
    }
    TraceSystemApi->ExitProbe(true);
}
ASSERT_INTERFACE_IMPLEMENTED(DtEtwpEventCallback, tDtEtwpEventCallback, "DtEtwpEventCallback does not match the interface type");

extern "C" __declspec(dllexport) NTSTATUS TraceInitSystem(TraceApi*** ppTraceApi, TraceCallbacks* pTraceTable, DWORD64* pMemTraceRoutine)
{
	// Set pointer to our global API table. NtosKern fills this table of pointers for us after load
	*ppTraceApi = &TraceSystemApi;
	DWORD64 max_idx = (DWORD64)pTraceTable->pCallbacks[0];
    
	if (max_idx) {
		for (DWORD64 idx = 0; idx < max_idx; idx++) {
			switch (idx) {
			case 1:
				pTraceTable->pCallbacks[idx] = &DtEtwpEventCallback;
				break;
			case 2:
				pTraceTable->pCallbacks[idx] = &StpCallbackEntry; 
				break;
			case 3:
				pTraceTable->pCallbacks[idx] = &StpCallbackReturn; 
				break;
			case 4:
				//FbtpCallback
				pTraceTable->pCallbacks[idx] = &NotImplementedRoutine; 
				break;
			case 5:
				//FbtpCallback
				pTraceTable->pCallbacks[idx] = &NotImplementedRoutine; 
				break;
			case 6:
				//FtpPidCallback
				pTraceTable->pCallbacks[idx] = &NotImplementedRoutine; 
				break;
			case 7:
				//FtpPidCallback
				pTraceTable->pCallbacks[idx] = &NotImplementedRoutine; 
				break;
			case 8:
				//FbtpImageUnloadCallback
				pTraceTable->pCallbacks[idx] = &NotImplementedRoutine; 
				break;
			default:
				break;
			}
		}
	}

	*pMemTraceRoutine = (DWORD64)TraceAccessMemory;
	return STATUS_SUCCESS;
}

PDEVICE_OBJECT g_DeviceObj;

NTSTATUS
DeviceCreate (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
/*++
Routine Description:
    Dispatches file create requests.  
    
Arguments:
    DeviceObject - The device object receiving the request.
    Irp - The request packet.
Return Value:
    STATUS_NOT_IMPLEMENTED
--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS Status = STATUS_SUCCESS;

    if (!LogInitialized) {
        Status = LogInitialize(LogPutLevelInfo | LogOptDisableFunctionName | LogOptDisableAppend, L"\\??\\C:\\strace.log");
        if (!NT_SUCCESS(Status))
        {
            DBGPRINT("Failed to initialize logger interface. Status = 0x%08x\r\n", Status);
            return Status;
        }
        LogInitialized = true;
    }

    if (!TlsLookasideInitialized) {
        Status = ExInitializeLookasideListEx(&TLSLookasideList, NULL, NULL, PagedPool, EX_LOOKASIDE_LIST_EX_FLAGS_RAISE_ON_FAIL, sizeof(TLSData), DRIVER_POOL_TAG, NULL);
        if (!NT_SUCCESS(Status)) {
            DBGPRINT("Failed to initialize TLS lookaside list. Status = 0x%08x\r\n", Status);
            goto exit;
        }
        TlsLookasideInitialized = true;
    }

exit:
    if (!NT_SUCCESS(Status))
    {
        if (LogInitialized) {
            LogDestroy();
            LogInitialized = false;
        }

        if (TlsLookasideInitialized) {
            ExDeleteLookasideListEx(&TLSLookasideList);
            TlsLookasideInitialized = false;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
DeviceClose (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
/*++
Routine Description:
    Dispatches close requests.
Arguments:
    DeviceObject - The device object receiving the request.
    Irp - The request packet.
Return Value:
    STATUS_SUCCESS
--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DeviceCleanup (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
/*++
Routine Description:
    Dispatches cleanup requests.  Does nothing right now.
Arguments:
    DeviceObject - The device object receiving the request.
    Irp - The request packet.
Return Value:
    STATUS_SUCCESS
--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS HandlePluginLoad() {
    // only 1 plugin is allowed to load at a time
    NTSTATUS status = STATUS_SUCCESS;
    if (!pluginData.isLoaded()) {
        status = pluginData.load();
        if(!NT_SUCCESS(status))
        {
            LOG_ERROR("[!] Plugin Loading Failed\r\n");
            status = STATUS_UNSUCCESSFUL;
            goto exit;
        }
        
        if (pluginData.pInitialize) {
            // The plugin must immediately copy this structure. It must be a local to avoid C++ static initializers, which are created if its a global
            PluginApis pluginApis(&LogPrint, &EtwTrace, &SetCallbackApi, &UnSetCallbackApi, &SetEtwCallback, &UnSetEtwCallback, &TraceAccessMemory, &SetTLSData, &GetTLSData);
            pluginData.pInitialize(pluginApis);

            // prevent double initialize regardless of rest
            pluginData.pInitialize = 0;
        }
        status = STATUS_SUCCESS;
    } else {
        LOG_ERROR("[!] Only one plugin may be loaded at a time, load failed\r\n");
        status = STATUS_UNSUCCESSFUL;
    }

exit:
    return status;
}

NTSTATUS HandlePluginUnLoad() {
    NTSTATUS status;
    if (pluginData.isLoaded()) {
        status = pluginData.unload();
        if (!NT_SUCCESS(status))
        {
            LOG_ERROR("[!] Plugin unload failed: 0x%08X\r\n", status);
            return status;
        }

        if (LogInitialized) {
            LogDestroy();
            LogInitialized = false;
        }
    } else {
        LOG_ERROR("[!] No plugin is loaded, unload failed\r\n");
        return STATUS_ALREADY_COMPLETE;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DeviceControl (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
/*++
Routine Description:
    Dispatches ioctl requests. 
Arguments:
    DeviceObject - The device object receiving the request.
    Irp - The request packet.
Return Value:
    Status returned from the method called.
--*/
{
    PIO_STACK_LOCATION IrpStack;
    ULONG Ioctl;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    switch (Ioctl)
    {
    case IOCTL_LOADDLL:
        LOG_INFO("Starting Plugin load\r\n");
        Status = HandlePluginLoad();
        break;
    case IOCTL_UNLOADDLL:
        LOG_INFO("Starting Plugin unload\r\n");
        Status = HandlePluginUnLoad();
        break;
    default:
        LOG_WARN("Unrecognized ioctl 0x%x\r\n", Ioctl);
        break;
    }
    
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}


VOID
DeviceUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
/*++
Routine Description:
    Cleans up any driver-level allocations and prepares for unload. All 
    this driver needs to do is to delete the device object and the 
    symbolic link between our device name and the Win32 visible name.
Arguments:
    DeviceObject - The device object receiving the request.
    Irp - The request packet.
Return Value:
    STATUS_NOT_IMPLEMENTED
--*/
{
    UNICODE_STRING  DosDevicesLinkName;

    if (LogInitialized) {
        LogIrpShutdownHandler();
        LogDestroy();
        LogInitialized = false;
    }

    if (TlsLookasideInitialized) {
        ExDeleteLookasideListEx(&TLSLookasideList);
        TlsLookasideInitialized = false;
    }

    //
    // Unregister any registered ETW providers.
    //
    g_ProviderCache.Destruct();

    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //
    RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);
    IoDeleteSymbolicLink(&DosDevicesLinkName);

    //
    // Finally delete our device object
    //
    IoDeleteDevice(DriverObject->DeviceObject);
    //LOG_INFO("Unloaded\n");
}

// https://github.com/microsoft/Windows-driver-samples/tree/master/general/registry/regfltr
NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath )
{
	NTSTATUS Status;
    UNICODE_STRING NtDeviceName;
    UNICODE_STRING DosDevicesLinkName;
    UNICODE_STRING DeviceSDDLString;
    
    UNREFERENCED_PARAMETER(RegistryPath);

    //LOG_INFO("DriverEntry()");
    //LOG_INFO("Use ed nt!Kd_IHVDRIVER_Mask 8 to enable more detailed printouts\n");

    //
    // Create our device object.
    //

    RtlInitUnicodeString(&NtDeviceName, NT_DEVICE_NAME);
    RtlInitUnicodeString(&DeviceSDDLString, DEVICE_SDDL);

    Status = IoCreateDevice(DriverObject,                 // pointer to driver object
                            0,                            // device extension size
                            &NtDeviceName,                // device name
                            FILE_DEVICE_UNKNOWN,          // device type
                            FILE_DEVICE_SECURE_OPEN,      // device characteristics
                            FALSE,                         
                            &g_DeviceObj);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    //
    // Set dispatch routines.
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = DeviceCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload                         = DeviceUnload;
    DriverObject->DeviceObject = g_DeviceObj;
    
    //
    // Create a link in the Win32 namespace.
    //
    RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);

    Status = IoCreateSymbolicLink(&DosDevicesLinkName, &NtDeviceName);
    
    if (!NT_SUCCESS(Status)){
        IoDeleteDevice(DriverObject->DeviceObject);
        return Status;
    }
    return STATUS_SUCCESS;
}
