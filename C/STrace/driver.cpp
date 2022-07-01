#include <ntifs.h>
#include <ntstatus.h>

#include "DynamicTrace.h"
#include "Logger.h"
#include "ManualMap.h"
#include "Interface.h"

class PluginData {
public:
    PluginData() {
        zero();
    }

    bool isLoaded() {
        return InterlockedAdd64((volatile LONG64*)&pImageBase, 0) != 0;
    }
    
    // Must free old plugin data before setting new one
    bool setPluginData(uint64_t base, tStpCallbackEntryPlugin entry, tStpCallbackReturnPlugin ret, tStpInitialize init, tStpDeInitialize deinit) {
        pCallbackEntry = entry;
        pCallbackReturn = ret;
        pInitialize = init;
        pDeInitialize = deinit;
        
        // set pImageBase last since it's used atomically for isLoaded
        auto expected = pImageBase;
        auto atomicGot = (uint64_t)_InterlockedCompareExchange64((volatile LONG64*)&pImageBase, base, expected);

        // if the swap worked we get what we expected
        return atomicGot == expected;
    }

    // Must free old plugin data before setting new one
    bool freePluginData() {
        // set pImageBase last since it's used atomically for isLoaded
        auto expected = pImageBase;
        auto atomicGot = (uint64_t)_InterlockedCompareExchange64((volatile LONG64*)&pImageBase, 0, expected);

        if (atomicGot == expected && expected != 0) {
            ExFreePoolWithTag((char*)expected, DRIVER_POOL_TAG);
            zero();
            return true;
        }
        return false;
    }

    tStpCallbackEntryPlugin pCallbackEntry;
    tStpCallbackReturnPlugin pCallbackReturn;

    // zeroed immediately after use, these are optional
    tStpInitialize pInitialize;
    tStpDeInitialize pDeInitialize;
private:
    void zero() {
        pImageBase = 0;
        pInitialize = 0;
        pCallbackEntry = 0;
        pCallbackReturn = 0;
        pDeInitialize = 0;
    }

    volatile uint64_t pImageBase;
};

// forward declare
extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs);
extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs);

NTSTATUS SetCallbackApi(const char* syscallName, BOOLEAN isEntry, ULONG64 probeId) {
    if (!TraceSystemApi || !TraceSystemApi->KeSetSystemServiceCallback) {
        return STATUS_UNSUCCESSFUL;
    }

    auto callback = (ULONG64)(isEntry ? (&StpCallbackEntry) : (&StpCallbackReturn));
    return TraceSystemApi->KeSetSystemServiceCallback(syscallName, isEntry, callback, probeId);
}

NTSTATUS UnSetCallbackApi(const char* syscallName, BOOLEAN isEntry) {
    if (!TraceSystemApi || !TraceSystemApi->KeSetSystemServiceCallback) {
        return STATUS_UNSUCCESSFUL;
    }

    return TraceSystemApi->KeSetSystemServiceCallback(syscallName, isEntry, 0, 0);
}

bool LogInitialized = false;
PluginData pluginData;

NTSTATUS NotImplementedRoutine()
{
	return STATUS_NOT_IMPLEMENTED;
}

ManualMapper g_DllMapper;

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
    TraceSystemApi->EnterProbe();
    if (!TraceSystemApi->isCallFromInsideProbe()) {
        CallerInfo callerInfo;
        callerInfo.CaptureStackTrace();

        MachineState ctx = { 0 };
        ctx.pRegArgs = pArgs;
        ctx.regArgsSize = pArgSize;
        ctx.pStackArgs = (uint64_t*)pStackArgs;
        ctx.paramCount = paramCount;

        if (pluginData.isLoaded() && pluginData.pCallbackEntry) {
            pluginData.pCallbackEntry(pService, probeId, ctx, callerInfo);
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
    TraceSystemApi->EnterProbe();
    if (!TraceSystemApi->isCallFromInsideProbe()) {
        CallerInfo callerInfo;

        MachineState ctx = { 0 };
        ctx.pRegArgs = pArgs;
        ctx.regArgsSize = pArgSize;
        ctx.pStackArgs = (uint64_t*)pStackArgs;
        ctx.paramCount = paramCount;

        if (pluginData.isLoaded() && pluginData.pCallbackReturn) {
            pluginData.pCallbackReturn(pService, probeId, ctx, callerInfo);
        }
    }
    TraceSystemApi->ExitProbe();
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackReturn, tStpCallbackReturn, "StpCallbackReturn does not match the interface type");

extern "C" __declspec(dllexport) NTSTATUS TraceInitSystem(TraceApi*** ppTraceApi, TraceCallbacks* pTraceTable, DWORD64* pMemTraceRoutine)
{
	// Set pointer to our global API table. NtosKern fills this table of pointers for us after load
	*ppTraceApi = &TraceSystemApi;
	DWORD64 max_idx = (DWORD64)pTraceTable->pCallbacks[0];
    
	if (max_idx) {
		for (DWORD64 idx = 0; idx < max_idx; idx++) {
			switch (idx) {
			case 1:
				// DtEtwpEventCallback
				pTraceTable->pCallbacks[idx] = &NotImplementedRoutine; 
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

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
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

    if (LogInitialized) {
        LogDestroy();
        LogInitialized = false;
    }

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

    if (LogInitialized) {
        LogIrpShutdownHandler();
        LogInitialized = false;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS HandleDllLoad(PIRP Irp, PIO_STACK_LOCATION IrpStack) {
    char* input = (char*)Irp->AssociatedIrp.SystemBuffer;
    uint64_t inputLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    // only 1 plugin is allowed to load at a time
    NTSTATUS status = STATUS_SUCCESS;
    if (!pluginData.isLoaded()) {
        // Executes DLLMain if it exists
        uint64_t dllBase = g_DllMapper.mapImage(input, inputLen);
        if (!dllBase) {
            LOG_ERROR("[!] Plugin Loading Failed\r\n");
            status = STATUS_UNSUCCESSFUL;
            goto exit;
        }

        auto entry = (tStpCallbackEntryPlugin)g_DllMapper.getExport(dllBase, "StpCallbackEntry");
        auto ret = (tStpCallbackReturnPlugin)g_DllMapper.getExport(dllBase, "StpCallbackReturn");
        auto init = (tStpInitialize)g_DllMapper.getExport(dllBase, "StpInitialize");
        auto deinit = (tStpDeInitialize)g_DllMapper.getExport(dllBase, "StpDeInitialize");
        
        uint32_t tries = 0;
        while (!pluginData.setPluginData(dllBase, entry, ret, init, deinit)) {
            if (tries++ >= 10) {
                LOG_ERROR("[!] Atomic plugin load failed\r\n");
                status = STATUS_UNSUCCESSFUL;
                goto exit;
            }
        }

        if (pluginData.pInitialize) {
            // The plugin must immediately copy this structure. It must be a local to avoid C++ static initializers, which are created if its a global
            PluginApis pluginApis(&MmGetSystemRoutineAddress, &LogPrint, &SetCallbackApi, &UnSetCallbackApi, &TraceAccessMemory);
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
    // Zero the output buffer (SystemBuffer is copied to output on IoCompletion)
    memset(input, 0, inputLen);

    // Assign read length to Information
    Irp->IoStatus.Information = inputLen;
    return status;
}

NTSTATUS HandleDllUnLoad() {
    if (pluginData.isLoaded()) {
        if (pluginData.pDeInitialize) {
            pluginData.pDeInitialize();

            // prevent double deinitialize regardless of rest
            pluginData.pDeInitialize = 0;
        }

        uint32_t tries = 0;
        while (!pluginData.freePluginData()) {
            if (tries++ >= 10) {
                LOG_ERROR("[!] Atomic plugin unload failed\r\n");
                return STATUS_UNSUCCESSFUL;
            }
        }

        if (LogInitialized) {
            LogDestroy();
            LogInitialized = false;
        }
    } else {
        LOG_ERROR("[!] No plugin is loaded, unload failed\r\n");
        return STATUS_UNSUCCESSFUL;
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

    if (!LogInitialized) {
        Status = LogInitialize(LogPutLevelInfo | LogOptDisableFunctionName | LogOptDisableAppend, L"\\??\\C:\\strace.log");
        if (!NT_SUCCESS(Status))
        {
            DBGPRINT("Failed to initialize logger interface. Status = 0x%08x\r\n", Status);
            goto exit;
        }
        LogInitialized = true;
    }
   
    switch (Ioctl)
    {
    case IOCTL_LOADDLL:
        LOG_INFO("Starting DLL load\r\n");
        Status = HandleDllLoad(Irp, IrpStack);
        break;
    case IOCTL_UNLOADDLL:
        LOG_INFO("Starting DLL unload\r\n");
        Status = HandleDllUnLoad();
        break;
    default:
        LOG_WARN("Unrecognized ioctl 0x%x\r\n", Ioctl);
        break;
    }

    exit:
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
    
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DriverObject->DeviceObject);
        return Status;
    }

    return STATUS_SUCCESS;
}
