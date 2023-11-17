#pragma once
#define WIN32_LEAN_AND_MEAN
#include <ntifs.h>
#include <ntimage.h>
#include "Logger.h"
#include "Interface.h"

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

#define _countof(array) (sizeof(array) / sizeof(array[0]))

UNICODE_STRING pluginServiceName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\StracePlugin");

const char* pluginFullPathNames[] = {
    "\\systemroot\\system32\\drivers\\plugin.sys",
    "\\??\\C:\\Windows\\system32\\drivers\\plugin.sys"
};

struct ExportDirectoryPtrs {
    uint32_t* addressOfFunctions;
    uint32_t* addressOfNames;
    uint16_t* addressOfNameOrdinals;
    IMAGE_EXPORT_DIRECTORY* exports;
};

class PluginData {
public:
    PluginData() {
        loaderLock = 0;
        zero();
    }

    bool isLoaded() {
        return InterlockedAdd(&loaded, 0) != 0;
    }

    NTSTATUS load() {

        NTSTATUS status;
        
        lock();
        if (!isLoaded()) {
            return STATUS_ALREADY_INITIALIZED;
        }

        status = ZwLoadDriver(&pluginServiceName);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("ZwLoadDriver Failed with: 0x%08X", status);
            goto exit;
        }

        status = setPluginBaseAddress();
        if (!NT_SUCCESS(status))
        {
            LOG_ERROR("setPluginBaseAddress failed to find plugin");
            goto exit;
        }

        pCallbackEntry = (tStpCallbackEntryPlugin)getExport("StpCallbackEntry");
        pCallbackReturn = (tStpCallbackReturnPlugin)getExport("StpCallbackReturn");
        pInitialize = (tStpInitialize)getExport("StpInitialize");
        pDeInitialize = (tStpDeInitialize)getExport("StpDeInitialize");
        pIsTarget = (tStpIsTarget)getExport("StpIsTarget");
        pDtEtwpEventCallback = (tDtEtwpEventCallback)getExport("DtEtwpEventCallback");

        if((pCallbackEntry && pCallbackReturn && pIsTarget && pDtEtwpEventCallback) == 0){
            LOG_ERROR("Failed to acquire plugin exports");
            status = STATUS_PROCEDURE_NOT_FOUND;
            goto exit;
        }

        InterlockedIncrement(&loaded);
        LOG_INFO("[+] Plugin Loaded at: %I64X\r\n", pImageBase);

    exit:
        unlock();
        return status;
    }

    // Must free old plugin data before setting new one
    NTSTATUS unload() {
        NTSTATUS status;
        // set pImageBase last since it's used atomically for isLoaded
        lock();
        if (!isLoaded())
        {
            status =  STATUS_ALREADY_COMPLETE;
        }
        InterlockedDecrement(&loaded);

        status = ZwUnloadDriver(&pluginServiceName);
        if (!NT_SUCCESS(status))
        {
            // If driver doesn't unload, then it is still loaded and we should
            // return the plugin to a loaded state and return an error
            LOG_INFO("[!] Failed to unload plugin driver");
            InterlockedIncrement(&loaded);
            goto exit;
        }
        zero();

        status = STATUS_SUCCESS;
    exit:
        unlock();
        return status;

    }

    tStpIsTarget pIsTarget;
    tStpCallbackEntryPlugin pCallbackEntry;
    tStpCallbackReturnPlugin pCallbackReturn;
    tDtEtwpEventCallback pDtEtwpEventCallback;

    // zeroed immediately after use, these are optional
    tStpInitialize pInitialize;
    tStpDeInitialize pDeInitialize;

private:

    void lock() {
        while (_interlockedbittestandset(&loaderLock, 0)) {};
    }

    void unlock() {
        _interlockedbittestandreset(&loaderLock, 0);
    }

    ExportDirectoryPtrs getExportDir(uint64_t hModule)
    {
        ExportDirectoryPtrs exportPtrs;
        exportPtrs.addressOfFunctions = nullptr;
        exportPtrs.addressOfNameOrdinals = nullptr;
        exportPtrs.addressOfNames = nullptr;
        exportPtrs.exports = nullptr;

        IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)hModule;
        IMAGE_NT_HEADERS64* pNT = RVA2VA(IMAGE_NT_HEADERS64*, hModule, pDos->e_lfanew);
        IMAGE_DATA_DIRECTORY* pDataDir = (IMAGE_DATA_DIRECTORY*)pNT->OptionalHeader.DataDirectory;

        if (pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL) {
            return exportPtrs;
        }

        IMAGE_EXPORT_DIRECTORY* pExports = RVA2VA(IMAGE_EXPORT_DIRECTORY*, hModule, pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        exportPtrs.addressOfFunctions = RVA2VA(uint32_t*, hModule, pExports->AddressOfFunctions);
        exportPtrs.addressOfNames = RVA2VA(uint32_t*, hModule, pExports->AddressOfNames);
        exportPtrs.addressOfNameOrdinals = RVA2VA(uint16_t*, hModule, pExports->AddressOfNameOrdinals);
        exportPtrs.exports = pExports;
        return exportPtrs;
    }

    uint64_t getExport(const char* procName) {
        ExportDirectoryPtrs exportPtrs = getExportDir(pImageBase);
        if (!exportPtrs.exports) {
            return 0;
        }

        for (uint32_t i = 0; i < exportPtrs.exports->NumberOfNames; i++) {
            char* exportName = RVA2VA(char*, pImageBase, exportPtrs.addressOfNames[i]);
            if (_stricmp(exportName, procName) == 0)
                return RVA2VA(uint64_t, pImageBase, exportPtrs.addressOfFunctions[i]);
        }
        return 0;
    }

    NTSTATUS setPluginBaseAddress()
    {
        NTSTATUS status;
        PRTL_PROCESS_MODULES modules = NULL;
        PRTL_PROCESS_MODULE_INFORMATION pmi;
        ULONG moduleInformationSize = 0;
        
        // Get Size
        status = ZwQuerySystemInformation(SystemModuleInformation, 0, moduleInformationSize, &moduleInformationSize);

        // multiply moduleInformationSize by two just in case somehow the size increases between previous call and now.
        modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, moduleInformationSize * 2, DRIVER_POOL_TAG);
        if (modules)
        {
            // get modules
            status = ZwQuerySystemInformation(SystemModuleInformation, modules, moduleInformationSize, &moduleInformationSize);
            if (!NT_SUCCESS(status)) {
                goto exit;
            }

            pmi = modules->Modules;
            for (ULONG i = 0; i < modules->NumberOfModules; i++)
            {
                DBGPRINT("Module: %s", pmi[i].FullPathName);
                for (int j = 0; j < _countof(pluginFullPathNames); j++)
                {
                    // RtlStringCbLength FullPathName - 1 because the ANSI_STRING maxLenght will need an extra byte 
                    if(_stricmp(pmi[i].FullPathName, pluginFullPathNames[j]) == 0)
                    {
                        DBGPRINT("Found Module: %s 0x%I64X", pmi[i].FullPathName, pmi[i].ImageBase);
                        pImageBase = (uint64_t)pmi[i].ImageBase;
                        status = STATUS_SUCCESS;
                        goto exit;
                    }
                }
            }
            status = STATUS_NOT_FOUND;
        }
    exit:
        if (modules) ExFreePoolWithTag(modules, DRIVER_POOL_TAG);
        return status;
    }

    void zero() {
        pImageBase = 0;
        pInitialize = 0;
        pCallbackEntry = 0;
        pCallbackReturn = 0;
        pDeInitialize = 0;
        pIsTarget = 0;
        pDtEtwpEventCallback = 0;
    }

    uint64_t pImageBase;
    volatile LONG loaderLock;
    volatile LONG loaded;
};