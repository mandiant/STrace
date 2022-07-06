#include <ntifs.h>
#include <ntddk.h>

#include "ManualMap.h"
#include "Logger.h"
#include "Constants.h"

/*
Modified from: https://github.com/ItsJustMeChris/Manual-Mapper/blob/master/Heroin/needle.cpp
and
https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/ManualMap/MMap.cpp
*/
#define DLL_PROCESS_ATTACH 1
typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK) (PVOID DllHandle, ULONG Reason, PVOID Reserved);

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)

#define LOWORD(l)           ((uint16_t)(((uintptr_t)(l)) & 0xffff))
#define HIWORD(l)           ((uint16_t)((((uintptr_t)(l)) >> 16) & 0xffff))

typedef struct _IMAGE_RELOC
{
	union
	{
		struct
		{
			uint16_t wOffset : 12;
			uint16_t wType : 4;
		};
		uint16_t wData;
	};
} IMAGE_RELOC, * PIMAGE_RELOC;

bool ManualMapper::loadImage(char* pBase) {
	if (!validateImage(pBase))
		return false;

	auto dosHeader = (IMAGE_DOS_HEADER*)pBase;
	auto ntHeader = (IMAGE_NT_HEADERS64*)(pBase + dosHeader->e_lfanew);
	auto pOptionalHeader = &ntHeader->OptionalHeader;
	auto _DllMain = pOptionalHeader->AddressOfEntryPoint ? (tDllMain)(pBase + pOptionalHeader->AddressOfEntryPoint) : 0;

	// I'm assuming this is signed, not sure?
	int64_t dwDelta = (int64_t)(pBase - pOptionalHeader->ImageBase);
	if (dwDelta) {
		if (!pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			LOG_ERROR("[!] image not allocated at preffered base, but has no relocations, loading will attempt to continue\r\n");
		}

		auto dwLimit = (uint64_t)pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		auto pRelocData = (PIMAGE_BASE_RELOCATION)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while ((uint64_t)pRelocData < dwLimit) {
			uint64_t dwRelocLimit = (uint64_t)pRelocData + pRelocData->SizeOfBlock;
			uint64_t lpBase = (uint64_t)pBase + pRelocData->VirtualAddress;
			PIMAGE_RELOC pReloc = (PIMAGE_RELOC)((uint64_t)pRelocData + sizeof(IMAGE_BASE_RELOCATION));
			
			while ((uint64_t)pReloc < dwRelocLimit)
			{
				uint16_t type = pReloc->wType;
				int32_t offset = pReloc->wOffset;

				switch (type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*((int32_t*)(lpBase + offset)) += (int32_t)dwDelta;
					break;
				case IMAGE_REL_BASED_DIR64:
					*((int64_t*)(lpBase + offset)) += dwDelta;
					break;
				default:
					break;
				}
				++pReloc;
			}
			pRelocData = (PIMAGE_BASE_RELOCATION)pReloc;
		}
	}

	// Initialize security cookies (needed on drivers Win8+). They do a cmp against the constant in the header
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress) {
		uint64_t pCookie = 0;

		switch (ntHeader->FileHeader.Machine)
		case IMAGE_FILE_MACHINE_AMD64: {
			pCookie = (uint64_t)(((IMAGE_LOAD_CONFIG_DIRECTORY64*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress))->SecurityCookie);

			//*(uint64_t*)pCookie = rand();
			*(uint64_t*)pCookie = 0x1337;

			// if we somehow hit default ++ it
			if (*(uint64_t*)pCookie == 0x2B992DDFA232)
				(*(uint64_t*)pCookie)++;

			break;
		}
	}

	// Walk imports
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		bool importsAtLeastOneBad = false;
		while (pImportDescr->Name) {
			char* szMod = pBase + pImportDescr->Name;

			uint64_t* pThunkRef = (uint64_t*)(pBase + pImportDescr->OriginalFirstThunk);
			uint64_t* pFuncRef = (uint64_t*)(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL64(*pThunkRef)) {
					USHORT ordinal = *pThunkRef & 0xFFFF;
					LOG_ERROR("[!] DLL Imports ordinal %d from %s. Imports are not supported...fatal\r\n", ordinal, szMod);
					importsAtLeastOneBad = true;
				} else {
					auto pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
					char* name = pImport->Name;
					if (strcmp(szMod, "ntoskrnl.exe") == 0) {
						ANSI_STRING name_ansi = {0};
						UNICODE_STRING name_unicode = {0};

						RtlInitAnsiString(&name_ansi, name);
						RtlAnsiStringToUnicodeString(&name_unicode, &name_ansi, TRUE);
						uint64_t pFn = (uint64_t)MmGetSystemRoutineAddress(&name_unicode);
						if (!pFn) {
							LOG_ERROR("[!] DLL Import %s from %s couldn't be found!...fatal\r\n", name, szMod);
							*pFuncRef = 0;
							importsAtLeastOneBad = true;
						} else {
							*pFuncRef = pFn;
						}
						RtlFreeUnicodeString(&name_unicode);
					} else {
						LOG_ERROR("[!] DLL Imports %s from %s. Imports are not supported...fatal\r\n", name, szMod);
						importsAtLeastOneBad = true;
					}
				}
			}
			++pImportDescr;
		}

		if (importsAtLeastOneBad) {
			return false;
		}
	}

	// Execute TLS
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		LOG_INFO("[+] Executing TLS entires\r\n");
		auto pTLS = (IMAGE_TLS_DIRECTORY64*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback) {
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	// Execute main
	if (_DllMain) {
		LOG_INFO("[+] Executing DLLMain\r\n");
		_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
	}
	else {
		LOG_INFO("[+] No DLLMain\r\n");
	}
	LOG_INFO("[+] DLL Load Done\r\n");
	return true;
}

bool ManualMapper::validateImage(char* pBase) {
	if (!pBase)
		return false;

	//Optional data
	auto dosHeader = (IMAGE_DOS_HEADER*)pBase;
	if (dosHeader->e_magic != 0x5A4D) {
		LOG_ERROR("DOS Magic Incorrect\r\n");
		return false;
	}

	auto ntHeader = (IMAGE_NT_HEADERS64*)(pBase + dosHeader->e_lfanew);
	if (ntHeader->Signature != 0x4550) {
		LOG_ERROR("NT Magic Incorrect\r\n");
		return false;
	}

	return true;
}

uint64_t ManualMapper::mapImage(char* imageData, uint64_t imageSize) {
	IMAGE_NT_HEADERS64* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER64* pOldOptionalHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	uint8_t* pTargetBase = nullptr;

	// layout is DOS_HEADER -> DOS_STUB -> NTHDR
	// 1. Ensure up to DOS_HEADER size
	// 2. Ensure up to start of NTHDR + Size of nthdr
	// 3. Validate headers
	if (imageSize < sizeof(IMAGE_DOS_HEADER) || 
		imageSize < ((((IMAGE_DOS_HEADER*)imageData)->e_lfanew) + sizeof(IMAGE_NT_HEADERS64)) || 
		!validateImage(imageData)) {
		return NULL;
	}

	// Save the old NT Header
	pOldNtHeader = (IMAGE_NT_HEADERS64*)(imageData + ((IMAGE_DOS_HEADER*)imageData)->e_lfanew);

	// Save the old optional header
	pOldOptionalHeader = &pOldNtHeader->OptionalHeader;

	// Save the old file header
	pOldFileHeader = &pOldNtHeader->FileHeader;

	// Ensure up to IMAGE_SECTION_HEADER (start of first section data)
	if (imageSize < pOldOptionalHeader->SizeOfHeaders) {
		LOG_ERROR("[!] DLL appears truncated\r\n");
		return NULL;
	}

	// If the machine type is not the current file type we fail
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		LOG_ERROR("[!] Only 64Bit DLLs are supported\r\n");
		return NULL;
	}

	pTargetBase = (uint8_t*)ExAllocatePoolWithTag(NonPagedPoolExecute, pOldOptionalHeader->SizeOfImage, DRIVER_POOL_TAG);
	if (!pTargetBase) {
		LOG_ERROR("[!] Failed to allocate final mapped image memory at any address\r\n");
		return NULL;
	}

	if (pOldFileHeader->NumberOfSections <= 0) {
		LOG_ERROR("[!] DLL has no sections, fatal\r\n");
		return NULL;
	}

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	// copy mem up until first section [0, section1)
	uint64_t rollingImageSize = pOldOptionalHeader->SizeOfHeaders;
	memcpy(pTargetBase, imageData, pOldOptionalHeader->SizeOfHeaders);

	// copy all the sections [sec1, secN)
	// validate each IMAGE_SECTION_DATA is present
	for (USHORT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {

		// Each section is a buffer of raw data
		rollingImageSize += pSectionHeader->SizeOfRawData;
		if (imageSize < rollingImageSize) {
			LOG_ERROR("[!] DLL appears truncated\r\n");
			return NULL;
		}

		memcpy(pTargetBase + pSectionHeader->VirtualAddress, imageData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
	}

	if (!loadImage((char*)pTargetBase)) {
		LOG_ERROR("[!] DLL Load Failed\r\n");
		return NULL;
	}

	return (uint64_t)pTargetBase;
}

ManualMapper::ExportDirectoryPtrs ManualMapper::getExportDir(uint64_t hModule) {
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

uint64_t ManualMapper::getExport(uint64_t hModule, const char* procName) {
	ExportDirectoryPtrs exportPtrs = getExportDir(hModule);
	if (!exportPtrs.exports) {
		return 0;
	}

	for (uint32_t i = 0; i < exportPtrs.exports->NumberOfNames; i++) {
		char* exportName = RVA2VA(char*, hModule, exportPtrs.addressOfNames[i]);
		if (_stricmp(exportName, procName) == 0)
			return RVA2VA(uint64_t, hModule, exportPtrs.addressOfFunctions[i]);
	}
	return 0;
}