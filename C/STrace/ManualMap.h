#pragma once

#define WIN32_LEAN_AND_MEAN
#include <ntimage.h>
#include "MyStdint.h"

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

class ManualMapper {
public:
	uint64_t mapImage(char* imageData, uint64_t imageSize);
	uint64_t getExport(uint64_t hModule,const char* procName);
private:
	struct ExportDirectoryPtrs {
		uint32_t* addressOfFunctions;
		uint32_t* addressOfNames;
		uint16_t* addressOfNameOrdinals;
		IMAGE_EXPORT_DIRECTORY* exports;
	};

	ExportDirectoryPtrs getExportDir(uint64_t moduleBase);
	bool loadImage(char* imageBase);
	bool validateImage(char* imageBase);
};

typedef bool(__stdcall* tDllMain)(char* hDll, uint32_t dwReason, char* pReserved);
