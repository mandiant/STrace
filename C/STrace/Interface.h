// This defines all the things shared between usermode and kernel
// Must be kept in sync with Interface.h in STraceCLI and STraceDll
#pragma once
#include <ntifs.h>
#include <ntstatus.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>

#include "MyStdint.h"
#include "Constants.h"
#include "NtStructs.h"

class MachineState
{
public:
	uint32_t  paramCount;
	uint32_t  regArgsSize;
	uint64_t* pStackArgs;
	uint64_t* pRegArgs;

	uint64_t read_argument(const uint32_t idx)
	{
		if (idx > paramCount || regArgsSize > paramCount)
			return 0;

		if (idx >= regArgsSize) {
			// stack array trims off the register array data, and indexes from that offset value
			return pStackArgs[idx - regArgsSize];
		}
		else {
			return pRegArgs[idx];
		}
	}
};

typedef NTSTATUS(*tLogPrintApi)(uint32_t Level, const char* FunctionName, const char* Format, ...);
typedef NTSTATUS(*tSetCallbackApi)(const char* syscallName, BOOLEAN isEntry, ULONG64 probeId);
typedef NTSTATUS(*tUnSetCallbackApi)(const char* syscallName, BOOLEAN isEntry);
typedef PVOID(NTAPI*tMmGetSystemRoutineAddress)(PUNICODE_STRING SystemRoutineName);
typedef BOOLEAN(*tTraceAccessMemory)(PVOID SafeAddress, ULONG_PTR UnsafeAddress, SIZE_T NumberOfBytes, SIZE_T ChunkSize, BOOLEAN DoRead);

class PluginApis {
public:
	PluginApis() = default;
	PluginApis(tMmGetSystemRoutineAddress getAddress, tLogPrintApi print, tSetCallbackApi setCallback, tUnSetCallbackApi unsetCallback, tTraceAccessMemory accessMemory) {
		pLogPrint = print;
		pSetCallback = setCallback;
		pUnsetCallback = unsetCallback;
		pGetSystemRoutineAddress = getAddress;
		pTraceAccessMemory = accessMemory;
	}

	tLogPrintApi pLogPrint;
	tSetCallbackApi pSetCallback;
	tUnSetCallbackApi pUnsetCallback;
	tMmGetSystemRoutineAddress pGetSystemRoutineAddress;
	tTraceAccessMemory pTraceAccessMemory;
};

extern "C" NTKERNELAPI char* NTAPI PsGetProcessImageFileName(PEPROCESS Process);
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);
extern "C" NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

#define MAX_PATH 260
#define FRAME_DEPTH 10

class CallerInfo
{
public:
	struct StackFrame {
		uint64_t frameaddress;
		uint64_t modulebase;;
		char modulePath[MAX_PATH];
	};

	char processName[100];
	uint64_t processId;
	StackFrame* frames;
	uint8_t frameDepth;
	bool isWow64;

	CallerInfo() {
		const auto frameArraySize = FRAME_DEPTH * sizeof(StackFrame);
		frames = (StackFrame*)ExAllocatePoolWithTag(NonPagedPoolNx, frameArraySize, DRIVER_POOL_TAG);
		if (frames) {
			frameDepth = FRAME_DEPTH;
			memset(frames, 0, frameArraySize);
		} else {
			// set depth to zero to hopefully avoid anyone iterating the null buffer
			frameDepth = 0;
			return;
		}

		memset(processName, 0, sizeof(processName));

		processId = ULONG64(PsGetCurrentProcessId());

		auto kproc = PsGetCurrentProcess();

		// this name is truncated by the OS
		strcpy_s(processName, PsGetProcessImageFileName(kproc));
		isWow64 = PsGetProcessWow64Process(kproc) != NULL;
	}

	~CallerInfo() {
		if (frames) {
			ExFreePoolWithTag(frames, DRIVER_POOL_TAG);
			frames = 0;
		}
	}

	bool IsTargetProcId(uint64_t pid) {
		return processId == pid;
	}

	bool IsTargetProcName(const char* procName)
	{
		return strcmp((const char*)processName, procName) == 0;
	}

	__forceinline void CaptureStackTrace() {
		// our allocation failed in the constructor :(
		if (!frames) {
			return;
		}

		uint64_t StackTraceData[FRAME_DEPTH] = { 0 };

		// we forceinlined, so *this* frame should not exist, so we can skip nothing
		const auto StackTraceFramesCount = KphCaptureStackBackTrace(0, FRAME_DEPTH, (PVOID*)StackTraceData, 0);

		// copy addresses over first
		for (uint32_t i = 0; i < StackTraceFramesCount; i++) {
			frames[i].frameaddress = StackTraceData[i];
		}

		EnumKernelModeModules([&](char* modulePath, uint64_t base, uint64_t size) {
			for (uint32_t i = 0; i < frameDepth; i++) {
				uint64_t frameaddress = StackTraceData[i];

				// fill out the module info if it's found, and not set yet
				if (frames[i].modulebase == 0 && frameaddress >= base && frameaddress < (base + size)) {
					frames[i].modulebase = base;
					strcpy_s(frames[i].modulePath, modulePath);
					frames[i].modulePath[sizeof(CallerInfo::StackFrame::modulePath) - 1] = 0;
				}
			}
		});

		// resolve return addresses to modulePaths + Base
		EnumUserModeModules([&](char* modulePath, uint64_t base, uint64_t size) {
			for (uint32_t i = 0; i < frameDepth; i++) {
				uint64_t frameaddress = StackTraceData[i];

				// fill out the module info if it's found, and not set yet
				if (frames[i].modulebase == 0 && frameaddress >= base && frameaddress < (base + size)) {
					frames[i].modulebase = base;
					strcpy_s(frames[i].modulePath, modulePath);
					frames[i].modulePath[sizeof(CallerInfo::StackFrame::modulePath) - 1] = 0;
				}
			}
		});
	}
private:
	template<typename T>
	bool EnumKernelModeModules(T&& callback) {
		return KphEnumerateSystemModules([callback](PRTL_PROCESS_MODULES modules) {
			for (size_t i = 0; i < modules->NumberOfModules; i++)
			{
				callback(modules->Modules[i].FullPathName, (uint64_t)modules->Modules[i].ImageBase, (uint64_t)modules->Modules[i].ImageSize);
			}
		}) == STATUS_SUCCESS;
	}

	template<typename T>
	bool EnumUserModeModules(T&& callback) {
		__try {
			if (isWow64)
			{
				PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(PsGetCurrentProcess());
				if (pPeb32 == NULL)
				{
					return false;
				}

				if (!pPeb32->Ldr)
				{
					return false;
				}

				// Search in InLoadOrderModuleList
				for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
					pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
					pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
				{

					PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

					// unicode_string from wchar_t*
					UNICODE_STRING ustr;
					RtlUnicodeStringInit(&ustr, (PWCH)pEntry->FullDllName.Buffer);

					char modulePath[MAX_PATH] = { 0 };
					ANSI_STRING ansi;
					ansi.Buffer = modulePath;
					ansi.Length = 0;
					ansi.MaximumLength = sizeof(modulePath);

					RtlUnicodeStringToAnsiString(&ansi, &ustr, FALSE);
					callback(modulePath, (uint64_t)pEntry->DllBase, (uint64_t)pEntry->SizeOfImage);
				}
			}
			// Native process
			else
			{
				PPEB pPeb = PsGetProcessPeb(PsGetCurrentProcess());
				if (!pPeb)
				{
					return false;
				}

				if (!pPeb->Ldr)
				{
					return false;
				}

				// Search in InLoadOrderModuleList
				for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
					pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
					pListEntry = pListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

					char modulePath[MAX_PATH] = { 0 };
					ANSI_STRING ansi;
					ansi.Buffer = modulePath;
					ansi.Length = 0;
					ansi.MaximumLength = sizeof(modulePath);

					RtlUnicodeStringToAnsiString(&ansi, &pEntry->FullDllName, FALSE);
					callback(modulePath, (uint64_t)pEntry->DllBase, (uint64_t)pEntry->SizeOfImage);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
		return true;
	}

	void UnicodeStrToNarrow(char buf[100], const char* fmt, ...) {
		va_list args;
		va_start(args, fmt);
		RtlStringCchVPrintfA(buf,
			RTL_NUMBER_OF(buf),
			fmt, args
		);
		va_end(args);
	}
};

typedef void(*tStpCallbackEntry)(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs);
typedef void(*tStpCallbackReturn)(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs);

typedef void(*tStpCallbackEntryPlugin)(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo);
typedef void(*tStpCallbackReturnPlugin)(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo);
typedef void(*tStpInitialize)(PluginApis& pApis);
typedef void(*tStpDeInitialize)();

// Assert a function is the same type as a function pointer typedef, or throw msg as a compiler error
#define ASSERT_INTERFACE_IMPLEMENTED(Implementer, tFnTypeDef, msg) static_assert(is_same_v<decltype(&Implementer), tFnTypeDef>, msg); 