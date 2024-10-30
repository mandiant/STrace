// This defines all the things shared between usermode and kernel
// Must be kept in sync with Interface.h in STraceCLI and STraceDll
#pragma warning(disable: 4996) //exallocatepoolwithtag

#pragma once
#include <ntifs.h>
#include <ntstatus.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>

#include "MyStdint.h"
#include "Constants.h"
#include "NtStructs.h"

// This is a very special read/write routine that interacts with MmAccessFault to avoid PAGE_FAULT_IN_NON_PAGED area bugchecks. 
// When dtrace is loaded this routines start/end address is recorded. Function boundary information is retreived via the unwind
// information as looked up by RtlLookupFunctionEntry. Any faults that occur within this boundary
// will _not_ BugCheck due to hardcoded logic in the kernel fault routines. Instead, when access faults are thrown the kernel
// will check if this routine generated them and return STATUS_ACCESS_VIOLATION instead. 

/**
SafeAddress: An address guaranteed to be paged in, in read mode this is the destination, in write mode it is the source
UnsafeAddress: A potentially paged out or inaccessible address/region. In read mode this is the source, in write it is the destination
NumberOfBytes: How many bytes in total to read or write
ChunkSize: How wide should reads/writes occur. NumberOfBytes is walked in a for loop and read/writes occur using this chunksize. ChunkSize must be a multiple of NumberOfBytes, overhanging bytes are not operated on.
The available sizes are only 1, 2, 4, or 8. All other chunksizes are a no-operation
DoRead: Should a read or write occur, in write mode the order of SafeAddress and UnsafeAddress are interpreted differently with respect to source/destination.

NOTE: to ensure proper unwind information is generated for RtlLookupFunctionEntry, the memory core must be in a __try __except block. This block
doesn't have to do anything important, but the kernel uses it to determine the bounds of the function and then ignore faults in that boundary.
**/
extern "C" __declspec(dllexport) BOOLEAN TraceAccessMemory(PVOID SafeAddress, ULONG_PTR UnsafeAddress, SIZE_T NumberOfBytes, SIZE_T ChunkSize, BOOLEAN DoRead);

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

typedef bool(*tSetTlsData)(uint64_t value, uint8_t slot);
typedef bool(*tGetTlsData)(uint64_t& value, uint8_t slot);
typedef NTSTATUS(*tLogPrintApi)(uint32_t Level, const char* FunctionName, const char* Format, ...);
typedef NTSTATUS(*tEtwTraceApi)(const char* providerName, const GUID* providerGuid, const char* eventName, uint8_t eventLevel, uint8_t eventChannel, uint64_t keyword, int numberOfFields, ...);
typedef NTSTATUS(*tSetCallbackApi)(const char* syscallName, ULONG64 probeId);
typedef NTSTATUS(*tUnSetCallbackApi)(const char* syscallName);
typedef NTSTATUS(*tSetEtwCallbackApi)(GUID providerGuid);
typedef NTSTATUS(*tUnSetEtwCallbackApi)();
typedef PVOID(NTAPI*tMmGetSystemRoutineAddress)(PUNICODE_STRING SystemRoutineName);
typedef BOOLEAN(*tTraceAccessMemory)(PVOID SafeAddress, ULONG_PTR UnsafeAddress, SIZE_T NumberOfBytes, SIZE_T ChunkSize, BOOLEAN DoRead);

class PluginApis {
public:
	PluginApis() = default;
	PluginApis(tMmGetSystemRoutineAddress getAddress, tLogPrintApi print, tEtwTraceApi etwTrace, tSetCallbackApi setCallback,
		tUnSetCallbackApi unsetCallback, tSetEtwCallbackApi etwSetCallback, tUnSetEtwCallbackApi etwUnSetCallback,
		tTraceAccessMemory accessMemory, tSetTlsData setTlsData, tGetTlsData getTlsData) {

		pSetTlsData = setTlsData;
		pGetTlsData = getTlsData;
		pLogPrint = print;
		pEtwTrace = etwTrace;
		pSetCallback = setCallback;
		pUnsetCallback = unsetCallback;
		pEtwSetCallback = etwSetCallback;
		pEtwUnSetCallback = etwUnSetCallback;
		pGetSystemRoutineAddress = getAddress;
		pTraceAccessMemory = accessMemory;
	}

	tSetTlsData pSetTlsData;
	tGetTlsData pGetTlsData;
	tLogPrintApi pLogPrint;
	tEtwTraceApi pEtwTrace;
	tSetCallbackApi pSetCallback;
	tUnSetCallbackApi pUnsetCallback;
	tSetEtwCallbackApi pEtwSetCallback;
	tUnSetEtwCallbackApi pEtwUnSetCallback;
	tMmGetSystemRoutineAddress pGetSystemRoutineAddress;
	tTraceAccessMemory pTraceAccessMemory;
};

extern "C" NTKERNELAPI char* NTAPI PsGetProcessImageFileName(PEPROCESS Process);
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);
extern "C" NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

#define MAX_PATH 260
#define MAX_FRAME_DEPTH 50

class CallerInfo
{
public:
	struct StackFrame {
		uint64_t frameaddress;
		uint64_t modulebase;
		char modulePath[MAX_PATH];
	};

	char processName[100];
	uint64_t processId;
	StackFrame* frames;
	uint8_t frameDepth;
	bool isWow64;

	CallerInfo() {
		frames = nullptr;
		frameDepth = 0;

		memset(processName, 0, sizeof(processName));

		processId = ULONG64(PsGetCurrentProcessId());

		auto kproc = PsGetCurrentProcess();

		// have to read the PEB for full name
		GetFullProcessName(processName, sizeof(processName));
		isWow64 = PsGetProcessWow64Process(kproc) != NULL;
	}

	~CallerInfo() {
		if (frames) {
			ExFreePoolWithTag(frames, DRIVER_POOL_TAG);
			frames = nullptr;
		}
	}

	bool IsTargetProcId(uint64_t pid) {
		return processId == pid;
	}

	bool IsTargetProcName(const char* procName)
	{
		return strcmp((const char*)processName, procName) == 0;
	}

	__forceinline void CaptureStackTrace(uint32_t skipFrameCount = 0) {
		uint64_t StackTraceData[MAX_FRAME_DEPTH] = { 0 };

		// we forceinlined, so *this* frame should not exist, so we can skip nothing
		const uint8_t StackTraceFramesCount = (uint8_t)KphCaptureStackBackTrace((ULONG)skipFrameCount, MAX_FRAME_DEPTH, (PVOID*)StackTraceData);

		// trace done, alloc our copy
		frames = (StackFrame*)ExAllocatePoolWithTag(NonPagedPoolNx, StackTraceFramesCount * sizeof(StackFrame), DRIVER_POOL_TAG);
		if (frames) {
			frameDepth = StackTraceFramesCount;
			memset(frames, 0, StackTraceFramesCount * sizeof(StackFrame));
		} else {
			return;
		}

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
					if (strlen(modulePath) <= sizeof(CallerInfo::StackFrame::modulePath)) {
						strcpy_s(frames[i].modulePath, modulePath);
					} else {
						strcpy_s(frames[i].modulePath, "NAME_TOO_LONG");
					}
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
					if (strlen(modulePath) <= sizeof(CallerInfo::StackFrame::modulePath)) {
						strcpy_s(frames[i].modulePath, modulePath);
					} else {
						strcpy_s(frames[i].modulePath, "NAME_TOO_LONG");
					}
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
		// copy the usermode structs to kernel. They can be stomped/changed out from under us
		__try {
			if (isWow64)
			{
				if (!PsGetProcessWow64Process(PsGetCurrentProcess())) {
					return false;
				}

				PEB32 peb32 = { 0 };
				if (!TraceAccessMemory(&peb32, (ULONG_PTR)PsGetProcessWow64Process(PsGetCurrentProcess()), sizeof(peb32), 1, true) || !peb32.Ldr)
				{
					return false;
				}

				PEB_LDR_DATA32 Ldr = { 0 };
				if (!TraceAccessMemory(&Ldr, (ULONG_PTR)peb32.Ldr, sizeof(Ldr), 1, true)) {
					return false;
				}

				ULONG_PTR pListEntryHead = (ULONG_PTR)&Ldr.InLoadOrderModuleList;
				ULONG_PTR pCurListEntry = pListEntryHead;

				LIST_ENTRY32 listEntry = { 0 };
				if (!TraceAccessMemory(&listEntry, pCurListEntry, sizeof(listEntry), 1, true)) {
					return false;
				}

				while (listEntry.Flink != pListEntryHead) {
					LDR_DATA_TABLE_ENTRY32 entry = { 0 };
					if (!TraceAccessMemory(&entry, (ULONG_PTR)CONTAINING_RECORD(pCurListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks), sizeof(entry), 1, true)) {
						return false;
					}

					// just check it's a valid string buffer
					wchar_t test = 0;
					if (!TraceAccessMemory(&test, (ULONG_PTR)entry.FullDllName.Buffer, sizeof(test), 1, true)) {
						return false;
					}

					// unicode_string from wchar_t*
					UNICODE_STRING ustr;
					RtlUnicodeStringInit(&ustr, (PWCH)entry.FullDllName.Buffer);

					char modulePath[MAX_PATH] = { 0 };
					ANSI_STRING ansi = { 0 };
					ansi.Buffer = modulePath;
					ansi.Length = 0;
					ansi.MaximumLength = sizeof(modulePath);

					RtlUnicodeStringToAnsiString(&ansi, &ustr, FALSE);
					callback(modulePath, (uint64_t)entry.DllBase, (uint64_t)entry.SizeOfImage);

					pCurListEntry = (ULONG_PTR)listEntry.Flink;
					if (!TraceAccessMemory(&listEntry, pCurListEntry, sizeof(listEntry), 1, true)) {
						return false;
					}
				}
			}
			// Native process
			else
			{
				if (!PsGetProcessPeb(PsGetCurrentProcess())) {
					return false;
				}

				PEB peb = { 0 };
				if (!TraceAccessMemory(&peb, (ULONG_PTR)PsGetProcessPeb(PsGetCurrentProcess()), sizeof(peb), 1, true) || !peb.Ldr)
				{
					return false;
				}

				PEB_LDR_DATA Ldr = { 0 };
				if (!TraceAccessMemory(&Ldr, (ULONG_PTR)peb.Ldr, sizeof(Ldr), 1, true)) {
					return false;
				}

				ULONG_PTR pListEntryHead = (ULONG_PTR)&Ldr.InLoadOrderModuleList;
				ULONG_PTR pCurListEntry = pListEntryHead;

				LIST_ENTRY listEntry = { 0 };
				if (!TraceAccessMemory(&listEntry, pCurListEntry, sizeof(listEntry), 1, true)) {
					return false;
				}

				while ((ULONG_PTR)listEntry.Flink != pListEntryHead) {
					LDR_DATA_TABLE_ENTRY entry = { 0 };
					if (!TraceAccessMemory(&entry, (ULONG_PTR)CONTAINING_RECORD(pCurListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks), sizeof(entry), 1, true)) {
						return false;
					}

					// just check it's a valid string buffer
					wchar_t test = 0;
					if (!TraceAccessMemory(&test, (ULONG_PTR)entry.FullDllName.Buffer, sizeof(test), 1, true)) {
						return false;
					}

					char modulePath[MAX_PATH] = { 0 };
					ANSI_STRING ansi = { 0 };
					ansi.Buffer = modulePath;
					ansi.Length = 0;
					ansi.MaximumLength = sizeof(modulePath);

					RtlUnicodeStringToAnsiString(&ansi, &entry.FullDllName, FALSE);
					callback(modulePath, (uint64_t)entry.DllBase, (uint64_t)entry.SizeOfImage);

					pCurListEntry = (ULONG_PTR)listEntry.Flink;
					if (!TraceAccessMemory(&listEntry, pCurListEntry, sizeof(listEntry), 1, true)) {
						return false;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
		return true;
	}

	bool GetFullProcessName(char* ImagePathNarrowBuffer, uint16_t ImagePathNarrowBufferLength) {
		UNICODE_STRING* procNameWide = NULL;
		if (SeLocateProcessImageName(PsGetCurrentProcess(), &procNameWide) == STATUS_SUCCESS) {
			
			memset(ImagePathNarrowBuffer, 0, ImagePathNarrowBufferLength);
			ANSI_STRING ansi = { 0 };
			ansi.Buffer = ImagePathNarrowBuffer;
			ansi.Length = 0;
			ansi.MaximumLength = ImagePathNarrowBufferLength;

			if (RtlUnicodeStringToAnsiString(&ansi, procNameWide, FALSE) == STATUS_SUCCESS) {
				ExFreePool(procNameWide);
				return true;
			} else {
				ExFreePool(procNameWide);
			}
		}
		return false;
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

typedef bool(*tStpIsTarget)(CallerInfo& callerinfo);
typedef void(*tStpCallbackEntry)(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs);
typedef void(*tStpCallbackReturn)(ULONG64 pService, ULONG32 probeId, ULONG32 paramCount, ULONG64* pArgs, ULONG32 pArgSize, void* pStackArgs);
typedef void(*tDtEtwpEventCallback)(EVENT_HEADER* EventHeader, ULONG32 a, GUID* ProviderGuid, ULONG32 b);

typedef void(*tStpCallbackEntryPlugin)(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo);
typedef void(*tStpCallbackReturnPlugin)(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo);
typedef void(*tStpInitialize)(PluginApis& pApis);
typedef void(*tStpDeInitialize)();

// Assert a function is the same type as a function pointer typedef, or throw msg as a compiler error
#define ASSERT_INTERFACE_IMPLEMENTED(Implementer, tFnTypeDef, msg) static_assert(is_same_v<decltype(&Implementer), tFnTypeDef>, msg);

// std::move reimplementation
// <https://en.cppreference.com/w/cpp/types/remove_reference>
template<typename T> struct remove_reference { typedef T type; };
template<typename T> struct remove_reference<T&> { typedef T type; };
template<typename T> struct remove_reference<T&&> { typedef T type; };

// <https://stackoverflow.com/a/7518365>
template<typename T>
typename remove_reference<T>::type&& move(T&& arg)
{
	return static_cast<typename remove_reference<T>::type&&>(arg);
}