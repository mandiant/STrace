#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <subauth.h>
#include <stdint.h>
#include <evntcons.h>
#include <type_traits>
#include "crt.h"

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

	template<typename T>
	void write_argument(const uint32_t idx, T value) {
		if (idx > paramCount || regArgsSize > paramCount)
			return;

		if (idx >= regArgsSize) {
			// stack array trims off the register array data, and indexes from that offset value
			pStackArgs[idx - regArgsSize] = (uint64_t)value;
		}
		else {
			pRegArgs[idx] = (uint64_t)value;
		}
	}

	uint64_t read_return_value() {
		return pRegArgs[0];
	}

	template<typename T>
	void write_return_value(T value) {
		pRegArgs[0] = (uint64_t)value;
	}
};

typedef LONG NTSTATUS;
typedef NTSTATUS(*tLogPrintApi)(uint32_t Level, const char* FunctionName, const char* Format, ...);
typedef NTSTATUS(*tSetCallbackApi)(const char* syscallName, BOOLEAN isEntry, ULONG64 probeId);
typedef NTSTATUS(*tUnSetCallbackApi)(const char* syscallName, BOOLEAN isEntry);
typedef NTSTATUS(*tSetEtwCallbackApi)(GUID providerGuid);
typedef NTSTATUS(*tUnSetEtwCallbackApi)(GUID providerGuid);
typedef PVOID(NTAPI* tMmGetSystemRoutineAddress)(PUNICODE_STRING SystemRoutineName);
typedef BOOLEAN(*tTraceAccessMemory)(PVOID SafeAddress, ULONG_PTR UnsafeAddress, SIZE_T NumberOfBytes, SIZE_T ChunkSize, BOOLEAN DoRead);

class PluginApis {
public:
	PluginApis() = default;

	tLogPrintApi pLogPrint;
	tSetCallbackApi pSetCallback;
	tUnSetCallbackApi pUnsetCallback;
	tSetEtwCallbackApi pEtwSetCallback;
	tUnSetEtwCallbackApi pEtwUnSetCallback;
	tMmGetSystemRoutineAddress pGetSystemRoutineAddress;
	tTraceAccessMemory pTraceAccessMemory;
};

#define MINCHAR     0x80        // winnt
#define MAXCHAR     0x7f        // winnt
#define MINSHORT    0x8000      // winnt
#define MAXSHORT    0x7fff      // winnt
#define MINLONG     0x80000000  // winnt
#define MAXLONG     0x7fffffff  // winnt
#define MAXUCHAR    0xff        // winnt
#define MAXUSHORT   0xffff      // winnt
#define MAXULONG    0xffffffff  // winnt

UNICODE_STRING WideToUnicodeString(PCWSTR SourceString);

template<typename T>
T ResolveApi(const wchar_t* name, PluginApis& apis) {
	auto ustr = WideToUnicodeString(name);
	return (T)apis.pGetSystemRoutineAddress(&ustr);
}

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
};

typedef void(*tStpInitialize)(PluginApis& pApis);
typedef void(*tStpDeInitialize)();
typedef void(*tDtEtwpEventCallback)(EVENT_HEADER* EventHeader, ULONG32 a, GUID* ProviderGuid, ULONG32 b);

typedef enum _LOG_LEVEL_OPTIONS
{
	LogLevelDebug = 0x10ul,
	LogLevelInfo = 0x20ul,
	LogLevelWarn = 0x40ul,
	LogLevelError = 0x80ul,
} LOG_LEVEL_OPTIONS;

// Assert a function is the same type as a function pointer typedef, or throw msg as a compiler error
#define ASSERT_INTERFACE_IMPLEMENTED(Implementer, tFnTypeDef, msg) static_assert(std::is_same_v<decltype(&Implementer), tFnTypeDef>, msg); 