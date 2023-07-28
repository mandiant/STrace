#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <subauth.h>
#include <stdint.h>
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
		if (idx > paramCount)
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
		if (idx > paramCount)
			return;

		if (idx >= regArgsSize) {
			// stack array trims off the register array data, and indexes from that offset value
			pStackArgs[idx - regArgsSize] = (uint64_t)value;
		}
		else {
			pRegArgs[idx] = (uint64_t)value;
		}
	}

	void redirect_syscall(uint64_t pFn) {
		// The syscall pointer is stored just after the args
		pRegArgs[4] = pFn;
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
typedef bool(*tSetTlsData)(uint64_t value, uint8_t slot);
typedef bool(*tGetTlsData)(uint64_t& value, uint8_t slot);
typedef NTSTATUS(*tLogPrintApi)(uint32_t Level, const char* FunctionName, const char* Format, ...);
typedef NTSTATUS(*tEtwTraceApi)(const char* providerName, const GUID* providerGuid, const char* eventName, int eventLevel, uint64_t flag, int numberOfFields, ...);
typedef NTSTATUS(*tSetCallbackApi)(const char* syscallName, ULONG64 probeId);
typedef NTSTATUS(*tUnSetCallbackApi)(const char* syscallName);
typedef NTSTATUS(*tSetEtwCallbackApi)(GUID providerGuid);
typedef NTSTATUS(*tUnSetEtwCallbackApi)();
typedef PVOID(NTAPI* tMmGetSystemRoutineAddress)(PUNICODE_STRING SystemRoutineName);
typedef BOOLEAN(*tTraceAccessMemory)(PVOID SafeAddress, ULONG_PTR UnsafeAddress, SIZE_T NumberOfBytes, SIZE_T ChunkSize, BOOLEAN DoRead);

class PluginApis {
public:
	PluginApis() = default;

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

typedef bool(*tStpIsTarget)(CallerInfo& callerinfo);
typedef void(*tStpCallbackEntryPlugin)(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo);
typedef void(*tStpCallbackReturnPlugin)(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo);
typedef void(*tStpInitialize)(PluginApis& pApis);
typedef void(*tStpDeInitialize)();

typedef enum _LOG_LEVEL_OPTIONS
{
	LogLevelDebug = 0x10ul,
	LogLevelInfo = 0x20ul,
	LogLevelWarn = 0x40ul,
	LogLevelError = 0x80ul,
} LOG_LEVEL_OPTIONS;

typedef enum _ETW_FIELD_TYPE
{
	EtwFieldNull,
	EtwFieldUnicodeString,
	EtwFieldAnsiString,
	EtwFieldInt8,
	EtwFieldUInt8,
	EtwFieldInt16,
	EtwFieldUInt16,
	EtwFieldInt32,
	EtwFieldUInt32,
	EtwFieldInt64,
	EtwFieldUInt64,
	EtwFieldFloat,
	EtwFieldDouble,
	EtwFieldBool32,
	EtwFieldBinary,
	EtwFieldGuid,
	EtwFieldPointer,
	EtwFieldFiletime,
	EtwFieldSystemTime,
	EtwFieldSid,
	EtwFieldHexInt32,
	EtwFieldHexInt64,
	EtwFieldPid = (EtwFieldInt32 | 0x05 << 8),
} ETW_FIELD_TYPE;

// Assert a function is the same type as a function pointer typedef, or throw msg as a compiler error
#define ASSERT_INTERFACE_IMPLEMENTED(Implementer, tFnTypeDef, msg) static_assert(std::is_same_v<decltype(&Implementer), tFnTypeDef>, msg); 