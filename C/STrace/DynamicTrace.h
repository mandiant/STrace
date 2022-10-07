#pragma once
#include <ntifs.h>
#include "MyStdint.h"
#include "Constants.h"

// ntoskrn has hardcoded check for this when doing TraceAccessMemory API calls
static const uint64_t DTRACE_IRQL = 15;

/*
TLSData lives per kthread, and exists from [entry, exit] callback. A new TLSData get allocated
after each entry -> exit. Ex: entry, *alloc*, exit, *de-alloc*, repeat...

To track when to do this, the calldepth is used. We free when it's zero, and only if it was zeroed by
in an exit probe. There's some boolean flags that guard which things can occur when. Since we call
these early in the callbacks, we need to check if we called OS apis, so that we can skip those frames for 
callstack tracing.
*/
static const uint8_t MAX_TLS_SLOT = 64;
struct TLSData {
	uint64_t calldepth;
	uint64_t arbitraryData[MAX_TLS_SLOT];
};

static bool TlsLookasideInitialized = false;
static LOOKASIDE_LIST_EX TLSLookasideList = { 0 };

// ntoskrnl!KiDynamicTraceContext
struct TraceApi
{
	ULONG32 supported_flags;
	ULONG32 kthread_tracingprivatedata_offset;
	ULONG32 kthread_tracingprivatedata_arraysize;
	ULONG32 kthread_trapframe_offset;
	ULONG64 kthread_teb_offset;

	/**
	This handles probe registration and removal.
	syscallName: The system call name to register, with the first two characters skipped, ie without Nt or Zw prefix
	isEntry: Register an entry or return probe, must match callback entry or return pointer
	callback: The callback to invoke on entry/return must be StpCallbackEntry and StpCallbackReturn respectively matching isEntry
	probeId: A user given ID to remember the entry by, passed to the callback routine

	To remove a callback provide syscallName, isEntry to specify removal of entry/return probe then zero for callback and probeId
	**/
	NTSTATUS(*KeSetSystemServiceCallback)(const char* syscallName, BOOLEAN isEntry, ULONG64 callback, ULONG64 probeId);
	void* KeSetTracepoint;

	/**
	This handles ETW probe registration and removal.
	**/
	NTSTATUS(*EtwRegisterEventCallback)(UINT32 a, ULONG64 callback, ULONG64 b);
	PKTHREAD(*PsGetBaseTrapFrame)(PKTHREAD thread, void* unk);
	void* KiGetTrapFrameRegister;
	void* MmEnumerateSystemImages;

	__forceinline bool EnterProbe() {
		auto recursiveCallDepth = getTlsDataCalldepth();

		bool called_children = false;
		setTlsDataCalldepth(recursiveCallDepth + 1, called_children, false);
		return called_children;
	}

	__forceinline bool ExitProbe(bool shouldFree = false) {
		auto recursiveCallDepth = getTlsDataCalldepth();

		bool called_children = false;
		setTlsDataCalldepth(recursiveCallDepth - 1, called_children, shouldFree);
		return called_children;
	}

	__forceinline bool isCallFromInsideProbe() {
		return getTlsDataCalldepth() > 1;
	}
	
	__forceinline TLSData* getRawTLSData() {
		PKTHREAD pThread = KeGetCurrentThread();

		// this is always one based on what i've seen. This might also be 'is tracing tls supported' rather than array size.
		// unless the value ever is something other than 1 in a future ntoskrnl we can't know
		if (kthread_tracingprivatedata_arraysize <= 0) {
			__debugbreak();
			return nullptr;
		}

		uint64_t* pTlsArray = (uint64_t*)(((char*)pThread) + kthread_tracingprivatedata_offset);
		return (TLSData*)pTlsArray[0];
	}
private:
	// helper routines I created based off of dtrace's internals, that use fields within this apis
	DECLSPEC_NOINLINE void setTlsDataCalldepth(uint64_t value, bool& calledChildren, bool shouldFree) {
		calledChildren = false;

		PKTHREAD pThread = KeGetCurrentThread();

		// this is always one based on what i've seen. This might also be 'is tracing tls supported' rather than array size.
		// unless the value ever is something other than 1 in a future ntoskrnl we can't know
		if (kthread_tracingprivatedata_arraysize <= 0) {
			__debugbreak();
			return;
		}

		__try {
			// array of pointers
			uint64_t* pTlsArray = (uint64_t*)(((char*)pThread) + kthread_tracingprivatedata_offset);

			// 0th ptr is TLSData*
			if (!pTlsArray[0]) {
				pTlsArray[0] = (uint64_t)ExAllocateFromLookasideListEx(&TLSLookasideList);
				if (!pTlsArray[0]) {
					__debugbreak();
					return;
				}
				calledChildren = true;
			}

			// if allowed, free the data when the value is zero
			if (shouldFree && value == 0) {
				ExFreeToLookasideListEx(&TLSLookasideList, (char*)pTlsArray[0]);
				pTlsArray[0] = 0;
				calledChildren = true;
			} else {
				((TLSData*)pTlsArray[0])->calldepth = value;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		
		}
	}

	DECLSPEC_NOINLINE uint64_t getTlsDataCalldepth() {
		PKTHREAD pThread = KeGetCurrentThread();

		// this is always one based on what i've seen. This might also be 'is tracing tls supported' rather than array size.
		// unless the value ever is something other than 1 in a future ntoskrnl we can't know
		if (kthread_tracingprivatedata_arraysize <= 0) {
			__debugbreak();
			return 0;
		}

		// array of pointers
		uint64_t value = 0;
		__try {
			uint64_t* pTlsArray = (uint64_t*)(((char*)pThread) + kthread_tracingprivatedata_offset);
			if (!pTlsArray[0]) {
				return 0;
			}

			value = ((TLSData*)pTlsArray[0])->calldepth;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {

		}
		return value;
	}
};

struct TraceCallbacks
{
	void* pCallbacks[9];
};

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

extern TraceApi* TraceSystemApi;

// These must be free functions
bool SetTLSData(uint64_t value, uint8_t slot);
bool GetTLSData(uint64_t& value, uint8_t slot);