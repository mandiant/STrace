#pragma once
#include <ntifs.h>
#include "MyStdint.h"

// ntoskrn has hardcoded check for this when doing TraceAccessMemory API calls
static const uint64_t DTRACE_IRQL = 15;

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
  NTSTATUS(*KeSetSystemServiceCallback)(const char *syscallName, BOOLEAN isEntry, ULONG64 callback, ULONG64 probeId);
  void *KeSetTracepoint;

  /**
  This handles ETW probe registration and removal.
  **/
  NTSTATUS(*EtwRegisterEventCallback)(UINT32 a, ULONG64 callback, ULONG64 b);
  PKTHREAD(*PsGetBaseTrapFrame)(PKTHREAD thread, void* unk);
  void *KiGetTrapFrameRegister;
  void *MmEnumerateSystemImages;

  void EnterProbe() {
	  auto recursiveCallDepth = getTlsValue();
	  setTlsValue(recursiveCallDepth + 1);
  }

  void ExitProbe() {
	  auto recursiveCallDepth = getTlsValue();
	  setTlsValue(recursiveCallDepth - 1);
  }

  bool isCallFromInsideProbe() {
	  return getTlsValue() > 1;
  }
private:
  // helper routines I created based off of dtrace's internals, that use fields within this apis
  void setTlsValue(uint64_t value) {
	  PKTHREAD pThread = KeGetCurrentThread();

	  // this is always one based on what i've seen. This might also be 'is tracing tls supported' rather than array size.
	  // unless the value ever is something other than 1 in a future ntoskrnl we can't know
	  if (kthread_tracingprivatedata_arraysize <= 0) {
		  __debugbreak();
		  return;
	  }

	  uint64_t* pTlsArray = (uint64_t*)(((char*)pThread) + kthread_tracingprivatedata_offset);
	  pTlsArray[0] = value;
  }

  uint64_t getTlsValue() {
	  PKTHREAD pThread = KeGetCurrentThread();

	  // this is always one based on what i've seen. This might also be 'is tracing tls supported' rather than array size.
	  // unless the value ever is something other than 1 in a future ntoskrnl we can't know
	  if (kthread_tracingprivatedata_arraysize <= 0) {
		  __debugbreak();
		  return 0;
	  }

	  uint64_t* pTlsArray = (uint64_t*)(((char*)pThread) + kthread_tracingprivatedata_offset);
	  return pTlsArray[0];
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
