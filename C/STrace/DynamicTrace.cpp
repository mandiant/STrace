#include "DynamicTrace.h"

TraceApi* TraceSystemApi;

extern "C" __declspec(dllexport) __declspec(noinline) BOOLEAN TraceAccessMemory(PVOID SafeAddress, ULONG_PTR UnsafeAddress, SIZE_T NumberOfBytes, SIZE_T ChunkSize, BOOLEAN DoRead)
{
	// Write entire memory routines in __try __except to generate relevant unwind information. 

	__try {
		char* source = (char*)UnsafeAddress;
		char* dest = (char*)SafeAddress;

		// Swap if write
		if (!DoRead) {
			char* tmp = source;
			source = dest;
			dest = tmp;
		}

		// It's done this way so that all read/write logic is contained within this function (rather than call memcpy)
		// We use a chunk-size so that faulting accesses across pages can be easily controlled by the user
		// Note: This routine can be implemented in any way as long as there are no calls within the body.
		while (NumberOfBytes) {
			if(NumberOfBytes < ChunkSize) {
				return FALSE;
			}
			
			switch (ChunkSize) {
			case 1:
				*dest = *source;
				break;
			case 2:
				*(uint16_t*)dest = *(uint16_t*)source;
				break;
			case 4:
				*(uint32_t*)dest = *(uint32_t*)source;
				break;
			case 8:
				*(uint64_t*)dest = *(uint64_t*)source;
				break;
			default:
				break;
			}
			NumberOfBytes -= ChunkSize;
			source += ChunkSize;
			dest += ChunkSize;
		}
	}__except(EXCEPTION_EXECUTE_HANDLER) {
		
	}
	return TRUE;
}