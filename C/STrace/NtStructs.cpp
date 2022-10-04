#include "NtStructs.h"

// https://github.com/processhacker/processhacker/blob/e96989fd396b28f71c080edc7be9e7256b5229d0/KProcessHacker/thread.c
#define MAX_STACK_DEPTH 256 // arbitrary
#define RTL_WALK_USER_MODE_STACK 0x00000001
ULONG KphCaptureStackBackTrace(
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _Out_writes_(FramesToCapture) PVOID* BackTrace,
    _Out_opt_ PULONG BackTraceHash
)
{
    PVOID backTrace[MAX_STACK_DEPTH];
    ULONG framesFound;
    ULONG hash;
    ULONG i;

    // Skip the current frame (for this function).
    FramesToSkip++;

    // Ensure that we won't overrun the buffer.
    if (FramesToCapture + FramesToSkip > MAX_STACK_DEPTH)
        return 0;

    // Walk the stack.
    framesFound = RtlWalkFrameChain(
        backTrace,
        FramesToCapture + FramesToSkip,
        0
    );

    //if (FlagOn(Flags, KPH_STACK_TRACE_CAPTURE_USER_STACK))
    //{
    framesFound += RtlWalkFrameChain(
        &backTrace[framesFound],
        (FramesToCapture + FramesToSkip) - framesFound,
        RTL_WALK_USER_MODE_STACK
    );
    //    }

        // Return nothing if we found fewer frames than we wanted to skip.
    if (framesFound <= FramesToSkip)
        return 0;

    // Copy over the stack trace. At the same time we calculate the stack trace hash by summing the
    // addresses.
    for (i = 0, hash = 0; i < FramesToCapture; i++)
    {
        if (FramesToSkip + i >= framesFound)
            break;

        BackTrace[i] = backTrace[FramesToSkip + i];
        hash += PtrToUlong(BackTrace[i]);
    }

    if (BackTraceHash)
        *BackTraceHash = hash;

    return i;
}