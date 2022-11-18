#include "NtStructs.h"

// https://github.com/processhacker/processhacker/blob/e96989fd396b28f71c080edc7be9e7256b5229d0/KProcessHacker/thread.c
#define MAX_STACK_DEPTH 256 // arbitrary
#define RTL_WALK_USER_MODE_STACK 0x00000001

ULONG KphCaptureStack(
    _Out_ PVOID* Frames,
    _In_ ULONG Count
)
{
    ULONG frames;
    frames = RtlWalkFrameChain(Frames, Count, 0);

    if (frames >= Count)
    {
        return frames;
    }

    frames += RtlWalkFrameChain(&Frames[frames],(Count - frames),RTL_WALK_USER_MODE_STACK);
    return frames;
}

ULONG KphCaptureStackBackTrace(
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _Out_writes_(FramesToCapture) PVOID* BackTrace
)
{
    PVOID backTrace[MAX_STACK_DEPTH] = {0};
    ULONG framesFound = 0;
    ULONG i = 0;
    //
    // Skip the current frame (for this function).
    //
    FramesToSkip++;

    if ((FramesToCapture + FramesToSkip) > MAX_STACK_DEPTH)
    {
        return 0;
    }

    framesFound = KphCaptureStack(backTrace, (FramesToCapture + FramesToSkip));

    //
    // Return nothing if we found fewer frames than we wanted to skip.
    //
    if (framesFound <= FramesToSkip)
    {
        return 0;
    }

    //
    // Copy over the stack trace.
    //
    for (i = 0; i < FramesToCapture; i++)
    {
        if ((FramesToSkip + i) >= framesFound)
        {
            break;
        }

        BackTrace[i] = backTrace[FramesToSkip + i];
    }
    return i;
}