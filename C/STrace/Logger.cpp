/**
 * Copyright (c) 2015-2016, tandasat. All rights reserved.
 * Use of this source code is governed by a MIT-style license:
 *
 * The MIT License ( MIT )
 *
 * Copyright (c) 2016 Satoshi Tanda
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files ( the "Software" ), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions :
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @file log.c
 * @authors Satoshi Tanda (tandasat)
 * @date 8/30/2018
 */

#if defined(ENABLE_LOG)

#include "Logger.h"
#include <ntimage.h>
#include <apiset.h>
 ///
 /// < Macros >
 ///

 // A size for log buffer in NonPagedPool. Two buffers are allocated with this
 // size. Exceeded logs are ignored silently. Make it bigger if a buffered log
 // size often reach this size.
#define LOG_BUFFER_SIZE_IN_PAGES    (64UL)
// An actual log buffer size in bytes.
#define LOG_BUFFER_SIZE             (LOG_BUFFER_SIZE_IN_PAGES << PAGE_SHIFT)
// A size that is usable for logging. Minus one because the last byte is kept for \0.
#define LOG_BUFFER_USABLE_SIZE      (LOG_BUFFER_SIZE - 1)
// An interval in milliseconds to flush buffered log entries into a log file.
#define LOG_FLUSH_INTERVAL          (50)

///
/// < Log Types >
///

typedef struct _LOG_BUFFER_INFO
{
    // A pointer to buffer currently used.
    // It is either LogBuffer1 or LogBuffer2.
    volatile CHAR* LogBufferHead;
    // A pointer to where the next log should be written.
    volatile CHAR* LogBufferTail;
    CHAR* LogBuffer1;
    CHAR* LogBuffer2;
    // Holds the biggest buffer usage to determine a necessary buffer size.
    SIZE_T LogMaxUsage;
    HANDLE LogFileHandle;
    KSPIN_LOCK SpinLock;
    ERESOURCE Resource;
    BOOLEAN ResourceInitialized;
    volatile BOOLEAN BufferFlushThreadShouldBeAlive;
    volatile BOOLEAN BufferFlushThreadStarted;
    HANDLE BufferFlushThreadHandle;
    WCHAR LogFilePath[200];
} LOG_BUFFER_INFO, * PLOG_BUFFER_INFO;

///
/// < Log Prototypes >
///

static
NTSTATUS
LogpInitializeBufferInfo(
    IN CONST WCHAR* LogFilePath,
    IN OUT PLOG_BUFFER_INFO Info
);

static
NTSTATUS
LogpInitializeLogFile(
    IN OUT PLOG_BUFFER_INFO Info
);

static
DRIVER_REINITIALIZE
LogpReinitializationRoutine;

static
VOID
LogpFinalizeBufferInfo(
    IN PLOG_BUFFER_INFO Info
);

static
NTSTATUS
LogpMakePrefix(
    IN ULONG Level,
    IN CONST CHAR* FunctionName,
    IN CONST CHAR* LogMessage,
    OUT CHAR* LogBuffer,
    IN SIZE_T LogBufferLength
);

static
CONST CHAR*
LogpFindBaseFunctionName(
    IN CONST CHAR* FunctionName
);

static
NTSTATUS
LogpPut(
    IN CHAR* Message,
    IN ULONG Attribute
);

static
NTSTATUS
LogpFlushLogBuffer(
    IN OUT PLOG_BUFFER_INFO Info
);

static
NTSTATUS
LogpWriteMessageToFile(
    IN CONST CHAR* Message,
    IN CONST LOG_BUFFER_INFO* Info
);

static
NTSTATUS
LogpBufferMessage(
    IN CONST CHAR* Message,
    IN OUT PLOG_BUFFER_INFO Info
);

static
VOID
LogpDoDbgPrint(
    IN CHAR* Message
);

FORCEINLINE
BOOLEAN
LogpIsLogFileEnabled(
    IN CONST LOG_BUFFER_INFO* Info
);

static
BOOLEAN
LogpIsLogFileActivated(
    IN CONST LOG_BUFFER_INFO* Info
);

static
BOOLEAN
LogpIsLogNeeded(
    IN ULONG Level
);

static
KSTART_ROUTINE
LogpBufferFlushThreadRoutine;

static
BOOLEAN
LogpFileExists(
    IN PUNICODE_STRING FilePath
);

static
VOID
LogpDbgBreak(
    VOID
);

typedef
NTSTATUS
(NTAPI* PNT_FLUSH_BUFFERS_FILE)(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );
static PNT_FLUSH_BUFFERS_FILE NtFlushBuffersFile = NULL;

static ULONG LogFlags = LogPutLevelDisable;
static LOG_BUFFER_INFO LogBufferInfo = { 0 };

/**
 * Log Implementation
 */

NTSTATUS
LogInitialize(
    IN ULONG Flag,
    IN CONST WCHAR* LogFilePath OPTIONAL
)
{
    NTSTATUS Status;
    BOOLEAN ReinitializeNeeded = FALSE;
    LogFlags = Flag;

    RtlZeroMemory(&LogBufferInfo, sizeof(LOG_BUFFER_INFO));

    //
    // Initialize a log file if a log file path is specified.
    //
    if (LogFilePath != NULL)
    {
        Status = LogpInitializeBufferInfo(LogFilePath, &LogBufferInfo);
        if (Status == STATUS_REINITIALIZATION_NEEDED)
        {
            ReinitializeNeeded = TRUE;
        }
        else if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    // Test the log.
    Status = LOG_INFO("Log has been %sinitialized.\r\n", (ReinitializeNeeded ? "partially " : ""));
    if (!NT_SUCCESS(Status))
    {
        goto Fail;
    }

#ifdef DBG
    LOG_DEBUG("Info=%016Ix, Buffer=%016Ix %016Ix, File=\"%S\"",
        &LogBufferInfo, LogBufferInfo.LogBuffer1, LogBufferInfo.LogBuffer2, LogFilePath);
#endif

    if (ReinitializeNeeded)
    {
        return STATUS_REINITIALIZATION_NEEDED;
    }

    return STATUS_SUCCESS;

Fail:
    if (LogFilePath)
    {
        LogpFinalizeBufferInfo(&LogBufferInfo);
    }

    return Status;
}

// Initialize a log file related code such as a flushing thread.
static
NTSTATUS
LogpInitializeBufferInfo(
    IN CONST WCHAR* LogFilePath,
    IN OUT PLOG_BUFFER_INFO Info
)
{
    NTSTATUS Status;
    PHYSICAL_ADDRESS HighestAcceptableAddress;

    if (!LogFilePath || !Info)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeInitializeSpinLock(&Info->SpinLock);

    Status = RtlStringCchCopyW(Info->LogFilePath,
        RTL_NUMBER_OF_FIELD(LOG_BUFFER_INFO, LogFilePath),
        LogFilePath);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = ExInitializeResourceLite(&Info->Resource);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Info->ResourceInitialized = TRUE;

    //
    // Allocate two log buffers as NonPagedPools.
    //
    HighestAcceptableAddress.QuadPart = MAXUINT64;
    Info->LogBuffer1 = (CHAR*)MmAllocateContiguousMemory(LOG_BUFFER_SIZE * 2,
        HighestAcceptableAddress);
    if (!Info->LogBuffer1)
    {
        LogpFinalizeBufferInfo(Info);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Info->LogBuffer2 = Info->LogBuffer1 + LOG_BUFFER_SIZE;

    //
    // Initialize these buffers
    //
    RtlFillMemory(Info->LogBuffer1, LOG_BUFFER_SIZE, 0xFFFFFFFF);  // for debugging
    Info->LogBuffer1[0] = '\0';
    Info->LogBuffer1[LOG_BUFFER_SIZE - 1] = '\0';

    RtlFillMemory(Info->LogBuffer2, LOG_BUFFER_SIZE, 0xFFFFFFFF); // for debugging
    Info->LogBuffer2[0] = '\0';
    Info->LogBuffer2[LOG_BUFFER_SIZE - 1] = '\0';

    //
    // Buffer should be used is LogBuffer1, and location should be written
    // logs is the head of the buffer.
    //
    Info->LogBufferHead = Info->LogBuffer1;
    Info->LogBufferTail = Info->LogBuffer1;

    //
    // Initialize the log file.
    //
    Status = LogpInitializeLogFile(Info);
    if (Status == STATUS_OBJECT_PATH_NOT_FOUND)
    {

        LOG_INFO("The log file needs to be activated later.");
        Status = STATUS_REINITIALIZATION_NEEDED;

    }
    else if (!NT_SUCCESS(Status))
    {

        LogpFinalizeBufferInfo(Info);
    }

    return Status;
}

// Initializes a log file and startes a log buffer thread.
static
NTSTATUS
LogpInitializeLogFile(
    IN OUT PLOG_BUFFER_INFO Info
)
{
    UNICODE_STRING LogFilePath;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER Interval;
    ULONG DesiredAccess;
    NTSTATUS Status;

    //
    // Check if the log file has already been initialized.
    //
    if (Info->LogFileHandle != NULL)
    {
        return STATUS_SUCCESS;
    }

    //
    // Initialize a log file path.
    //
    LogFilePath.Length = (UINT16)(wcslen(Info->LogFilePath) * sizeof(WCHAR));
    LogFilePath.MaximumLength = RTL_NUMBER_OF_FIELD(LOG_BUFFER_INFO, LogFilePath);
    LogFilePath.Buffer = (WCHAR*)Info->LogFilePath;
    InitializeObjectAttributes(&Attributes,
        &LogFilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    //
    // Check if the file already exists.
    //
    if ((LogFlags & LogOptDisableAppend) && LogpFileExists(&LogFilePath))
    {

        Status = ZwDeleteFile(&Attributes);
        if (!NT_SUCCESS(Status))
        {
            LogpDbgBreak();
            return Status;
        }
    }

    //
    // Create the file handle.
    //
    DesiredAccess = (ULONG)((LogFlags & LogOptDisableAppend) ? FILE_WRITE_DATA : FILE_APPEND_DATA);
    Status = ZwCreateFile(&Info->LogFileHandle,
        DesiredAccess | SYNCHRONIZE,
        &Attributes,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_SYSTEM,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    //
    // Initialize a log buffer flush thread.
    //
    Info->BufferFlushThreadShouldBeAlive = TRUE;
    Status = PsCreateSystemThread(&Info->BufferFlushThreadHandle,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        LogpBufferFlushThreadRoutine,
        Info
    );
    if (!NT_SUCCESS(Status))
    {
        ZwClose(Info->LogFileHandle);
        Info->LogFileHandle = NULL;
        Info->BufferFlushThreadShouldBeAlive = FALSE;
        return Status;
    }

    //
    // Wait until the thead has started
    //
    while (!Info->BufferFlushThreadStarted)
    {
        Interval = RtlConvertLongToLargeInteger((INT32)(-10000 * LOG_FLUSH_INTERVAL));
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }

    return Status;
}

VOID
LogRegisterReinitialization(
    IN PDRIVER_OBJECT DriverObject
)
{
    IoRegisterBootDriverReinitialization(DriverObject, LogpReinitializationRoutine, &LogBufferInfo);
#if defined(DBG)
    LOG_DEBUG("The log file will be activated later.");
#endif
}

// Initializes a log file at the re-initialization phase.
static
VOID
LogpReinitializationRoutine(
    IN PDRIVER_OBJECT DriverObject,
    IN PVOID Context,
    IN ULONG Count
)
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(Count);

    NT_ASSERT(Context != NULL);

    Status = LogpInitializeLogFile((PLOG_BUFFER_INFO)Context);

    NT_ASSERT(NT_SUCCESS(Status));

    if (NT_SUCCESS(Status))
    {
        LOG_INFO("The log file has been activated.");
    }
}

// Terminates the log functions without releasing resources.
VOID
LogIrpShutdownHandler(
    VOID
)
{
    LARGE_INTEGER Interval;

    PAGED_CODE();

#if defined(DBG)
    LOG_DEBUG("Flushing... (Max log usage = %08x bytes)", LogBufferInfo.LogMaxUsage);
#endif

    //
    // Indicate that the log is disabled.
    //
    LogFlags = LogPutLevelDisable;

    //
    // Wait until the log buffer is emptied.
    //
    while (LogBufferInfo.LogBufferHead[0])
    {
        Interval = RtlConvertLongToLargeInteger((INT32)(-10000 * LOG_FLUSH_INTERVAL));
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }
}

// Destroys the log functions.
VOID
LogDestroy(
    VOID
)
{
#if defined(DBG)
    LOG_DEBUG("Finalizing... (Max log usage = %08x bytes)", LogBufferInfo.LogMaxUsage);
#endif

    LogFlags = LogPutLevelDisable;
    LogpFinalizeBufferInfo(&LogBufferInfo);
}

// Terminates a log file related code.
static
VOID
LogpFinalizeBufferInfo(
    IN PLOG_BUFFER_INFO Info
)
{
    NTSTATUS Status;

    NT_ASSERT(Info != NULL);
    
    // Closing the log buffer flush thread.
    if (Info->BufferFlushThreadHandle)
    {

        Info->BufferFlushThreadShouldBeAlive = FALSE;

        Status = ZwWaitForSingleObject(Info->BufferFlushThreadHandle, FALSE, NULL);
        if (!NT_SUCCESS(Status))
        {
            LogpDbgBreak();
        }

        ZwClose(Info->BufferFlushThreadHandle);
        Info->BufferFlushThreadHandle = NULL;
    }

    // Clean up other things.
    if (Info->LogFileHandle)
    {
        ZwClose(Info->LogFileHandle);
        Info->LogFileHandle = NULL;
    }

    if (Info->LogBuffer1)
    {
        MmFreeContiguousMemory(Info->LogBuffer1);
        Info->LogBuffer1 = NULL;
    }

    if (Info->ResourceInitialized)
    {
        ExDeleteResourceLite(&Info->Resource);
        Info->ResourceInitialized = FALSE;
    }
}

// Actual implementation of logging API.
NTSTATUS
LogPrint(
    IN unsigned int Level,
    IN CONST CHAR* FunctionName,
    IN CONST CHAR* Format,
    ...
)
{
    NTSTATUS Status;
    va_list Args;

    SIZE_T cchRemaining;
    SIZE_T cchLength;
    SIZE_T cchPrinted;
    SIZE_T cchLengthToCopy;

    CHAR* LogMessage, * LogMessageEnd;
    CHAR LogMessageBuffer[411 + 1];
    CHAR Message[512];

    // A single entry of a log should not exceed 512 bytes. See
    // Reading and Filtering Debugging Messages in MSDN for details.
    C_ASSERT(RTL_NUMBER_OF(Message) <= 512);

    if (!LogpIsLogNeeded(Level))
    {
        return STATUS_SUCCESS;
    }

    LogMessage = LogMessageBuffer;

    va_start(Args, Format);
    Status = RtlStringCchVPrintfExA(LogMessage,
        RTL_NUMBER_OF(LogMessageBuffer),
        &LogMessageEnd,
        &cchRemaining,
        STRSAFE_NO_TRUNCATION,
        Format,
        Args
    );
    va_end(Args);

    //
    // Treat STATUS_BUFFER_OVERFLOW as just a warning.
    //
    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_SUCCESS)
    {
        LogpDbgBreak();
        return Status;
    }

    //
    // Handle buffer overflow.
    //
    if (Status == STATUS_BUFFER_OVERFLOW)
    {
        cchLength = cchRemaining;

        LogMessage = (CHAR*)ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
        if (!LogMessage)
        {
            LogpDbgBreak();
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        va_start(Args, Format);
        Status = RtlStringCchVPrintfExA(LogMessage,
            PAGE_SIZE,
            &LogMessageEnd,
            &cchRemaining,
            STRSAFE_NO_TRUNCATION,
            Format,
            Args
        );
        va_end(Args);

        if (Status != STATUS_SUCCESS)
        {
            LogpDbgBreak();
            return Status;
        }

        cchLength = (LogMessageEnd - LogMessage);

    }
    else
    {

        if (LogMessage[0] == '\0')
        {
            LogpDbgBreak();
            return STATUS_INVALID_PARAMETER;
        }
        cchLength = 0;
    }

    if (cchLength)
    {

        cchPrinted = 0;
        do
        {
            cchLengthToCopy = min(cchLength - cchPrinted, sizeof(LogMessageBuffer) - sizeof(LogMessageBuffer[0]));
            RtlZeroMemory(&LogMessageBuffer, sizeof(LogMessageBuffer) - sizeof(LogMessageBuffer[0]));
            RtlCopyMemory(LogMessageBuffer, LogMessage + cchPrinted, cchLengthToCopy);

            if (cchPrinted == 0)
            {

                Status = LogpMakePrefix(Level & 0xF0,
                    FunctionName,
                    LogMessageBuffer,
                    Message,
                    RTL_NUMBER_OF(Message)
                );

            }
            else
            {

                Status = RtlStringCchPrintfExA(Message,
                    RTL_NUMBER_OF(Message),
                    NULL,
                    NULL,
                    STRSAFE_NO_TRUNCATION,
                    "> %s\r\n",
                    LogMessageBuffer
                );
            }

            if (!NT_SUCCESS(Status))
            {
                LogpDbgBreak();
                break;
            }

            cchPrinted += cchLengthToCopy;

            Status = LogpPut(Message, Level & 0x0F);
            if (!NT_SUCCESS(Status))
            {
                DBGPRINT("LogpPut failed - Status = 0x%08X Log is: %s\n", Status, Message);
                //LogpDbgBreak();
                break;
            }

        } while (cchPrinted < cchLength);

        //
        // Free the previously allocated log message pool.
        //
        ExFreePool(LogMessage);

    }
    else
    {

        //
        // No overflow occurred, we should be safe to print.
        //
        Status = LogpMakePrefix(Level & 0xF0, FunctionName, LogMessage, Message, RTL_NUMBER_OF(Message));
        if (!NT_SUCCESS(Status))
        {
            LogpDbgBreak();
            return Status;
        }

        Status = LogpPut(Message, Level & 0x0F);
        if (!NT_SUCCESS(Status))
        {
            DBGPRINT("LogpPut failed - Status = 0x%08X Log is: %s\n", Status, Message);
            //LogpDbgBreak();
        }
    }

    return Status;
}

// Concatenates meta information such as the current time and a process ID to
// user given log message.
static
NTSTATUS
LogpMakePrefix(
    IN ULONG Level,
    IN CONST CHAR* FunctionName,
    IN CONST CHAR* LogMessage,
    OUT CHAR* LogBuffer,
    IN SIZE_T LogBufferLength
)
{
    NTSTATUS Status;
    ULONG LogLevelIndex;
    CHAR TimeBuffer[20];
    CHAR FunctionNameBuffer[50];
    CHAR ProcessorNumber[10];
    ULONG CurrentProcessorNumber;
    TIME_FIELDS TimeFields;
    LARGE_INTEGER SystemTime;
    LARGE_INTEGER LocalTime;
    CONST CHAR* BaseFunctionName;

    static CHAR CONST* LogLevelStrings[4] = { "DBG ", "INF ", "WRN ", "ERR " };

    //
    // Get the log level prefix index.
    //
    if (!_BitScanForward((unsigned long*)&LogLevelIndex, (Level >> 4)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Want the current time.
    //
    if (!(LogFlags & LogOptDisableTime))
    {

        KeQuerySystemTime(&SystemTime);
        ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
        RtlTimeToTimeFields(&LocalTime, &TimeFields);
        Status = RtlStringCchPrintfA(TimeBuffer,
            RTL_NUMBER_OF(TimeBuffer),
            "%02u:%02u:%02u.%03u  ",
            TimeFields.Hour,
            TimeFields.Minute,
            TimeFields.Second,
            TimeFields.Milliseconds
        );
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }

    }
    else
    {
        TimeBuffer[0] = '\0';
    }

    //
    // Want the function name.
    //
    if (!(LogFlags & LogOptDisableFunctionName))
    {

        BaseFunctionName = LogpFindBaseFunctionName(FunctionName);
        if (BaseFunctionName)
        {

            Status = RtlStringCchPrintfA(FunctionNameBuffer,
                RTL_NUMBER_OF(FunctionNameBuffer),
                "%-40s  ",
                BaseFunctionName
            );
            if (!NT_SUCCESS(Status))
            {
                return Status;
            }

        }
        else
        {
            FunctionNameBuffer[0] = '\0';
        }
    }
    else
    {
        FunctionNameBuffer[0] = '\0';
    }

    //
    // Want the processor number.
    //
    if (!(LogFlags & LogOptDisableProcessorNumber))
    {

        CurrentProcessorNumber = KeGetCurrentProcessorNumberEx(NULL);
        Status = RtlStringCchPrintfA(ProcessorNumber,
            RTL_NUMBER_OF(ProcessorNumber),
            CurrentProcessorNumber >= 10 ? "#%lu" : "#%lu ",
            CurrentProcessorNumber
        );
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }

    }
    else
    {
        *((UINT16*)ProcessorNumber) = 0x2020; // "  "
        ProcessorNumber[2] = '\0';
    }

    //
    // It uses PsGetProcessId(PsGetCurrentProcess()) instead of
    // PsGetCurrentThreadProcessId() because the latter sometimes returns
    // unwanted value, for example:
    // PID == 4 but its image name != ntoskrnl.exe
    // The author is guessing that it is related to attaching processes but
    // not quite sure. The former way works as expected.
    //
    Status = RtlStringCchPrintfA(LogBuffer,
        LogBufferLength,
        "%s%s%s%6Iu  %s%s",
        TimeBuffer,
        LogLevelStrings[LogLevelIndex],
        ProcessorNumber,
        (ULONG_PTR)PsGetCurrentThreadId(),
        FunctionNameBuffer,
        LogMessage
    );
    return Status;
}

// Returns the function's base name, for example,
// NamespaceName::ClassName::MethodName will be returned as MethodName.
static
CONST CHAR*
LogpFindBaseFunctionName(
    IN CONST CHAR* FunctionName
)
{
    const char* p;
    const char* BaseFunctionName;

    if (!FunctionName)
    {
        return NULL;
    }

    p = FunctionName;
    BaseFunctionName = FunctionName;

    while (*(p++))
    {
        if (*p == ':')
            BaseFunctionName = p + 1;
    }

    return BaseFunctionName;
}

// Logs the entry according to attribute and the thread condition.
static
NTSTATUS
LogpPut(
    IN CHAR* Message,
    IN ULONG Attribute
)
{
    //TODO: remove this arg
    UNREFERENCED_PARAMETER(Attribute);

    NTSTATUS Status = STATUS_SUCCESS;

    //
    // Log the entry to a file or buffer.
    //
    if (LogpIsLogFileEnabled(&LogBufferInfo))
    {

        // Can it log it to a file now?
        if (KeGetCurrentIrql() == PASSIVE_LEVEL && LogpIsLogFileActivated(&LogBufferInfo))
        {
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:28123) // The function is not permitted to be called at a high IRQ level.
#endif 
            if (!KeAreAllApcsDisabled())
            {

                // Yes, it can! Lets see if we can buffer it though for performance
                auto UsedBufferSize = (SIZE_T)(LogBufferInfo.LogBufferTail - LogBufferInfo.LogBufferHead);
                auto UsableSpaceLeft = UsedBufferSize > LOG_BUFFER_USABLE_SIZE ? 0 : LOG_BUFFER_USABLE_SIZE - UsedBufferSize;
                if (strlen(Message) + 1 <= UsableSpaceLeft) {
                    Status = LogpBufferMessage(Message, &LogBufferInfo);
                } else {
                    LogpFlushLogBuffer(&LogBufferInfo);
                    Status = LogpWriteMessageToFile(Message, &LogBufferInfo);
                }
            }
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
        }
        else
        {
            Status = LogpBufferMessage(Message, &LogBufferInfo);
        }
    }

    // Print to kernel debugger?
    // if( KeGetCurrentIrql() < CLOCK_LEVEL) {
    LogpDoDbgPrint(Message);
    // }

    return Status;
}

// Switches the current log buffer, saves the contents of old buffer to the log
// file, and prints them out as necessary. This function does not flush the log
// file, so code should call LogpWriteMessageToFile() or ZwFlushBuffersFile() later.
static
NTSTATUS
LogpFlushLogBuffer(
    IN OUT PLOG_BUFFER_INFO Info
)
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;
    IO_STATUS_BLOCK IoStatus;
    CHAR* OldLogBuffer;
    CHAR* CurrentLogEntry;
    ULONG CurrentLogEntryLength;

    NT_ASSERT(Info != NULL);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Status = STATUS_SUCCESS;

    //
    // Enter a critical section and acquire a reader lock for info in order to
    // write a log file safely.
    //
    ExEnterCriticalRegionAndAcquireResourceExclusive(&Info->Resource);

    //
    // Acquire a spin lock for Info.LogBuffer(s) in order
    // to switch its head safely.
    //
    KeAcquireInStackQueuedSpinLock(&Info->SpinLock, &LockHandle);

    OldLogBuffer = (CHAR*)(Info->LogBufferHead);
    Info->LogBufferHead = (OldLogBuffer == Info->LogBuffer1)
        ? Info->LogBuffer2
        : Info->LogBuffer1;
    Info->LogBufferHead[0] = '\0';
    Info->LogBufferTail = Info->LogBufferHead;

    KeReleaseInStackQueuedSpinLock(&LockHandle);

    //
    // Write all log entries in old log buffer.
    //
    for (CurrentLogEntry = OldLogBuffer; *CurrentLogEntry; /**/)
    {
        CurrentLogEntryLength = (ULONG)strlen(CurrentLogEntry);

        Status = ZwWriteFile(Info->LogFileHandle,
            NULL,
            NULL,
            NULL,
            &IoStatus,
            CurrentLogEntry,
            CurrentLogEntryLength,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(Status))
        {

            //
            // It could happen when you did not register IRP_SHUTDOWN and call
            // LogIrpShutdownHandler and the system tried to log to a file after
            // a file system was unmounted.
            //
            LogpDbgBreak();
        }

        CurrentLogEntry += ((ULONGLONG)CurrentLogEntryLength + 1);
    }

    OldLogBuffer[0] = '\0';

    ExReleaseResourceAndLeaveCriticalRegion(&Info->Resource);

    return Status;
}

// Logs the current log entry to and flush the log file.
static
NTSTATUS
LogpWriteMessageToFile(
    IN CONST CHAR* Message,
    IN CONST LOG_BUFFER_INFO* Info
)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;
    ULONG MessageLength;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    MessageLength = (ULONG)strlen(Message);

    Status = ZwWriteFile(Info->LogFileHandle,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        (PVOID)Message,
        MessageLength,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(Status))
    {

        //
        // It could happen when you did not register IRP_SHUTDOWN and call
        // LogIrpShutdownHandler and the system tried to log to a file
        // after a file system was unmounted.
        //
        LogpDbgBreak();
    }

    Status = ZwFlushBuffersFile(Info->LogFileHandle, &IoStatusBlock);

    return Status;
}

// Buffer the log entry to the log buffer.
static
NTSTATUS
LogpBufferMessage(
    IN CONST CHAR* Message,
    IN OUT PLOG_BUFFER_INFO Info
)
{
    NTSTATUS Status;
    KIRQL OldIrql;
    KLOCK_QUEUE_HANDLE LockHandle;
    SIZE_T UsedBufferSize;
    SIZE_T MessageLength;

    //NT_ASSERT( Info != NULL );

    //
    // Acquire a spin lock to add the log safely.
    //
    OldIrql = KeGetCurrentIrql();
    if (OldIrql < DISPATCH_LEVEL)
    {
        KeAcquireInStackQueuedSpinLock(&Info->SpinLock, &LockHandle);
    }
    else
    {
        KeAcquireInStackQueuedSpinLockAtDpcLevel(&Info->SpinLock, &LockHandle);
    }

    NT_ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);

    //
    // Copy the current log to the buffer.
    //
    UsedBufferSize = (SIZE_T)(Info->LogBufferTail - Info->LogBufferHead);
    Status = RtlStringCchCopyA((NTSTRSAFE_PSTR)Info->LogBufferTail,
        LOG_BUFFER_USABLE_SIZE - UsedBufferSize,
        Message);

    //
    // Update Info->LogMaxUsage if necessary.
    //
    if (NT_SUCCESS(Status))
    {

        MessageLength = (SIZE_T)(strlen(Message) + 1);

        Info->LogBufferTail += MessageLength;
        UsedBufferSize += MessageLength;

        if (UsedBufferSize > Info->LogMaxUsage)
        {
            Info->LogMaxUsage = UsedBufferSize;  // Update
        }

    }
    else
    {

        Info->LogMaxUsage = LOG_BUFFER_SIZE;  // Indicates overflow
    }

    *Info->LogBufferTail = '\0';

    //
    // Release the spin lock.
    //
    if (OldIrql < DISPATCH_LEVEL)
    {
        KeReleaseInStackQueuedSpinLock(&LockHandle);
    }
    else
    {
        KeReleaseInStackQueuedSpinLockFromDpcLevel(&LockHandle);
    }

    return Status;
}

// Calls DbgPrintEx while converting \r\n to \n\0
static
VOID
LogpDoDbgPrint(
    IN CHAR* Message
)
{
    UNREFERENCED_PARAMETER(Message);
    /*size_t LocationOfCr;
    LocationOfCr = strlen(Message) - 2;
    Message[LocationOfCr] = '\n';
    Message[LocationOfCr + 1] = '\0';
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", Message);*/
}

// Returns true when a log file is enabled.
FORCEINLINE
BOOLEAN
LogpIsLogFileEnabled(
    IN CONST LOG_BUFFER_INFO* Info
)
{
    if (Info->LogBuffer1 != NULL)
    {
        NT_ASSERT(Info->LogBuffer2 != NULL);
        NT_ASSERT(Info->LogBufferHead != NULL);
        NT_ASSERT(Info->LogBufferTail != NULL);
        return TRUE;
    }

    NT_ASSERT(!Info->LogBuffer2);
    NT_ASSERT(!Info->LogBufferHead);
    NT_ASSERT(!Info->LogBufferTail);
    return FALSE;
}

// Returns true when a log file is opened.
static
BOOLEAN
LogpIsLogFileActivated(
    IN CONST LOG_BUFFER_INFO* Info
)
{
    if (Info->BufferFlushThreadShouldBeAlive)
    {
        NT_ASSERT(Info->BufferFlushThreadHandle != NULL);
        NT_ASSERT(Info->LogFileHandle != NULL);
        return TRUE;
    }

    NT_ASSERT(!Info->BufferFlushThreadHandle);
    NT_ASSERT(!Info->LogFileHandle);
    return FALSE;
}

// Returns true when logging is necessary according to the log's severity and
// a set log level.
static
BOOLEAN
LogpIsLogNeeded(
    IN ULONG Level
)
{
    return (BOOLEAN)((LogFlags & Level) != 0);
}

// A thread runs as long as Info.BufferFlushThreadShouldBeAlive is true and
// flushes a log buffer to a log file every kLogpLogFlushIntervalMsec msec.
static
VOID
LogpBufferFlushThreadRoutine(
    IN PVOID StartContext
)
{
    NTSTATUS Status;
    LARGE_INTEGER Interval;
    PLOG_BUFFER_INFO Info;

    PAGED_CODE();

    Status = STATUS_SUCCESS;
    Info = (PLOG_BUFFER_INFO)StartContext;
    Info->BufferFlushThreadStarted = TRUE;

#if defined(DBG)
    LOG_DEBUG("Log thread started (TID=%x)", (ULONG)(ULONG_PTR)PsGetCurrentThreadId());
#endif

    while (Info->BufferFlushThreadShouldBeAlive)
    {
        NT_ASSERT(LogpIsLogFileActivated(Info));

        if (Info->LogBufferHead[0])
        {
            NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
            NT_ASSERT(!KeAreAllApcsDisabled());

            Status = LogpFlushLogBuffer(Info);

            //
            // Do not flush the file for overall performance. Even a case of bug check,
            // we should be able to recover logs by looking at both log buffers!
            //
        }

        //
        // Sleep the current thread's execution for LOG_FLUSH_INTERVAL milliseconds.
        //
        Interval.QuadPart = -(LOG_FLUSH_INTERVAL * 1000 * 10);
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }

    PsTerminateSystemThread(Status);
}

// Determines if a specified file path exists.
static
BOOLEAN
LogpFileExists(
    IN PUNICODE_STRING FilePath
)
{
    NTSTATUS Status;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, FilePath, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwCreateFile(&FileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &ObjectAttributes,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (NT_SUCCESS(Status))
    {
        ZwClose(FileHandle);
        return TRUE;
    }

    return FALSE;
}

// Sets a break point that works only when windbg is present
static
VOID
LogpDbgBreak(
    VOID
)
{
    if (!KD_DEBUGGER_NOT_PRESENT)
    {
        __debugbreak();
    }
}

#endif // ENABLE_LOG