#include "Etw.h"

constexpr LPCWSTR ETW_SESSION_NAME = L"DTraceLoggingSession";
constexpr GUID ETW_SESSION_GUID = { 0xabe4e548, 0x7c7d, 0x456e, { 0x98, 0x5a, 0x67, 0xfa, 0xa5, 0x19, 0xbb, 0xf7 } };  // {ABE4E548-7C7D-456E-985A-67FAA519BBF7}

PEVENT_TRACE_PROPERTIES_V2 AllocEventProperties();

/**
Format of a message to subscribe a provider to a session.
**/
typedef struct _SubscribeProviderMessage
{
    ETW_NOTIFICATION_HEADER Header;
    ULONG ControlCode;
    UCHAR Level;
    UCHAR field_4D;
    USHORT TraceHandle;
    ULONG EnableProperty;
    ULONG field_54;
    ULONGLONG MatchAnyKeyword;
    ULONGLONG MatchAllKeyword;
    UCHAR Unknown[16];
} SubscribeProviderMessage;

NTSTATUS EtwStartTracingSession(OUT TRACEHANDLE* pTraceHandle)
{
    PEVENT_TRACE_PROPERTIES_V2 eventProperties = AllocEventProperties();
    if (eventProperties == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    ULONG returnSize = 0;
    NTSTATUS status = ZwTraceControl(
        EtwpStartTrace,
        eventProperties,
        eventProperties->Wnode.BufferSize,
        eventProperties,
        eventProperties->Wnode.BufferSize,
        &returnSize
    );
    if (status == STATUS_SUCCESS) {
        *pTraceHandle = eventProperties->Wnode.Version;
    } else {
        *pTraceHandle = NULL;
    }

    ExFreePool(eventProperties);
    return status;
}

NTSTATUS EtwStopTracingSession()
{
    PEVENT_TRACE_PROPERTIES_V2 eventProperties = AllocEventProperties();
    if (eventProperties == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    ULONG returnSize = 0;
    NTSTATUS status = ZwTraceControl(
        EtwpStopTrace,
        eventProperties,
        eventProperties->Wnode.BufferSize,
        eventProperties,
        eventProperties->Wnode.BufferSize,
        &returnSize
    );
    ExFreePool(eventProperties);
    return status;
}

NTSTATUS EtwAddProviderToTracingSession(TRACEHANDLE TraceHandle, GUID ProviderGuid)
{
    SubscribeProviderMessage notification;
    memset(&notification, 0, sizeof(SubscribeProviderMessage));
    notification.Header.NotificationType = EtwNotificationTypeEnable;
    notification.Header.NotificationSize = sizeof(SubscribeProviderMessage);
    notification.Header.DestinationGuid = ProviderGuid;
    notification.Header.Reserved2 = 0x00000000FFFFFFFF;
    notification.ControlCode = EVENT_CONTROL_CODE_ENABLE_PROVIDER;
    notification.Level = TRACE_LEVEL_VERBOSE;
    notification.TraceHandle = (USHORT)(TraceHandle & 0x000000000000FFFF);

    // <https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/control/sendnotification.htm>
    ULONG returnSize = 0;
    return ZwTraceControl(
        EtwpSendNotification,
        &notification,
        notification.Header.NotificationSize,
        &notification,
        sizeof(ETW_NOTIFICATION_HEADER),
        &returnSize
    );
}

PEVENT_TRACE_PROPERTIES_V2 AllocEventProperties()
{
    SIZE_T eventPropertiesSize = sizeof(EVENT_TRACE_PROPERTIES_V2) + sizeof(UNICODE_STRING) + (wcslen(ETW_SESSION_NAME) * 2);
    PEVENT_TRACE_PROPERTIES_V2 eventProperties = (PEVENT_TRACE_PROPERTIES_V2)ExAllocatePoolWithTag(NonPagedPoolNx, eventPropertiesSize, 'wteS');
    if (!eventProperties) {
        return NULL;
    }

    memset(eventProperties, 0, eventPropertiesSize);
    eventProperties->Wnode.BufferSize = 0xB0;
    eventProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    eventProperties->Wnode.Guid = ETW_SESSION_GUID;
    eventProperties->LogFileMode = EVENT_TRACE_INDEPENDENT_SESSION_MODE | EVENT_TRACE_BUFFERING_MODE;
    eventProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES_V2) + sizeof(UNICODE_STRING);

    // nt!EtwpCaptureString seems to expect a UNICODE_STRING?
    // This is not documented anywhere, MSDN says this should just be the null-terminated wide string
    UNICODE_STRING loggerName = {0};
    loggerName.Length = (USHORT)(wcslen(ETW_SESSION_NAME) * 2);
    loggerName.MaximumLength = (USHORT)(wcslen(ETW_SESSION_NAME) * 2);
    loggerName.Buffer = (wchar_t*)(((PUCHAR)eventProperties) + eventProperties->LoggerNameOffset);
    memcpy((wchar_t*)(((PUCHAR)eventProperties) + sizeof(EVENT_TRACE_PROPERTIES_V2)), &loggerName, sizeof(UNICODE_STRING));
    wcscpy(loggerName.Buffer, ETW_SESSION_NAME);

    return eventProperties;
}