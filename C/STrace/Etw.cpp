#include "Etw.h"

constexpr LPCWSTR ETW_SESSION_NAME = L"DTraceLoggingSession";
constexpr GUID ETW_SESSION_GUID = { 0x11111111, 0x2222, 0x3333, { 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 } };

PEVENT_TRACE_PROPERTIES_V2 AllocEventProperties();

/**
Format of a message to subscribe a provider to a session.
**/
constexpr size_t SubscribeProviderMessagePayloadSize = 0x78;
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
    unsigned char Payload[88];
} SubscribeProviderMessage;

NTSTATUS EtwStartTracingSession(OUT TRACEHANDLE* pTraceHandle)
{
    PEVENT_TRACE_PROPERTIES_V2 eventProperties = AllocEventProperties();
    if (eventProperties == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    ULONG returnSize = 0;
    NTSTATUS status = ZwTraceControl(EtwpStartTrace, eventProperties, eventProperties->Wnode.BufferSize, eventProperties, eventProperties->Wnode.BufferSize, &returnSize);
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
    NTSTATUS status = ZwTraceControl(EtwpStopTrace, eventProperties, eventProperties->Wnode.BufferSize, eventProperties, eventProperties->Wnode.BufferSize, &returnSize);
    ExFreePool(eventProperties);
    return status;
}

NTSTATUS EtwAddProviderToTracingSession(TRACEHANDLE TraceHandle, GUID ProviderGuid)
{
    SubscribeProviderMessage notification;
    memset(&notification, 0, sizeof(SubscribeProviderMessage));
    notification.Header.NotificationType = EtwNotificationTypeEnable;
    notification.Header.NotificationSize = SubscribeProviderMessagePayloadSize;
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
        SubscribeProviderMessagePayloadSize,
        &notification,
        sizeof(ETW_NOTIFICATION_HEADER),
        &returnSize
    );
}

PEVENT_TRACE_PROPERTIES_V2 AllocEventProperties()
{
    SIZE_T eventPropertiesSize = sizeof(EVENT_TRACE_PROPERTIES_V2) + sizeof(UNICODE_STRING) + (wcslen(ETW_SESSION_NAME) * 2);
    PEVENT_TRACE_PROPERTIES_V2 eventProperties = (PEVENT_TRACE_PROPERTIES_V2)ExAllocatePool2(POOL_FLAG_NON_PAGED, eventPropertiesSize, 'wteS');
    if (!eventProperties) {
        return NULL;
    }

    eventProperties->Wnode.BufferSize = 0xB0;
    eventProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    eventProperties->Wnode.Guid = ETW_SESSION_GUID;
    eventProperties->LogFileMode = EVENT_TRACE_INDEPENDENT_SESSION_MODE | EVENT_TRACE_BUFFERING_MODE;
    eventProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES_V2) + sizeof(UNICODE_STRING);

    // nt!EtwpCaptureString seems to expect a UNICODE_STRING?
    // This is not documented anywhere, MSDN says this should just be the null-terminated wide string
    UNICODE_STRING loggerName;
    loggerName.Length = (USHORT)(wcslen(ETW_SESSION_NAME) * 2);
    loggerName.MaximumLength = (USHORT)(wcslen(ETW_SESSION_NAME) * 2);
    loggerName.Buffer = (wchar_t*)(((PUCHAR)eventProperties) + eventProperties->LoggerNameOffset);
    memcpy((wchar_t*)(((PUCHAR)eventProperties) + sizeof(EVENT_TRACE_PROPERTIES_V2)), &loggerName, sizeof(UNICODE_STRING));
    wcscpy(loggerName.Buffer, ETW_SESSION_NAME);

    return eventProperties;
}