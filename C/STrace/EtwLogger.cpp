#include "EtwLogger.h"

#include "vector.h"

#define va_copy(dest, src) (dest = src)

// Cache of all created providers.
MyVector<detail::EtwProvider> g_ProviderCache;

#pragma region ETW_FIELD_TYPE

// ETW field type definitions, see TlgIn_t and TlgOut_t in TraceLoggingProvider.h
#define ETW_FIELD(in, out)  (in | 0x80 | out << 8)
#define ETW_FIELD_HAS_OUT_TYPE(field) ((field & 0x80) == 0x80)
#define ETW_IN_TYPE(field) (field & 0xFF)
#define ETW_OUT_TYPE(field) ((field & 0xFF00) >> 8)

typedef enum _ETW_IN_FIELD_TYPE
{
	EtwInNull,
	EtwInUnicodeString,
	EtwInAnsiString,
	EtwInInt8,
	EtwInUInt8,
	EtwInInt16,
	EtwInUInt16,
	EtwInInt32,
	EtwInUInt32,
	EtwInInt64,
	EtwInUInt64,
	EtwInFloat,
	EtwInDouble,
	EtwInBool32,
	EtwInBinary,
	EtwInGuid,
	EtwInPointer,
	EtwInFiletime,
	EtwInSystemTime,
	EtwInSid,
	EtwInHexInt32,
	EtwInHexInt64,
	EtwInCountedString,
	EtwInCountedAnsiString,
} ETW_IN_FIELD_TYPE;

typedef enum _ETW_OUT_FIELD_TYPE
{
	EtwOutNull,
	EtwOutNoPrint,
	EtwOutString,
	EtwOutBoolean,
	EtwOutHex,
	EtwOutPid,
	EtwOutTid,
	EtwOutPort,
	EtwOutIpV4,
	EtwOutIpV6,
	EtwOutSocketAddress,
	EtwOutXml,
	EtwOutJson,
	EtwOutWin32Error,
	EtwOutNtstatus,
	EtwOutHresult,
	EtwOutFiletime,
	EtwOutSigned,
	EtwOutUnsigned,
} ETW_OUT_FIELD_TYPE;

typedef enum _ETW_FIELD_TYPE
{
	EtwFieldInt8 = EtwInInt8,
	EtwFieldUInt8 = EtwInUInt8,
	EtwFieldInt16 = EtwInInt16,
	EtwFieldUInt16 = EtwInUInt16,
	EtwFieldInt32 = EtwInInt32,
	EtwFieldUInt32 = EtwInUInt32,
	EtwFieldInt64 = EtwInInt64,
	EtwFieldUInt64 = EtwInUInt64,
	EtwFieldFloat32 = EtwInFloat,
	EtwFieldFloat64 = EtwInDouble,
	EtwFieldBool = EtwInBool32,
	EtwFieldGuid = EtwInGuid,
	EtwFieldPointer = EtwInPointer,
	EtwFieldFiletime = EtwInFiletime,
	EtwFieldSystemTime = EtwInSystemTime,
	EtwFieldHexInt8 = ETW_FIELD(EtwInUInt8, EtwOutHex),
	EtwFieldHexUInt8 = ETW_FIELD(EtwInUInt8, EtwOutHex),
	EtwFieldHexInt32 = EtwInHexInt32,
	EtwFieldHexUInt32 = EtwInHexInt32,
	EtwFieldHexInt64 = EtwInHexInt64,
	EtwFieldHexUInt64 = EtwInHexInt64,
	EtwFieldWChar = ETW_FIELD(EtwInUInt16, EtwOutString),
	EtwFieldChar = ETW_FIELD(EtwInUInt8, EtwOutString),
	EtwFieldBoolean = ETW_FIELD(EtwInUInt8, EtwOutBoolean),
	EtwFieldHexInt16 = ETW_FIELD(EtwInUInt16, EtwOutHex),
	EtwFieldHexUInt16 = ETW_FIELD(EtwInUInt16, EtwOutHex),
	EtwFieldPid = ETW_FIELD(EtwInUInt32, EtwOutPid),
	EtwFieldTid = ETW_FIELD(EtwInUInt32, EtwOutTid),
	EtwFieldPort = ETW_FIELD(EtwInUInt16, EtwOutPort),
	EtwFieldWinError = ETW_FIELD(EtwInUInt32, EtwOutWin32Error),
	EtwFieldNtstatus = ETW_FIELD(EtwInUInt32, EtwOutNtstatus),
	EtwFieldHresult = ETW_FIELD(EtwInInt32, EtwOutHresult),
	EtwFieldString = EtwInAnsiString,
	EtwFieldWideString = EtwInUnicodeString,
	EtwFieldCountedString = EtwInCountedAnsiString,
	EtwFieldCountedWideString = EtwFieldCountedString,
	EtwFieldAnsiString = EtwInCountedAnsiString,
	EtwFieldUnicodeString = EtwInCountedString,
	EtwFieldBinary = EtwInBinary,
	EtwFieldSocketAddress = ETW_FIELD(EtwInBinary, EtwOutSocketAddress),
	EtwFieldSid = EtwInSid,
} ETW_FIELD_TYPE;

#pragma endregion

namespace detail
{

#pragma region EtwProvider

EtwProvider::EtwProvider(LPCGUID providerGuid) : m_guid(providerGuid), m_regHandle(), m_providerMetadataDesc(), m_events()
{
}

EtwProvider::EtwProvider(EtwProvider&& other)
{
	m_guid = other.m_guid;
	m_regHandle = other.m_regHandle;
	m_providerMetadataDesc = other.m_providerMetadataDesc;
	m_events = move(other.m_events);
}

EtwProvider& EtwProvider::operator=(EtwProvider&& other)
{
	m_guid = other.m_guid;
	m_regHandle = other.m_regHandle;
	m_providerMetadataDesc = other.m_providerMetadataDesc;
	m_events = move(other.m_events);

	return *this;
}

NTSTATUS EtwProvider::Initialize(const char* providerName)
{
	// Register the kernel-mode ETW provider.
	auto status = EtwRegister(m_guid, NULL, NULL, &m_regHandle);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	// Create packaged provider metadata structure.
	// <https://learn.microsoft.com/en-us/windows/win32/etw/provider-traits>
	const auto providerMetadataLength = (uint16_t)((strlen(providerName) + 1) + sizeof(uint16_t));
	const auto providerMetadata = (struct ProviderMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, providerMetadataLength, 'wteO');
	if (providerMetadata == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	memset(providerMetadata, 0, providerMetadataLength);
	providerMetadata->TotalLength = providerMetadataLength;
	strcpy(providerMetadata->ProviderName, providerName);

	// Tell the provider to use the metadata structure.
	status = EtwSetInformation(m_regHandle, EventProviderSetTraits, providerMetadata, providerMetadataLength);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	// Create an EVENT_DATA_DESCRIPTOR pointing to the metadata.
	EventDataDescCreate(&m_providerMetadataDesc, providerMetadata, providerMetadata->TotalLength);
	m_providerMetadataDesc.Type = EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA;  // Descriptor contains provider metadata.

	return STATUS_SUCCESS;
}

EtwProvider::~EtwProvider()
{
	m_events.Destruct();

	if (m_regHandle != 0)
	{
		EtwUnregister(m_regHandle);
	}

	if (m_providerMetadataDesc.Ptr != NULL)
	{
		ExFreePool((PVOID)m_providerMetadataDesc.Ptr);
		m_providerMetadataDesc.Ptr = NULL;
	}
}

NTSTATUS EtwProvider::AddEvent(const char* eventName, int numberOfFields, va_list fields)
{
	auto status = STATUS_SUCCESS;

	if (FindEvent(eventName) == NULL)
	{
		EtwProviderEvent event;
		status = event.Initialize(eventName, numberOfFields, fields);
		if (status != STATUS_SUCCESS)
		{
			return status;
		}
		m_events.push_back(move(event));
	}

	return status;
}

NTSTATUS EtwProvider::WriteEvent(const char* eventName, uint8_t eventLevel, uint8_t eventChannel, uint64_t keyword, int numberOfFields, va_list fields)
{
	// Find the event to use.
	const auto event = FindEvent(eventName);
	if (event == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	// Allocate space for the data descriptors, including two additional slots
	// for provider and event metadata.
	const auto numberOfDescriptors = numberOfFields + 2;
	const auto allocSize = numberOfDescriptors * sizeof(EVENT_DATA_DESCRIPTOR);
	const auto dataDescriptors = (PEVENT_DATA_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, 'wteP');
	if (dataDescriptors == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	memset(dataDescriptors, 0, allocSize);

	// Set the provider and event metadata descriptors.
	dataDescriptors[0] = m_providerMetadataDesc;
	dataDescriptors[1] = event->MetadataDescriptor();

	// Create a descriptor for each individual field.
	va_list args;
	va_copy(args, fields);
	for (auto i = 0; i < numberOfFields; i++)
	{
		va_arg(args, const char*);
		const auto fieldType = va_arg(args, ETW_FIELD_TYPE);
		const auto fieldValue = va_arg(args, size_t);

		dataDescriptors[i + 2] = CreateTraceProperty(fieldType, GetFieldAddress(fieldType, fieldValue));
		if (dataDescriptors[i + 2].Ptr == NULL)
		{
			va_end(args);
			return STATUS_UNSUCCESSFUL;
		}
	}
	va_end(args);

	// Create the event descriptor.
	EVENT_DESCRIPTOR eventDescriptor;
	memset(&eventDescriptor, 0, sizeof(EVENT_DESCRIPTOR));
	eventDescriptor.Channel = eventChannel;
	eventDescriptor.Keyword = keyword;
	eventDescriptor.Level = eventLevel;

	// Write the event.
	const auto status = EtwWrite(m_regHandle, &eventDescriptor, NULL, numberOfDescriptors, dataDescriptors);

	// Free the memory allocated for the event fields.
	for (auto i = 2; i < numberOfDescriptors; i++)
	{
		if (dataDescriptors[i].Ptr) {
			ExFreePool((PVOID)dataDescriptors[i].Ptr);
			dataDescriptors[i].Ptr = NULL;
		}
	}
	ExFreePool(dataDescriptors);

	return status;
}

LPCGUID EtwProvider::Guid() const
{
	return m_guid;
}

EtwProviderEvent* EtwProvider::FindEvent(const char* eventName)
{
	for (auto i = 0; i < m_events.len(); i++)
	{
		if (strcmp(eventName, m_events[i].Name()) == 0)
		{
			return &m_events[i];
		}
	}

	return NULL;
}

size_t EtwProvider::SizeOfField(ETW_FIELD_TYPE fieldType, char* fieldValue)
{
	size_t sizeOfField = 0;

	// Size is determined by the in type, see TraceLoggingProvider.h#L1773
	// (as of SDK 10.0.14393.0).
	switch (ETW_IN_TYPE(fieldType) & 0x7f)
	{
	case EtwInNull:
		sizeOfField = 0;
		break;
	case EtwInUnicodeString:
		sizeOfField = (wcslen((wchar_t*)fieldValue) + 1) * sizeof(wchar_t);
		break;
	case EtwInAnsiString:
		sizeOfField = strlen(fieldValue) + 1;
		break;
	case EtwInInt8:
		sizeOfField = sizeof(int8_t);
		break;
	case EtwInUInt8:
		sizeOfField = sizeof(uint8_t);
		break;
	case EtwInInt16:
		sizeOfField = sizeof(int16_t);
		break;
	case EtwInUInt16:
		sizeOfField = sizeof(uint16_t);
		break;
	case EtwInInt32:
		sizeOfField = sizeof(int32_t);
		break;
	case EtwInUInt32:
		sizeOfField = sizeof(uint32_t);
		break;
	case EtwInInt64:
		sizeOfField = sizeof(int64_t);
		break;
	case EtwInUInt64:
		sizeOfField = sizeof(uint64_t);
		break;
	case EtwInFloat:
		sizeOfField = sizeof(float);
		break;
	case EtwInDouble:
		sizeOfField = sizeof(double);
		break;
	case EtwInBool32:
		sizeOfField = sizeof(int32_t);
		break;
	case EtwInGuid:
		sizeOfField = sizeof(GUID);
		break;
	case EtwInFiletime:
		sizeOfField = sizeof(DWORD) * 2;
		break;
	case EtwInSystemTime:
		sizeOfField = sizeof(uint16_t) * 8;
		break;
	case EtwInSid:
		sizeOfField = sizeof(SID);
		break;
	case EtwInHexInt32:
		sizeOfField = sizeof(int32_t);
		break;
	case EtwInHexInt64:
		sizeOfField = sizeof(int64_t);
		break;
	case EtwInCountedString:
		sizeOfField = ((PUNICODE_STRING)fieldValue)->Length;
		break;
	case EtwInCountedAnsiString:
		sizeOfField = ((PSTRING)fieldValue)->Length;
		break;
	default:
		sizeOfField = 0;
		break;
	}

	return sizeOfField;
}

char* EtwProvider::GetFieldAddress(ETW_FIELD_TYPE fieldType, const size_t& fieldValue)
{
	// Get the address of the field value for the field's descriptor.
	//
	// Scalar values are provided as-is, so we want to the address of them,
	// whereas string values already come through as pointers to the value.
	switch (ETW_IN_TYPE(fieldType))
	{
	case EtwInAnsiString:
	case EtwInUnicodeString:
		return (char*)fieldValue;
	case EtwInCountedAnsiString:
		return (char*)(((PSTRING)fieldValue)->Buffer);
	case EtwInCountedString:
		return (char*)(((PUNICODE_STRING)fieldValue)->Buffer);
	default:
		return (char*)&fieldValue;
	}
}

EVENT_DATA_DESCRIPTOR EtwProvider::CreateTraceProperty(ETW_FIELD_TYPE fieldType, char* fieldValue)
{
	// Copy the input value to its own space.
	EVENT_DATA_DESCRIPTOR fieldDesc;
	memset(&fieldDesc, 0, sizeof(EVENT_DATA_DESCRIPTOR));

	const auto fieldSize = SizeOfField(fieldType, fieldValue);
	const auto newSpace = ExAllocatePoolWithTag(NonPagedPoolNx, fieldSize, 'wteE');
	if (newSpace == NULL)
	{
		return fieldDesc;
	}
	memcpy(newSpace, fieldValue, fieldSize);

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(&fieldDesc, newSpace, (ULONG)fieldSize);

	return fieldDesc;
}

#pragma endregion

#pragma region EtwProviderEvent

EtwProviderEvent::EtwProviderEvent() : m_eventMetadataDesc()
{
}

NTSTATUS EtwProviderEvent::Initialize(const char* eventName, int numberOfFields, va_list fields)
{
	// Allocate the total size of the event metadata structure.
	//
	// This consists of, in order:
	//
	// * The total length of the structure
	// * The event tag byte (currently always 0)
	// * The name of the event
	// * An array of field metadata structures, which are:
	//     * the name of the field
	//     * a single byte for the in type
	//     * an optional byte for the out type, if defined
	const auto eventMetadataHeaderLength = strlen(eventName) + 1 + sizeof(uint16_t) + sizeof(uint8_t);

	// Calculate the total size to allocate for the event metadata - the size
	// of the header plus the sum of length of each field name and the type byte(s).
	va_list args;
	va_copy(args, fields);
	auto eventMetadataLength = (uint16_t)eventMetadataHeaderLength;
	for (auto i = 0; i < numberOfFields; i++)
	{
		const auto fieldName = va_arg(args, const char*);
		eventMetadataLength += (uint16_t)(strlen(fieldName) + 1);

		// If the field has an out type, then we need an additional byte for that.
		eventMetadataLength += sizeof(uint8_t);
		const auto fieldType = va_arg(args, ETW_FIELD_TYPE);
		if (ETW_FIELD_HAS_OUT_TYPE(fieldType))
		{
			eventMetadataLength += sizeof(uint8_t);
		}

		va_arg(args, char*);
	}
	va_end(args);

	const auto eventMetadata = (struct EventMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, eventMetadataLength, 'wteE');
	if (eventMetadata == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	memset(eventMetadata, 0, eventMetadataLength);

	// Set the first three fields, metadata about the event.
	eventMetadata->TotalLength = eventMetadataLength;
	eventMetadata->Tag = 0;
	strcpy(eventMetadata->EventName, eventName);

	// Set the metadata for each field.
	char* currentLocation = ((char*)eventMetadata) + eventMetadataHeaderLength;
	va_copy(args, fields);
	for (auto i = 0; i < numberOfFields; i++)
	{
		const auto fieldName = va_arg(args, const char*);
		const auto fieldType = va_arg(args, ETW_FIELD_TYPE);
		va_arg(args, char*);

		// Copy the field name to the start of the metadata entry.
		strcpy(currentLocation, fieldName);
		currentLocation += strlen(fieldName) + 1;

		// Set the type byte(s). The in type is always set, the out type
		// is only set if it is defined.
		*currentLocation = ETW_IN_TYPE(fieldType);
		++currentLocation;
		if (ETW_FIELD_HAS_OUT_TYPE(fieldType))
		{
			*currentLocation = ETW_OUT_TYPE(fieldType);
			++currentLocation;
		}
	}
	va_end(args);

	// Create an EVENT_DATA_DESCRIPTOR pointing to the metadata.
	EventDataDescCreate(&m_eventMetadataDesc, eventMetadata, eventMetadata->TotalLength);
	m_eventMetadataDesc.Type = EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA;  // Descriptor contains event metadata.

	return STATUS_SUCCESS;
}

EtwProviderEvent::~EtwProviderEvent()
{
	if (m_eventMetadataDesc.Ptr != NULL)
	{
		ExFreePool((PVOID)m_eventMetadataDesc.Ptr);
		m_eventMetadataDesc.Ptr = NULL;
	}
}

const char* EtwProviderEvent::Name() const
{
	return ((EventMetadata*)m_eventMetadataDesc.Ptr)->EventName;
}

EVENT_DATA_DESCRIPTOR EtwProviderEvent::MetadataDescriptor() const
{
	return m_eventMetadataDesc;
}

#pragma endregion

} // namespace detail

detail::EtwProvider* FindProvider(LPCGUID providerGuid)
{
	for (auto i = 0; i < g_ProviderCache.len(); i++)
	{
		if (memcmp(providerGuid, g_ProviderCache[i].Guid(), sizeof(GUID)) == 0)
		{
			return &g_ProviderCache[i];
		}
	}

	return NULL;
}

NTSTATUS EtwTrace(
	const char* providerName,
	const GUID* providerGuid,
	const char* eventName,
	uint8_t eventLevel,
	uint8_t eventChannel,
	uint64_t keyword,
	int numberOfFields,
	...
)
{
	// It is unsafe to call EtwRegister() at higher than PASSIVE_LEVEL
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	// If we have already made a provider with the given GUID, get it out of the
	// cache, otherwise create and register a new provider with the name and GUID.
	auto etwProvider = FindProvider(providerGuid);
	if (etwProvider == NULL)
	{
		// emplace so we don't call dtor on a temporary
		g_ProviderCache.emplace_back(providerGuid);
		etwProvider = &g_ProviderCache.back();

		// initialize the class here
		const auto status = etwProvider->Initialize(providerName);
		if (status != STATUS_SUCCESS)
		{
			// oof failed, remove paritally init'd object
			g_ProviderCache.pop_back();
			return status;
		}
	}

	// Add the event to the provider.
	va_list args;
	va_start(args, numberOfFields);
	auto status = etwProvider->AddEvent(eventName, numberOfFields, args);
	va_end(args);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	// Write the event.
	va_list args2;
	va_start(args2, numberOfFields);
	status = etwProvider->WriteEvent(eventName, eventLevel, eventChannel, keyword, numberOfFields, args2);
	va_end(args2);

	return status;
}