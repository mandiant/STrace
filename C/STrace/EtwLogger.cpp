#include "EtwLogger.h"

#include "vector.h"

#define va_copy(dest, src) (dest = src)

// Cache of all created providers.
MyVector<detail::EtwProvider> g_ProviderCache;

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

namespace detail
{

EtwProvider::EtwProvider(LPCGUID providerGuid) : m_guid{ providerGuid }, m_regHandle{}, m_providerMetadataDesc{}
{
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

void EtwProvider::Destruct()
{
	if (m_regHandle != 0)
	{
		EtwUnregister(m_regHandle);
	}

	if (m_providerMetadataDesc.Ptr != NULL)
	{
		ExFreePool((PVOID)m_providerMetadataDesc.Ptr);
	}
}

NTSTATUS EtwProvider::WriteEvent(PCEVENT_DESCRIPTOR eventDescriptor, ULONG numberOfDescriptors, PEVENT_DATA_DESCRIPTOR descriptors) const
{
	return EtwWrite(m_regHandle, eventDescriptor, NULL, numberOfDescriptors, descriptors);
}

LPCGUID EtwProvider::Guid() const noexcept
{
	return m_guid;
}

EVENT_DATA_DESCRIPTOR EtwProvider::ProviderMetadataDescriptor() const noexcept
{
	return m_providerMetadataDesc;
}

} // namespace detail

struct EventMetadata
{
	uint16_t TotalLength;
	uint8_t Tag;
	char EventName[ANYSIZE_ARRAY];
};

__declspec(noinline) EVENT_DATA_DESCRIPTOR CreateEventMetadata(const char* eventName, int numberOfFields, va_list args)
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
	//     * a single byte for the type.
	const auto eventMetadataHeaderLength = strlen(eventName) + 1 + sizeof(uint16_t) + sizeof(uint8_t);

	// Calculate the total size to allocate for the event metadata - the size
	// of the header plus the sum of length of each field name and the type byte.
	va_list args2;
	va_copy(args2, args);
	auto eventMetadataLength = (uint16_t)eventMetadataHeaderLength;
	for (auto i = 0; i < numberOfFields; i++)
	{
		const auto fieldName = va_arg(args2, const char*);
		eventMetadataLength += (uint16_t)(strlen(fieldName) + 1 + sizeof(uint8_t));
		va_arg(args2, int);
		va_arg(args2, void*);
	}
	va_end(args2);

	const auto eventMetadata = (struct EventMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, eventMetadataLength, 'wteE');
	if (eventMetadata == NULL)
	{
		return EVENT_DATA_DESCRIPTOR{};
	}

	memset(eventMetadata, 0, eventMetadataLength);

	// Set the first three fields, metadata about the event.
	eventMetadata->TotalLength = eventMetadataLength;
	eventMetadata->Tag = 0;
	strcpy(eventMetadata->EventName, eventName);

	// Set the metadata for each field.
	char* currentLocation = ((char*)eventMetadata) + eventMetadataHeaderLength;
	va_copy(args2, args);
	for (auto i = 0; i < numberOfFields; i++)
	{
		const auto fieldName = va_arg(args2, const char*);
		const auto fieldType = va_arg(args2, int);
		va_arg(args2, void*);

		strcpy(currentLocation, fieldName);
		currentLocation[strlen(fieldName) + 1] = (uint8_t)fieldType;

		currentLocation += strlen(fieldName) + 1 + sizeof(uint8_t);
	}
	va_end(args2);

	// Create an EVENT_DATA_DESCRIPTOR pointing to the metadata.
	EVENT_DATA_DESCRIPTOR eventMetadataDesc;
	EventDataDescCreate(&eventMetadataDesc, eventMetadata, eventMetadata->TotalLength);
	eventMetadataDesc.Type = EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA;  // Descriptor contains event metadata.

	return eventMetadataDesc;
}

detail::EtwProvider* FindProvider(LPCGUID providerGuid)
{
	for (auto i = 0; i < g_ProviderCache.len(); i++)
	{
		if ((g_ProviderCache[i].Guid()->Data1 == providerGuid->Data1) &&
			(g_ProviderCache[i].Guid()->Data2 == providerGuid->Data2) &&
			(g_ProviderCache[i].Guid()->Data3 == providerGuid->Data3) &&
			(g_ProviderCache[i].Guid()->Data4[0] == providerGuid->Data4[0]) &&
			(g_ProviderCache[i].Guid()->Data4[1] == providerGuid->Data4[1]) &&
			(g_ProviderCache[i].Guid()->Data4[2] == providerGuid->Data4[2]) &&
			(g_ProviderCache[i].Guid()->Data4[3] == providerGuid->Data4[3]) &&
			(g_ProviderCache[i].Guid()->Data4[4] == providerGuid->Data4[4]) &&
			(g_ProviderCache[i].Guid()->Data4[5] == providerGuid->Data4[5]) &&
			(g_ProviderCache[i].Guid()->Data4[6] == providerGuid->Data4[6]) &&
			(g_ProviderCache[i].Guid()->Data4[7] == providerGuid->Data4[7]))
		{
			return &g_ProviderCache[i];
		}
	}

	return NULL;
}

__declspec(noinline) size_t SizeOfField(int fieldType, void* fieldValue)
{
	size_t sizeOfField = 0;

	switch (fieldType & 0x000000FF)
	{
	case EtwFieldAnsiString:
		sizeOfField = strlen((char*)fieldValue) + 1;
		break;
	case EtwFieldInt8:
		sizeOfField = sizeof(int8_t);
		break;
	case EtwFieldUInt8:
		sizeOfField = sizeof(uint8_t);
		break;
	case EtwFieldInt16:
		sizeOfField = sizeof(int16_t);
		break;
	case EtwFieldUInt16:
		sizeOfField = sizeof(uint16_t);
		break;
	case EtwFieldInt32:
		sizeOfField = sizeof(int32_t);
		break;
	case EtwFieldUInt32:
		sizeOfField = sizeof(uint32_t);
		break;
	case EtwFieldInt64:
		sizeOfField = sizeof(int64_t);
		break;
	case EtwFieldUInt64:
		sizeOfField = sizeof(uint64_t);
		break;
	case EtwFieldFloat:
		sizeOfField = sizeof(float);
		break;
	case EtwFieldDouble:
		sizeOfField = sizeof(double);
		break;
	case EtwFieldBool32:
		sizeOfField = 4;
		break;
	case EtwFieldGuid:
		sizeOfField = sizeof(GUID);
		break;
	// TODO: more fields
	default:
		sizeOfField = 0;
		break;
	}

	return sizeOfField;
}

__declspec(noinline) EVENT_DATA_DESCRIPTOR CreateTraceProperty(int fieldType, void* fieldValue)
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

__declspec(noinline) EVENT_DESCRIPTOR CreateEventDescriptor(uint64_t keyword, uint8_t level)
{
	EVENT_DESCRIPTOR desc;
	memset(&desc, 0, sizeof(EVENT_DESCRIPTOR));
	desc.Channel = 11;  // All "manifest-free" events should go to channel 11 by default
	desc.Keyword = keyword;
	desc.Level = level;

	return desc;
}

__declspec(noinline) void Cleanup(PEVENT_DATA_DESCRIPTOR eventDescriptors, int numberOfDescriptors)
{
	if (eventDescriptors != NULL)
	{
		for (int i = 1 /* skip the first descriptor */; i < numberOfDescriptors; i++)
		{
			if (eventDescriptors[i].Ptr != NULL)
			{
				ExFreePool((PVOID)eventDescriptors[i].Ptr);
			}
		}

		ExFreePool(eventDescriptors);
	}
}

NTSTATUS EtwTrace(
	const char* providerName,
	const GUID* providerGuid,
	const char* eventName,
	uint8_t eventLevel,
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
		detail::EtwProvider newEtwProvider{ providerGuid };
		const auto status = newEtwProvider.Initialize(providerName);
		if (status != STATUS_SUCCESS)
		{
			return status;
		}

		g_ProviderCache.push_back(newEtwProvider);
		etwProvider = &g_ProviderCache.back();
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

	// Create the provider metadata descriptor, and tell the provider to use the
	// metadata given by the descriptor.
	dataDescriptors[0] = etwProvider->ProviderMetadataDescriptor();

	// Create the event metadata descriptor.
	va_list args;
	va_start(args, numberOfFields);
	dataDescriptors[1] = CreateEventMetadata(eventName, numberOfFields, args);
	if (dataDescriptors[1].Ptr == NULL)
	{
		Cleanup(dataDescriptors, numberOfDescriptors);
		return STATUS_UNSUCCESSFUL;
	}
	va_end(args);

	// Create a descriptor for each individual field.
	va_list args2;
	va_start(args2, numberOfFields);
	for (auto i = 0; i < numberOfFields; i++)
	{
		va_arg(args2, const char*);
		const auto fieldType = va_arg(args2, int);
		auto fieldValue = va_arg(args2, size_t);

		dataDescriptors[i + 2] = CreateTraceProperty(
			fieldType,
			fieldType != EtwFieldAnsiString ? &fieldValue : (void*)fieldValue);
		if (dataDescriptors[i + 2].Ptr == NULL)
		{
			Cleanup(dataDescriptors, numberOfDescriptors);
			return STATUS_UNSUCCESSFUL;
		}
	}
	va_end(args2);

	// Create the top-level event descriptor.
	const auto eventDesc = CreateEventDescriptor(keyword, eventLevel);

	// Write the event.
	const auto status = etwProvider->WriteEvent(&eventDesc, numberOfDescriptors, dataDescriptors);

	// Unregister the event and deallocate memory.
	Cleanup(dataDescriptors, numberOfDescriptors);

	return status;
}