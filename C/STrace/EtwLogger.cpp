#include "EtwLogger.h"

#define va_copy(dest, src) (dest = src)

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

struct ProviderMetadata
{
	uint16_t TotalLength;
	char ProviderName[ANYSIZE_ARRAY];
};

struct EventMetadata
{
	uint16_t TotalLength;
	uint8_t Tag;
	char EventName[ANYSIZE_ARRAY];
};

__declspec(noinline) EVENT_DATA_DESCRIPTOR CreateProviderMetadata(const char* providerName)
{
	// Create packaged provider metadata structure.
	// <https://learn.microsoft.com/en-us/windows/win32/etw/provider-traits>
	const auto providerMetadataLength = (uint16_t)((strlen(providerName) + 1) + sizeof(uint16_t));
	const auto providerMetadata = (struct ProviderMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, providerMetadataLength, 'wteO');
	if (providerMetadata == NULL)
	{
		return EVENT_DATA_DESCRIPTOR{};
	}

	RtlSecureZeroMemory(providerMetadata, providerMetadataLength);
	providerMetadata->TotalLength = providerMetadataLength;
	strcpy(providerMetadata->ProviderName, providerName);

	// Create an EVENT_DATA_DESCRIPTOR pointing to the metadata.
	EVENT_DATA_DESCRIPTOR providerMetadataDesc;
	EventDataDescCreate(&providerMetadataDesc, providerMetadata, providerMetadata->TotalLength);
	providerMetadataDesc.Type = EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA;  // Descriptor contains provider metadata.

	return providerMetadataDesc;
}

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

	RtlSecureZeroMemory(eventMetadata, eventMetadataLength);

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

__declspec(noinline) size_t SizeOfField(int fieldType, void* fieldValue)
{
	size_t sizeOfField = 0;

	switch (fieldType)
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
	RtlSecureZeroMemory(&desc, sizeof(EVENT_DESCRIPTOR));
	desc.Channel = 11;  // All "manifest-free" events should go to channel 11 by default
	desc.Keyword = keyword;
	desc.Level = level;

	return desc;
}

__declspec(noinline) void Cleanup(REGHANDLE regHandle = 0, PEVENT_DATA_DESCRIPTOR eventDescriptors = NULL, int numberOfDescriptors = 0)
{
	if (regHandle != 0)
	{
		EtwUnregister(regHandle);
	}

	if (eventDescriptors != NULL)
	{
		for (int i = 0; i < numberOfDescriptors; i++)
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
		return STATUS_NOT_IMPLEMENTED;
	}

	// Register the kernel-mode ETW provider.
	REGHANDLE regHandle = 0;
	NTSTATUS status = EtwRegister(providerGuid, NULL, NULL, OUT & regHandle);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	// Allocate space for the data descriptors, including two additional slots
	// for provider and event metadata.
	const auto numberOfDescriptors = numberOfFields + 2;
	const auto allocSize = numberOfDescriptors * sizeof(EVENT_DATA_DESCRIPTOR);
	const auto dataDescriptors = (PEVENT_DATA_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, 'wteP');
	if (dataDescriptors == NULL)
	{
		Cleanup(regHandle);
		return STATUS_UNSUCCESSFUL;
	}
	RtlSecureZeroMemory(dataDescriptors, allocSize);

	// Create the provider metadata descriptor, and tell the provider to use the
	// metadata given by the descriptor.
	dataDescriptors[0] = CreateProviderMetadata(providerName);
	if (dataDescriptors[0].Ptr == NULL)
	{
		Cleanup(regHandle, dataDescriptors, numberOfDescriptors);
		return STATUS_UNSUCCESSFUL;
	}

	status = EtwSetInformation(regHandle, EventProviderSetTraits, (PVOID)dataDescriptors[0].Ptr, dataDescriptors[0].Size);
	if (status != STATUS_SUCCESS)
	{
		Cleanup(regHandle, dataDescriptors, numberOfDescriptors);
		return status;
	}

	// Create the event metadata descriptor.
	va_list args;
	va_start(args, numberOfFields);
	dataDescriptors[1] = CreateEventMetadata(eventName, numberOfFields, args);
	if (dataDescriptors[1].Ptr == NULL)
	{
		Cleanup(regHandle, dataDescriptors, numberOfDescriptors);
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
			Cleanup(regHandle, dataDescriptors, numberOfDescriptors);
			return STATUS_UNSUCCESSFUL;
		}
	}
	va_end(args2);

	// Create the top-level event descriptor.
	const auto eventDesc = CreateEventDescriptor(keyword, eventLevel);

	// Write the event.
	status = EtwWrite(regHandle, &eventDesc, NULL, numberOfDescriptors, dataDescriptors);

	// Unregister the event and deallocate memory.
	Cleanup(regHandle, dataDescriptors, numberOfDescriptors);

	return status;
}