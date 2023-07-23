#pragma once
#include "Interface.h"

namespace detail
{

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

EVENT_DATA_DESCRIPTOR CreateProviderMetadata(const char* providerName)
{
	// Create packaged provider metadata structure.
	// <https://learn.microsoft.com/en-us/windows/win32/etw/provider-traits>
	const auto providerMetadataLength = (uint16_t)((strlen(providerName) + 1) + sizeof(uint16_t));
	const auto providerMetadata = (struct detail::ProviderMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, providerMetadataLength, 'wteO');
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

size_t SizeOfFieldsMeta()
{
	return 0;
}

template<typename FieldValue, typename... Rest>
size_t SizeOfFieldsMeta(const char* fieldName, int fieldType, FieldValue& fieldValue, Rest... rest)
{
	UNREFERENCED_PARAMETER(fieldType);
	UNREFERENCED_PARAMETER(fieldValue);
	return strlen(fieldName) + 1 + sizeof(uint8_t) + SizeOfFieldsMeta(rest...);
}

void SetFieldMetadata(uint8_t* current)
{
	UNREFERENCED_PARAMETER(current);
}

template<typename FieldValue, typename... Rest>
void SetFieldMetadata(uint8_t* current, const char* fieldName, int fieldType, FieldValue& fieldValue, Rest... rest)
{
	UNREFERENCED_PARAMETER(fieldValue);

	strcpy((char*)current, fieldName);
	current[strlen(fieldName) + 1] = (uint8_t)fieldType;

	current += strlen(fieldName) + 1 + sizeof(uint8_t);
	SetFieldMetadata(current, rest...);
}

template<typename... Arguments>
EVENT_DATA_DESCRIPTOR CreateEventMetadata(const char* eventName, Arguments... args)
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
	const auto eventMetadataLength = (uint16_t)(eventMetadataHeaderLength + SizeOfFieldsMeta(args...));
	const auto eventMetadata = (struct detail::EventMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, eventMetadataLength, 'wteE');
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
	uint8_t* currentLocation = ((uint8_t*)eventMetadata) + eventMetadataHeaderLength;
	detail::SetFieldMetadata(currentLocation, args...);

	// Create an EVENT_DATA_DESCRIPTOR pointing to the metadata.
	EVENT_DATA_DESCRIPTOR eventMetadataDesc;
	EventDataDescCreate(&eventMetadataDesc, eventMetadata, eventMetadata->TotalLength);
	eventMetadataDesc.Type = EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA;  // Descriptor contains event metadata.

	return eventMetadataDesc;
}

// final recursion case, string-specific overload
NTSTATUS CreateTracePropertyRecursive(OUT PEVENT_DATA_DESCRIPTOR propertyDataDescriptors, const char* fieldName, int fieldType, const char* fieldValue)
{
	// fieldName and fieldType are used in the event metadata descriptor, not here.
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Copy the input value to its own space.
	const auto newSpace = (char*)ExAllocatePoolWithTag(NonPagedPoolNx, strlen(fieldValue) + 1, 'wteE');
	if (newSpace == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	strcpy(newSpace, fieldValue);

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT propertyDataDescriptors, newSpace, (ULONG)(strlen(fieldValue) + 1));

	return STATUS_SUCCESS;
}

// final recursion case
template<typename FieldValue>
NTSTATUS CreateTracePropertyRecursive(OUT PEVENT_DATA_DESCRIPTOR propertyDataDescriptors, const char* fieldName, int fieldType, FieldValue& fieldValue)
{
	// fieldName and fieldType are used in the event metadata descriptor, not here.
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Copy the input value to its own space.
	const auto newSpace = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(FieldValue), 'wteE');
	if (newSpace == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	memcpy(newSpace, &fieldValue, sizeof(FieldValue));

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT propertyDataDescriptors, newSpace, sizeof(FieldValue));

	return STATUS_SUCCESS;
}

// string-specific overload
template<typename... Rest>
NTSTATUS CreateTracePropertyRecursive(OUT PEVENT_DATA_DESCRIPTOR propertyDataDescriptors, const char* fieldName, int fieldType, const char* fieldValue, Rest... rest)
{
	// fieldName and fieldType are used in the event metadata descriptor, not here.
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Copy the input value to its own space.
	const auto newSpace = (char*)ExAllocatePoolWithTag(NonPagedPoolNx, strlen(fieldValue) + 1, 'wteE');
	if (newSpace == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	strcpy(newSpace, fieldValue);

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT propertyDataDescriptors, newSpace, (ULONG)(strlen(fieldValue) + 1));

	// Create the next descriptor with the next field value.
	return CreateTracePropertyRecursive(++propertyDataDescriptors, rest...);
}

template<typename FieldValue, typename... Rest>
NTSTATUS CreateTracePropertyRecursive(OUT PEVENT_DATA_DESCRIPTOR propertyDataDescriptors, const char* fieldName, int fieldType, FieldValue& fieldValue, Rest... rest)
{
	// fieldName and fieldType are used in the event metadata descriptor, not here.
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Copy the input value to its own space.
	const auto newSpace = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(FieldValue), 'wteE');
	if (newSpace == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	memcpy(newSpace, &fieldValue, sizeof(FieldValue));

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT propertyDataDescriptors, newSpace, sizeof(FieldValue));

	// Create the next descriptor with the next field value.
	return CreateTracePropertyRecursive(++propertyDataDescriptors, rest...);
}

EVENT_DESCRIPTOR CreateEventDescriptor(uint64_t keyword, uint8_t level)
{
	EVENT_DESCRIPTOR desc;
	RtlSecureZeroMemory(&desc, sizeof(EVENT_DESCRIPTOR));
	desc.Channel = 11;  // All "manifest-free" events should go to channel 11 by default
	desc.Keyword = keyword;
	desc.Level = level;

	return desc;
}

void Cleanup(REGHANDLE regHandle = 0, PEVENT_DATA_DESCRIPTOR eventDescriptors = NULL, int numberOfDescriptors = 0)
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

}  // namespace detail

template<typename... Arguments>
NTSTATUS EtwTrace(
	const char* providerName,
	const GUID* providerGuid,
	const char* eventName,
	uint8_t eventLevel,
	uint64_t keyword,
	Arguments... args
)
{
	// It is unsafe to call EtwRegister() at higher than PASSIVE_LEVEL
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_NOT_IMPLEMENTED;
	}

	// Register the kernel-mode ETW provider.
	REGHANDLE regHandle = 0;
	NTSTATUS status = EtwRegister(providerGuid, NULL, NULL, OUT &regHandle);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	// Allocate space for the data descriptors, including two additional slots
	// for provider and event metadata.
	constexpr auto numberOfFields = sizeof...(Arguments) / 3;
	constexpr auto numberOfDescriptors = numberOfFields + 2;
	constexpr auto allocSize = numberOfDescriptors * sizeof(EVENT_DATA_DESCRIPTOR);
	const auto dataDescriptors = (PEVENT_DATA_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, 'wteP');
	if (dataDescriptors == NULL)
	{
		detail::Cleanup(regHandle);
		return STATUS_UNSUCCESSFUL;
	}
	RtlSecureZeroMemory(dataDescriptors, allocSize);

	// Create the provider metadata descriptor, and tell the provider to use the
	// metadata given by the descriptor.
	dataDescriptors[0] = detail::CreateProviderMetadata(providerName);
	if (dataDescriptors[0].Ptr == NULL)
	{
		detail::Cleanup(regHandle, dataDescriptors, numberOfDescriptors);
		return STATUS_UNSUCCESSFUL;
	}

	status = EtwSetInformation(regHandle, EventProviderSetTraits, (PVOID)dataDescriptors[0].Ptr, dataDescriptors[0].Size);
	if (status != STATUS_SUCCESS)
	{
		detail::Cleanup(regHandle, dataDescriptors, numberOfDescriptors);
		return status;
	}

	// Create the event metadata descriptor.
	dataDescriptors[1] = detail::CreateEventMetadata(eventName, args...);
	if (dataDescriptors[1].Ptr == NULL)
	{
		detail::Cleanup(regHandle, dataDescriptors, numberOfDescriptors);
		return STATUS_UNSUCCESSFUL;
	}

	// Create a descriptor for each individual field.
	status = detail::CreateTracePropertyRecursive(&dataDescriptors[2], args...);
	if (status != STATUS_SUCCESS)
	{
		detail::Cleanup(regHandle, dataDescriptors, numberOfDescriptors);
		return status;
	}

	// Create the top-level event descriptor.
	const auto eventDesc = detail::CreateEventDescriptor(keyword, eventLevel);

	// Write the event.
	status = EtwWrite(regHandle, &eventDesc, NULL, numberOfDescriptors, dataDescriptors);

	// Unregister the event and deallocate memory.
	detail::Cleanup(regHandle, dataDescriptors, numberOfDescriptors);

	return status;
}