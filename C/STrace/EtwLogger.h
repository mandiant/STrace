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

__declspec(noinline) EVENT_DATA_DESCRIPTOR CreateProviderMetadata(const char* providerName)
{
	// Create packaged provider metadata structure.
	// <https://learn.microsoft.com/en-us/windows/win32/etw/provider-traits>
	const auto providerMetadataLength = (uint16_t)((strlen(providerName) + 1) + sizeof(uint16_t));
	const auto providerMetadata = (struct detail::ProviderMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, providerMetadataLength, 'wteO');
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

template<typename FieldName = const char*, typename FieldType = int, typename FieldValue, typename... Rest>
size_t SizeOfFieldsMeta(FieldName fieldName, FieldType fieldType, FieldValue& fieldValue, Rest... rest)
{
	UNREFERENCED_PARAMETER(fieldType);
	UNREFERENCED_PARAMETER(fieldValue);
	return strlen(fieldName) + 1 + sizeof(uint8_t) + SizeOfFieldsMeta(rest...);
}

void SetFieldMetadata(uint8_t* current)
{
	UNREFERENCED_PARAMETER(current);
}

template<typename FieldName = const char*, typename FieldType = int, typename FieldValue, typename... Rest>
void SetFieldMetadata(uint8_t* current, FieldName fieldName, FieldType fieldType, FieldValue& fieldValue, Rest... rest)
{
	UNREFERENCED_PARAMETER(fieldValue);

	strcpy((char*)current, fieldName);
	current[strlen(fieldName) + 1] = (uint8_t)fieldType;

	current += strlen(fieldName) + 1 + sizeof(uint8_t);
	SetFieldMetadata(current, rest...);
}

template<typename... Arguments>
__declspec(noinline) EVENT_DATA_DESCRIPTOR CreateEventMetadata(const char* eventName, Arguments... args)
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

__declspec(noinline) void EtwCreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current)
{
	UNREFERENCED_PARAMETER(fields);
	UNREFERENCED_PARAMETER(current);
}

template<typename FieldName = const char*, typename FieldType = int, typename FieldValue, typename... Rest>
__declspec(noinline) void EtwCreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current, FieldName fieldName, FieldType fieldType, FieldValue& fieldValue, Rest... rest)
{
	// fieldName and fieldType are used in the event metadata descriptor.
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT &fields[current], &fieldValue, sizeof(FieldValue));

	// Add the next triplet of name, type and value to the event fields.
	EtwCreateTracePropertyRecursive(fields, current + 1, rest...);
}

EVENT_DESCRIPTOR EtwCreateEventDescriptor(uint64_t keyword, uint8_t level)
{
	EVENT_DESCRIPTOR desc;
	RtlSecureZeroMemory(&desc, sizeof(EVENT_DESCRIPTOR));
	desc.Channel = 11;  // All "manifest-free" events should go to channel 11 by default
	desc.Keyword = keyword;
	desc.Level = level;

	return desc;
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
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		return STATUS_NOT_IMPLEMENTED;
	}

	// Register the kernel-mode ETW provider.
	REGHANDLE regHandle = 0;
	NTSTATUS status = EtwRegister(providerGuid, NULL, NULL, OUT &regHandle);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	// Create the provider metadata descriptor, and tell the provider to use the
	// metadata given by the descriptor.
	const auto providerMetadataDesc = detail::CreateProviderMetadata(providerName);
	status = EtwSetInformation(regHandle, EventProviderSetTraits, (PVOID)providerMetadataDesc.Ptr, providerMetadataDesc.Size);
	if (status != STATUS_SUCCESS)
	{
		EtwUnregister(regHandle);
		ExFreePool((PVOID)providerMetadataDesc.Ptr);
		return status;
	}

	// Create the event metadata descriptor.
	const auto eventMetadataDesc = detail::CreateEventMetadata(eventName, args...);

	// Create the collection of parameters, with additional space for the metadata
	// descriptors at the front.
	constexpr auto numberOfFields = sizeof...(Arguments) / 3;
	constexpr auto numberOfDescriptors = numberOfFields + 2;
	constexpr auto allocSize = numberOfDescriptors * sizeof(EVENT_DATA_DESCRIPTOR);
	const auto fields = (PEVENT_DATA_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, 'wteP');
	RtlSecureZeroMemory(fields, allocSize);

	// Copy the metadata descriptors to the start of the descriptor array.
	memcpy(&fields[0], &providerMetadataDesc, sizeof(EVENT_DATA_DESCRIPTOR));
	memcpy(&fields[1], &eventMetadataDesc, sizeof(EVENT_DATA_DESCRIPTOR));

	// Create an event data descriptor for each property.
	detail::EtwCreateTracePropertyRecursive(OUT fields, 2, args...);

	// Create the top-level event descriptor.
	const auto eventDesc = detail::EtwCreateEventDescriptor(keyword, eventLevel);

	// Write the event.
	status = EtwWrite(regHandle, &eventDesc, NULL, numberOfDescriptors, fields);

	EtwUnregister(regHandle);
	ExFreePool((PVOID)providerMetadataDesc.Ptr);
	ExFreePool((PVOID)eventMetadataDesc.Ptr);
	ExFreePool(fields);

	return status;
}