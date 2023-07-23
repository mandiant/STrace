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
__declspec(noinline) void CreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current, const char* fieldName, int fieldType, const char* fieldValue)
{
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT &fields[current], fieldValue, (ULONG)strlen(fieldValue) + 1);
}

// final recursion case
template<typename FieldValue>
__declspec(noinline) void CreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current, const char* fieldName, int fieldType, FieldValue& fieldValue)
{
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT &fields[current], &fieldValue, sizeof(FieldValue));
}

// string-specific overload
template<typename... Rest>
__declspec(noinline) void CreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current, const char* fieldName, int fieldType, const char* fieldValue, Rest... rest)
{
	// fieldName and fieldType are used in the event metadata descriptor.
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT &fields[current], fieldValue, (ULONG)strlen(fieldValue) + 1);

	// Add the next triplet of name, type and value to the event fields.
	CreateTracePropertyRecursive(fields, current + 1, rest...);
}

template<typename FieldValue, typename... Rest>
__declspec(noinline) void CreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current, const char* fieldName, int fieldType, FieldValue& fieldValue, Rest... rest)
{
	// fieldName and fieldType are used in the event metadata descriptor.
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	// Create the event data descriptor pointing to the value of the field.
	EventDataDescCreate(OUT &fields[current], &fieldValue, sizeof(FieldValue));

	// Add the next triplet of name, type and value to the event fields.
	CreateTracePropertyRecursive(fields, current + 1, rest...);
}

template<typename... Arguments>
__declspec(noinline) PEVENT_DATA_DESCRIPTOR CreatePropertyDataDescriptors(
	EVENT_DATA_DESCRIPTOR providerMetadata,
	EVENT_DATA_DESCRIPTOR eventMetadata,
	Arguments... args)
{
	// Create the collection of parameters, with additional space for the metadata
	// descriptors at the front.
	constexpr auto numberOfFields = sizeof...(Arguments) / 3;
	constexpr auto numberOfDescriptors = numberOfFields + 2;
	constexpr auto allocSize = numberOfDescriptors * sizeof(EVENT_DATA_DESCRIPTOR);
	const auto fields = (PEVENT_DATA_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, 'wteP');
	if (fields == NULL)
	{
		return NULL;
	}
	RtlSecureZeroMemory(fields, allocSize);

	// Copy the metadata descriptors to the start of the descriptor array.
	memcpy(&fields[0], &providerMetadata, sizeof(EVENT_DATA_DESCRIPTOR));
	memcpy(&fields[1], &eventMetadata, sizeof(EVENT_DATA_DESCRIPTOR));

	// Create an event data descriptor for each property.
	CreateTracePropertyRecursive(OUT fields, 2, args...);

	return fields;
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

void Cleanup(REGHANDLE regHandle = 0, PVOID providerMetadata = NULL, PVOID eventMetadata = NULL, PVOID eventDescriptors = NULL)
{
	if (regHandle != 0)
	{
		EtwUnregister(regHandle);
	}

	if (providerMetadata != NULL)
	{
		ExFreePool(providerMetadata);
	}

	if (eventMetadata != NULL)
	{
		ExFreePool(eventMetadata);
	}

	if (eventDescriptors != NULL)
	{
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

	// Create the provider metadata descriptor, and tell the provider to use the
	// metadata given by the descriptor.
	const auto providerMetadataDesc = detail::CreateProviderMetadata(providerName);
	if (providerMetadataDesc.Ptr == NULL)
	{
		detail::Cleanup(regHandle);
		return STATUS_UNSUCCESSFUL;
	}

	status = EtwSetInformation(regHandle, EventProviderSetTraits, (PVOID)providerMetadataDesc.Ptr, providerMetadataDesc.Size);
	if (status != STATUS_SUCCESS)
	{
		detail::Cleanup(regHandle, (PVOID)providerMetadataDesc.Ptr);
		return status;
	}

	// Create the event metadata descriptor.
	const auto eventMetadataDesc = detail::CreateEventMetadata(eventName, args...);
	if (eventMetadataDesc.Ptr == NULL)
	{
		detail::Cleanup(regHandle, (PVOID)providerMetadataDesc.Ptr);
		return STATUS_UNSUCCESSFUL;
	}

	// Create the main array of data descriptors, which starts with one for the
	// provider metadata, then one for the event metadata, then one for each of
	// the fields.
	const auto dataDescriptors = detail::CreatePropertyDataDescriptors(providerMetadataDesc, eventMetadataDesc, args...);
	if (dataDescriptors == NULL)
	{
		detail::Cleanup(regHandle, (PVOID)providerMetadataDesc.Ptr, (PVOID)eventMetadataDesc.Ptr);
		return STATUS_UNSUCCESSFUL;
	}

	// Create the top-level event descriptor.
	const auto eventDesc = detail::CreateEventDescriptor(keyword, eventLevel);

	// Write the event.
	constexpr auto numberOfDescriptors = (sizeof...(Arguments) / 3) + 2;
	status = EtwWrite(regHandle, &eventDesc, NULL, numberOfDescriptors, dataDescriptors);

	// Unregister the event and deallocate memory.
	detail::Cleanup(regHandle, (PVOID)providerMetadataDesc.Ptr, (PVOID)eventMetadataDesc.Ptr, dataDescriptors);

	return status;
}