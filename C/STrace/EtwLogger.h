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

__declspec(noinline) EVENT_DATA_DESCRIPTOR CreateEventMetadata(const char* eventName)
{
	// Create packaged event metadata structure.
	// TODO: Add in field metadata, which comes after the name.
	const auto eventMetadataLength = (uint16_t)((strlen(eventName) + 1) + sizeof(uint16_t) + sizeof(uint8_t));
	const auto eventMetadata = (struct detail::EventMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, eventMetadataLength, 'wteE');
	RtlSecureZeroMemory(eventMetadata, eventMetadataLength);
	eventMetadata->TotalLength = eventMetadataLength;
	strcpy(eventMetadata->EventName, eventName);

	// Create an EVENT_DATA_DESCRIPTOR pointing to the metadata.
	EVENT_DATA_DESCRIPTOR eventMetadataDesc;
	EventDataDescCreate(&eventMetadataDesc, eventMetadata, eventMetadata->TotalLength);
	eventMetadataDesc.Type = EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA;  // Descriptor contains event metadata.

	return eventMetadataDesc;
}

__declspec(noinline) NTSTATUS EtwCreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current)
{
	UNREFERENCED_PARAMETER(fields);
	UNREFERENCED_PARAMETER(current);
	return STATUS_SUCCESS;
}

template<typename FieldName = const char*, typename FieldType = int, typename FieldValue, typename... Rest>
__declspec(noinline) NTSTATUS EtwCreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current, FieldName fieldName, FieldType fieldType, FieldValue fieldValue, Rest... rest)
{
	// use fieldName, fieldType and fieldValue to add to fields
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	EventDataDescCreate(OUT &fields[current], &fieldValue, sizeof(FieldValue));

	// Add the next triplet of name, type and value to the event fields.
	return EtwCreateTracePropertyRecursive(fields, current + 1, rest...);
}

}  // namespace detail

template<typename... Arguments>
NTSTATUS EtwTrace(
	const char* providerName,
	const GUID* providerGuid,
	const char* eventName,
	int eventLevel,
	uint64_t flag,
	Arguments... args
)
{
	UNREFERENCED_PARAMETER(flag);

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
	const auto eventMetadataDesc = detail::CreateEventMetadata(eventName);

	// Create the collection of parameters, with additional space for the metadata
	// descriptors at the front.
	constexpr auto numberOfFields = sizeof...(Arguments) / 3;
	constexpr auto numberOfDescriptors = numberOfFields + 2;
	constexpr auto allocSize = numberOfDescriptors * sizeof(EVENT_DATA_DESCRIPTOR);
	const auto fields = (PEVENT_DATA_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, 'wteP');
	RtlSecureZeroMemory(fields, allocSize);
	memcpy(&fields[0], &providerMetadataDesc, sizeof(EVENT_DATA_DESCRIPTOR));
	memcpy(&fields[1], &eventMetadataDesc, sizeof(EVENT_DATA_DESCRIPTOR));
	status = detail::EtwCreateTracePropertyRecursive(OUT fields, 2, args...);
	if (status != STATUS_SUCCESS)
	{
		EtwUnregister(regHandle);
		ExFreePool((PVOID)providerMetadataDesc.Ptr);
		ExFreePool((PVOID)eventMetadataDesc.Ptr);
		ExFreePool(fields);
		return status;
	}

	// Create the event descriptor.
	EVENT_DESCRIPTOR desc;
	RtlSecureZeroMemory(&desc, sizeof(EVENT_DESCRIPTOR));
	desc.Level = (UCHAR)(eventLevel & 0xFF);

	// Write the event.
	status = EtwWrite(regHandle, &desc, NULL, numberOfDescriptors, fields);

	EtwUnregister(regHandle);
	ExFreePool((PVOID)providerMetadataDesc.Ptr);
	ExFreePool((PVOID)eventMetadataDesc.Ptr);
	ExFreePool(fields);

	return status;
}