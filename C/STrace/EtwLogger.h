#pragma once
#include "Interface.h"

namespace detail
{

NTSTATUS EtwCreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current)
{
	UNREFERENCED_PARAMETER(fields);
	UNREFERENCED_PARAMETER(current);
	return STATUS_SUCCESS;
}

template<typename FieldName = const char*, typename FieldType = int, typename FieldValue, typename... Rest>
NTSTATUS EtwCreateTracePropertyRecursive(OUT EVENT_DATA_DESCRIPTOR fields[], int current, FieldName fieldName, FieldType fieldType, FieldValue fieldValue, Rest... rest)
{
	// use fieldName, fieldType and fieldValue to add to fields
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);

	EventDataDescCreate(OUT &fields[current], &fieldValue, sizeof(FieldValue));

	// Add the next triplet of name, type and value to the event fields.
	return EtwCreateTracePropertyRecursive(fields, current + 1, rest...);
}

struct ProviderMetadata
{
	uint16_t TotalLength;
	char ProviderName[ANYSIZE_ARRAY];
};

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
	UNREFERENCED_PARAMETER(eventName);
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

	// Set the name and other metadata about the provider.
	EVENT_DATA_DESCRIPTOR providerMetadataDesc;
	const auto providerMetadataLength = (uint16_t)(strlen(providerName) + sizeof(uint16_t));
	const auto providerMetadata = (struct detail::ProviderMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, providerMetadataLength, 'wteO');
	providerMetadata->TotalLength = providerMetadataLength;
	strcpy(providerMetadata->ProviderName, providerName);
	EventDataDescCreate(&providerMetadataDesc, providerMetadata, providerMetadata->TotalLength);
	providerMetadataDesc.Type = 2;  // Descriptor contains provider metadata.
	status = EtwSetInformation(regHandle, EventProviderSetTraits, providerMetadata, 1234);

	// Create the collection of parameters.
	const auto numberOfFields = sizeof...(Arguments) / 3;
	const auto allocSize = numberOfFields * sizeof(EVENT_DATA_DESCRIPTOR);
	const auto fields = (PEVENT_DATA_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, 'wteP');
	status = detail::EtwCreateTracePropertyRecursive(OUT fields, 0, args...);
	if (status != STATUS_SUCCESS)
	{
		goto error;
	}

	// Create the event descriptor.
	EVENT_DESCRIPTOR desc;
	desc.Level = (UCHAR)(eventLevel & 0xFF);

	// Write the event.
	status = EtwWrite(regHandle, &desc, NULL, numberOfFields, fields);
	if (status != STATUS_SUCCESS)
	{
		goto error;
	}

error:
	// Unregister the kernel-mode ETW provider.
	EtwUnregister(regHandle);

	ExFreePool(providerMetadata);
	ExFreePool(fields);
	return status;
}