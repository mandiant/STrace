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

__declspec(noinline) NTSTATUS CreateProviderMetadata(REGHANDLE regHandle, const char* providerName, OUT EVENT_DATA_DESCRIPTOR& providerMetadataDesc)
{
	// Create packaged provider metadata structure.
	// <https://learn.microsoft.com/en-us/windows/win32/etw/provider-traits>
	const auto providerMetadataLength = (uint16_t)((strlen(providerName) + 1) + sizeof(uint16_t));
	const auto providerMetadata = (struct detail::ProviderMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, providerMetadataLength, 'wteO');
	RtlSecureZeroMemory(providerMetadata, providerMetadataLength);
	providerMetadata->TotalLength = providerMetadataLength;
	strcpy(providerMetadata->ProviderName, providerName);

	// Create an EVENT_DATA_DESCRIPTOR pointing to the metadata.
	EventDataDescCreate(&providerMetadataDesc, providerMetadata, providerMetadata->TotalLength);
	providerMetadataDesc.Type = EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA;  // Descriptor contains provider metadata.

	// Set the metadata on the provider.
	const auto status = EtwSetInformation(regHandle, EventProviderSetTraits, providerMetadata, providerMetadata->TotalLength);

	// TODO: De-allocate the original copy (???)
	//ExFreePool(providerMetadata);

	// Do we need to call EtwSetInformation at all? Or just stick the
	// EVENT_DATA_DESCRIPTOR at the front of the list passed to EtwWriteEvent
	// (along with another one for the event metadata?). DTrace source does have a
	// call to the (userspace equivalent of) EtwSetInformation, but is it called?
	// Whereas this file (<https://github.com/billti/cpp-etw/blob/master/etw-provider.h>)
	// references the function but does not actually call it, and just sticks the
	// descriptors in front of the write.
	//
	// Note that what is sent to EtwSetInformation is NOT a data descriptor, it's
	// the plain format.

	return status;
}

__declspec(noinline) void CreateEventMetadata(const char* eventName, OUT EVENT_DATA_DESCRIPTOR& eventMetadataDesc)
{
	// Create packaged event metadata structure.
	// TODO: Add in field metadata, which comes after the name.
	const auto eventMetadataLength = (uint16_t)((strlen(eventName) + 1) + sizeof(uint16_t) + 1);
	const auto eventMetadata = (struct detail::EventMetadata*)ExAllocatePoolWithTag(NonPagedPoolNx, eventMetadataLength, 'wteE');
	RtlSecureZeroMemory(eventMetadata, eventMetadataLength);
	eventMetadata->TotalLength = eventMetadataLength;
	strcpy(eventMetadata->EventName, eventName);

	// Create an EVENT_DATA_DESCRIPTOR pointing to the metadata.
	EventDataDescCreate(&eventMetadataDesc, eventMetadata, eventMetadata->TotalLength);
	eventMetadataDesc.Type = EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA;  // Descriptor contains event metadata.
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

	// Set the name and other metadata about the provider.
	EVENT_DATA_DESCRIPTOR providerMetadataDesc;
	status = detail::CreateProviderMetadata(regHandle, providerName, OUT providerMetadataDesc);
	if (status != STATUS_SUCCESS)
	{
		//EtwUnregister(regHandle);
		return status;
	}

	// Create the event metadata descriptor.
	EVENT_DATA_DESCRIPTOR eventMetadataDesc;
	detail::CreateEventMetadata(eventName, eventMetadataDesc);

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
		//EtwUnregister(regHandle);
		ExFreePool(fields);
		return status;
	}

	// Create the event descriptor.
	EVENT_DESCRIPTOR desc;
	RtlSecureZeroMemory(&desc, sizeof(EVENT_DESCRIPTOR));
	desc.Level = (UCHAR)(eventLevel & 0xFF);

	// Write the event.
	status = EtwWrite(regHandle, &desc, NULL, numberOfDescriptors, fields);
	if (status != STATUS_SUCCESS)
	{
		//EtwUnregister(regHandle);
		ExFreePool(fields);
		return status;
	}

	//TODO: EtwUnregister(regHandle);
	ExFreePool(fields);

	return status;
}