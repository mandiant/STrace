#pragma once
#include "Interface.h"

namespace detail
{

struct FieldsCollection {};

template<const char* FieldName, int FieldType, typename FieldValue, typename... Rest>
NTSTATUS EtwTracePropertyRecursive(OUT FieldsCollection& fields, const char* fieldName, int fieldType, FieldValue fieldValue, Rest... rest)
{
	// use fieldName, fieldType and fieldValue to add to fields
	// in userspace this would use an EVENT_DATA_DESCRIPTOR and EventDataDescCreate
	UNREFERENCED_PARAMETER(fields);
	UNREFERENCED_PARAMETER(fieldName);
	UNREFERENCED_PARAMETER(fieldType);
	UNREFERENCED_PARAMETER(fieldValue);

	// Add the next triplet of name, type and value to the event fields.
	return EtwTracePropertyRecursive(fields, rest...);
}

template<>
NTSTATUS EtwTracePropertyRecursive(OUT FieldsCollection& fields)
{
	UNREFERENCED_PARAMETER(fields);
	return STATUS_SUCCESS;
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
	UNREFERENCED_PARAMETER(providerName);
	UNREFERENCED_PARAMETER(eventName);
	UNREFERENCED_PARAMETER(eventLevel);
	UNREFERENCED_PARAMETER(flag);

	// Register the kernel-mode ETW provider.
	REGHANDLE regHandle;
	NTSTATUS status = EtwRegister(providerGuid, NULL, NULL, OUT &regHandle);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	// Create the collection of parameters.
	detail::FieldsCollection fields;
	status = detail::EtwTracePropertyRecursive(OUT fields, args...);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	// Write the event.
	// <https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/event/index.htm>
	return ZwTraceEvent((HANDLE)regHandle,  0/* flags */, 0/* fieldSize, */, NULL/* fields */);
}