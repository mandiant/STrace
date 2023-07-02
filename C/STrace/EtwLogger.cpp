#include "EtwLogger.h"

NTSTATUS
LogEtwEvent(
	const char* providerName,
	const GUID* providerGuid,
	const char* eventName,
	int eventLevel,
	uint64_t flag,
	const char* field1Name,
	const char* field1Type,
	int field1Value
	/* TODO: varArgs */
)
{
	UNREFERENCED_PARAMETER(providerName);
	UNREFERENCED_PARAMETER(providerGuid);
	UNREFERENCED_PARAMETER(eventName);
	UNREFERENCED_PARAMETER(eventLevel);
	UNREFERENCED_PARAMETER(flag);
	UNREFERENCED_PARAMETER(field1Name);
	UNREFERENCED_PARAMETER(field1Type);
	UNREFERENCED_PARAMETER(field1Value);

	// TODO - EventRegister goes here?
	return 0;
}