#pragma once
#include <stdint.h>

#include <ntdef.h>

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
);