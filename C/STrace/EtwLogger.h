#pragma once
#include "Interface.h"
#include "vector.h"

namespace detail
{

class EtwProviderEvent
{
public:
	EtwProviderEvent();
	void Destruct();

	NTSTATUS Initialize(const char* eventName, int numberOfFields, va_list fields);

	const char* Name() const;
	EVENT_DATA_DESCRIPTOR MetadataDescriptor() const;

private:
	struct EventMetadata
	{
		uint16_t TotalLength;
		uint8_t Tag;
		char EventName[ANYSIZE_ARRAY];
	};

	EVENT_DATA_DESCRIPTOR m_eventMetadataDesc;
};

class EtwProvider
{
public:
	EtwProvider(LPCGUID providerGuid);
	EtwProvider(const EtwProvider& other) = delete;
	EtwProvider(EtwProvider&& other);
	EtwProvider& operator=(const EtwProvider& other) = delete;
	EtwProvider& operator=(EtwProvider&& other);
	void Destruct();

	NTSTATUS Initialize(const char* name);
	NTSTATUS AddEvent(const char* eventName, int numberOfFields, va_list fields);
	NTSTATUS WriteEvent(const char* eventName, PCEVENT_DESCRIPTOR eventDescriptor, int numberOfFields, va_list fields);

	LPCGUID Guid() const noexcept;

private:
	struct ProviderMetadata
	{
		uint16_t TotalLength;
		char ProviderName[ANYSIZE_ARRAY];
	};

	EtwProviderEvent* FindEvent(const char* eventName);
	static size_t SizeOfField(int fieldType, void* fieldValue);
	static EVENT_DATA_DESCRIPTOR CreateTraceProperty(int fieldType, void* fieldValue);

	LPCGUID m_guid;
	REGHANDLE m_regHandle;
	EVENT_DATA_DESCRIPTOR m_providerMetadataDesc;
	MyVector<EtwProviderEvent> m_events;
};

} // namespace detail

// Cache of all created providers.
extern MyVector<detail::EtwProvider> g_ProviderCache;

NTSTATUS EtwTrace(
	const char* providerName,
	const GUID* providerGuid,
	const char* eventName,
	uint8_t eventLevel,
	uint64_t keyword,
	int numberOfFields,
	...
);
