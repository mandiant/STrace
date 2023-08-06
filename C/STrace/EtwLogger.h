#pragma once
#include "Interface.h"
#include "vector.h"

namespace detail
{

class EtwProvider
{
public:
	EtwProvider(LPCGUID providerGuid);
	void Destruct();

	NTSTATUS Initialize(const char* name);
	NTSTATUS WriteEvent(PCEVENT_DESCRIPTOR eventDescriptor, ULONG numberOfDescriptors, PEVENT_DATA_DESCRIPTOR descriptors) const;

	LPCGUID Guid() const noexcept;
	EVENT_DATA_DESCRIPTOR ProviderMetadataDescriptor() const noexcept;
private:
	struct ProviderMetadata
	{
		uint16_t TotalLength;
		char ProviderName[ANYSIZE_ARRAY];
	};

	LPCGUID m_guid;
	REGHANDLE m_regHandle;
	EVENT_DATA_DESCRIPTOR m_providerMetadataDesc;
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
