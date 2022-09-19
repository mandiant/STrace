#pragma once
#include "Interface.h"

/**
Create a new ETW tracing session for the driver.
OUT pTraceHandle: Output parameter to a handle to the created session.
**/
NTSTATUS EtwStartTracingSession(OUT TRACEHANDLE* pTraceHandle);

/**
Stop the driver's ETW tracing session, if any.
**/
NTSTATUS EtwStopTracingSession();

/**
Add a provider to the given ETW tracing session.
TraceHandle: The handle to the tracing session to add the provider to.
ProviderGuid: The GUID of the provider to add to the session.
**/
NTSTATUS EtwAddProviderToTracingSession(TRACEHANDLE TraceHandle, GUID ProviderGuid);