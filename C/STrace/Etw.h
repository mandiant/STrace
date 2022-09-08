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