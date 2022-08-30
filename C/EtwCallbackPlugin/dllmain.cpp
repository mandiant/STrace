#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <evntcons.h>

extern "C" __declspec(dllexport) void DtEtwpEventCallback(PEVENT_HEADER EventHeader, ULONG32 a, GUID* ProviderGuid, ULONG32 b)
{
    __debugbreak();
}

BOOL APIENTRY Main(HMODULE hModule, DWORD  reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
