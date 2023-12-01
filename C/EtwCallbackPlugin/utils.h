#pragma once

// Include order matters here sadly. The C++ headers below may include C headers that re-define kernel apis. We must define our things first.
#include <ntifs.h>
#include "Interface.h"
#include "string.h"

// $(VC_IncludePath); required for these imports to work in the driver
#define _ITERATOR_DEBUG_LEVEL 0
#include <utility>
#include <array>
#include <span>
#include <type_traits>

#define ObjectNameInformation (OBJECT_INFORMATION_CLASS)1

const unsigned long POOL_TAG = '0RTS';
const wchar_t* backup_directory = L"\\??\\C:\\deleted";

// You must pass a temporary buffer, so that sprintf may write into that first.
// It's an argument, because then multiple calls can share the same temp buffer.
// If it's a local, the compiler inlines these poorly and explodes local stack space quickly.
typedef int(__cdecl* t_snprintf)(char*, size_t, const char*, ...);
t_snprintf g_p_snprintf = nullptr;

template<size_t BUFSZ, typename... Args>
int string_printf(String& str, char(&tmpBuf)[BUFSZ], Args&&... args) {
    memset(tmpBuf, 0, sizeof(BUFSZ));
   
    //assert(g_p_snprintf != nullptr)
    int size = g_p_snprintf(tmpBuf, BUFSZ, std::forward<Args>(args)...);
    if (size < 0) {
        return -1;
    }

    str += (char*)tmpBuf;
    return size;
}

using hash_t = uint64_t;

consteval uint64_t fnv1a_imp(uint64_t h, const char* s)
{
    return (*s == 0) ? h :
        fnv1a_imp((h ^ static_cast<uint64_t>(*s)) * 1099511628211ull, s + 1);
}

consteval uint64_t fnv1a(const char* s)
{
    return fnv1a_imp(14695981039346656037ull, s);
}

// Abuse template instantion rules to generate a unique name for a given type. Each template is a unique function in C++.
// Then, convert that string to a numeric hash. Stable for the lifetime of the application, may change between compilations.
template<typename T>
consteval uint64_t get_type_id() {
    return fnv1a(__FUNCSIG__);
}

// given a typedef, match the arg list and convert each arg to a typeid. Store results in an array.
template<typename T>
struct arg_types {};

template<typename R, typename... A>
struct arg_types<R(*)(A...)> {
    static constexpr std::array<uint64_t, sizeof...(A)> value = { get_type_id<A>()... };
};

// msvc doesn't implement a constructor for std::span from iterators. This does that...
template<typename It>
consteval auto make_span(It begin, It end) {
    return std::span<std::remove_reference_t<std::iter_reference_t<It>>>(&(*begin), std::distance(begin, end));
}

template<typename Func>
class FinalAction {
public:
    FinalAction(Func f) :FinalActionFunc(std::move(f)) {}
    ~FinalAction()
    {
        FinalActionFunc();
    }
private:
    Func FinalActionFunc;

    /*Uses RAII to call a final function on destruction
    C++ 11 version of java's finally (kindof)*/
};

template <typename F>
FinalAction<F> finally(F f) {
    return FinalAction<F>(f);
}

template<typename T>
T FnCast(uint64_t fnToCast, T pFnCastTo) {
    PH_UNUSED(pFnCastTo);
    return (T)fnToCast;
}

template<typename T>
T FnCast(void* fnToCast, T pFnCastTo) {
    PH_UNUSED(pFnCastTo);
    return (T)fnToCast;
}

template<typename T, typename T2 = uint64_t>
std::remove_pointer_t<T> readUserArgPtr(T2 pUserAddress, PluginApis& pApis) {
    std::remove_pointer_t<T> tmp = { 0 };

    // if this read fails we just return the type's default value. This is fine.
    if (!pApis.pTraceAccessMemory(&tmp, (uint64_t)pUserAddress, sizeof(tmp), 1, TRUE)) {
        return std::remove_pointer_t<T>{ 0 }; // return a new value, the other may have been partially written
    }
    return tmp;
}

bool createFile(PUNICODE_STRING filePath, PHANDLE hFileOut) {
    *hFileOut = NULL;

    OBJECT_ATTRIBUTES attrs = { 0 };
    InitializeObjectAttributes(&attrs, filePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status = ZwCreateFile(hFileOut,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &attrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_SYSTEM,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);
    return Status == STATUS_SUCCESS;
}

bool openFile(PUNICODE_STRING filePath, PHANDLE hFileOut) {
    *hFileOut = NULL;

    OBJECT_ATTRIBUTES attrs = { 0 };
    InitializeObjectAttributes(&attrs, filePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status = ZwOpenFile(hFileOut,
        FILE_READ_DATA | SYNCHRONIZE,
        &attrs,
        &IoStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );
    return Status == STATUS_SUCCESS;
}

// backupFileName must begin with a slash, or be a filepath with slashes
bool backupFile(PWSTR backupDir, UNICODE_STRING backupFileName, HANDLE hFileSource) {
    if (!backupFileName.Buffer || backupFileName.Length <= sizeof(wchar_t))
        return false;

    // scan backwards until first slash
    PWCHAR fileName = backupFileName.Buffer + (backupFileName.Length - sizeof(wchar_t));
    size_t fileNameLen = 0;
    while (*fileName != L'\\') {
        fileName--;
        fileNameLen++;
    }

    UNICODE_STRING backupPath = { 0 };
    backupPath.Length = (USHORT)(wcslen(backupDir) * sizeof(wchar_t));
    backupPath.MaximumLength = (USHORT)(backupPath.Length + (fileNameLen * sizeof(wchar_t)));
    backupPath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPoolNx, backupPath.MaximumLength, POOL_TAG);
    memcpy(backupPath.Buffer, backupDir, backupPath.Length);

    NTSTATUS status = RtlAppendUnicodeToString(&backupPath, fileName);
    if (status != STATUS_SUCCESS)
        return false;

    HANDLE hFileCopy = NULL;
    auto close_handles = finally([&] {
        if (hFileCopy != NULL) {
            ZwClose(hFileCopy);
        }
        });

    if (!createFile(&backupPath, &hFileCopy))
        return false;

    LARGE_INTEGER pos = { 0 };
    IO_STATUS_BLOCK iosb = { 0 };

    LARGE_INTEGER pos_write = { 0 };
    IO_STATUS_BLOCK iosb_write = { 0 };

    while (true) {
        char pBuf[512] = { 0 };
        status = ZwReadFile(
            hFileSource,
            NULL, NULL, NULL,
            &iosb,
            pBuf, (ULONG)sizeof(pBuf),
            &pos,
            NULL
        );

        if (status == STATUS_END_OF_FILE) {
            if (iosb.Information == 0) {
                break;
            }
        }

        if (status != STATUS_SUCCESS) {
            break;
        }

        status = ZwWriteFile(hFileCopy,
            NULL, NULL, NULL,
            &iosb_write,
            pBuf, (ULONG)sizeof(pBuf),
            &pos_write,
            NULL
        );

        if (iosb_write.Status != STATUS_SUCCESS) {
            break;
        }

        if (status != STATUS_SUCCESS) {
            break;
        }

        pos.QuadPart += iosb.Information;
        pos_write.QuadPart += iosb_write.Information;
    }
    return true;
}

VOID NTAPI FreeUnicodeString(PUNICODE_STRING UnicodeString, ULONG Tag)
{
    if (UnicodeString->Buffer)
    {
        ExFreePoolWithTag(UnicodeString->Buffer, Tag);
    }
}

NTSTATUS DuplicateUnicodeString(PCUNICODE_STRING SourceString, PUNICODE_STRING DestinationString, ULONG Tag)
{
    if (SourceString == NULL || DestinationString == NULL ||
        SourceString->Length > SourceString->MaximumLength ||
        (SourceString->Length == 0 && SourceString->MaximumLength > 0 && SourceString->Buffer == NULL))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (SourceString->Length == 0)
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
    else {
        SIZE_T DestMaxLength = SourceString->Length;

        DestinationString->Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPoolNx, DestMaxLength, Tag);
        if (DestinationString->Buffer == NULL)
            return STATUS_NO_MEMORY;

        memcpy(DestinationString->Buffer, SourceString->Buffer, SourceString->Length);
        DestinationString->Length = SourceString->Length;
        DestinationString->MaximumLength = (USHORT)DestMaxLength;
    }
    return STATUS_SUCCESS;
}