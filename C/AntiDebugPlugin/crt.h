#pragma once

//https://stackoverflow.com/questions/2938966/how-to-use-vc-intrinsic-functions-w-o-run-time-library

extern "C" size_t strlen(const char* str);
#pragma intrinsic(strlen)

extern "C" size_t wcslen(const wchar_t* str);
#pragma intrinsic(wcslen)

extern "C" char* strcpy(char* a, const char* b);
#pragma intrinsic(strcpy)

extern "C" void* memset(void* dest, int val, size_t len);
#pragma intrinsic(memset)

extern "C" void* memcpy(void* dest, const void* src, size_t n);
#pragma intrinsic(memcpy)

extern "C" int strcmp(const char* s1, const char* s2);
#pragma intrinsic(strcmp)

extern "C" int wcscmp(const wchar_t* s1, const wchar_t* s2);
#pragma intrinsic(wcscmp)

extern "C" void __chkstk();