#include <stdint.h>
#include "crt.h"
#include "KernelApis.h"
#include "Interface.h"

#pragma function(strlen)
extern "C" size_t strlen(const char* str)
{
    const char* s;
    for (s = str; *s; ++s);
    return (s - str);
}

#pragma function(wcslen)
extern "C" size_t wcslen(const wchar_t* str) {
    const wchar_t* s;
    for (s = str; *s; ++s);
    return (s - str);
}

#pragma function(strcpy)
extern "C" char* strcpy(char* a, const char* b)
{
    char* saved = a;
    while (*a++ = *b++);
    return saved;
}

#pragma function(memset)
extern "C" void* memset(void* dest, int val, size_t len)
{
    unsigned char* ptr = (unsigned char*)dest;
    while (len--)
        *ptr++ = val;
    return dest;
}

#pragma function(memcpy)
extern "C" void* memcpy(void* dest, const void* src, size_t n) {
    char* d = (char*)dest;
    const char* s = (char*)src;
    while (n--)
        *d++ = *s++;
    return dest;
}

#pragma function(strcmp)
int strcmp(const char* s1, const char* s2)
{
    while (*s1 == *s2++) {
        if (*s1++ == 0) {
            return 0;
        }
    }
    return (*(unsigned char*)s1 - *(unsigned char*)--s2);
}

void __chkstk() {
    // chkstk being inserted by the compiler means we took up too much stack space.
    // this would otherwise crashus with a page fault. So uh, lets debug break instead.
    // If you see this, fix your code to not use so much local stack space per function.
    __debugbreak();
}