#pragma once

class String {
public:
    String() noexcept {
        len = 0;
        capacity = 20;
        pStr = allocate(capacity);
    }

    // non-copyable
    String(const String&) = delete;
    String& operator=(const String&) = delete;

    // but movable (defining this is necessary to prevent double free)
    String(String&& other) noexcept {
        pStr = other.pStr;
        capacity = other.capacity;
        len = other.len;
        other.pStr = nullptr;
    };

    String& operator=(String&& other) noexcept {
        pStr = other.pStr;
        capacity = other.capacity;
        len = other.len;
        other.pStr = nullptr;
        return *this;
    }

    String(const char* str) {
        len = strlen(str);
        capacity = (len + 1) * 2;
        pStr = allocate(capacity);
        memcpy(pStr, str, len);
        pStr[len] = 0;
    }

    ~String() noexcept {
        // delete on nullptr is well defined as safe.
        // branching on !pStr inhibits copy optimizations, so don't
        deallocate(pStr);
    }

    void resize(size_t newSize) {
        size_t old_capacity = capacity;
        if (newSize < old_capacity)
            return;

        capacity = newSize;

        auto old_pStr = pStr;
        pStr = allocate(capacity);
        memset(pStr, 0, capacity);
        memcpy(pStr, old_pStr, len);
        pStr[len] = 0;

        deallocate(old_pStr);
    }

    String& operator+=(const char* s) {
        size_t additional_len = strlen(s);
        resize(len + additional_len + 1); // null term
        memcpy(&pStr[len], s, additional_len + 1);
        len += additional_len;
        return *this;
    }

    char* data() {
        return pStr;
    }

    size_t size() {
        return len;
    }

    operator const char* () {
        return pStr;
    }

    operator char* () {
        return (char*)pStr;
    }
private:
    char* allocate(size_t size) {
        return (char*)ExAllocatePoolWithTag(NonPagedPoolNx, size, '0RTS');
    }

    void deallocate(char* p) {
        if (!p) {
            return;
        }

        ExFreePoolWithTag(p, '0RTS');
        p = nullptr;
    }

    char* pStr;
    size_t len;
    size_t capacity;
};