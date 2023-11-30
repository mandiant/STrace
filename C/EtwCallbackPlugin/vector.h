#pragma once
#undef calloc
#undef malloc
#undef realloc
#undef free
#include "new.h"
#include <stdint.h>
#include <intrin.h>

template<typename T>
class MyVector {
public:
	MyVector(size_t count, PluginApis& apis) : m_apis(apis) {
		size = 0;
		capacity = 0;
		data = nullptr;
		reserve(count);
	}

	MyVector(PluginApis& apis) : m_apis(apis) {
		size = 0;
		capacity = 0;
		data = nullptr;
	}

	~MyVector() {
		if (data) {
			for (size_t i = 0; i < size; i++) {
				data[i].T::~T();
			}
			deallocate((char*)data);
			data = nullptr;
		}
	}

	// non-copy
	MyVector(const MyVector&) = delete;
	MyVector& operator=(const MyVector&) = delete;

	// non-moveable
	MyVector(MyVector&&) = delete;
	MyVector& operator=(MyVector&&) = delete;

	void push_back(const T& item) {
		if (size >= capacity) {
			reserve((size + 1) * 2); // grow 2x, +1 incase it's zero
		}
		data[size++] = item;
	}

	void push_back(T&& item) {
		if (size >= capacity) {
			reserve((size + 1) * 2); // grow 2x
		}
		data[size++] = std::move(item);
	}

	void pop_back() {
		data[size].T::~T();
		size--;
	}

	void erase(size_t idx) {
		if (idx < size) {
			data[idx].T::~T();

			size_t leftOvers = size - idx;
			T* start = &data[idx];
			T* next = &data[idx + 1];
			for (int i = 0; i < leftOvers; i++) {
				*start++ = std::move(*next++);
			}
			size--;
		}
	}

	T& back() {
		return data[size - 1];
	}

	T& front() {
		return data[0];
	}

	T& operator[](size_t idx) {
		return data[idx];
	}

	void reserve(size_t count) {
		T* new_data = (T*)allocate(sizeof(T) * count);

		if (data) {
			// resize might want us to shrink
			size_t copy_amount = count < size ? count : size;
			for (size_t i = 0; i < size; i++) {
				new_data[i] = std::move(data[i]);
			}
			deallocate((char*)data);
			data = nullptr;
		}
		
		capacity = count;
		data = new_data;
	}

	void resize(size_t count) {
		reserve(count);
		size = count;
	}

	size_t len() {
		return size;
	}
private:
	char* allocate(size_t size) {
		auto pExAllocatePoolWithTag = ResolveApi<tExAllocatePoolWithTag>(L"ExAllocatePoolWithTag", m_apis);
		if (!pExAllocatePoolWithTag) {
			__debugbreak();
		}
		return (char*)pExAllocatePoolWithTag(NonPagedPoolNx, size, '0CEV');
	}

	void deallocate(char* p) {
		auto pExFreePoolWithTag = ResolveApi<tExFreePoolWithTag>(L"ExFreePoolWithTag", m_apis);
		if (!pExFreePoolWithTag) {
			__debugbreak();
		}
		pExFreePoolWithTag(p, '0CEV');
	}

	size_t size;
	size_t capacity;
	T* data;

	PluginApis& m_apis;
};