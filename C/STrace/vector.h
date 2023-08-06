#pragma once

namespace detail
{

// <https://en.cppreference.com/w/cpp/types/remove_reference>
template<typename T> struct remove_reference { typedef T type; };
template<typename T> struct remove_reference<T&> { typedef T type; };
template<typename T> struct remove_reference<T&&> { typedef T type; };

// <https://stackoverflow.com/a/7518365>
template<typename T>
typename remove_reference<T>::type&& move(T&& arg)
{
	return static_cast<typename remove_reference<T>::type&&>(arg);
}

} // namespace detail

template<typename T>
class MyVector {
public:
	MyVector(size_t count) {
		size = 0;
		capacity = 0;
		data = nullptr;
		reserve(count);
	}

	MyVector() {
		size = 0;
		capacity = 0;
		data = nullptr;
	}

	// non-copy
	MyVector(const MyVector&) = delete;
	MyVector& operator=(const MyVector&) = delete;

	// non-moveable
	MyVector(MyVector&&) = delete;
	MyVector& operator=(MyVector&&) = delete;

	void Destruct() {
		if (data) {
			for (size_t i = 0; i < size; i++) {
				data[i].T::~T();
			}
			deallocate((char*)data);
			data = nullptr;
		}
	}

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
		data[size++] = detail::move(item);
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
				*start++ = detail::move(*next++);
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
			for (size_t i = 0; i < size; i++) {
				new_data[i] = detail::move(data[i]);
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
	char* allocate(size_t s) {
		return (char*)ExAllocatePoolWithTag(NonPagedPoolNx, s, '0CEV');
	}

	void deallocate(char* p) {
		if (!p) {
			return;
		}

		ExFreePoolWithTag(p, '0CEV');
		p = nullptr;
	}

	size_t size;
	size_t capacity;
	T* data;
};