#pragma once
#include <functional>

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

class ServiceHandle {
public:
	ServiceHandle() : handle(NULL) { }
	ServiceHandle(SC_HANDLE h) : handle(h) { }
	ServiceHandle(ServiceHandle& sh) = delete;
	ServiceHandle(ServiceHandle&& sh) = delete;

	~ServiceHandle() {
		if (isValid())
		{
			CloseServiceHandle(handle);
		}
	}

	BOOL isValid() {
		return handle != NULL;
	}

	BOOL isInvalid() {
		return handle == NULL;
	}

	SC_HANDLE handle = NULL;
};