#include "Interface.h"

UNICODE_STRING WideToUnicodeString(PCWSTR SourceString)
{
	UNICODE_STRING DestinationString;

	SIZE_T Size;
	CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL); // an even number

	if (SourceString)
	{
		Size = wcslen(SourceString) * sizeof(WCHAR);
		if (Size > MaxSize)
			Size = MaxSize;
		DestinationString.Length = (USHORT)Size;
		DestinationString.MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
	}
	else {
		DestinationString.Length = 0;
		DestinationString.MaximumLength = 0;
	}

	DestinationString.Buffer = (PWCHAR)SourceString;
	return DestinationString;
}