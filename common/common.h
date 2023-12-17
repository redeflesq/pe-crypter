#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>

#include "../common/lz4/lz4.h"
#include "../common/lz4/lz4hc.h"

#ifdef _WIN64
#	define A64
#else
#	define A86
#endif

#ifdef A86
typedef DWORD DWORDT;
typedef PDWORD PDWORDT;
#else
typedef DWORD64 DWORDT;
typedef PDWORD64 PDWORDT;
#endif

#define CRYPTER_USE_LZ4_COMPRESSION 1
//#define CRYPTER_USE_XOR_ENCRYPTION 1

#define MALLOC(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define MFREE(ptr) HeapFree(GetProcessHeap(), NULL, ptr)

#define STUB_DEFAULT_KEY "oUf!rOsj6x*FgyNjBuTuW#R0jZSOg!kD1D8ZYc$YDZbgiXaoxVS@xCOW%y%sdVES"
#define STUB_DEFAULT_SEPARATOR "mxE98lDhF6mGxJd6"

PUCHAR GenerateRandomString(UINT size);
UINT FindSig(PUCHAR bin, UINT bin_size, PUCHAR find, UINT find_size, UINT count);
VOID XORBinary(PUCHAR bin, UINT bin_size, PUCHAR key, UINT key_size);

// lz4 :)
int BinRead32(const void* ptr);
void BinWrite32(void* memPtr, int value);