#include "common.h"

UINT FindSig(PUCHAR bin, UINT bin_size, PUCHAR find, UINT find_size, UINT count)
{
	for (int i = 0; i < bin_size; i++)
	{
		int j = 0;

		for (; j < find_size; j++)
		{
			if (*(bin + i + j) != *(find + j))
				break;
		}

		if (j == find_size) {
			if (!count) return i;
			else count--;
		}
	}

	return 0;
}

VOID XORBinary(PUCHAR bin, UINT bin_size, PUCHAR key, UINT key_size)
{
	for (int i = 0; i != bin_size; i++)
		*(bin + i) ^= key[i % key_size];
}

typedef struct { unsigned int u32; } LZ4_unalign32;

int BinRead32(const void* ptr) { return ((const LZ4_unalign32*)ptr)->u32; }
void BinWrite32(void* memPtr, int value) { ((LZ4_unalign32*)memPtr)->u32 = value; }