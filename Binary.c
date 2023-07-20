#include "Binary.h"

int GetFileSizeFp(FILE* file)
{
	int size = 0;
	fseek(file, 0, SEEK_END);
	size = ftell(file);
	fseek(file, 0, SEEK_SET);
	rewind(file);
	return size;
}

FILE* OpenBinaryFile(char* file)
{
	FILE* m_fpStub = fopen(file, "rb");

	if (m_fpStub == NULL) {
		return NULL;
	}
	else
	{
		return m_fpStub;
	}
}

int ReadBinaryFile(char* file, char** buf)
{
	int m_iStubSize = 0;
	FILE* m_fpStub = OpenBinaryFile(file);

	m_iStubSize = GetFileSizeFp(m_fpStub);

	if (m_iStubSize <= 0) {
		goto exit;
	}

	*buf = (char*)malloc(m_iStubSize * sizeof(char));

	if (!*buf) {
		goto exit;
	}

	int m_iResult = fread(*buf, sizeof(char), m_iStubSize, m_fpStub);

	if (m_iResult != m_iStubSize) {
		goto exit;
	}

	fclose(m_fpStub);
exit:
	return m_iStubSize;
}

int FindStringInBinaryFile(char* bin, int bin_size, char* find, int find_size, int count)
{
	for (int i = 0; i < bin_size; i++)
	{
		register int j = 0;
		for (; j < find_size; j++)
		{
			if (*(bin + i + j) != *(find + j)) {
				break;
			}
		}
		if (j == find_size) {
			if (!count) {
				return i;
			}
			else
			{
				count--;
			}
		}

	}
	return 0;
}

int WriteBinaryFile(char* file, char* data, int size)
{
	int m_iResult = 0;

	FILE* m_fpOutput = fopen(file, "wb+");
	if (!m_fpOutput) {
		goto exit;
	}

	m_iResult = fwrite(data, sizeof(char), size, m_fpOutput);

	fclose(m_fpOutput);

	if (m_iResult != size) {
		goto exit;
	}
exit:
	return m_iResult;
}

void XORBinary(char* bin, int bin_size, char* key, int key_size)
{
	for (int i = 0; i != bin_size; i++) {
		*(bin + i) ^= key[i % key_size];
	}
}
