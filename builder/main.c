#define _CRT_SECURE_NO_WARNINGS

#include "../common/common.h"

#include <stdio.h>
#include <time.h>

#include "../common/lz4/lz4hc.h"

#define ASCII_START 32
#define ASCII_END 126

static PUCHAR GenerateRandomString(UINT size)
{
	srand(time(NULL) + size);
	int i;
	PUCHAR res = MALLOC(size + 1);
	for (i = 0; i < size; i++)
		res[i] = (char)(rand() % (ASCII_END - ASCII_START)) + ASCII_START;
	res[i] = '\0';
	return res;
}

static BOOL ValidatePE(LPVOID lpData)
{
	PIMAGE_DOS_HEADER lpImageDosHeader = (PIMAGE_DOS_HEADER)lpData;

	if (lpImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Not found DOS signature\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS lpImageNtHeaders = (PIMAGE_NT_HEADERS)((DWORDT)lpData + lpImageDosHeader->e_lfanew);

	if (lpImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("Not found NT signature\n");
		return FALSE;
	}

#ifdef A86
	if (lpImageNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		printf("x64 is not supported on this version\n");
		return FALSE;
	}
#else
	if (lpImageNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		printf("x32 is not supported on this version\n");
		return FALSE;
	}
#endif

	return TRUE;
}

static int CryptFile(HANDLE hInputFile, HANDLE hStubFile, HANDLE hOutputFile)
{
	LARGE_INTEGER size;
	if (!GetFileSizeEx(hStubFile, &size))
		return -1; // error condition, could call GetLastError to find out more
	
	DWORD iStubSize = size.QuadPart;
	PUCHAR lpStubData = MALLOC(iStubSize * sizeof(UCHAR));
	if (!lpStubData)
		return -1;
	
	DWORD iStubBytesReaded = 0;
	if (!ReadFile(hStubFile, lpStubData, iStubSize, &iStubBytesReaded, NULL) || iStubBytesReaded != iStubSize) {
		printf("Unable to read stub file\n");
		MFREE(lpStubData);
		return -1;
	}

	printf("Stub file size: %d\n", iStubSize);
	
	/* INSERT NEW ENCRYPTION KEY */
	UCHAR sKey[64] = STUB_DEFAULT_KEY;
	PUCHAR sNewKey;
	UINT iKeyLength = sizeof sKey;
	{
		UINT iKeyPos = FindSig(lpStubData, iStubSize, sKey, iKeyLength, 0);
		if (!iKeyPos) {
			printf("Encryption key in stub not found\n");
			MFREE(lpStubData);
			return -1;
		}

		printf("Encryption key position in stub start: %d\n", iKeyPos);
		printf("Encryption key position in stub end: %d\n", iKeyPos + iKeyLength);

		sNewKey = GenerateRandomString(iKeyLength);

		printf("Insert new key into stub: '%s'\n", sNewKey);

		// replace default key
		for (UINT i = 0; i < iKeyLength; i++)
			*(lpStubData + iKeyPos + i) = *(sNewKey + i);
	}

	/* INSERT NEW SEPARATOR */
	UCHAR sSeparator[16] = STUB_DEFAULT_SEPARATOR;
	PUCHAR sNewSeparator;
	int iSeparatorLength = sizeof sSeparator;
	{
		int iSeparatorPos = FindSig(lpStubData, iStubSize, sSeparator, iSeparatorLength, 0);
		if (!iSeparatorPos) {
			printf("Separator in stub not found\n");
			MFREE(lpStubData);
			return -1;
		}

		printf("Separator position in stub start: %d\n", iSeparatorPos);
		printf("Separator position in stub end: %d\n", iSeparatorPos + iSeparatorLength);

		sNewSeparator = GenerateRandomString(iSeparatorLength);

		printf("Insert new separator into stub: '%s'\n", sNewSeparator);

		// replace default separator
		for (int i = 0; i < iSeparatorLength; i++)
			*(lpStubData + iSeparatorPos + i) = *(sNewSeparator + i);
	}

	memset(&size, 0, sizeof size);
	if (!GetFileSizeEx(hInputFile, &size)) {
		MFREE(lpStubData);
		return -1;
	}

	DWORD iInputSize = size.QuadPart;
	PUCHAR lpInputData = MALLOC(iInputSize * sizeof(UCHAR));
	if (!lpInputData) {
		MFREE(lpStubData);
		return -1;
	}

	DWORD iInputBytesReaded = 0;
	if (!ReadFile(hInputFile, lpInputData, iInputSize, &iInputBytesReaded, NULL) || 
		iInputBytesReaded != iInputSize ||
		!ValidatePE(lpInputData)
		) {
		printf("Unable to read input file\n");
		MFREE(lpStubData);
		MFREE(lpInputData);
		return -1;
	}

#if CRYPTER_USE_LZ4_COMPRESSION
	// do compress
	int iMaxCompressedSize = LZ4_compressBound(iInputSize);

	PUCHAR lpInputCompressedData = MALLOC(iMaxCompressedSize + sizeof(int));

	int iOldInputSize = iInputSize;

	iInputSize = LZ4_compress_HC(lpInputData, (char*)((int*)lpInputCompressedData + 1), iOldInputSize, iMaxCompressedSize, LZ4HC_CLEVEL_MAX) + sizeof(int);

	printf(
		"Input file size after compress: %dB\n"
		"Compress ratio: %.1f%%\n"
		, iInputSize, ((float)iInputSize / (float)iOldInputSize) * 100.f);

	MFREE(lpInputData);

	lpInputData = lpInputCompressedData;

	BinWrite32(lpInputData, iOldInputSize);
#endif

	XORBinary(lpInputData, iInputSize, sNewKey, iKeyLength);

	MFREE(sNewKey);

	int iOutputSize = iStubSize + iSeparatorLength + iInputSize;
	PUCHAR lpOutputData = MALLOC(iOutputSize * sizeof(UCHAR));

	int i = 0, j = 0;

	for (i = 0; i < iStubSize; i++)
		*(lpOutputData + j++) = *(lpStubData + i);

	MFREE(lpStubData);

	for (i = 0; i < iSeparatorLength; i++)
		*(lpOutputData + j++) = *(sNewSeparator + i);

	MFREE(sNewSeparator);

	for (i = 0; i < iInputSize; i++)
		*(lpOutputData + j++) = *(lpInputData + i);

	MFREE(lpInputData);
	
	printf("Total write bytes (stub & separator & input): %dB\n", j);

	DWORD dwOutputDataWritten = 0;
	WriteFile(hOutputFile, lpOutputData, iOutputSize, &dwOutputDataWritten, NULL);

	MFREE(lpOutputData);

	printf("Output file size: %dB\n", iOutputSize);

	return 0;
}

/*
 * Example of use: 
 * 
 * 1) without additional arguments
 * builder.exe cryptme.undefined_extension
 * builder.exe cryptme.exe
 * builder.exe C:\cryptme.exe
 * builder.exe "C:\test folder\crypt me.exe"
 * 
 * 2) with additional arguments
 * builder.exe -input cryptme.exe
 * builder.exe -input "D:\test\test.exe" -stub "C:\stub.exe"
 * builder.exe -input input.exe -output E:\output_crypted.www
 */

int main(int argc, char* argv[])
{
	LPCSTR	sOutputFilename = NULL,
		sInputFilename = NULL,
		sStubFilename = NULL;

	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-input"))
			sInputFilename = argv[++i];
		else if (!strcmp(argv[i], "-stub"))
			sStubFilename = argv[++i];
		else if (!strcmp(argv[i], "-output"))
			sOutputFilename = argv[++i];
	}

	if (argc < 3 || sInputFilename == NULL) {
		if (argc == 2 && sInputFilename == NULL) // if only one argument
			sInputFilename = argv[1];
		else { // if use additional arguments but..
			printf("Not enough arguments..\nExamples:\nbuilder.exe -input cryptme.exe \nbuilder.exe -input cryptme.exe -stub stub.exe -output crypted.exe\nbuilder.exe cryptme.exe");
			return 0;
		}
	}

#ifdef _DEBUG
	printf("%s-%s-%s\n",
		sInputFilename != NULL ? sInputFilename : "No",
		sStubFilename != NULL ? sStubFilename : "No",
		sOutputFilename != NULL ? sOutputFilename : "No"
	);
#endif

	char	sOutputFullpath[MAX_PATH] = { 0 },
		sInputFullpath[MAX_PATH] = { 0 },
		sStubFullpath[MAX_PATH] = { 0 };

	if (!GetFullPathNameA(sInputFilename, MAX_PATH, sInputFullpath, NULL)) {
		printf("Can't create full path of input file\n");
		return 0;
	}

	if (sStubFilename != NULL) {
		if (!GetFullPathNameA(sStubFilename, MAX_PATH, sStubFullpath, NULL)) {
			printf("Can't create full path of stub file\n");
			return 0;
		}
	}
	else {
		char* szCurrentFilepath = MALLOC(MAX_PATH * sizeof(char));
		GetModuleFileNameA(NULL, szCurrentFilepath, MAX_PATH);
		strcpy(sStubFullpath, szCurrentFilepath); // copy buffer
		MFREE(szCurrentFilepath);
		char* ofilename = strrchr(sStubFullpath, '\\') + 1; // get pointer to last "\" character of copied buffer
		memset(ofilename, 0, strlen(ofilename)); // remove filename & extension from filepath
		strcat(ofilename, "stub.exe"); // rename
	}

	if (sOutputFilename != NULL) {
		if (!GetFullPathNameA(sOutputFilename, MAX_PATH, sOutputFullpath, NULL)) {
			printf("Can't create full path of output file\n");
			return 0;
		}
	}
	else {
		strcpy(sOutputFullpath, sInputFullpath); // copy buffer
		char* ofilename = strrchr(sOutputFullpath, '\\') + 1; // get pointer to last "\" character of copied buffer
		char* ofileext = strrchr(ofilename, '.'); // get pointer lastest ".", to find extension
		char oextbuf[7] = { 0 }; // buffer for file extension
		strcpy(oextbuf, ofileext); // copy extension to buffer
		memset(ofileext, 0, strlen(ofileext)); // remove extension from filepath
		strcat(ofilename, "_crypted"); // append postfix
		strcat(ofilename, oextbuf); // append saved extension
	}

#ifdef _DEBUG
	printf("Input: %s\nStub: %s\nOutput: %s\n",
		sInputFullpath != NULL ? sInputFullpath : "No",
		sStubFullpath != NULL ? sStubFullpath : "No",
		sOutputFullpath != NULL ? sOutputFullpath : "No"
	);
#endif

	HANDLE hInputFile = CreateFileA(sInputFullpath, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE) {
		printf("Unable to open input file\n");
		return 0;
	}

	HANDLE hStubFile = CreateFileA(sStubFullpath, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hStubFile == INVALID_HANDLE_VALUE) {
		printf("Unable to open stub\n");
		return 0;
	}

	HANDLE hOutputFile = CreateFileA(sOutputFullpath, FILE_WRITE_DATA, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE) {
		printf("Unable to create output file\n");
		return 0;
	}

	int ret = CryptFile(hInputFile, hStubFile, hOutputFile);

	CloseHandle(hOutputFile);
	CloseHandle(hStubFile);
	CloseHandle(hInputFile);

	if (ret < 0)
		DeleteFileA(sOutputFullpath);

	return ret;
}