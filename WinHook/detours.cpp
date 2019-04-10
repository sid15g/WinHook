#include <algorithm>
#include <sstream>
#include <string>
#include <ctime>
#include <stdlib.h>
#include <map>

#include "stdafx.h"
#include "ApisHooked.h"
#include "utility.h"

using namespace std;

static bool EXPLORER = false;
static std::string logFile;
static FILE *pHookLog = NULL;
static map<std::string, int> logs;

void APIPRIVATE setExplorer(bool value) {
	EXPLORER = value;
}

std::string APIPRIVATE getUserHome() {
	char* buf = nullptr;
	size_t sz = 0;
	_dupenv_s(&buf, &sz, "USERPROFILE");
	//printf("%s\n", buf);
	return std::string(buf);
}

char* APIPRIVATE getCurrentDateTime() {

	const int size = 80 * sizeof(char);
	char* buf = (char*)calloc(80, sizeof(char));
	time_t now = time(0);
	struct tm  tstruct;
	memset(buf, '\0', size);

	localtime_s(&tstruct, &now);
	strftime(buf, size, "%Y %m %d.%X", &tstruct);
	return buf;
}

std::string APIPRIVATE getPid() {
	std::ostringstream stream;
	unsigned int pid = GetCurrentProcessId();
	stream << pid;
	return stream.str();
}

int APIPRIVATE msgBox(char* messg) {
	return MessageBoxA(
		NULL,
		(LPCSTR)messg,
		(LPCSTR)"WinHook Log",
		MB_USERICON | MB_DEFBUTTON2
	);
}

FILE* init_log() {
	std::string userprofile = getUserHome();
	logFile = userprofile + std::string("\\Desktop\\winhook.txt");
	//cout << logFile << endl;
	//	fopen_s(&pHookLog, "C:\\Users\\WindowsPMA\\Desktop\\winhook.txt", "a+");
	fopen_s(&pHookLog, (char*)logFile.c_str(), "a+");
	return pHookLog;
}

void APIPRIVATE printLogToFile() {
	map<std::string, int>::iterator it = logs.begin();

	while (it != logs.end()) {
		std::string apiName = it->first;
		int count = it->second;

		fprintf(pHookLog, " %s \t %d\n", (char*)apiName.c_str(), count);
		it++;
	}//end of loop

}

void APIPRIVATE log_call(std::string apiName) {
	if (!pHookLog) {
		OutputDebugString((LPCWSTR)"File opening failed");
	}
	else {
		map<std::string, int>::iterator it = logs.find(apiName);

		if ( it == logs.end()) {
			logs.insert(std::make_pair(apiName, 1));
		}
		else {
			logs[apiName] = it->second + 1;
		}
		
		if (EXPLORER) {
			fprintf(pHookLog, "%s|%s\n", getCurrentDateTime(), (char*)apiName.c_str());
		}
	}
}

void APIPRIVATE log_callA(std::string apiName) {
	log_call(apiName);
	msgBox((char*)apiName.c_str());
}

void APIPRIVATE Attach(PVOID *ppPointer, PVOID pDetour) {
	
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(ppPointer, pDetour);

	if (DetourTransactionCommit() == NO_ERROR) {
		OutputDebugString((LPCWSTR)" Detour Attach successfully");
	}
	else {
		OutputDebugString((LPCWSTR)" Detoured Attach failed");
	}

}

void APIPRIVATE Detach(PVOID *ppPointer, PVOID pDetour) {

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(ppPointer, pDetour);

	if (DetourTransactionCommit() == NO_ERROR) {
		OutputDebugString((LPCWSTR)" Detour Detach successfully");
	}
	else {
		OutputDebugString((LPCWSTR)" Detour Detach failed");
	}

}

void APIPRIVATE attach_all() {
	
	Attach(&(PVOID&)pRegCreateKeyExA, MyRegCreateKeyExA);
	Attach(&(PVOID&)pRegCreateKeyExW, MyRegCreateKeyExW);
	Attach(&(PVOID&)pRegSetValueExA, MyRegSetValueExA);
	Attach(&(PVOID&)pRegSetValueExW, MyRegSetValueExW);
	Attach(&(PVOID&)pRegCreateKeyA, MyRegCreateKeyA);
	Attach(&(PVOID&)pRegCreateKeyW, MyRegCreateKeyW);
	Attach(&(PVOID&)pRegDeleteKeyA, MyRegDeleteKeyA);
	Attach(&(PVOID&)pRegDeleteKeyW, MyRegDeleteKeyW);
	Attach(&(PVOID&)pRegCloseKey, MyRegCloseKey);

	Attach(&(PVOID&)pCreateToolhelp32Snapshot, MyCreateToolhelp32Snapshot);
	Attach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
	Attach(&(PVOID&)pCreateThread, MyCreateThread);

	
	Attach(&(PVOID&)pCreateFileA, MyCreateFileA);
	Attach(&(PVOID&)pCreateFileW, MyCreateFileW);
	Attach(&(PVOID&)pOpenFile, MyOpenFile);
	Attach(&(PVOID&)p_lopen, My_lopen);
	Attach(&(PVOID&)pDeleteFileA, MyDeleteFileA);
	Attach(&(PVOID&)pDeleteFileW, MyDeleteFileW);
	

	Attach(&(PVOID&)pOpenProcess, MyOpenProcess);
	Attach(&(PVOID&)pVirtualAlloc, MyVirtualAlloc);
	Attach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
	Attach(&(PVOID&)pVirtualQuery, MyVirtualQuery);
	Attach(&(PVOID&)pVirtualQueryEx, MyVirtualQueryEx);
	Attach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
	Attach(&(PVOID&)pCreateRemoteThreadEx, MyCreateRemoteThreadEx);
	Attach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);
	Attach(&(PVOID&)pReadProcessMemory, MyReadProcessMemory);
	

	Attach(&(PVOID&)pSetWindowsHookExA, MySetWindowsHookExA);
	Attach(&(PVOID&)pSetWindowsHookExW, MySetWindowsHookExW);
	Attach(&(PVOID&)pCallNextHookEx, MyCallNextHookEx);
	Attach(&(PVOID&)pUnhookWindowsHookEx, MyUnhookWindowsHookEx);

	Attach(&(PVOID&)pCryptBinaryToStringA, MyCryptBinaryToStringA);
	Attach(&(PVOID&)pCryptBinaryToStringW, MyCryptBinaryToStringW);
	Attach(&(PVOID&)pCreateEventA, MyCreateEventA);
	Attach(&(PVOID&)pCreateEventW, MyCreateEventW);
	Attach(&(PVOID&)pCreateEventExA, MyCreateEventExA);
	Attach(&(PVOID&)pCreateEventExW, MyCreateEventExW);

	Attach(&(PVOID&)pNtOpenFile, MyNtOpenFile);
	Attach(&(PVOID&)pNtCreateFile, MyNtCreateFile);
	Attach(&(PVOID&)pNtRenameKey, MyNtRenameKey);

	Attach(&(PVOID&)psocket, MySocket);
	Attach(&(PVOID&)psend, MySend);
	Attach(&(PVOID&)precv, MyRecv);
	Attach(&(PVOID&)plisten, MyListen);
	Attach(&(PVOID&)pconnect, MyConnect);
	Attach(&(PVOID&)pbind, MyBind);
	Attach(&(PVOID&)pgethostbyname, MyGethostbyname);
	Attach(&(PVOID&)pgethostbyaddr, MyGethostbyaddr);

	Attach(&(PVOID&)pIsDebuggerPresent, MyIsDebuggerPresent);
	Attach(&(PVOID&)pCheckRemoteDebuggerPresent, MyCheckRemoteDebuggerPresent);
	Attach(&(PVOID&)pOutputDebugStringA, MyOutputDebugStringA);
	Attach(&(PVOID&)pOutputDebugStringW, MyOutputDebugStringW);

	Attach(&(PVOID&)pURLDownloadToFile, MyURLDownloadToFile);
	Attach(&(PVOID&)pHttpOpenRequestA, MyHttpOpenRequestA);
	Attach(&(PVOID&)pHttpOpenRequestW, MyHttpOpenRequestW);
	Attach(&(PVOID&)pHttpSendRequestA, MyHttpSendRequestA);
	Attach(&(PVOID&)pHttpSendRequestW, MyHttpSendRequestW);
	Attach(&(PVOID&)pInternetConnectA, MyInternetConnectA);
	Attach(&(PVOID&)pInternetConnectW, MyInternetConnectW);
	Attach(&(PVOID&)pInternetCrackUrlA, MyInternetCrackUrlA);
	Attach(&(PVOID&)pInternetCrackUrlW, MyInternetCrackUrlW);
	Attach(&(PVOID&)pInternetOpenA, MyInternetOpenA);
	Attach(&(PVOID&)pInternetOpenW, MyInternetOpenW);
	Attach(&(PVOID&)pInternetOpenUrlA, MyInternetOpenUrlA);
	Attach(&(PVOID&)pInternetOpenUrlW, MyInternetOpenUrlW);

	Attach(&(PVOID&)pWinExec, MyWinExec);
	Attach(&(PVOID&)pSecureZeroMemory, MySecureZeroMemory);
	Attach(&(PVOID&)pmemcpy, MyMemcpy);
	Attach(&(PVOID&)pwmemcpy, MyWmemcpy);
	Attach(&(PVOID&)pmemcpy_s, MyMemcpy_s);
	Attach(&(PVOID&)pwmemcpy_s, MyWmemcpy_s);

	if (!EXPLORER) {
		Attach(&(PVOID&)pmemset, MyMemset);
		Attach(&(PVOID&)pwmemset, MyWmemset);
	}

	Attach(&(PVOID&)pVirtualProtect, MyVirtualProtect);
	Attach(&(PVOID&)pVirtualProtectEx, MyVirtualProtectEx);
	Attach(&(PVOID&)pLoadLibraryA, MyLoadLibraryA);
	Attach(&(PVOID&)pLoadLibraryW, MyLoadLibraryW);
	Attach(&(PVOID&)pLoadLibraryExA, MyLoadLibraryExA);
	Attach(&(PVOID&)pLoadLibraryExW, MyLoadLibraryExW);
	
}

void APIPRIVATE detach_all() {
	
	Detach(&(PVOID&)pRegCreateKeyExA, MyRegCreateKeyExA);
	Detach(&(PVOID&)pRegCreateKeyExW, MyRegCreateKeyExW);
	Detach(&(PVOID&)pRegSetValueExA, MyRegSetValueExA);
	Detach(&(PVOID&)pRegSetValueExW, MyRegSetValueExW);
	Detach(&(PVOID&)pRegCreateKeyA, MyRegCreateKeyA);
	Detach(&(PVOID&)pRegCreateKeyW, MyRegCreateKeyW);
	Detach(&(PVOID&)pRegDeleteKeyA, MyRegDeleteKeyA);
	Detach(&(PVOID&)pRegDeleteKeyW, MyRegDeleteKeyW);
	Detach(&(PVOID&)pRegCloseKey, MyRegCloseKey);

	Detach(&(PVOID&)pCreateToolhelp32Snapshot, MyCreateToolhelp32Snapshot);
	Detach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
	Detach(&(PVOID&)pCreateThread, MyCreateThread);
	
	
	Detach(&(PVOID&)pCreateFileA, MyCreateFileA);
	Detach(&(PVOID&)pCreateFileW, MyCreateFileW);
	Detach(&(PVOID&)pOpenFile, MyOpenFile);
	Detach(&(PVOID&)p_lopen, My_lopen);
	Detach(&(PVOID&)pDeleteFileA, MyDeleteFileA);
	Detach(&(PVOID&)pDeleteFileW, MyDeleteFileW);
	

	Detach(&(PVOID&)pOpenProcess, MyOpenProcess);
	Detach(&(PVOID&)pVirtualAlloc, MyVirtualAlloc);
	Detach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
	Detach(&(PVOID&)pVirtualQuery, MyVirtualQuery);
	Detach(&(PVOID&)pVirtualQueryEx, MyVirtualQueryEx);
	Detach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
	Detach(&(PVOID&)pCreateRemoteThreadEx, MyCreateRemoteThreadEx);
	Detach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);
	Detach(&(PVOID&)pReadProcessMemory, MyReadProcessMemory);
	

	Detach(&(PVOID&)pSetWindowsHookExA, MySetWindowsHookExA);
	Detach(&(PVOID&)pSetWindowsHookExW, MySetWindowsHookExW);
	Detach(&(PVOID&)pCallNextHookEx, MyCallNextHookEx);
	Detach(&(PVOID&)pUnhookWindowsHookEx, MyUnhookWindowsHookEx);


	Detach(&(PVOID&)pCryptBinaryToStringA, MyCryptBinaryToStringA);
	Detach(&(PVOID&)pCryptBinaryToStringW, MyCryptBinaryToStringW);
	Detach(&(PVOID&)pCreateEventA, MyCreateEventA);
	Detach(&(PVOID&)pCreateEventW, MyCreateEventW);
	Detach(&(PVOID&)pCreateEventExA, MyCreateEventExA);
	Detach(&(PVOID&)pCreateEventExW, MyCreateEventExW);

	Detach(&(PVOID&)pNtOpenFile, MyNtOpenFile);
	Detach(&(PVOID&)pNtCreateFile, MyNtCreateFile);
	Detach(&(PVOID&)pNtRenameKey, MyNtRenameKey);

	Detach(&(PVOID&)psocket, MySocket);
	Detach(&(PVOID&)psend, MySend);
	Detach(&(PVOID&)precv, MyRecv);
	Detach(&(PVOID&)plisten, MyListen);
	Detach(&(PVOID&)pconnect, MyConnect);
	Detach(&(PVOID&)pbind, MyBind);
	Detach(&(PVOID&)pgethostbyname, MyGethostbyname);
	Detach(&(PVOID&)pgethostbyaddr, MyGethostbyaddr);

	Detach(&(PVOID&)pIsDebuggerPresent, MyIsDebuggerPresent);
	Detach(&(PVOID&)pCheckRemoteDebuggerPresent, MyCheckRemoteDebuggerPresent);
	Detach(&(PVOID&)pOutputDebugStringA, MyOutputDebugStringA);
	Detach(&(PVOID&)pOutputDebugStringW, MyOutputDebugStringW);

	Detach(&(PVOID&)pURLDownloadToFile, MyURLDownloadToFile);
	Detach(&(PVOID&)pHttpOpenRequestA, MyHttpOpenRequestA);
	Detach(&(PVOID&)pHttpOpenRequestW, MyHttpOpenRequestW);
	Detach(&(PVOID&)pHttpSendRequestA, MyHttpSendRequestA);
	Detach(&(PVOID&)pHttpSendRequestW, MyHttpSendRequestW);
	Detach(&(PVOID&)pInternetConnectA, MyInternetConnectA);
	Detach(&(PVOID&)pInternetConnectW, MyInternetConnectW);
	Detach(&(PVOID&)pInternetCrackUrlA, MyInternetCrackUrlA);
	Detach(&(PVOID&)pInternetCrackUrlW, MyInternetCrackUrlW);
	Detach(&(PVOID&)pInternetOpenA, MyInternetOpenA);
	Detach(&(PVOID&)pInternetOpenW, MyInternetOpenW);
	Detach(&(PVOID&)pInternetOpenUrlA, MyInternetOpenUrlA);
	Detach(&(PVOID&)pInternetOpenUrlW, MyInternetOpenUrlW);

	Detach(&(PVOID&)pWinExec, MyWinExec);
	Detach(&(PVOID&)pSecureZeroMemory, MySecureZeroMemory);
	Detach(&(PVOID&)pmemcpy, MyMemcpy);
	Detach(&(PVOID&)pwmemcpy, MyWmemcpy);
	Detach(&(PVOID&)pmemcpy_s, MyMemcpy_s);
	Detach(&(PVOID&)pwmemcpy_s, MyWmemcpy_s);
	if (!EXPLORER) {
		Detach(&(PVOID&)pmemset, MyMemset);
		Detach(&(PVOID&)pwmemset, MyWmemset);
	}

	Detach(&(PVOID&)pVirtualProtect, MyVirtualProtect);
	Detach(&(PVOID&)pVirtualProtectEx, MyVirtualProtectEx);
	Detach(&(PVOID&)pLoadLibraryA, MyLoadLibraryA);
	Detach(&(PVOID&)pLoadLibraryW, MyLoadLibraryW);
	Detach(&(PVOID&)pLoadLibraryExA, MyLoadLibraryExA);
	Detach(&(PVOID&)pLoadLibraryExW, MyLoadLibraryExW);
	
}

void APIPRIVATE safe_log_callA() {
	Detach(&(PVOID&)pCreateFileA, MyCreateFileA);
	log_call("CreateFileA");
	Attach(&(PVOID&)pCreateFileA, MyCreateFileA);
}

void APIPRIVATE safe_log_callW() {
	Detach(&(PVOID&)pCreateFileW, MyCreateFileW);
	log_call("CreateFileW");
	Attach(&(PVOID&)pCreateFileW, MyCreateFileW);
}

void APIPRIVATE safe_log_callNT() {
	Detach(&(PVOID&)pNtCreateFile, MyNtCreateFile);
	log_call("NtCreateFile");
	Attach(&(PVOID&)pNtCreateFile, MyNtCreateFile);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

	switch (dwReason) {
		case DLL_THREAD_ATTACH:
		case DLL_PROCESS_ATTACH: {
			logFile = getUserHome() + std::string("\\Desktop\\winhook_" + getPid() +"_log.txt");
			fopen_s(&pHookLog, (char*)logFile.c_str(), "a+");

			//log_call("WinHook Loaded");
			//msgBox((char*)logFile.c_str());

			DisableThreadLibraryCalls(hinst);
			attach_all();
		}
		break;
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH: {
			//log_call("WinHook Detached");
			detach_all();

			printLogToFile();
			fclose(pHookLog);
		}
		break;
	}
	return TRUE;

}//end of main

//====================================================================================

LSTATUS WINAPI MyRegCreateKeyExA(
	HKEY                        hKey,
	LPCSTR                      lpSubKey,
	DWORD                       Reserved,
	LPSTR                       lpClass,
	DWORD                       dwOptions,
	REGSAM                      samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY                       phkResult,
	LPDWORD                     lpdwDisposition
) {
	log_call("RegCreateKeyExA");
	return pRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions,
		samDesired, lpSecurityAttributes, phkResult, lpdwDisposition );
}

LSTATUS WINAPI MyRegCreateKeyExW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD Reserved,
	LPWSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
) {
	log_call("RegCreateKeyExW");
	return pRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions,
		samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

LSTATUS WINAPI MyRegSetValueExA(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
) {
	log_call("RegSetValueExA");
	return pRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

LSTATUS WINAPI MyRegSetValueExW(
	HKEY hKey,
	LPCWSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
) {
	log_call("RegSetValueExW");
	return pRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

LSTATUS WINAPI MyRegCreateKeyA(
	HKEY hKey,
	LPCSTR lpSubKey,
	PHKEY phkResult
) {
	log_call("RegCreateKeyA");
	return pRegCreateKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS WINAPI MyRegCreateKeyW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	PHKEY phkResult
) {
	log_call("RegCreateKeyW");
	return pRegCreateKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS WINAPI MyRegDeleteKeyA(
	HKEY   hKey,
	LPCSTR lpSubKey
) {
	log_call("RegDeleteKeyA");
	return pRegDeleteKeyA(hKey, lpSubKey);
}

LSTATUS WINAPI MyRegDeleteKeyW(
	HKEY   hKey,
	LPCWSTR lpSubKey
) {
	log_call("RegDeleteKeyW");
	return pRegDeleteKeyW(hKey, lpSubKey);
}

LSTATUS WINAPI MyRegCloseKey(
	HKEY hKey
) {
	log_call("RegCloseKey");
	return pRegCloseKey(hKey);
}

//====================================================================================

HANDLE WINAPI MyCreateToolhelp32Snapshot(
	DWORD dwFlags,
	DWORD th32ProcessID
) {
	log_call("CreateToolhelp32Snapshot");
	return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}


BOOL WINAPI MyCreateProcessA(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
) {
	log_call("CreateProcessA");
	return pCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

HANDLE WINAPI MyCreateThread(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
) {
	log_call("CreateThread");
	return pCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE WINAPI MyOpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
) {
	log_call("OpenProcess");
	return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

LPVOID WINAPI MyVirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
) {
	log_call("VirtualAlloc");
	return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID WINAPI MyVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
) {
	log_call("VirtualAllocEx");
	return pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

HANDLE WINAPI MyCreateRemoteThread(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
) {
	log_call("CreateRemoteThread");
	return pCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE WINAPI MyCreateRemoteThreadEx(
	HANDLE                       hProcess,
	LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	SIZE_T                       dwStackSize,
	LPTHREAD_START_ROUTINE       lpStartAddress,
	LPVOID                       lpParameter,
	DWORD                        dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD                      lpThreadId
) {
	log_call("CreateRemoteThreadEx");
	return pCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}

BOOL WINAPI MyWriteProcessMemory(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
) {
	log_call("WriteProcessMemory");
	return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL WINAPI MyReadProcessMemory(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesRead
) {
	log_call("ReadProcessMemory");
	return pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL WINAPI MyVirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) {
	log_call("VirtualProtect");
	return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL WINAPI MyVirtualProtectEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) {
	log_call("VirtualProtectEx");
	return pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

SIZE_T WINAPI MyVirtualQuery(
	LPCVOID                   lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T                    dwLength
) {
	log_call("VirtualQuery");
	return pVirtualQuery(lpAddress, lpBuffer, dwLength);
}

SIZE_T WINAPI MyVirtualQueryEx(
	HANDLE                    hProcess,
	LPCVOID                   lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T                    dwLength
) {
	log_call("VirtualQueryEx");
	return pVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
}

HMODULE WINAPI MyLoadLibraryA(
	LPCSTR lpLibFileName
) {
	log_call("LoadLibraryA");
	return pLoadLibraryA(lpLibFileName);
}

HMODULE WINAPI MyLoadLibraryW(
	LPCWSTR lpLibFileName
) {
	log_call("LoadLibraryW");
	return pLoadLibraryW(lpLibFileName);
}

HMODULE WINAPI MyLoadLibraryExA(
	LPCSTR lpLibFileName,
	HANDLE hFile,
	DWORD  dwFlags
) {
	log_call("LoadLibraryExA");
	return pLoadLibraryExA(lpLibFileName, hFile, dwFlags);
}

HMODULE WINAPI MyLoadLibraryExW(
	LPCWSTR lpLibFileName,
	HANDLE hFile,
	DWORD  dwFlags
) {
	log_call("LoadLibraryExW");
	return pLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

//====================================================================================

HANDLE WINAPI MyCreateFileA(
	LPCSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	safe_log_callA();
	return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	safe_log_callW();
	return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


HFILE WINAPI MyOpenFile(
	LPCSTR     lpFileName,
	LPOFSTRUCT lpReOpenBuff,
	UINT       uStyle
) {
	log_call("OpenFile");
	return pOpenFile(lpFileName, lpReOpenBuff, uStyle);
}

HFILE WINAPI My_lopen(
	LPCSTR lpPathName,
	int iReadWrite
) {
	log_call("_lopen");
	return p_lopen(lpPathName, iReadWrite);
}

BOOL WINAPI MyDeleteFileA(
	LPCSTR lpFileName
) {
	log_call("DeleteFileA");
	return pDeleteFileA(lpFileName);
}

BOOL WINAPI MyDeleteFileW(
	LPCWSTR lpFileName
) {
	log_call("DeleteFileW");
	return pDeleteFileW(lpFileName);
}

//====================================================================================

HHOOK WINAPI MySetWindowsHookExA(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId
) {
	log_call("SetWindowsHookExA");
	return pSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
}

HHOOK WINAPI MySetWindowsHookExW(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId
) {
	log_call("SetWindowsHookExW");
	return pSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
}

LRESULT WINAPI MyCallNextHookEx(
	HHOOK  hhk,
	int    nCode,
	WPARAM wParam,
	LPARAM lParam
) {
	log_call("CallNextHookEx");
	return pCallNextHookEx(hhk, nCode, wParam, lParam);
}

BOOL WINAPI MyUnhookWindowsHookEx(
	HHOOK hhk
) {
	log_call("UnhookWindowsHookEx");
	return pUnhookWindowsHookEx(hhk);
}

//====================================================================================

BOOL WINAPI MyCryptBinaryToStringA(
	const BYTE *pbBinary,
	DWORD      cbBinary,
	DWORD      dwFlags,
	LPSTR      pszString,
	DWORD      *pcchString
) {
	log_call("CryptBinaryToStringA");	
	return pCryptBinaryToStringA(pbBinary, cbBinary, dwFlags, pszString, pcchString);
}

BOOL WINAPI MyCryptBinaryToStringW(
	const BYTE *pbBinary,
	DWORD      cbBinary,
	DWORD      dwFlags,
	LPWSTR      pszString,
	DWORD      *pcchString
) {
	log_call("CryptBinaryToStringW");
	return pCryptBinaryToStringW(pbBinary, cbBinary, dwFlags, pszString, pcchString);
}

HANDLE WINAPI MyCreateEventA(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCSTR                lpName
) {
	log_call("CreateEventA");
	return pCreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
}

HANDLE WINAPI MyCreateEventW(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCWSTR               lpName
) {
	log_call("CreateEventW");
	return pCreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
}

HANDLE WINAPI MyCreateEventExA(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	LPCSTR                lpName,
	DWORD                 dwFlags,
	DWORD                 dwDesiredAccess
) {
	log_call("CreateEventExA");
	return pCreateEventExA(lpEventAttributes, lpName, dwFlags, dwDesiredAccess);
}

HANDLE WINAPI MyCreateEventExW(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	LPCWSTR               lpName,
	DWORD                 dwFlags,
	DWORD                 dwDesiredAccess
) {
	log_call("CreateEventExW");
	return pCreateEventExW(lpEventAttributes, lpName, dwFlags, dwDesiredAccess);
}

//====================================================================================


NTSTATUS WINAPI MyNtOpenFile(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN ULONG              ShareAccess,
	IN ULONG              OpenOptions
) {
	log_call("NtOpenFile");
	return pNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS WINAPI MyNtCreateFile(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength
) {
	safe_log_callNT();
	return pNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, 
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS WINAPI MyNtRenameKey(
	HANDLE          KeyHandle,
	PUNICODE_STRING NewName
) {
	log_call("NtRenameKey");
	return pNtRenameKey(KeyHandle, NewName);
}

//====================================================================================

SOCKET WINAPI MySocket(
	int af,
	int type,
	int protocol
) {
	log_call("socket");
	return psocket(af, type, protocol);
}

int WINAPI MySend(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
) {
	log_call("send");
	return psend(s, buf, len, flags);
}

int WINAPI MyRecv(
	SOCKET s,
	char   *buf,
	int    len,
	int    flags
) {
	log_call("recv");
	return precv(s, buf, len, flags);
}

int WINAPI MyListen(
	SOCKET s,
	int backlog
) {
	log_call("listen");
	return plisten(s, backlog);
}

int WINAPI MyConnect(
	SOCKET s,
	const struct sockaddr *name,
	int namelen
) {
	log_call("connect");
	return pconnect(s, name, namelen);
}

int WINAPI MyBind(
	SOCKET s,
	const struct sockaddr *addr,
	int namelen
) {
	log_call("bind");
	return pbind(s, addr, namelen);
}

hostent* WINAPI MyGethostbyname(
	const char *name
) {
	log_call("gethostbyname");
	return pgethostbyname(name);
}

hostent* WINAPI MyGethostbyaddr(
	const char *addr,
	int        len,
	int        type
) {
	log_call("gethostbyaddr");
	return pgethostbyaddr(addr, len, type);
}

//====================================================================================

BOOL WINAPI MyIsDebuggerPresent(void) {
	log_call("IsDebuggerPresent");
	return pIsDebuggerPresent();
}

BOOL WINAPI MyCheckRemoteDebuggerPresent(
	HANDLE hProcess,
	PBOOL  pbDebuggerPresent
) {
	log_call("CheckRemoteDebuggerPresent");
	return pCheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
}

void WINAPI MyOutputDebugStringA(
	LPCSTR lpOutputString
) {
	log_call("OutputDebugStringA");
	return pOutputDebugStringA(lpOutputString);
}

void WINAPI MyOutputDebugStringW(
	LPCWSTR lpOutputString
) {
	log_call("OutputDebugStringW");
	return pOutputDebugStringW(lpOutputString);
}

//====================================================================================

void* __cdecl MyMemcpy(
	void *dest,
	const void *src,
	size_t count
) {
	log_call("memcpy");
	return pmemcpy(dest, src, count);
}

wchar_t* __cdecl MyWmemcpy(
	wchar_t *dest,
	const wchar_t *src,
	size_t count
) {
	log_call("wmemcpy");
	return pwmemcpy(dest, src, count);
}

errno_t __cdecl MyMemcpy_s(
	void *dest,
	size_t destSize,
	const void *src,
	size_t count
) {
	log_call("memcpy_s");
	return pmemcpy_s(dest, destSize, src, count);
}

errno_t __cdecl MyWmemcpy_s(
	wchar_t *dest,
	size_t destSize,
	const wchar_t *src,
	size_t count
) {
	log_call("wmemcpy_s");
	return pwmemcpy_s(dest, destSize, src, count);
}

void* __cdecl MyMemset(
	void *dest,
	int c,
	size_t count
) {
	log_call("memset");
	return pmemset(dest, c, count);
}

wchar_t* __cdecl MyWmemset(
	wchar_t *dest,
	wchar_t c,
	size_t count
) {
	log_call("wmemset");
	return pwmemset(dest, c, count);
}

PVOID __cdecl MySecureZeroMemory(
	PVOID  ptr,
	SIZE_T cnt
) {
	log_call("SecureZeroMemory");
	return pSecureZeroMemory(ptr, cnt);
}

UINT WINAPI MyWinExec(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
) {
	log_call("WinExec");
	return pWinExec(lpCmdLine, uCmdShow);
}

//====================================================================================

HRESULT WINAPI MyURLDownloadToFile(
	LPUNKNOWN            pCaller,
	LPCTSTR              szURL,
	LPCTSTR              szFileName,
	DWORD                dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
) {
	log_call("URLDownloadToFile");
	return pURLDownloadToFile(pCaller, szURL, szFileName, dwReserved, lpfnCB);
}

HINTERNET WINAPI MyHttpOpenRequestA(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR    *lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
) {
	log_call("HttpOpenRequestA");
	return pHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion,
		lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
}

HINTERNET WINAPI MyHttpOpenRequestW(
	HINTERNET hConnect,
	LPCWSTR    lpszVerb,
	LPCWSTR    lpszObjectName,
	LPCWSTR    lpszVersion,
	LPCWSTR    lpszReferrer,
	LPCWSTR    *lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
) {
	log_call("HttpOpenRequestW");
	return pHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion,
		lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
}

BOOL WINAPI MyHttpSendRequestA(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
) {
	log_call("HttpSendRequestA");
	return pHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI MyHttpSendRequestW(
	HINTERNET hRequest,
	LPCWSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
) {
	log_call("HttpSendRequestW");
	return pHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

HINTERNET WINAPI MyInternetConnectA(
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
) {
	log_call("InternetConnectA");
	return pInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword,
		dwService, dwFlags, dwContext);
}

HINTERNET WINAPI MyInternetConnectW(
	HINTERNET     hInternet,
	LPCWSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCWSTR        lpszUserName,
	LPCWSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
) {
	log_call("InternetConnectW");
	return pInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword,
		dwService, dwFlags, dwContext);
}

BOOL WINAPI MyInternetCrackUrlA(
	LPCSTR            lpszUrl,
	DWORD             dwUrlLength,
	DWORD             dwFlags,
	LPURL_COMPONENTSA lpUrlComponents
) {
	log_call("InternetCrackUrlA");
	return pInternetCrackUrlA(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
}

BOOL WINAPI MyInternetCrackUrlW(
	LPCWSTR            lpszUrl,
	DWORD             dwUrlLength,
	DWORD             dwFlags,
	LPURL_COMPONENTSW lpUrlComponents
) {
	log_call("InternetCrackUrlW");
	return pInternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
}

HINTERNET WINAPI MyInternetOpenA(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
) {
	log_call("InternetOpenA");
	return pInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HINTERNET WINAPI MyInternetOpenW(
	LPCWSTR lpszAgent,
	DWORD  dwAccessType,
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD  dwFlags
) {
	log_call("InternetOpenW");
	return pInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HINTERNET WINAPI MyInternetOpenUrlA(
	HINTERNET hInternet,
	LPCSTR    lpszUrl,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
) {
	log_call("InternetOpenUrlA");
	return pInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

HINTERNET WINAPI MyInternetOpenUrlW(
	HINTERNET hInternet,
	LPCWSTR    lpszUrl,
	LPCWSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
) {
	log_call("InternetOpenUrlW");
	return pInternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

//====================================================================================