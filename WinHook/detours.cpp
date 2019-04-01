#include <algorithm>
#include <sstream>
#include <string>
#include <ctime>
#include <stdlib.h>

#include "stdafx.h"
#include "ApisHooked.h"
#include "utility.h"

using namespace std;


static std::string logFile;
static FILE *pHookLog = NULL;

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

void APIPRIVATE log_call(std::string apiName) {
	if (!pHookLog) {
		OutputDebugString((LPCWSTR)"File opening failed");
	}
	else {
		fprintf(pHookLog, "%s|%s\n", getCurrentDateTime(), (char*)apiName.c_str());
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
	//Attach(&(PVOID&)pCreateFileW, MyCreateFileW);
	Attach(&(PVOID&)pOpenFile, MyOpenFile);
	Attach(&(PVOID&)pDeleteFileA, MyDeleteFileA);
	Attach(&(PVOID&)pDeleteFileW, MyDeleteFileW);
	

	Attach(&(PVOID&)pOpenProcess, MyOpenProcess);
	Attach(&(PVOID&)pVirtualAlloc, MyVirtualAlloc);
	Attach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
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

	/*
	Attach(&(PVOID&)pVirtualProtect, MyVirtualProtect);
	Attach(&(PVOID&)pVirtualProtectEx, MyVirtualProtectEx);
	Attach(&(PVOID&)pLoadLibraryA, MyLoadLibraryA);
	Attach(&(PVOID&)pLoadLibraryW, MyLoadLibraryW);
	Attach(&(PVOID&)pLoadLibraryExA, MyLoadLibraryExA);
	Attach(&(PVOID&)pLoadLibraryExW, MyLoadLibraryExW);
	*/
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
	//Detach(&(PVOID&)pCreateFileW, MyCreateFileW);
	Detach(&(PVOID&)pOpenFile, MyOpenFile);
	Detach(&(PVOID&)pDeleteFileA, MyDeleteFileA);
	Detach(&(PVOID&)pDeleteFileW, MyDeleteFileW);

	Detach(&(PVOID&)pOpenProcess, MyOpenProcess);
	Detach(&(PVOID&)pVirtualAlloc, MyVirtualAlloc);
	Detach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
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

	/*
	Detach(&(PVOID&)pVirtualProtect, MyVirtualProtect);
	Detach(&(PVOID&)pVirtualProtectEx, MyVirtualProtectEx);
	Detach(&(PVOID&)pLoadLibraryA, MyLoadLibraryA);
	Detach(&(PVOID&)pLoadLibraryW, MyLoadLibraryW);
	Detach(&(PVOID&)pLoadLibraryExA, MyLoadLibraryExA);
	Detach(&(PVOID&)pLoadLibraryExW, MyLoadLibraryExW);
	*/
}

void APIPRIVATE safe_log_callA(std::string apiName) {
	Detach(&(PVOID&)pCreateFileA, MyCreateFileA);
	log_call(apiName);
	Attach(&(PVOID&)pCreateFileA, MyCreateFileA);
}

void APIPRIVATE safe_log_callW(std::string apiName) {
	Detach(&(PVOID&)pCreateFileW, MyCreateFileW);
	log_call(apiName);
	Attach(&(PVOID&)pCreateFileW, MyCreateFileW);
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

	switch (dwReason) {

		case DLL_PROCESS_ATTACH: {
			logFile = getUserHome() + std::string("\\Desktop\\winhook_" + getPid() +"_log.txt");
			fopen_s(&pHookLog, (char*)logFile.c_str(), "a+");

			//log_call("WinHook Loaded");
			//msgBox((char*)logFile.c_str());

			DisableThreadLibraryCalls(hinst);
			attach_all();
			break;
		}
		case DLL_PROCESS_DETACH: {
			//log_call("WinHook Detached");
			detach_all();
			fclose(pHookLog);
			break;
		}
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
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
	safe_log_callA("CreateFileA");
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
	safe_log_callW("CreateFileW");
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