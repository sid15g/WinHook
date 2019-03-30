#include <Windows.h>
#include <detours.h>
#include <algorithm>
#include <iostream>
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

void APIPRIVATE log_call(std::string apiName) {

	std::string userprofile = getUserHome();
	logFile = userprofile + std::string("\\Desktop\\winhook.txt");
	//cout << logFile << endl;

	fopen_s(&pHookLog, (char*)logFile.c_str(), "a+");
//	fopen_s(&pHookLog, "C:\\Users\\WindowsPMA\\Desktop\\winhook.txt", "a+");

	if (!pHookLog) {
		cout << "File opening failed" << endl;
	}
	else {
		fprintf(pHookLog, "%s|%s\n", getCurrentDateTime(), (char*)apiName.c_str());
		fclose(pHookLog);
	}

}

void APIPRIVATE log_callA(std::string apiName) {
	log_call(apiName);
	msgBox((char*)apiName.c_str());
}

void APIPRIVATE attach() {
	DetourAttach(&(PVOID&)pRegCreateKeyExA, MyRegCreateKeyExA);
	DetourAttach(&(PVOID&)pRegCreateKeyExW, MyRegCreateKeyExW);
	DetourAttach(&(PVOID&)pRegSetValueExA, MyRegSetValueExA);
	DetourAttach(&(PVOID&)pRegSetValueExW, MyRegSetValueExW);
	DetourAttach(&(PVOID&)pRegCreateKeyA, MyRegCreateKeyA);
	DetourAttach(&(PVOID&)pRegCreateKeyW, MyRegCreateKeyW);
	DetourAttach(&(PVOID&)pRegDeleteKeyA, MyRegDeleteKeyA);
	DetourAttach(&(PVOID&)pRegDeleteKeyW, MyRegDeleteKeyW);
	DetourAttach(&(PVOID&)pRegCloseKey, MyRegCloseKey);

	DetourAttach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
	DetourAttach(&(PVOID&)pCreateThread, MyCreateThread);
	DetourAttach(&(PVOID&)pVirtualProtect, MyVirtualProtect);

	DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
	DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);
	
	//DetourAttach(&(PVOID&)change, change);
}

void APIPRIVATE detach() {
	DetourDetach(&(PVOID&)pRegCreateKeyExA, MyRegCreateKeyExA);
	DetourDetach(&(PVOID&)pRegCreateKeyExW, MyRegCreateKeyExW);
	DetourDetach(&(PVOID&)pRegSetValueExA, MyRegSetValueExA);
	DetourDetach(&(PVOID&)pRegSetValueExW, MyRegSetValueExW);
	DetourDetach(&(PVOID&)pRegCreateKeyA, MyRegCreateKeyA);
	DetourDetach(&(PVOID&)pRegCreateKeyW, MyRegCreateKeyW);
	DetourDetach(&(PVOID&)pRegDeleteKeyA, MyRegDeleteKeyA);
	DetourDetach(&(PVOID&)pRegDeleteKeyW, MyRegDeleteKeyW);
	DetourDetach(&(PVOID&)pRegCloseKey, MyRegCloseKey);

	DetourDetach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
	DetourDetach(&(PVOID&)pCreateThread, MyCreateThread);
	DetourDetach(&(PVOID&)pVirtualProtect, MyVirtualProtect);

	DetourDetach(&(PVOID&)pCreateFileA, MyCreateFileA);
	DetourDetach(&(PVOID&)pCreateFileW, MyCreateFileW);

	//DetourDetach(&(PVOID&)change, change);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

	switch (dwReason) {

		case DLL_PROCESS_ATTACH: {

			logFile = getUserHome() + std::string("\\Desktop\\winhook_" + getPid() +"_log.txt");
			//log_call("WinHook Loaded");

			DisableThreadLibraryCalls(hinst);
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			attach();
			if (DetourTransactionCommit() == NO_ERROR)
				OutputDebugString((LPCWSTR)"send() detoured successfully");
			break;
		}
		case DLL_PROCESS_DETACH: {

			log_call("WinHook Detached");
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			detach();
			if (DetourTransactionCommit() == NO_ERROR)
				OutputDebugString((LPCWSTR)"send() detoured successfully");
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
	return RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions,
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
	return RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions,
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
	return RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
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
	return RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

LSTATUS WINAPI MyRegCreateKeyA(
	HKEY hKey,
	LPCSTR lpSubKey,
	PHKEY phkResult
) {
	log_call("RegCreateKeyA");
	return RegCreateKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS WINAPI MyRegCreateKeyW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	PHKEY phkResult
) {
	log_call("RegCreateKeyW");
	return RegCreateKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS WINAPI MyRegDeleteKeyA(
	HKEY   hKey,
	LPCSTR lpSubKey
) {
	log_call("RegDeleteKeyA");
	return RegDeleteKeyA(hKey, lpSubKey);
}

LSTATUS WINAPI MyRegDeleteKeyW(
	HKEY   hKey,
	LPCWSTR lpSubKey
) {
	log_call("RegDeleteKeyW");
	return RegDeleteKeyW(hKey, lpSubKey);
}

LSTATUS WINAPI MyRegCloseKey(
	HKEY hKey
) {
	log_call("RegCloseKey");
	return RegCloseKey(hKey);
}

//====================================================================================

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
	return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
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
	return CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

BOOL WINAPI MyVirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) {
	log_call("VirtualProtect");
	return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

HANDLE WINAPI MyCreateFileA(
	LPCSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	log_call("CreateFileA");
	return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
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
	log_call("CreateFileW");
	return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}