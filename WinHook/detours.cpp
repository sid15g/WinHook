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

void init_log() {
	std::string userprofile = getUserHome();
	logFile = userprofile + std::string("\\Desktop\\winhook.txt");
	//cout << logFile << endl;
}

void APIPRIVATE log_call(std::string apiName) {

	msgBox((char*)"log call");
	fopen_s(&pHookLog, (char*)logFile.c_str(), "a+");
//	fopen_s(&pHookLog, "C:\\Users\\WindowsPMA\\Desktop\\winhook.txt", "a+");

	if (!pHookLog) {
		OutputDebugString((LPCWSTR)"File opening failed");
		msgBox((char*)"log failed");
	}
	else {
		msgBox((char*)"file opened");
		fprintf(pHookLog, "%s|%s\n", getCurrentDateTime(), (char*)apiName.c_str());
		fclose(pHookLog);
		msgBox((char*)"logged");
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
	/*
	Attach(&(PVOID&)pRegCreateKeyExA, MyRegCreateKeyExA);
	Attach(&(PVOID&)pRegCreateKeyExW, MyRegCreateKeyExW);
	Attach(&(PVOID&)pRegSetValueExA, MyRegSetValueExA);
	Attach(&(PVOID&)pRegSetValueExW, MyRegSetValueExW);
	Attach(&(PVOID&)pRegCreateKeyA, MyRegCreateKeyA);
	Attach(&(PVOID&)pRegCreateKeyW, MyRegCreateKeyW);
	Attach(&(PVOID&)pRegDeleteKeyA, MyRegDeleteKeyA);
	Attach(&(PVOID&)pRegDeleteKeyW, MyRegDeleteKeyW);
	Attach(&(PVOID&)pRegCloseKey, MyRegCloseKey);

	Attach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
	Attach(&(PVOID&)pCreateThread, MyCreateThread);
	Attach(&(PVOID&)pVirtualProtect, MyVirtualProtect);
	*/
	Attach(&(PVOID&)pCreateFileA, MyCreateFileA);
	Attach(&(PVOID&)pCreateFileW, MyCreateFileW);

	//Attach(&(PVOID&)change, change);
}

void APIPRIVATE detach_all() {
	/*
	Detach(&(PVOID&)pRegCreateKeyExA, MyRegCreateKeyExA);
	Detach(&(PVOID&)pRegCreateKeyExW, MyRegCreateKeyExW);
	Detach(&(PVOID&)pRegSetValueExA, MyRegSetValueExA);
	Detach(&(PVOID&)pRegSetValueExW, MyRegSetValueExW);
	Detach(&(PVOID&)pRegCreateKeyA, MyRegCreateKeyA);
	Detach(&(PVOID&)pRegCreateKeyW, MyRegCreateKeyW);
	Detach(&(PVOID&)pRegDeleteKeyA, MyRegDeleteKeyA);
	Detach(&(PVOID&)pRegDeleteKeyW, MyRegDeleteKeyW);
	Detach(&(PVOID&)pRegCloseKey, MyRegCloseKey);

	Detach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
	Detach(&(PVOID&)pCreateThread, MyCreateThread);
	Detach(&(PVOID&)pVirtualProtect, MyVirtualProtect);
	*/
	Detach(&(PVOID&)pCreateFileA, MyCreateFileA);
	Detach(&(PVOID&)pCreateFileW, MyCreateFileW);

	//Detach(&(PVOID&)change, change);
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
			//log_call("WinHook Loaded");
			msgBox((char*)logFile.c_str());

			DisableThreadLibraryCalls(hinst);
			attach_all();
			break;
		}
		case DLL_PROCESS_DETACH: {
			//log_call("WinHook Detached");
			detach_all();
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

BOOL WINAPI MyVirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) {
	log_call("VirtualProtect");
	return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
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