#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <time.h>

#include "stdafx.h"
#include "ApisHooked.h"

using namespace std;

std::string logFile;
FILE *pHookLog;

std::string APIPRIVATE getCurrentDateTime() {

	char* buf = (char*)malloc(sizeof(char) * 80);
	time_t     now = time(0);
	struct tm  tstruct;
	memset(buf, '\0', sizeof(buf));

	localtime_s(&tstruct, &now);
	strftime(buf, sizeof(buf), "%Y%m%d%X", &tstruct);
	return std::string(buf);
}

std::string APIPRIVATE getPid() {
	std::ostringstream stream;
	unsigned int pid = GetCurrentProcessId();
	stream << pid;
	return stream.str();
}

void APIPRIVATE log_call(std::string apiName) {
	fopen_s(&pHookLog, (char*)logFile.c_str(), "a+");
	fprintf(pHookLog, "%s\n", (char*)apiName.c_str());
	fclose(pHookLog);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

	switch (dwReason) {

		case DLL_PROCESS_ATTACH: {

			std::string pid = getPid();
			logFile = "C:\\winhook_" + pid + "_" + getCurrentDateTime() +".txt";

			DisableThreadLibraryCalls(hinst);
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
			if (DetourTransactionCommit() == NO_ERROR)
				OutputDebugString((LPCWSTR)"send() detoured successfully");
			break;
		}
		case DLL_PROCESS_DETACH: {
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
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