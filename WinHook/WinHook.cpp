// WinHook.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <string>
#include <tlhelp32.h>
#include <iostream>
#include <clocale>
#include <locale>
#include <vector>

#include "pedump.h"
#include "winhook.h"
#include "stdafx.h"

using namespace std;

/*
	Reference: https://stackoverflow.com/questions/4804298/how-to-convert-wstring-into-string
*/
std::string convert(std::wstring ws) {
	std::setlocale(LC_ALL, "");
	const std::locale locale("");
	typedef std::codecvt<wchar_t, char, std::mbstate_t> converter_type;
	const converter_type& converter = std::use_facet<converter_type>(locale);
	std::vector<char> to(ws.length() * converter.max_length());
	std::mbstate_t state;
	const wchar_t* from_next;
	char* to_next;
	const converter_type::result result = converter.out(state, ws.data(), ws.data() + ws.length(), from_next, &to[0], &to[0] + to.size(), to_next);
	if (result == converter_type::ok or result == converter_type::noconv) {
		const std::string s(&to[0], to_next);
		//std::cout << "std::string =     " << s << std::endl;
		return s;
	}
	return NULL;
}

/**
  Reference: Microsoft Documents

  typedef struct _PROCESS_INFORMATION {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD  dwProcessId;
	DWORD  dwThreadId;
  } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

*/

LPPROCESS_INFORMATION open_process(char *lpApplicationName, int wait_time) {

	STARTUPINFOA si;
	LPPROCESS_INFORMATION pi = (PROCESS_INFORMATION*)malloc(sizeof(PROCESS_INFORMATION));

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(si);

	printf(" Creating process with file path %s.\n", lpApplicationName);

	if (CreateProcessA(lpApplicationName,
		(LPSTR)L"",           // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0, //CREATE_NEW_CONSOLE,
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory
		&si,            // Pointer to STARTUPINFO structure
		pi             // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
	)) {
		WaitForInputIdle(pi->hProcess, wait_time);
		//CloseHandle( pi.hProcess );
		//CloseHandle( pi.hThread );
	} else {
		printf("CreateProcess Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
	}

	return pi;

}//end of Function


PROCESSENTRY32* snapshotAllProcesses(DWORD processId) {

	PROCESSENTRY32 *pe32 = (PROCESSENTRY32*)malloc(sizeof(PROCESSENTRY32));

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
	}
	else {
		pe32->dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hProcessSnap, pe32))
		{
			printf("Process32First Failed, GetLastError() = %u\n", (uint32_t)GetLastError()); // show cause of failure
			CloseHandle(hProcessSnap);          // clean the snapshot object
		}
		else {
			do {

				_tprintf(TEXT(" Reading Process (%s) : (%lu)"), pe32->szExeFile, pe32->th32ProcessID);

				// Retrieve the priority class.
				DWORD dwPriorityClass = 0;
				HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pe32->th32ProcessID);

				if (hProcess == NULL)
					printf("OpenProcess Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
				else if (pe32->th32ProcessID == processId) {
					CloseHandle(hProcessSnap);
					return pe32;
				}

			} while (Process32Next(hProcessSnap, pe32) );
		}
	}

	CloseHandle(hProcessSnap);
	return NULL;
}


MODULEENTRY32* snapshotAllModules(DWORD processId, std::string dllName) {

	MODULEENTRY32 *me32 = (MODULEENTRY32*)malloc(sizeof(MODULEENTRY32));

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, processId);

	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
	}
	else {
		me32->dwSize = sizeof(MODULEENTRY32);

		if (!Module32First(hModuleSnap, me32))
		{
			printf("Module32First Failed, GetLastError() = %u\n", (uint32_t)GetLastError()); // show cause of failure
			CloseHandle(hModuleSnap);
		}
		else {
			do {

				std::wstring moduleName = std::wstring(me32->szModule);
				std::wcout << moduleName << '\n';

				if (me32->szModule == NULL)
					printf("Module32Next Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
				else if (dllName.compare((char*)moduleName.c_str()) == 0) {	
					printf("=========== Module Found =============\n");
					CloseHandle(hModuleSnap);
					return me32;
				}

			} while (Module32Next(hModuleSnap, me32));
		}
	}

	CloseHandle(hModuleSnap);
	return NULL;
}

HMODULE enum_modules(HANDLE hProcess, std::string dllName) {

	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	HMODULE hMods[1024];
	DWORD cbNeeded;
	long unsigned int i;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {

		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			if (GetModuleFileNameEx(hProcess, hMods[i], szProcessName, sizeof(szProcessName) / sizeof(TCHAR)))
			{
				std::wstring mname = std::wstring(szProcessName);
				std::string mnamestr = convert(mname);

//				_tprintf(TEXT("\tName: %s\n"), szProcessName);
				
				if ( dllName.compare(std::string(mnamestr)) == 0) {
					cout << "=========== Module Found =============" << endl;
					cout << "\tModule Name: " << mnamestr << endl;
					printf("\tLocation (0x%08X)\n", (unsigned int)hMods[i] );
					return hMods[i];
				}
				else {
					//cout << "\tModule Name: " << mnamestr << endl;
				}
			}
			else {
				printf("GetModuleFileNameEx Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
			}
		}//end of loop

	}
	else {
		printf("EnumProcessModules Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
	}
	
	return NULL;

}//end of function


bool stricompare(std::string str1, std::string str2) {
	return false;
}

/**
* Usage:
  winhook.exe -e TargetExe
*/
int main(int argc, char *argv[]) {

	if (argc < 3) {
		printf("\nUsage : winhook.exe -e TargetExe -f APIName \n");
		ExitProcess(0);
	}
	else {

		std::setlocale(LC_CTYPE, "");
		char *dllname = (char*)"kernel32.dll";
		std::string apiname = std::string("CreateThread");
		std::string dllpath = std::string("C:\\Windows\\system32\\") + std::string(dllname);
		//dumpExe(argv[2]);
		//cout << dllpath << endl;

		if (ifApiExists(argv[2], apiname) == 1) {
	
			LPPROCESS_INFORMATION lpInfo = open_process(argv[2], 1000);

			if ( lpInfo->dwProcessId ) {
				printf("Started %lu\n", lpInfo->dwProcessId);
				//snapshotAllModules(lpInfo->dwProcessId, std::string(dllname));
				HMODULE dll = enum_modules(lpInfo->hProcess, dllpath);

				if ( dll != NULL) {
					hook_api(apiname, dllpath, dll);
					Sleep(5000);
				}
			}

			CloseHandle(lpInfo->hProcess);
			CloseHandle(lpInfo->hThread);

		}
		else {
			printf("\n API not found in the import table \n");
		}

	}//end of if-else

	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
