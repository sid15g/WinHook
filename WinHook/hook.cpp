#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <iostream>

#include "winhook.h"
#include "stdafx.h"

using namespace std;

LPCWSTR s2ws(const std::string& s) {
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r.c_str();
}

DWORD findAPI(std::string apiName, std::string dllName)   {

	HMODULE hModule = LoadLibrary(s2ws(dllName));
	DWORD funcAdr = (DWORD) GetProcAddress(hModule, (LPCSTR)apiName.c_str());
	printf("API ProcAddress: 0x%08X \n ", (unsigned int)funcAdr);
	return funcAdr;
}

void hook_callback_action() {
  printf("ok ok ok");
}

HHOOK hook_api(std::string apiName, std::string dllName, HMODULE dll) {

  DWORD apiAddress = findAPI(apiName, dllName);
  DWORD baseAddress = (DWORD)dll;

  HOOKPROC proc = (HOOKPROC)hook_callback_action;
  HHOOK hook = SetWindowsHookEx(WH_SYSMSGFILTER, proc, NULL, 0);
  
	if (!hook) {
		cout << "Failed to install hook!" << "Error" << MB_ICONERROR << endl;
		return NULL;
	} else {
		printf("hooked");
		return hook;
	}

}//end of function

int unhook_api(HHOOK hook) {
  UnhookWindowsHookEx(hook);
  return 0;
}//end of function
