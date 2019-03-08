#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <strsafe.h>

#include "winhook.h"
#include "stdafx.h"

using namespace std;

#pragma comment( lib, "user32.lib") 
#pragma comment( lib, "gdi32.lib")


void LookUpTheMessage(PMSG, LPTSTR);

typedef struct _HOOKDATA {
	int nType;
	HOOKPROC hkprc;
	HHOOK hhook;
	HOOKPROC apiAddress;
	HMODULE baseAddress;
} *PHookData;


PHookData hookptr;
HWND gh_hwndMain;
static HMENU hmenu;
static BOOL start = false, afHOOK;


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

HOOKPROC findAPI(std::string apiName, std::string dllName)   {

	HMODULE hModule = LoadLibrary(s2ws(dllName));
	HOOKPROC funcAdr = (HOOKPROC)GetProcAddress(hModule, (LPCSTR)apiName.c_str());
	printf("API ProcAddress: 0x%08X \n ", (unsigned int)funcAdr);
	return funcAdr;
} 

void hook_api(std::string apiName, std::string dllName, HMODULE dll) {

	HOOKPROC proc = (HOOKPROC)MessageProc;

	hookptr = (PHookData)malloc(sizeof(_HOOKDATA));
	hookptr->hkprc = proc;
	hookptr->nType = WH_SYSMSGFILTER;
	hookptr->baseAddress = dll;
	hookptr->apiAddress = findAPI(apiName, dllName);

	start = true;
	printf("Hooking...");

}//end of function


LRESULT WINAPI MainWndProc(HWND hwndMain, UINT uMsg, WPARAM wParam, LPARAM lParam) {

	gh_hwndMain = hwndMain;
	int index;

	switch (uMsg) {
		case WM_CREATE:
			if (start) {
				hmenu = GetMenu(hwndMain);
				afHOOK = false;
				return 0;
			}
			else {
				return DefWindowProc(hwndMain, uMsg, wParam, lParam);
			}
			break;
		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case WH_SYSMSGFILTER:
					if (!afHOOK) {
						
						HHOOK hook = SetWindowsHookEx(WH_SYSMSGFILTER, hookptr->apiAddress, hookptr->baseAddress, 0);
						hookptr->hhook = hook;

						if (!hook) {
							cout << "Failed to install hook!" << "Error" << MB_ICONERROR << endl;
							return 0;
						} else {
							printf("Hooked\n");
							unhook_api(hook);
							//todo
							return 1;
						}
					}
					else {

					}
					break;
				default:
					return DefWindowProc(hwndMain, uMsg, wParam, lParam);

			};//End of switch
		default:
			return DefWindowProc(hwndMain, uMsg, wParam, lParam);
	};

	return 0;
}

LRESULT CALLBACK MessageProc(int nCode, WPARAM wParam, LPARAM lParam) {
	return 0;
}

int unhook_api(HHOOK hook) {
  UnhookWindowsHookEx(hook);
  return 0;
}//end of function
