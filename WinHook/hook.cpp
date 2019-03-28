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
	
	cout << "WinProc Called" << endl;

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
							afHOOK = false;
							return 0;
						} else {
							printf("Hooked\n");
							CheckMenuItem(hmenu, index, MF_BYCOMMAND | MF_UNCHECKED);
							afHOOK = true;
							return 1;
						}
					} else {
						unhook_api(hookptr->hhook);
						CheckMenuItem(hmenu, index, MF_BYCOMMAND | MF_UNCHECKED);
						afHOOK = false;
					}
					break;
				default:
					return DefWindowProc(hwndMain, uMsg, wParam, lParam);

			};//End of switch
		default:
			return DefWindowProc(hwndMain, uMsg, wParam, lParam);
	};

	return 0;
}//end of function


/** 
* Hook Procedure used with SetWindowsHookEx
* @Params:
*	** ncode: Hook code that the hook procedure uses to determine the action to perform
*	** wParam and lParam: Its value depends on the type of the hook
*						  Typically contains information about a message that was sent or posted.
*/
LRESULT CALLBACK MessageProc(int nCode, WPARAM wParam, LPARAM lParam) {
	CHAR szBuf[128], szMsg[16], szCode[32];
	HDC hdc;
	size_t cch;
	static int c = 0;
	HRESULT hResult;


	if (nCode < 0)  // do not process message 
		return CallNextHookEx(hookptr->hhook, nCode, wParam, lParam);

	switch (nCode)
	{
	case MSGF_DIALOGBOX:
		hResult = StringCchCopyA(szCode, 32 / sizeof(TCHAR), "MSGF_DIALOGBOX");
		if (FAILED(hResult))
		{
			// TODO: write error handler
		}
		break;

	case MSGF_MENU:
		hResult = StringCchCopyA(szCode, 32 / sizeof(TCHAR), "MSGF_MENU");
		if (FAILED(hResult))
		{
			// TODO: write error handler
		}
		break;

	case MSGF_SCROLLBAR:
		hResult = StringCchCopyA(szCode, 32 / sizeof(TCHAR), "MSGF_SCROLLBAR");
		if (FAILED(hResult))
		{
			// TODO: write error handler
		}
		break;

	default:
		hResult = StringCchPrintfA(szCode, 128 / sizeof(TCHAR), "Unknown: %d", nCode);
		if (FAILED(hResult))
		{
			// TODO: write error handler
		}
		break;
	}

	// Call an application-defined function that converts a message 
	// constant to a string and copies it to a buffer. 

	LookUpTheMessage((PMSG)lParam, (LPTSTR)szMsg);

	hdc = GetDC(gh_hwndMain);
	hResult = StringCchPrintfA(szBuf, 128 / sizeof(TCHAR),
		"MSGFILTER  nCode: %s, msg: %s, %d times    ",
		szCode, szMsg, c++);
	if (FAILED(hResult))
	{
		// TODO: write error handler
	}
	hResult = StringCchLengthA(szBuf, 128 / sizeof(TCHAR), &cch);
	if (FAILED(hResult))
	{
		// TODO: write error handler
	}
	TextOutA(hdc, 2, 135, szBuf, cch);
	ReleaseDC(gh_hwndMain, hdc);

	return CallNextHookEx(hookptr->hhook, nCode, wParam, lParam);

}

int unhook_api(HHOOK hook) {
  UnhookWindowsHookEx(hook);
  return 0;
}//end of function


void LookUpTheMessage(PMSG msg, LPTSTR str) {
	cout << "Got: " << endl;
	cout << msg << " || " << str << endl;
	cout << endl;
}