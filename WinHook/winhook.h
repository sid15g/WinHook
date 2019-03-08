#include "stdafx.h"
#include <string.h>

void hook_api(std:: string apiName, std::string dllName, HMODULE dll);
int unhook_api(HHOOK hook);

LRESULT WINAPI MessageProc(int, WPARAM, LPARAM);