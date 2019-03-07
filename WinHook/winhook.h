#include "stdafx.h"
#include <string.h>

HHOOK hook_api(std:: string apiName, std::string dllName, HMODULE dll);
int unhook_api(HHOOK hook);
