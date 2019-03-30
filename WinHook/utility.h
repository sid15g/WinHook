#include <Windows.h>

#include "stdafx.h"

void init_log();
int APIPRIVATE msgBox(char* messg);
std::string APIPRIVATE getPid();
char* APIPRIVATE getCurrentDateTime();
void APIPRIVATE log_call(std::string apiName);
void APIPRIVATE log_callA(std::string apiName);