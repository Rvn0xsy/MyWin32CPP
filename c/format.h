#pragma once
#include <stdarg.h>
#include <stdio.h>
#include <Windows.h>

FILE* logfile;
int rprintf(const char* format, ...);
int rprintf_error(DWORD errCode);
BOOL rprintf_open_log(char* filename);
VOID rprintf_close_log();