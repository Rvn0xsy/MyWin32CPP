
#include "format.h"

int rprintf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    printf("[+]");
    int ret = vprintf(format, args);
    printf("\n");
    fflush(stdout);
    if (logfile)
    {
        fprintf(logfile, "[+]");
        vfprintf(logfile, format, args);
        fprintf(logfile, "\n");
        fflush(logfile);
    }
    va_end(args);
    return ret;
}

int rprintf_error(DWORD errCode)
{
    if (errCode == 0)
    {
        errCode = GetLastError();
    }
    LPVOID buffer;
    if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER| FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        errCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPCSTR)&buffer,
        0,
        NULL)) {
        rprintf("%s", buffer);
        fflush(stderr);
        LocalFree(buffer);
    }
    return 0;
}

BOOL rprintf_open_log(char* filename)
{
    if (filename == NULL)
    {
        return FALSE;
    }
    logfile = fopen(filename, "a");
    if (logfile != NULL)
    {
        return TRUE;
    }
    return FALSE;
}

VOID rprintf_close_log()
{
    if (logfile)
    {
        fclose(logfile);
    }
    return;
}

int main()
{
    rprintf_open_log("log.log");
    rprintf("My Name is [%s]\n", "Allen");
    rprintf_error(5);
    rprintf_close_log();
	return 0;
}
