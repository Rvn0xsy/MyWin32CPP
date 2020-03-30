#include <Windows.h>
#include <stdio.h>  
// Windows 服务代码模板
////////////////////////////////////////////////////////////////////////////////////
// sc create Monitor binpath= Monitor.exe
// sc start Monitor
// sc delete Monitor
////////////////////////////////////////////////////////////////////////////////////
/**********************************************************************************/
////////////////////////////////////////////////////////////////////////////////////
// New-Service –Name Monitor –DisplayName Monitor –BinaryPathName "D:\Monitor\Monitor.exe" –StartupType Automatic
// Start-Service Monitor
// Stop-Service Monitor
////////////////////////////////////////////////////////////////////////////////////



#define SLEEP_TIME 5000                          /*间隔时间*/
#define LOGFILE "D:\\log.txt"              /*信息输出文件*/

SERVICE_STATUS ServiceStatus;  /*服务状态*/
SERVICE_STATUS_HANDLE hStatus; /*服务状态句柄*/

void  ServiceMain(int argc, char** argv);
void  CtrlHandler(DWORD request);
int   InitService();

int main(int argc, CHAR * argv[])
{
    WCHAR WserviceName[] = TEXT("Monitor");
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = WserviceName;
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
    StartServiceCtrlDispatcher(ServiceTable);

    return 0;
}

int WriteToLog(const char* str)
{
    FILE* pfile;
    fopen_s(&pfile, LOGFILE, "a+");
    if (pfile == NULL)
    {
        return -1;
    }
    fprintf_s(pfile, "%s\n", str);
    fclose(pfile);

    return 0;
}

/*Service initialization*/
int InitService()
{
    CHAR Message[] = "Monitoring started.";
    OutputDebugString(TEXT("Monitoring started."));
    int result;
    result = WriteToLog(Message);

    return(result);
}

/*Control Handler*/
void CtrlHandler(DWORD request)
{
    switch (request)
    {
    case SERVICE_CONTROL_STOP:
        
        WriteToLog("Monitoring stopped.");
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    case SERVICE_CONTROL_SHUTDOWN:
        WriteToLog("Monitoring stopped.");

        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    default:
        break;
    }
    /* Report current status  */
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
}

void ServiceMain(int argc, char** argv)
{
    WCHAR WserviceName[] = TEXT("Monitor");
    int error;
    ServiceStatus.dwServiceType =
        SERVICE_WIN32;
    ServiceStatus.dwCurrentState =
        SERVICE_START_PENDING;
    /*在本例中只接受系统关机和停止服务两种控制命令*/
    ServiceStatus.dwControlsAccepted =
        SERVICE_ACCEPT_SHUTDOWN |
        SERVICE_ACCEPT_STOP;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    hStatus = ::RegisterServiceCtrlHandler(
        WserviceName,
        (LPHANDLER_FUNCTION)CtrlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0)
    {

        WriteToLog("RegisterServiceCtrlHandler failed");
        return;
    }
    WriteToLog("RegisterServiceCtrlHandler success");
    /* Initialize Service   */
    error = InitService();
    if (error)
    {
        /* Initialization failed  */
        ServiceStatus.dwCurrentState =
            SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = -1;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    }
    /*向SCM 报告运行状态*/
    ServiceStatus.dwCurrentState =
        SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    /*do something you want to do in this while loop*/
    MEMORYSTATUS memstatus;
    while (ServiceStatus.dwCurrentState ==
        SERVICE_RUNNING)
    {
        char buffer[16];
        GlobalMemoryStatus(&memstatus);
        int availmb = memstatus.dwAvailPhys / 1024 / 1024;
        sprintf_s(buffer, 100, "available memory is %dMB", availmb);
        int result = WriteToLog(buffer);
        if (result)
        {
            ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            ServiceStatus.dwWin32ExitCode = -1;
            SetServiceStatus(hStatus,
                &ServiceStatus);
            return;
        }
        Sleep(SLEEP_TIME);
    }
    WriteToLog("service stopped");
    return;
}
