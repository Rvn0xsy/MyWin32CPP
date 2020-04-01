// Psexec.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <winnetwk.h>

#pragma comment(lib, "ws2_32")   
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib,"Advapi32.lib")

DWORD ConnectSMBServer(LPCWSTR lpwsHost, LPCWSTR lpwsUser, LPCWSTR lpwsPassword);
BOOL UploadFileBySMB(LPCWSTR lpwsSrcPath, LPCWSTR lpwsDstPath);
BOOL CreateServiceWithSCM(LPCWSTR lpwsSCMServer, LPCWSTR lpwsServiceName, LPCWSTR lpwsServicePath);

int wmain(int argc, wchar_t* argv[])
{
    std::cout << "[ PS|> :) Hello PsExec By Rvn0xsy !" << std::endl;
    std::cout << "[ Blog |> https://payloads.online !" << std::endl;
    LPCWSTR lpwsHost = TEXT("192.168.3.130"); // 目标机器地址
    LPCWSTR lpwsUserName = TEXT("Administrator"); // 账号
    LPCWSTR lpwsPassword = TEXT("123456"); // 密码
    LPCWSTR lpwsSrcPath = TEXT("C:\\Users\\Administrator\\NewPsexec.exe"); // 本地文件路径
    LPCWSTR lpwsDstPath = TEXT("\\\\192.168.3.130\\admin$\\NewPsexec.exe"); // 远程文件路径
    LPCWSTR lpwsServiceName = TEXT("NewPsexec"); // 服务名称
    LPCWSTR lpwsServicePath = TEXT("%SystemRoot%\\NewPsexec.exe"); // 目标机器落地位置

    if (ConnectSMBServer(lpwsHost, lpwsUserName, lpwsPassword) == 0) {
        BOOL bRetVal = FALSE;
        bRetVal=UploadFileBySMB(lpwsSrcPath, lpwsDstPath);
        if (bRetVal) {
            std::cout << "Upload Success !" << std::endl;
            // 如果上传成功即可创建服务
            CreateServiceWithSCM(lpwsHost, lpwsServiceName, lpwsServicePath);
        }
        else {
            std::cout << "Upload Failed ! Error : "<< GetLastError() << std::endl;
            return GetLastError();
        }
    }
}

DWORD ConnectSMBServer(LPCWSTR lpwsHost, LPCWSTR lpwsUserName, LPCWSTR lpwsPassword)
{
    // 用于存放SMB共享资源格式
    PWCHAR lpwsIPC = new WCHAR[MAX_PATH]; 
    DWORD dwRetVal; // 函数返回值
    NETRESOURCE nr; // 连接的详细信息
    DWORD dwFlags; // 连接选项

    ZeroMemory(&nr, sizeof(NETRESOURCE));
    swprintf(lpwsIPC, MAX_PATH,TEXT("\\\\%s\\admin$"), lpwsHost);
    nr.dwType = RESOURCETYPE_ANY; // 枚举所有资源
    nr.lpLocalName = NULL;
    nr.lpRemoteName = lpwsIPC; // 资源的网络名
    nr.lpProvider = NULL; 

    // 如果设置了此位标志，则操作系统将在用户登录时自动尝试恢复连接。
    dwFlags = CONNECT_UPDATE_PROFILE; 

    dwRetVal = WNetAddConnection2(&nr,lpwsPassword, lpwsUserName, dwFlags);
    if (dwRetVal == NO_ERROR) {
        // 返回NO_ERROR则成功
        wprintf(L"Connection added to %s\n", nr.lpRemoteName);
        return dwRetVal;
    }
    
    wprintf(L"WNetAddConnection2 failed with error: %u\n", dwRetVal);
    return -1;
}

BOOL UploadFileBySMB(LPCWSTR lpwsSrcPath, LPCWSTR lpwsDstPath)
{
    DWORD dwRetVal;
    dwRetVal = CopyFile(lpwsSrcPath, lpwsDstPath, FALSE);
    return dwRetVal > 0 ? TRUE : FALSE;
}

BOOL CreateServiceWithSCM(LPCWSTR lpwsSCMServer, LPCWSTR lpwsServiceName, LPCWSTR lpwsServicePath)
{
    std::wcout << TEXT("Will Create Service ") << lpwsServiceName << std::endl;
    SC_HANDLE hSCM;
    SC_HANDLE hService;
    SERVICE_STATUS ss;
    // GENERIC_WRITE = STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
    hSCM = OpenSCManager(lpwsSCMServer, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL) {
        std::cout << "OpenSCManager Error: " << GetLastError() << std::endl;
        return -1;
    }
    
    hService = CreateService(
        hSCM, // 服务控制管理器数据库的句柄
        lpwsServiceName, // 要安装的服务的名称
        lpwsServiceName, // 用户界面程序用来标识服务的显示名称
        GENERIC_ALL, // 访问权限
        SERVICE_WIN32_OWN_PROCESS, // 与一个或多个其他服务共享一个流程的服务
        SERVICE_DEMAND_START, // 当进程调用StartService函数时，由服务控制管理器启动的服务 。
        SERVICE_ERROR_IGNORE, // 启动程序将忽略该错误并继续启动操作
        lpwsServicePath, // 服务二进制文件的标准路径
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (hService == NULL) {
        std::cout << "CreateService Error: " << GetLastError() << std::endl;
        return -1;
    }
    std::wcout << TEXT("Create Service Success : ") << lpwsServicePath << std::endl;
    hService = OpenService(hSCM, lpwsServiceName, GENERIC_ALL);
    if (hService == NULL) {
        std::cout << "OpenService Error: " << GetLastError() << std::endl;
        return -1;
    }
    std::cout << "OpenService Success!" << std::endl;
    
    StartService(hService, NULL, NULL);
    
    return 0;
}
