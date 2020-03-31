#pragma once
#define _WIN32_DCOM
#include <iostream>

#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
using namespace std;

/*

建议采用：Wmi Explorer进行调试
1. https://www.ks-soft.net/hostmon.eng/downpage.htm
2. https://www.ip-tools.biz/download/wmiexplorer.zip

调用方法：

int wmain(void)
{
	WMIClass WMIC;
	std::wstring wsResult;
	LPCWSTR Keys[] = { TEXT("Name") }; // 这里为要查询的列
	WMIC.OpenWMINameSpace(TEXT("ROOT\\CIMV2"));
	WMIC.WMIQuery(TEXT("select * from Win32_Share"));
	WMIC.ViewData(Keys, 1 , wsResult);
	std::wcout << wsResult << std::endl;
}

*/

class WMIClass
{
private:
	HRESULT hres;
	IWbemServices* pSvc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemLocator* pLoc = NULL;
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
public:
	WMIClass();
	BOOL OpenWMINameSpace(LPCWSTR NameSpacePath);
	BOOL WMIQuery(LPCWSTR WMIQueryStr);
	BOOL ViewData();
	BOOL ViewData(LPCWSTR Keys[], DWORD dwKeysNum,std::wstring & result);
	~WMIClass();
};

