#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include <Winhttp.h>
#include <iostream>
#include <vector>
#include <strsafe.h>

/*
使用例子：

	libWinHttpClient HttpClient;
	HttpClient.ConnectServer(L"192.168.3.161", 80);
	std::vector<BYTE> bResonse;
	HttpClient.DownLoadFile(L"/icons/openlogo-75.png", TEXT("openlogo-75.png"));

*/

#define LIB_HTTP_USER_AGENT L"Mozilla/5.02 (Linux; Android 4.1.1; Nexus 7 Build/JRO03D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Safari"
#define HTTP_POST TEXT("POST")
#define HTTP_GET TEXT("GET")
#define HTTP_DELETE TEXT("DELETE")
#define HTTP_OPTIONS TEXT("OPTIONS")
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Winhttp.lib")

class libWinHttpClient
{

private:
	HINTERNET   hSession = NULL;
	HINTERNET	hConnect = NULL;
	HINTERNET	hRequest = NULL;
	std::vector<std::wstring> szHeaders; // 请求头
	VOID SetHeaders(); // 设置请求头
	DWORD GetResponseContentLength(); // 获取响应内容长度
	BOOL SendRequest(); // 发送请求
	BOOL SendRequest(LPVOID pswzSendData, DWORD dwSendDataLen); // 发送带参数的请求
public:
	libWinHttpClient(); // 初始化Session
	// 连接服务器
	BOOL ConnectServer(LPCWSTR pswzServerName, INTERNET_PORT nServerPort);
	BOOL HttpAddHeaders(LPCWSTR szHeader); // 添加HTTP头
	BOOL HttpAddHeaders(std::vector<std::wstring> szHeaders); // 添加多个HTTP头
	// 发送GET请求
	DWORD HttpGet(
		LPCWSTR pszServerURI,
		std::vector<BYTE>& wszResponse
	);
	// 发送POST请求
	DWORD HttpPost(
		LPCWSTR pszServerURI,
		LPVOID pszSendData,
		DWORD dwSendDataLen,
		std::vector<BYTE>& wszResponse
	);
	// 下载文件
	BOOL DownLoadFile(LPCWSTR pszServerURI, LPCWSTR pszDesFileName);

	~libWinHttpClient();
};

