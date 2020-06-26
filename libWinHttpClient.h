#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include <Winhttp.h>
#include <iostream>
#include <vector>
#include <strsafe.h>

/*
ʹ�����ӣ�

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
	std::vector<std::wstring> szHeaders; // ����ͷ
	VOID SetHeaders(); // ��������ͷ
	DWORD GetResponseContentLength(); // ��ȡ��Ӧ���ݳ���
	BOOL SendRequest(); // ��������
	BOOL SendRequest(LPVOID pswzSendData, DWORD dwSendDataLen); // ���ʹ�����������
public:
	libWinHttpClient(); // ��ʼ��Session
	// ���ӷ�����
	BOOL ConnectServer(LPCWSTR pswzServerName, INTERNET_PORT nServerPort);
	BOOL HttpAddHeaders(LPCWSTR szHeader); // ���HTTPͷ
	BOOL HttpAddHeaders(std::vector<std::wstring> szHeaders); // ��Ӷ��HTTPͷ
	// ����GET����
	DWORD HttpGet(
		LPCWSTR pszServerURI,
		std::vector<BYTE>& wszResponse
	);
	// ����POST����
	DWORD HttpPost(
		LPCWSTR pszServerURI,
		LPVOID pszSendData,
		DWORD dwSendDataLen,
		std::vector<BYTE>& wszResponse
	);
	// �����ļ�
	BOOL DownLoadFile(LPCWSTR pszServerURI, LPCWSTR pszDesFileName);

	~libWinHttpClient();
};

