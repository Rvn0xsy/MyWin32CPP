#include "libWinHttpClient.h"

BOOL libWinHttpClient::ConnectServer(LPCWSTR pswzServerName, INTERNET_PORT nServerPort, BOOL isHTTPS)
{
	if (hSession == NULL) {
		// Session初始化错误！
		return FALSE;
	}
	hConnect = WinHttpConnect(hSession, pswzServerName, nServerPort, 0);
	if (hConnect != NULL) {
		this->isHTTPS = isHTTPS;
		if (isHTTPS) {
			DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
			WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
			WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);
			this->dwRequestFlags |= WINHTTP_FLAG_SECURE;
		}
		return TRUE;
	}
	
	return FALSE;
}

// 添加 Headers
VOID libWinHttpClient::SetHeaders()
{
	INT nHeaderCount = this->szHeaders.size();
	wprintf(TEXT("[+] Header Size : %d \n"), nHeaderCount);
	if (nHeaderCount <= 0) {
		return VOID();
	}
	for (INT i = 0; i < nHeaderCount; i++)
	{
		wprintf(TEXT("[+] Header : %s \n"), szHeaders[i].data());
		WinHttpAddRequestHeaders(hRequest,
			szHeaders[i].data(),
			szHeaders[i].length(),
			WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
	}
	return VOID();
}

// 获取相应码
DWORD libWinHttpClient::GetResponseContentLength()
{
	DWORD dwResponseLength = 0;
	DWORD dwCch = sizeof(DWORD);
	WinHttpQueryHeaders(hRequest,
		WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX,
		&dwResponseLength,
		&dwCch,
		WINHTTP_NO_HEADER_INDEX);
	return dwResponseLength;

}

BOOL libWinHttpClient::SendRequest()
{
	BOOL bIsSend = FALSE;
	if (hRequest == NULL)
		return FALSE;
	// 发送HTTP请求
	bIsSend = WinHttpSendRequest(
		hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0,
		WINHTTP_NO_REQUEST_DATA,
		NULL,
		0,
		0);
	if (bIsSend) {
		// 开始接受响应
		WinHttpReceiveResponse(hRequest, NULL);
		return TRUE;
	}
	return bIsSend;
}

BOOL libWinHttpClient::SendRequest(LPVOID pswzSendData, DWORD dwSendDataLen)
{
	// 如果不填写请求长度,默认不发送任何数据
	if (dwSendDataLen == 0) {
		return this->SendRequest();
	}
	// 是否请求成功
	BOOL bIsSend = FALSE;
	if (hRequest == NULL)
		return FALSE;
	// 发送HTTP请求
	bIsSend = WinHttpSendRequest(
		hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0,
		pswzSendData,
		dwSendDataLen,
		dwSendDataLen,
		0);
	if (bIsSend) {
		// 开始接受响应
		WinHttpReceiveResponse(hRequest, NULL);
		return TRUE;
	}
	return bIsSend;
}

// 初始化
libWinHttpClient::libWinHttpClient() {
	// 初始化 HTTP Open
	hSession = WinHttpOpen(
		LIB_HTTP_USER_AGENT,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0);

}

BOOL libWinHttpClient::HttpAddHeaders(LPCWSTR szHeader)
{
	// 如果长度大于0则添加
	if (lstrlen(szHeader) > 0) {
		// 添加Header
		wprintf(TEXT(" [+]AddHeaders : %s \n"), szHeader);
		this->szHeaders.push_back(szHeader);
		return TRUE;
	}
	return FALSE;
}

BOOL libWinHttpClient::HttpAddHeaders(std::vector<std::wstring> szHeaders)
{
	// 直接赋值外部Headers,后面的将直接替换
	this->szHeaders = szHeaders;
	return 0;
}


DWORD libWinHttpClient::HttpGet(LPCWSTR pszServerURI, std::vector<BYTE>& wszResponse)
{
	DWORD dwResponseContentLen = 0; // 响应体大小
	LPVOID lpszResponseBody = NULL; // 响应内容
	// 连接服务器
	if (!hConnect) {
		// 连接错误！
		return -1;
	}
	// 连接成功
	printf("[+] hSession WinHttpConnect Host \n");

	// 创建请求对象
	hRequest = WinHttpOpenRequest(
		hConnect,
		TEXT("GET"),   // Request Method
		pszServerURI,  // Request URI
		NULL,
		WINHTTP_NO_REFERER, // 没有Referer
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		this->dwRequestFlags
	);

	// 设置HTTP头
	this->SetHeaders();

	// 发送HTTP请求
	if (this->SendRequest() == FALSE) {
		return -1;
	}
	// 获取响应 ContentLength,如果没有内容,则返回 0
	dwResponseContentLen = this->GetResponseContentLength();
	if (dwResponseContentLen == 0) {
		return dwResponseContentLen;
	}
	// 申请内存空间用于存放返回内容
	lpszResponseBody = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwResponseContentLen);
	// 从HTTP响应读取内容
	if (WinHttpReadData(hRequest, lpszResponseBody, dwResponseContentLen, &dwResponseContentLen) == FALSE) {
		return -1;
	}
	printf("[+] GET Request Content-Length : %d \n", dwResponseContentLen);
	// 将响应内容返回
	for (DWORD i = 0; i < dwResponseContentLen; i++)
	{
		BYTE byS = (BYTE) * ((PCHAR)lpszResponseBody + i);
		wszResponse.push_back(byS);
	}

	printf("[+] Error %u in WinHttpReadData.\n", GetLastError());
	// 释放原先申请的内存
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpszResponseBody);
	// 关闭请求句柄
	if (hRequest) WinHttpCloseHandle(hRequest);
	// 返回网页大小
	return dwResponseContentLen;
}

DWORD libWinHttpClient::HttpPost(LPCWSTR pszServerURI, LPVOID pszSendData, DWORD dwSendDataLen, std::vector<BYTE>& wszResponse)
{
	DWORD dwResponseContentLen = 0; // 响应体大小
	LPVOID lpszResponseBody = NULL; // 响应内容
	// 连接服务器
	if (!hConnect) {
		// 连接错误！
		return -1;
	}
	// 连接成功
	printf("[+] hSession WinHttpConnect Host \n");
	// 创建请求对象
	hRequest = WinHttpOpenRequest(
		hConnect,
		HTTP_POST,   // Request Method
		pszServerURI,  // Request URI
		NULL,
		WINHTTP_NO_REFERER, // 没有Referer
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		this->dwRequestFlags
	);
	// 设置HTTP头
	this->SetHeaders();

	// 发送HTTP请求
	if (this->SendRequest(pszSendData, dwSendDataLen) == FALSE) {
		return -1;
	}
	// 获取响应 ContentLength,如果没有内容,则返回 0
	dwResponseContentLen = this->GetResponseContentLength();
	if (dwResponseContentLen == 0) {
		return dwResponseContentLen;
	}
	// 申请内存空间用于存放返回内容
	lpszResponseBody = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwResponseContentLen);
	// 从HTTP响应读取内容
	if (WinHttpReadData(hRequest, lpszResponseBody, dwResponseContentLen, &dwResponseContentLen) == FALSE) {
		return -1;
	}
	printf("[+] POST Request Content-Length : %d \n", dwResponseContentLen);
	// 将响应内容返回
	for (DWORD i = 0; i < dwResponseContentLen; i++)
	{
		BYTE byS = (BYTE) * ((PCHAR)lpszResponseBody + i);
		wszResponse.push_back(byS);

	}
	// 释放原先申请的内存
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpszResponseBody);
	// 关闭请求句柄
	if (hRequest) WinHttpCloseHandle(hRequest);
	// 返回网页大小
	return dwResponseContentLen;
}

// 下载文件，保存到图片
BOOL libWinHttpClient::DownLoadFile(LPCWSTR pszServerURI, LPCWSTR pszDesFileName)
{
	HANDLE hFile = INVALID_HANDLE_VALUE; // 文件句柄
	std::vector<BYTE> wszResponse;
	// 发送GET请求
	DWORD dwFileSize = this->HttpGet(pszServerURI, wszResponse);
	// 如果文件大小为0，则不下载
	if (dwFileSize < 0) {
		return TRUE;
	}
	// 创建文件
	hFile = CreateFile(pszDesFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"[+] CreateFile Error!");
		return FALSE;
	}
	for (auto i = wszResponse.begin(); i < wszResponse.end(); i++)
	{
		BYTE ctr = *i;
		DWORD dwNumberOfBytesWritten = 0;
		WriteFile(hFile, (BYTE*)&ctr, 1, &dwNumberOfBytesWritten, NULL);
	}
	CloseHandle(hFile);
	return TRUE;
}


libWinHttpClient::~libWinHttpClient()
{
	if (hConnect) CloseHandle(hConnect);
	if (hSession) CloseHandle(hSession);
}