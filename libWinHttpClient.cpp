#include "libWinHttpClient.h"

BOOL libWinHttpClient::ConnectServer(LPCWSTR pswzServerName, INTERNET_PORT nServerPort, BOOL isHTTPS)
{
	if (hSession == NULL) {
		// Session��ʼ������
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

// ��� Headers
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

// ��ȡ��Ӧ��
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
	// ����HTTP����
	bIsSend = WinHttpSendRequest(
		hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0,
		WINHTTP_NO_REQUEST_DATA,
		NULL,
		0,
		0);
	if (bIsSend) {
		// ��ʼ������Ӧ
		WinHttpReceiveResponse(hRequest, NULL);
		return TRUE;
	}
	return bIsSend;
}

BOOL libWinHttpClient::SendRequest(LPVOID pswzSendData, DWORD dwSendDataLen)
{
	// �������д���󳤶�,Ĭ�ϲ������κ�����
	if (dwSendDataLen == 0) {
		return this->SendRequest();
	}
	// �Ƿ�����ɹ�
	BOOL bIsSend = FALSE;
	if (hRequest == NULL)
		return FALSE;
	// ����HTTP����
	bIsSend = WinHttpSendRequest(
		hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0,
		pswzSendData,
		dwSendDataLen,
		dwSendDataLen,
		0);
	if (bIsSend) {
		// ��ʼ������Ӧ
		WinHttpReceiveResponse(hRequest, NULL);
		return TRUE;
	}
	return bIsSend;
}

// ��ʼ��
libWinHttpClient::libWinHttpClient() {
	// ��ʼ�� HTTP Open
	hSession = WinHttpOpen(
		LIB_HTTP_USER_AGENT,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0);

}

BOOL libWinHttpClient::HttpAddHeaders(LPCWSTR szHeader)
{
	// ������ȴ���0�����
	if (lstrlen(szHeader) > 0) {
		// ���Header
		wprintf(TEXT(" [+]AddHeaders : %s \n"), szHeader);
		this->szHeaders.push_back(szHeader);
		return TRUE;
	}
	return FALSE;
}

BOOL libWinHttpClient::HttpAddHeaders(std::vector<std::wstring> szHeaders)
{
	// ֱ�Ӹ�ֵ�ⲿHeaders,����Ľ�ֱ���滻
	this->szHeaders = szHeaders;
	return 0;
}


DWORD libWinHttpClient::HttpGet(LPCWSTR pszServerURI, std::vector<BYTE>& wszResponse)
{
	DWORD dwResponseContentLen = 0; // ��Ӧ���С
	LPVOID lpszResponseBody = NULL; // ��Ӧ����
	// ���ӷ�����
	if (!hConnect) {
		// ���Ӵ���
		return -1;
	}
	// ���ӳɹ�
	printf("[+] hSession WinHttpConnect Host \n");

	// �����������
	hRequest = WinHttpOpenRequest(
		hConnect,
		TEXT("GET"),   // Request Method
		pszServerURI,  // Request URI
		NULL,
		WINHTTP_NO_REFERER, // û��Referer
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		this->dwRequestFlags
	);

	// ����HTTPͷ
	this->SetHeaders();

	// ����HTTP����
	if (this->SendRequest() == FALSE) {
		return -1;
	}
	// ��ȡ��Ӧ ContentLength,���û������,�򷵻� 0
	dwResponseContentLen = this->GetResponseContentLength();
	if (dwResponseContentLen == 0) {
		return dwResponseContentLen;
	}
	// �����ڴ�ռ����ڴ�ŷ�������
	lpszResponseBody = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwResponseContentLen);
	// ��HTTP��Ӧ��ȡ����
	if (WinHttpReadData(hRequest, lpszResponseBody, dwResponseContentLen, &dwResponseContentLen) == FALSE) {
		return -1;
	}
	printf("[+] GET Request Content-Length : %d \n", dwResponseContentLen);
	// ����Ӧ���ݷ���
	for (DWORD i = 0; i < dwResponseContentLen; i++)
	{
		BYTE byS = (BYTE) * ((PCHAR)lpszResponseBody + i);
		wszResponse.push_back(byS);
	}

	printf("[+] Error %u in WinHttpReadData.\n", GetLastError());
	// �ͷ�ԭ��������ڴ�
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpszResponseBody);
	// �ر�������
	if (hRequest) WinHttpCloseHandle(hRequest);
	// ������ҳ��С
	return dwResponseContentLen;
}

DWORD libWinHttpClient::HttpPost(LPCWSTR pszServerURI, LPVOID pszSendData, DWORD dwSendDataLen, std::vector<BYTE>& wszResponse)
{
	DWORD dwResponseContentLen = 0; // ��Ӧ���С
	LPVOID lpszResponseBody = NULL; // ��Ӧ����
	// ���ӷ�����
	if (!hConnect) {
		// ���Ӵ���
		return -1;
	}
	// ���ӳɹ�
	printf("[+] hSession WinHttpConnect Host \n");
	// �����������
	hRequest = WinHttpOpenRequest(
		hConnect,
		HTTP_POST,   // Request Method
		pszServerURI,  // Request URI
		NULL,
		WINHTTP_NO_REFERER, // û��Referer
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		this->dwRequestFlags
	);
	// ����HTTPͷ
	this->SetHeaders();

	// ����HTTP����
	if (this->SendRequest(pszSendData, dwSendDataLen) == FALSE) {
		return -1;
	}
	// ��ȡ��Ӧ ContentLength,���û������,�򷵻� 0
	dwResponseContentLen = this->GetResponseContentLength();
	if (dwResponseContentLen == 0) {
		return dwResponseContentLen;
	}
	// �����ڴ�ռ����ڴ�ŷ�������
	lpszResponseBody = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwResponseContentLen);
	// ��HTTP��Ӧ��ȡ����
	if (WinHttpReadData(hRequest, lpszResponseBody, dwResponseContentLen, &dwResponseContentLen) == FALSE) {
		return -1;
	}
	printf("[+] POST Request Content-Length : %d \n", dwResponseContentLen);
	// ����Ӧ���ݷ���
	for (DWORD i = 0; i < dwResponseContentLen; i++)
	{
		BYTE byS = (BYTE) * ((PCHAR)lpszResponseBody + i);
		wszResponse.push_back(byS);

	}
	// �ͷ�ԭ��������ڴ�
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpszResponseBody);
	// �ر�������
	if (hRequest) WinHttpCloseHandle(hRequest);
	// ������ҳ��С
	return dwResponseContentLen;
}

// �����ļ������浽ͼƬ
BOOL libWinHttpClient::DownLoadFile(LPCWSTR pszServerURI, LPCWSTR pszDesFileName)
{
	HANDLE hFile = INVALID_HANDLE_VALUE; // �ļ����
	std::vector<BYTE> wszResponse;
	// ����GET����
	DWORD dwFileSize = this->HttpGet(pszServerURI, wszResponse);
	// ����ļ���СΪ0��������
	if (dwFileSize < 0) {
		return TRUE;
	}
	// �����ļ�
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