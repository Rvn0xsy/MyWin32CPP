// CryptoTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <iostream>
#include <wincrypt.h>
#include <string>
#include <tchar.h>
#pragma comment(lib, "crypt32.lib")


using namespace std;

LPCWSTR CSP_NAME = TEXT("MyKeyContainer");
LPCTSTR pszContainerName = TEXT("My Sample Key Container");


void MyHandleError(LPCTSTR psz)
{
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
    _ftprintf(stderr, TEXT("Program terminating. \n"));
    exit(1);
} // End of MyHandleError.


std::string BinToBase64(BYTE *  binstr, DWORD dwBinLen) {
    std::string base64str;
    DWORD dwBase64DataLen = 0;
    char* chBase64Data = NULL;
    BYTE* pbOutBuffer = NULL;
    DWORD dwOutBufferLen = 0;
    CryptBinaryToStringA(binstr, dwBinLen, CRYPT_STRING_BASE64, NULL, &dwBase64DataLen);
    chBase64Data = (char*)malloc(dwBase64DataLen + 1);
    CryptBinaryToStringA(binstr, dwBinLen, CRYPT_STRING_BASE64, chBase64Data, &dwBase64DataLen);
    base64str.clear();
    base64str.append(chBase64Data);
    return base64str;
}

void cryptoAPI_encrypt(string text, unsigned char* pwd, std::string & encryptstr, int& out_len)
{
    int dataLen = text.length();
    BYTE* encryptText;
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    int dwLength = 0;
    if (CryptAcquireContext(&hCryptProv, pszContainerName, NULL, PROV_RSA_AES, NULL))
    {
        _tprintf(
            TEXT("A crypto context with the %s key container ")
            TEXT("has been acquired.\n"),
            pszContainerName);
    }else {
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            if (CryptAcquireContext(
                &hCryptProv,
                pszContainerName,
                NULL,
                PROV_RSA_FULL,
                CRYPT_NEWKEYSET))
            {
                _tprintf(TEXT("A new key container has been ")
                    TEXT("created.\n"));
            }
            else
            {
                MyHandleError(TEXT("Could not create a new key ")
                    TEXT("container.\n"));
            }
        }
        else
        {
            MyHandleError(TEXT("CryptAcquireContext failed.\n"));
        }
    }
    
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash))
    {
        MyHandleError(TEXT("CryptCreateHash failed.\n"));
        return;
    }

    BYTE* pPwd = pwd;
    if (!CryptHashData(hHash, pPwd, 16, 0))
    {
        MyHandleError(TEXT("CryptHashData failed.\n"));
        return;
    }

    if (!CryptDeriveKey(hCryptProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        MyHandleError(TEXT("CryptDeriveKey failed.\n"));
        return;
    }
    
    encryptText = (BYTE*)malloc(dataLen * 4);
    memcpy(encryptText, text.c_str(), dataLen);
    DWORD dwLen = dataLen;

    if (!CryptEncrypt(hKey, NULL, true, 0, encryptText, &dwLen, dataLen *4))
    {
        MyHandleError(TEXT("CryptEncrypt failed.\n"));
        return;
    }
    encryptstr = BinToBase64(encryptText, dwLen);
    if (!CryptDecrypt(hKey, NULL, true, 0, encryptText, &dwLen))
    {
        MyHandleError(TEXT("CryptEncrypt failed.\n"));
        return;
    }
    encryptText[dwLen] = '\0';
    printf("[+]CryptEncrypt : %d \n", dwLen);
    printf("[+]CryptDecrypt : %s \n", encryptText);
    out_len = dwLen;
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);

}

int main()
{
    string text("HelloWo------------------rld!");
    string encryptText;
    unsigned char  Password[] = "whxasgx_2esbav1";
    unsigned char ** result = NULL;
    int resultLen = 0;
    cryptoAPI_encrypt(text, Password, encryptText, resultLen);
    printf("[+] len : %d ", resultLen);
    cout << encryptText << endl;
    // std::cout << "Hello World!\n";
    cout << BinToBase64(Password, 16);

}
