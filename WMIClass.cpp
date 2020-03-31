#include "WMIClass.h"

WMIClass::WMIClass()
{
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        // Program has failed.
        cout << "Failed to initialize COM library. Error code = 0x"
            << hex << hres << endl;
       
    }

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );


    if (FAILED(hres))
    {
        cout << "Failed to initialize security. Error code = 0x"
            << hex << hres << endl;
        CoUninitialize();
    }

}

BOOL WMIClass::OpenWMINameSpace(LPCWSTR NameSpacePath)
{
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return FALSE;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    

    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(NameSpacePath), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object 
        &pSvc                    // pointer to IWbemServices proxy
        );
    if (FAILED(hres))
    {
        cout << "Could not connect. Error code = 0x"
            << hex << hres << endl;
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }
    cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;
    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
        );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x"
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;               // Program has failed.
    }
    return TRUE;
}

BOOL WMIClass::WMIQuery(LPCWSTR WMIQueryStr)
{
    pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(WMIQueryStr),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        cout << "Query for operating system name failed."
            << " Error code = 0x"
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;               // Program has failed.
    }
    return TRUE;
}

BOOL WMIClass::ViewData()
{
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,&pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;

        // Get the value of the Name property
        hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        wcout << "OS Name : " << vtProp.bstrVal << endl;
        VariantClear(&vtProp);

        pclsObj->Release();
    }
    return TRUE;
}

BOOL WMIClass::ViewData(LPCWSTR Keys[],  DWORD dwKeysNum, std::wstring& result) {
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        // Get the value of the Name property
        for (size_t i = 0; i < dwKeysNum; i++)
        {
            VARIANT vtProp;
            hr = pclsObj->Get(Keys[i], 0, &vtProp, 0, 0);
            result.append(Keys[i]);
            result.append(TEXT(": "));
            result.append(vtProp.bstrVal);
            result.append(TEXT("\n"));
            VariantClear(&vtProp);
        }
        pclsObj->Release();
    }
    return TRUE;
}

WMIClass::~WMIClass()
{
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
}
