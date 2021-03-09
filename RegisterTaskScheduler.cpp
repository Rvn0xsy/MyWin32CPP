#include "RegisterTaskScheduler.h"

RegisterTaskScheduler::RegisterTaskScheduler()
{
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        printf("CoInitializeEx failed: %x \n", hr);
        return;
    }
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL);

    if (FAILED(hr))
    {
        printf("CoInitializeSecurity failed: %x \n", hr);
        CoUninitialize();
        return;
    }
    hr = CoCreateInstance(CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService);
    if (FAILED(hr))
    {
        printf("Failed to create an instance of ITaskService: %x", hr);
        CoUninitialize();
        return;
    }
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
        printf("Failed to Connect an ITaskService: %x", hr);
        CoUninitialize();
        return;
    }
}

BOOL RegisterTaskScheduler::SetSchedulerName(PCCH Name)
{
    this->pSechedulerName = Name;
    return TRUE;
}

BOOL RegisterTaskScheduler::SetSchedulerXMLContent(PCCH XML)
{
    pSechedulerXML = XML;
    return TRUE;
}

BOOL RegisterTaskScheduler::ChangeFolder(PCCH Path)
{
    pService->GetFolder(_bstr_t(Path), &pRootFolder);
    
    return 0;
}

BOOL RegisterTaskScheduler::ChangeFolder(ITaskFolder* Folder)
{
    this->pRootFolder = Folder;
    return TRUE;
}


ITaskFolder* RegisterTaskScheduler::CreateFolder(PCCH FolderName)
{
    ITaskFolder* NewFolder = NULL;
    hr = pRootFolder->CreateFolder(_bstr_t(FolderName), _variant_t(), &NewFolder);
    if (FAILED(hr)) {
        return NULL;
    }
    return NewFolder;
}

BOOL RegisterTaskScheduler::RegisterTask()
{
   hr = pRootFolder->RegisterTask(
        _bstr_t(this->pSechedulerName.c_str()),
        _bstr_t(this->pSechedulerXML.c_str()),
        TASK_CREATE_OR_UPDATE,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(),
        &pRegisteredTask
    );
   if (FAILED(hr)) {
       printf("Error saving the Task: %x", hr);
       return FALSE;
   }
   BSTR path;
   pRegisteredTask->get_Path(&path);
   printf("Path: %ls\n", path);

   return TRUE;
}

RegisterTaskScheduler::~RegisterTaskScheduler()
{
    pRegisteredTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
}
