#pragma once

/*

Example :

#define _WIN32_DCOM
#include "RegisterTaskScheduler.h"

int __cdecl wmain()
{

    const char* XML = R"(<?xml version="1.0" ?>
    <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo>
        <Source>Microsoft Corporation</Source>
        <Author>Microsoft Corporation</Author>
        <URI>\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents</URI>
      </RegistrationInfo>
      <Triggers>
        <TimeTrigger>
          <Repetition>
            <Interval>PT1H</Interval>
            <StopAtDurationEnd>false</StopAtDurationEnd>
          </Repetition>
          <StartBoundary>2000-01-01T00:00:00</StartBoundary>
          <Enabled>true</Enabled>
        </TimeTrigger>
      </Triggers>
      <Principals>
        <Principal id="LocalSystem">
          <UserId>S-1-5-18</UserId>
          <RunLevel>HighestAvailable</RunLevel>
        </Principal>
      </Principals>
      <Settings>
        <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <StartWhenAvailable>true</StartWhenAvailable>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
          <StopOnIdleEnd>true</StopOnIdleEnd>
          <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>true</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        <Priority>0</Priority>
      </Settings>
      <Actions Context="LocalSystem">
        <Exec>
          <Command>%windir%\system32\rundll32.exe</Command>
          <Arguments>main.dll msg</Arguments>
        </Exec>
      </Actions>
    </Task>)";


    RegisterTaskScheduler* RegTsk = new RegisterTaskScheduler;

    RegTsk->SetSchedulerName("whoami");
    RegTsk->SetSchedulerXMLContent(XML);
    RegTsk->ChangeFolder("\\Microsoft\\Windows\\AppID\\Test");
    RegTsk->RegisterTask();

    delete RegTsk;

}


*/

#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <wincred.h>
//  Include the task header file.
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")



class RegisterTaskScheduler
{

public:
	RegisterTaskScheduler();

	BOOL SetSchedulerName(PCCH Name);
	BOOL SetSchedulerXMLContent(PCCH XML);
	BOOL ChangeFolder(PCCH Path);
	BOOL ChangeFolder(ITaskFolder* Folder);
	ITaskFolder * CreateFolder(PCCH FolderName);
	BOOL RegisterTask();
	~RegisterTaskScheduler();
private:
	std::string pSechedulerXML;
	std::string pSechedulerName;
	HRESULT hr = NULL;
	ITaskService* pService = NULL;
	ITaskFolder* pRootFolder = NULL;
	IRegisteredTask* pRegisteredTask = NULL;
};

