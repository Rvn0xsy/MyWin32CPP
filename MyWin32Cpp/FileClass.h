#pragma once
#include <Windows.h>
#include <strsafe.h>

namespace File {
	class FileClass
	{
	public:

		FileClass();
		BOOL CreateFileWithOpen(PTCHAR);
		FileClass(PTCHAR);
		BOOL setFileName(PTCHAR);
		BOOL setDesiredAccess(DWORD);
		BOOL setShareMode(DWORD);
		BOOL setSecurityAttributes(SECURITY_ATTRIBUTES*);
		BOOL setCreationDisposition(DWORD);
		BOOL setTemplateFile(HANDLE);
		BOOL OpenFile();
		DWORD Write(DWORD, LPCVOID);
		DWORD Read(DWORD, LPVOID);
		BOOL CloseFile();
		~FileClass();
	private:
		VOID Init();
		HANDLE File;
		PTCHAR lpFileName = NULL;
		DWORD dwDesiredAccess = NULL;
		DWORD dwShareMode = NULL;
		LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL;
		DWORD dwCreationDisposition = NULL;
		DWORD dwFlagsAndAttributes = NULL;
		HANDLE hTemplateFile = NULL;
		BOOL isClosed;
	};


}
