#include "FileClass.h"

File::FileClass::FileClass() {
	this->Init();
}

File::FileClass::FileClass(PTCHAR pFileName) {
	this->Init();
	this->lpFileName = pFileName;
}

File::FileClass::~FileClass() {
	if (this->isClosed) {
		return;
	}
	this->CloseFile();
}

VOID File::FileClass::Init() {
	this->File = NULL;
	this->lpFileName = NULL;
	this->dwDesiredAccess = GENERIC_ALL;
	this->dwShareMode = FILE_SHARE_READ;
	this->lpSecurityAttributes = NULL;
	this->dwCreationDisposition = OPEN_EXISTING;
	this->dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
	this->hTemplateFile = NULL;
}

BOOL File::FileClass::CloseFile() {
	if (this->isClosed == FALSE) {
		this->isClosed = TRUE;
		return CloseHandle(File);
	}
	return TRUE;
}

BOOL File::FileClass::OpenFile() {
	
	this->File = ::CreateFile(
		this->lpFileName, 
		this->dwDesiredAccess,
		this->dwShareMode,
		this->lpSecurityAttributes,
		this->dwCreationDisposition,
		this->dwFlagsAndAttributes,
		this->hTemplateFile
	);
	return (this->File != INVALID_HANDLE_VALUE);
}

BOOL File::FileClass::setFileName(PTCHAR pFileName) {
	this->lpFileName = pFileName;
	return TRUE;
}
BOOL File::FileClass::setCreationDisposition(DWORD dwCreationDisposition) {
	this->dwCreationDisposition = dwCreationDisposition;
	return TRUE;
}

BOOL File::FileClass::setShareMode(DWORD dwShareMode) {
	this->dwShareMode = dwShareMode;
	return TRUE;
}


BOOL File::FileClass::setSecurityAttributes(SECURITY_ATTRIBUTES * lpSecurityAttributes) {
	this->lpSecurityAttributes = lpSecurityAttributes;
	return TRUE;
}

BOOL File::FileClass::setTemplateFile(HANDLE hTemplateFile) {
	this->hTemplateFile = hTemplateFile;
	return (this->hTemplateFile != INVALID_HANDLE_VALUE);
}

BOOL File::FileClass::setDesiredAccess(DWORD dwDesiredAccess) {
	this->dwDesiredAccess = dwDesiredAccess;
	return TRUE;
}

DWORD File::FileClass::Write(DWORD dwSize, LPCVOID lpWriteData) {
	DWORD dwWriteSize = 0;
	if (::WriteFile(this->File, lpWriteData, dwSize, &dwWriteSize, NULL)) {
		return dwWriteSize;
	}
	return 0;
}

DWORD File::FileClass::Read(DWORD dwSize, LPVOID lpReadData) {
	this->setCreationDisposition(OPEN_EXISTING);
	this->setShareMode(FILE_SHARE_READ);
	this->setDesiredAccess(GENERIC_READ);
	
	DWORD dwWriteSize = 0;
	if (::ReadFile(this->File, lpReadData, dwSize, &dwWriteSize, NULL)) {
		return dwWriteSize;
	}
	return 0;
}

BOOL File::FileClass::CreateFileWithOpen(PTCHAR pFileName) {
	this->lpFileName = pFileName;
	this->OpenFile();
	// File::FileClass::OpenFile();
	return (this->File != INVALID_HANDLE_VALUE);
}