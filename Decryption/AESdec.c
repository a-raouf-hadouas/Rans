#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

#include"aes.h"



#define AES_256_KEY_SIZE  32 
#define IV_SIZE    16  


BOOL RemovePadding(uint8_t* ciphertext, SIZE_T* szciphertext) {
	BOOL bSuccess = FALSE;

	if (*szciphertext == 0 || *szciphertext % 16 != 0) {
		printf("[!] Invalid ciphertext length.\n");
		return bSuccess;
	}

	SIZE_T padding_len = ciphertext[*szciphertext - 1];

	if (padding_len > 16 || padding_len == 0) {
		printf("[!] Invalid padding.\n");
		return bSuccess;
	}

	
	for (SIZE_T i = *szciphertext - padding_len; i < *szciphertext; i++) {
		if (ciphertext[i] != padding_len) {
			printf("[!] Inconsistent padding bytes.\n");
			return bSuccess;
		}
	}


	*szciphertext -= padding_len;

	bSuccess = TRUE;
	return bSuccess;
}

VOID AESdecryptFile(uint8_t* key, uint8_t* iv, uint8_t* ciphertext) {
	
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);
	AES_ctx_set_iv(&ctx, iv);
	AES_CBC_decrypt_buffer(&ctx, ciphertext, IV_SIZE);
}

BOOL ReadFromFile(PBYTE* pData, WCHAR* filePath, SIZE_T* szData) {
	
	PBYTE buffer = NULL;
	HANDLE hFile = NULL;
	DWORD numberOfBytesRead = 0;
	LARGE_INTEGER fileSize = { 0 };
	BOOL success = FALSE;

	if (!pData || !filePath || !szData) {
		printf("[!] Invalid parameters passed to ReadFromFile %d\n",GetLastError());
		return success;
	}


	if (GetFileAttributesW(filePath) == INVALID_FILE_ATTRIBUTES) {
		printf("[!] File not found! Check the file path: %d\n", GetLastError());
		return success;
	}


	hFile = CreateFileW(
		filePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Cannot open file for read: %d\n", GetLastError());
		goto _EndFunction;
	}

	if (!GetFileSizeEx(hFile, &fileSize)) {
		printf("[!] Cannot get file size: %d\n", GetLastError());
		goto _EndFunction;
	}

	if (fileSize.QuadPart == 0) {
		printf("[!] File is empty\n");
		goto _EndFunction;
	}

	if (fileSize.QuadPart > SIZE_MAX) {
		printf("[!] File is too large to read into memory\n");
		goto _EndFunction;
	}

	buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)fileSize.QuadPart);
	SecureZeroMemory(buffer,(SIZE_T)fileSize.QuadPart);
	if (!buffer) {
		printf("[!] Memory allocation failed\n");
		goto _EndFunction;
	}

	if (!ReadFile(hFile, buffer, (DWORD)fileSize.QuadPart, &numberOfBytesRead, NULL) || numberOfBytesRead != (DWORD)fileSize.QuadPart) {
		printf("[!] ReadFile failed or incomplete read: %d\n", GetLastError());
		goto _EndFunction;
	}

	*pData = buffer;
	*szData = (SIZE_T)fileSize.QuadPart;
	success = TRUE;
	buffer = NULL;

_EndFunction:
	if (hFile) {
		CloseHandle(hFile);
	}
	if (buffer) {
		HeapFree(GetProcessHeap(), 0, buffer);
	}
	return success;
}

BOOL WriteToFile(PBYTE buffer, WCHAR* filePath, SIZE_T numberOfBytesToWrite) { 
	
	BOOL bSuccess = FALSE;
	HANDLE hFile = NULL;
	DWORD numberOfBytesWritten = 0;

	if (!buffer || !filePath || numberOfBytesToWrite == 0) {
		printf("[!] Invalid parameters passed to WriteToFile\n");
		return FALSE;
	}

	hFile = CreateFileW(
		filePath,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Cannot open file for write %d\n", GetLastError());
		return FALSE;
	}


	if (SetFilePointer(hFile, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		printf("[!] Cannot set file pointer %d\n", GetLastError());
		goto _EndFunction;
	}

	if (!SetEndOfFile(hFile)) {
		printf("[!] Cannot truncate file %d\n", GetLastError());
		goto _EndFunction;
	}


	SIZE_T bytesRemaining = numberOfBytesToWrite;
	SIZE_T currentOffset = 0;
	while (bytesRemaining > 0) {
		DWORD bytesToWrite = (bytesRemaining > MAXDWORD) ? MAXDWORD : (DWORD)bytesRemaining;

		if (!WriteFile(hFile, buffer + currentOffset, bytesToWrite, &numberOfBytesWritten, NULL)) {
			printf("[!] Cannot WriteFile %d\n", GetLastError());
			goto _EndFunction;
		}

		if (numberOfBytesWritten != bytesToWrite) {
			printf("[!] Incomplete write: expected %lu bytes, wrote %lu bytes\n",
				bytesToWrite, numberOfBytesWritten);
			goto _EndFunction;
		}

		bytesRemaining -= numberOfBytesWritten;
		currentOffset += numberOfBytesWritten;
	}

	bSuccess = TRUE;

_EndFunction:
	if (hFile) {
		CloseHandle(hFile);
	}
	return bSuccess;
}

BOOL DirectoryFiles(LPWSTR pDirectoryPath, BYTE* key, BYTE* iv) {
	
	PBYTE pData = NULL;
	SIZE_T szData = 0;
	WCHAR* filePath = (WCHAR*)malloc(MAX_PATH * sizeof(WCHAR));

	WCHAR searchPattren[MAX_PATH * sizeof(WCHAR)];  
	WIN32_FIND_DATA fileData;
	DWORD dwError = 0; 
	LARGE_INTEGER szFile = { 0 };

	StringCchCopy(searchPattren, MAX_PATH * sizeof(WCHAR), pDirectoryPath);
	StringCchCat(searchPattren, MAX_PATH * sizeof(WCHAR), L"\\*");

	HANDLE hSearch = FindFirstFileW(searchPattren, &fileData);
	if (hSearch == INVALID_HANDLE_VALUE) {
		printf("[!] Invalid Search Handle %d\n", GetLastError());
		return FALSE;
	}

	do {
		if (wcscmp(fileData.cFileName, L".") == 0 || wcscmp(fileData.cFileName, L"..") == 0) {
			continue;
		}
		if (wcscmp(fileData.cFileName, L"docs_1") == 0 || wcscmp(fileData.cFileName, L"docs_2") == 0 || wcscmp(fileData.cFileName, L"desktop.ini") == 0) {
			wprintf(L"%s Skipped\n", fileData.cFileName);
			continue;
		}
		StringCchCopy(filePath, MAX_PATH * sizeof(WCHAR), pDirectoryPath);
		StringCchCat(filePath, MAX_PATH * sizeof(WCHAR), L"\\");
		StringCchCat(filePath, MAX_PATH * sizeof(WCHAR), fileData.cFileName);

		if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			wprintf(L" %s   <DIR>\n", fileData.cFileName);
			if (!DirectoryFiles(filePath, key, iv)) {
				printf("[!] DirectoryFiles doesn't work %d\n", GetLastError());
				continue;
			}
		}
		else {
			szFile.LowPart = fileData.nFileSizeLow;
			szFile.HighPart = fileData.nFileSizeHigh;
			wprintf(L" %s %lld bytes\n", fileData.cFileName, szFile.QuadPart);

			if (!ReadFromFile(&pData, filePath, &szData)) {
				printf("[!] Cannot ReadFromFile %d\n", GetLastError());
				continue;
			}

			SIZE_T count = 0;
			SIZE_T	szciphertext = IV_SIZE;
			uint8_t ciphertext[16];
			uint8_t* decryptedData = NULL;
			SIZE_T totalDecryptedSize = 0;
			uint8_t* tempBuffer = NULL;


			while (count < szData) {
				memset(ciphertext, 0, 16);
				for (int i = 0; i < 16; i++) {
					if (count < szData) {
						ciphertext[i] = pData[count];
						count++;
					}
					else break;
				}

				AESdecryptFile(key, iv, ciphertext);

				SIZE_T padding_len = ciphertext[szciphertext - 1];

					if (padding_len < 16 && padding_len > 0 && count >= szData) {
						if (!RemovePadding(ciphertext, &szciphertext)) {
							printf("[!] Can not remove padding from ciphertext %d\n", GetLastError());
							if (pData) HeapFree(GetProcessHeap(), 0, pData);
							if (decryptedData) free(decryptedData);
							return FALSE;
						}
					}

				tempBuffer = (uint8_t*)realloc(decryptedData, totalDecryptedSize + szciphertext);
				if (!tempBuffer) {
					printf("[!] Memory allocation failed for encrypted data\n");
					if (pData) HeapFree(GetProcessHeap(), 0, pData);
					if (decryptedData) free(decryptedData);
					return FALSE;
				}
				decryptedData = tempBuffer;

				memcpy(decryptedData + totalDecryptedSize, ciphertext, szciphertext);
				totalDecryptedSize += szciphertext;

			}

			if (!WriteToFile(decryptedData, filePath, totalDecryptedSize)) {
				printf("[!] WriteToFile Failed with %d\n", GetLastError());
				if (pData) HeapFree(GetProcessHeap(), 0, pData);
				if (decryptedData) free(decryptedData);
				return FALSE;
			}
			if (pData) {
				HeapFree(GetProcessHeap(), 0, pData);
				pData = NULL;
			}
			if (decryptedData) {
				free(decryptedData);
				decryptedData = NULL;  
			}
		}

	} while (FindNextFile(hSearch, &fileData) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES)
	{
		printf("[!] Error! %d\n", GetLastError());
		return FALSE;
	}
	FindClose(hSearch);
	return TRUE;
}

int main() {
	PBYTE keyValue = NULL;
	PBYTE iv = NULL; 
	SIZE_T  szkey = AES_256_KEY_SIZE;
	SIZE_T  szkeyRead = NULL;
	SIZE_T  szIvRead = NULL;
	WCHAR	userName[MAX_PATH * sizeof(WCHAR)];
	WCHAR	keyPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	WCHAR	directoryPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	WCHAR	ivPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	SIZE_T	szName = MAX_PATH * sizeof(WCHAR);

	if (!GetUserNameW(userName, &szName)) {
		printf("[!] GetUserName failed with %d", GetLastError());
		return -1;
	}

	StringCchCat(keyPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(keyPath, MAX_PATH * sizeof(WCHAR), L"\\Documents\\docs_1");

	StringCchCat(ivPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(ivPath, MAX_PATH * sizeof(WCHAR), L"\\Documents\\docs_2");

	if (!ReadFromFile(&keyValue, keyPath, &szkeyRead) || szkey != szkeyRead) {
		printf("[!] WriteToFile Failed with %d\n", GetLastError());
		return -1;
	}
	if (!ReadFromFile(&iv, ivPath, &szIvRead) || szIvRead != IV_SIZE) {
		printf("[!] WriteToFile Failed with %d\n", GetLastError());
		return -1;
	}

	printf("[+] AES Key (%d bytes):\n", (int)szkey);
	for (int i = 0; i < AES_256_KEY_SIZE; i++) {
		printf("%02X ", keyValue[i]);
	}

	printf("\n");


	printf("[+] IV:\n");
	for (int i = 0; i < IV_SIZE; i++) {
		printf("%02X ", iv[i]);
	}
	printf("\n");


	StringCchCat(directoryPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(directoryPath, MAX_PATH * sizeof(WCHAR), L"\\Documents");


	printf("[*]Press Enter to Decrypt the files... \n");
	getchar();

	if (!DirectoryFiles(directoryPath, keyValue, iv)) {
		printf("[!] DerecotryFiles don't work %d\n", GetLastError());
		return -1;
	}


	printf("\nDone!\n");


	getchar();




	return 0;
}