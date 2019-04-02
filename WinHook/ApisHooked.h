#include <Windows.h>
#include <Wincrypt.h>
#include <TlHelp32.h>
#include <synchapi.h>
#include <winternl.h>
#include <detours.h>

#include "stdafx.h"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

//====================================================================================


LSTATUS(WINAPI *pRegCreateKeyExA)(
	HKEY                        hKey,
	LPCSTR                      lpSubKey,
	DWORD                       Reserved,
	LPSTR                       lpClass,
	DWORD                       dwOptions,
	REGSAM                      samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY                       phkResult,
	LPDWORD                     lpdwDisposition
	) = RegCreateKeyExA;

LSTATUS WINAPI MyRegCreateKeyExA(
	HKEY                        hKey,
	LPCSTR                      lpSubKey,
	DWORD                       Reserved,
	LPSTR                       lpClass,
	DWORD                       dwOptions,
	REGSAM                      samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY                       phkResult,
	LPDWORD                     lpdwDisposition
);

//====================================================================================

LSTATUS (WINAPI *pRegCreateKeyExW)(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD Reserved,
	LPWSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
) = RegCreateKeyExW;

LSTATUS WINAPI MyRegCreateKeyExW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD Reserved,
	LPWSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
);

//====================================================================================

LSTATUS(WINAPI *pRegSetValueExA)(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
	) = RegSetValueExA;

LSTATUS WINAPI MyRegSetValueExA(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
);

//====================================================================================

LSTATUS (WINAPI *pRegSetValueExW)(
	HKEY hKey,
	LPCWSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
) = RegSetValueExW;

LSTATUS WINAPI MyRegSetValueExW(
	HKEY hKey,
	LPCWSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
);

//====================================================================================

LSTATUS (WINAPI *pRegCreateKeyA)(
	HKEY hKey,
	LPCSTR lpSubKey,
	PHKEY phkResult
) = RegCreateKeyA;

LSTATUS WINAPI MyRegCreateKeyA(
	HKEY hKey,
	LPCSTR lpSubKey,
	PHKEY phkResult
);

//====================================================================================

LSTATUS (WINAPI *pRegCreateKeyW)(
	HKEY hKey,
	LPCWSTR lpSubKey,
	PHKEY phkResult
) = RegCreateKeyW;

LSTATUS WINAPI MyRegCreateKeyW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	PHKEY phkResult
);

//====================================================================================

LSTATUS(WINAPI *pRegDeleteKeyA)(
	HKEY   hKey,
	LPCSTR lpSubKey
	) = RegDeleteKeyA;

LSTATUS WINAPI MyRegDeleteKeyA(
	HKEY   hKey,
	LPCSTR lpSubKey
);

//====================================================================================

LSTATUS(WINAPI *pRegDeleteKeyW)(
	HKEY   hKey,
	LPCWSTR lpSubKey
	) = RegDeleteKeyW;

LSTATUS WINAPI MyRegDeleteKeyW(
	HKEY   hKey,
	LPCWSTR lpSubKey
);

//====================================================================================

LSTATUS(WINAPI *pRegCloseKey)(
	HKEY hKey
	) = RegCloseKey;

LSTATUS WINAPI MyRegCloseKey(
	HKEY hKey
);

//====================================================================================
//====================================================================================

HANDLE (WINAPI *pCreateToolhelp32Snapshot)(
	DWORD dwFlags,
	DWORD th32ProcessID
) = CreateToolhelp32Snapshot;

HANDLE WINAPI MyCreateToolhelp32Snapshot(
	DWORD dwFlags,
	DWORD th32ProcessID
);

//====================================================================================

BOOL (WINAPI *pCreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
) = CreateProcessA;

BOOL WINAPI MyCreateProcessA(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

//====================================================================================

HANDLE (WINAPI *pCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
) = CreateThread;

HANDLE WINAPI MyCreateThread(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

//====================================================================================

HANDLE (WINAPI *pOpenProcess)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
) = OpenProcess;

HANDLE WINAPI MyOpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
);

//====================================================================================

LPVOID (WINAPI *pVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
) = VirtualAlloc;

LPVOID WINAPI MyVirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

//====================================================================================

LPVOID (WINAPI *pVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
) = VirtualAllocEx;

LPVOID WINAPI MyVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

//====================================================================================

HANDLE (WINAPI *pCreateRemoteThread)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
) = CreateRemoteThread;

HANDLE WINAPI MyCreateRemoteThread(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
);

//====================================================================================

HANDLE (WINAPI *pCreateRemoteThreadEx)(
	HANDLE                       hProcess,
	LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	SIZE_T                       dwStackSize,
	LPTHREAD_START_ROUTINE       lpStartAddress,
	LPVOID                       lpParameter,
	DWORD                        dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD                      lpThreadId
) = CreateRemoteThreadEx;

HANDLE WINAPI MyCreateRemoteThreadEx(
	HANDLE                       hProcess,
	LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	SIZE_T                       dwStackSize,
	LPTHREAD_START_ROUTINE       lpStartAddress,
	LPVOID                       lpParameter,
	DWORD                        dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD                      lpThreadId
);

//====================================================================================

BOOL (WINAPI *pWriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
) = WriteProcessMemory;

BOOL WINAPI MyWriteProcessMemory(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
);

//====================================================================================

BOOL (WINAPI *pReadProcessMemory)(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesRead
) = ReadProcessMemory;

BOOL WINAPI MyReadProcessMemory(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesRead
);

//====================================================================================

BOOL (WINAPI *pVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) = VirtualProtect;

BOOL WINAPI MyVirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

//====================================================================================

BOOL (WINAPI *pVirtualProtectEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) = VirtualProtectEx;

BOOL WINAPI MyVirtualProtectEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

//====================================================================================

HMODULE (WINAPI *pLoadLibraryA)(
	LPCSTR lpLibFileName
) = LoadLibraryA;

HMODULE WINAPI MyLoadLibraryA(
	LPCSTR lpLibFileName
);

//====================================================================================

HMODULE (WINAPI *pLoadLibraryW)(
	LPCWSTR lpLibFileName
) = LoadLibraryW;

HMODULE WINAPI MyLoadLibraryW(
	LPCWSTR lpLibFileName
);

//====================================================================================

HMODULE (WINAPI *pLoadLibraryExA)(
	LPCSTR lpLibFileName,
	HANDLE hFile,
	DWORD  dwFlags
) = LoadLibraryExA;

HMODULE WINAPI MyLoadLibraryExA(
	LPCSTR lpLibFileName,
	HANDLE hFile,
	DWORD  dwFlags
);

//====================================================================================

HMODULE (WINAPI *pLoadLibraryExW)(
	LPCWSTR lpLibFileName,
	HANDLE hFile,
	DWORD  dwFlags
) = LoadLibraryExW;

HMODULE WINAPI MyLoadLibraryExW(
	LPCWSTR lpLibFileName,
	HANDLE hFile,
	DWORD  dwFlags
);


//====================================================================================
//====================================================================================

HANDLE (WINAPI *pCreateFileA)(
	LPCSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) = CreateFileA;

HANDLE WINAPI MyCreateFileA(
	LPCSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

//====================================================================================

HANDLE(WINAPI *pCreateFileW)(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	) = CreateFileW;

HANDLE WINAPI MyCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

//====================================================================================

HFILE (WINAPI *pOpenFile)(
	LPCSTR     lpFileName,
	LPOFSTRUCT lpReOpenBuff,
	UINT       uStyle
) = OpenFile;


HFILE WINAPI MyOpenFile(
	LPCSTR     lpFileName,
	LPOFSTRUCT lpReOpenBuff,
	UINT       uStyle
);

//====================================================================================

HFILE (WINAPI *p_lopen)(
	LPCSTR lpPathName,
	int iReadWrite
) = _lopen;

HFILE WINAPI My_lopen(
	LPCSTR lpPathName,
	int iReadWrite
);

//====================================================================================

BOOL (WINAPI *pDeleteFileA)(
	LPCSTR lpFileName
) = DeleteFileA;

BOOL WINAPI MyDeleteFileA(
	LPCSTR lpFileName
);

//====================================================================================

BOOL(WINAPI *pDeleteFileW)(
	LPCWSTR lpFileName
) = DeleteFileW;

BOOL WINAPI MyDeleteFileW(
	LPCWSTR lpFileName
);


//====================================================================================
//====================================================================================

HHOOK (WINAPI *pSetWindowsHookExA)(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId
) = SetWindowsHookExA;

HHOOK WINAPI MySetWindowsHookExA(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId
);

//====================================================================================

HHOOK(WINAPI *pSetWindowsHookExW)(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId
	) = SetWindowsHookExW;

HHOOK WINAPI MySetWindowsHookExW(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId
);

//====================================================================================

LRESULT (WINAPI *pCallNextHookEx)(
	HHOOK  hhk,
	int    nCode,
	WPARAM wParam,
	LPARAM lParam
) = CallNextHookEx;

LRESULT WINAPI MyCallNextHookEx(
	HHOOK  hhk,
	int    nCode,
	WPARAM wParam,
	LPARAM lParam
);

//====================================================================================

BOOL (WINAPI *pUnhookWindowsHookEx)(
	HHOOK hhk
) = UnhookWindowsHookEx;


BOOL WINAPI MyUnhookWindowsHookEx(
	HHOOK hhk
);

//====================================================================================
//====================================================================================


BOOL (WINAPI *pCryptBinaryToStringA)(
	const BYTE *pbBinary,
	DWORD      cbBinary,
	DWORD      dwFlags,
	LPSTR      pszString,
	DWORD      *pcchString
) = CryptBinaryToStringA;

BOOL WINAPI MyCryptBinaryToStringA(
	const BYTE *pbBinary,
	DWORD      cbBinary,
	DWORD      dwFlags,
	LPSTR      pszString,
	DWORD      *pcchString
);

//====================================================================================

BOOL(WINAPI *pCryptBinaryToStringW)(
	const BYTE *pbBinary,
	DWORD      cbBinary,
	DWORD      dwFlags,
	LPWSTR      pszString,
	DWORD      *pcchString
	) = CryptBinaryToStringW;

BOOL WINAPI MyCryptBinaryToStringW(
	const BYTE *pbBinary,
	DWORD      cbBinary,
	DWORD      dwFlags,
	LPWSTR      pszString,
	DWORD      *pcchString
);

//====================================================================================

HANDLE (WINAPI *pCreateEventA)(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCSTR                lpName
) = CreateEventA;

HANDLE WINAPI MyCreateEventA(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCSTR                lpName
);

//====================================================================================

HANDLE (WINAPI *pCreateEventW)(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCWSTR               lpName
) = CreateEventW;

HANDLE WINAPI MyCreateEventW(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCWSTR               lpName
);

//====================================================================================

HANDLE (WINAPI *pCreateEventExA)(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	LPCSTR                lpName,
	DWORD                 dwFlags,
	DWORD                 dwDesiredAccess
) = CreateEventExA;

HANDLE WINAPI MyCreateEventExA(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	LPCSTR                lpName,
	DWORD                 dwFlags,
	DWORD                 dwDesiredAccess
);

//====================================================================================

HANDLE (WINAPI *pCreateEventExW)(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	LPCWSTR               lpName,
	DWORD                 dwFlags,
	DWORD                 dwDesiredAccess
) = CreateEventExW;

HANDLE WINAPI MyCreateEventExW(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	LPCWSTR               lpName,
	DWORD                 dwFlags,
	DWORD                 dwDesiredAccess
);

//====================================================================================
//====================================================================================

NTSTATUS (WINAPI *pNtOpenFile)(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN ULONG              ShareAccess,
	IN ULONG              OpenOptions
) = NtOpenFile;

NTSTATUS WINAPI MyNtOpenFile(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN ULONG              ShareAccess,
	IN ULONG              OpenOptions
);

//====================================================================================

NTSTATUS (WINAPI *pNtCreateFile)(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength
) = NtCreateFile;

NTSTATUS WINAPI MyNtCreateFile(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength
);

//====================================================================================

NTSTATUS (WINAPI *pNtRenameKey)(
	HANDLE          KeyHandle,
	PUNICODE_STRING NewName
) = NtRenameKey;

NTSTATUS WINAPI MyNtRenameKey(
	HANDLE          KeyHandle,
	PUNICODE_STRING NewName
);

//====================================================================================

SOCKET (WINAPI *psocket)(
	int af,
	int type,
	int protocol
) = socket;

SOCKET WINAPI MySocket(
	int af,
	int type,
	int protocol
);

//====================================================================================

int (WINAPI *psend)(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
) = send;

int WINAPI MySend(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
);

//====================================================================================

int (WINAPI *precv)(
	SOCKET s,
	char   *buf,
	int    len,
	int    flags
) = recv;

int WINAPI MyRecv(
	SOCKET s,
	char   *buf,
	int    len,
	int    flags
);

//====================================================================================

hostent* (WINAPI *pgethostbyname)(
	const char *name
) = gethostbyname;

hostent* WINAPI MyGethostbyname(
	const char *name
);

//====================================================================================

hostent* (WINAPI *pgethostbyaddr)(
	const char *addr,
	int        len,
	int        type
) = gethostbyaddr;

hostent* WINAPI MyGethostbyaddr(
	const char *addr,
	int        len,
	int        type
);

//====================================================================================

BOOL (WINAPI *pIsDebuggerPresent)(void) = IsDebuggerPresent;

BOOL WINAPI MyIsDebuggerPresent(void);

//====================================================================================

BOOL (WINAPI *pCheckRemoteDebuggerPresent)(
	HANDLE hProcess,
	PBOOL  pbDebuggerPresent
) = CheckRemoteDebuggerPresent;

BOOL WINAPI MyCheckRemoteDebuggerPresent(
	HANDLE hProcess,
	PBOOL  pbDebuggerPresent
);

//====================================================================================

void (WINAPI *pOutputDebugStringA)(
	LPCSTR lpOutputString
) = OutputDebugStringA;

void WINAPI MyOutputDebugStringA(
	LPCSTR lpOutputString
);

//====================================================================================

void (WINAPI *pOutputDebugStringW)(
	LPCWSTR lpOutputString
) = OutputDebugStringW;

void WINAPI MyOutputDebugStringW(
	LPCWSTR lpOutputString
);

//====================================================================================