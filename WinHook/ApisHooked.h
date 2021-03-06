#include <Windows.h>
#include <Wincrypt.h>
#include <TlHelp32.h>
#include <synchapi.h>
#include <winternl.h>
#include <wininet.h>
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

SIZE_T (WINAPI *pVirtualQuery)(
	LPCVOID                   lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T                    dwLength
) = VirtualQuery;

SIZE_T WINAPI MyVirtualQuery(
	LPCVOID                   lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T                    dwLength
);

//====================================================================================

SIZE_T (WINAPI *pVirtualQueryEx)(
	HANDLE                    hProcess,
	LPCVOID                   lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T                    dwLength
) = VirtualQueryEx;

SIZE_T WINAPI MyVirtualQueryEx(
	HANDLE                    hProcess,
	LPCVOID                   lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T                    dwLength
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

BOOL (WINAPI *pLookupPrivilegeValueA)(
	LPCSTR lpSystemName,
	LPCSTR lpName,
	PLUID  lpLuid
) = LookupPrivilegeValueA;

BOOL WINAPI MyLookupPrivilegeValueA(
	LPCSTR lpSystemName,
	LPCSTR lpName,
	PLUID  lpLuid
);

//====================================================================================

BOOL(WINAPI *pLookupPrivilegeValueW)(
	LPCWSTR lpSystemName,
	LPCWSTR lpName,
	PLUID  lpLuid
	) = LookupPrivilegeValueW;

BOOL WINAPI MyLookupPrivilegeValueW(
	LPCWSTR lpSystemName,
	LPCWSTR lpName,
	PLUID  lpLuid
);

//====================================================================================


BOOL (WINAPI *pExitWindowsEx)(
	UINT  uFlags,
	DWORD dwReason
) = ExitWindowsEx;

BOOL WINAPI MyExitWindowsEx(
	UINT  uFlags,
	DWORD dwReason
);

//====================================================================================

SHORT (WINAPI *pGetAsyncKeyState)(
	int vKey
	) = GetAsyncKeyState;

SHORT WINAPI MyGetAsyncKeyState(
	int vKey
);

//====================================================================================

SHORT (WINAPI *pGetKeyState)(
	int nVirtKey
	) = GetKeyState;

SHORT WINAPI MyGetKeyState(
	int nVirtKey
);

//====================================================================================

BOOL(WINAPI *pGetKeyboardState)(
	PBYTE lpKeyState
	) = GetKeyboardState;

BOOL WINAPI MyGetKeyboardState(
	PBYTE lpKeyState
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


BOOL (WINAPI *pCryptDecrypt)(
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen
) = CryptDecrypt;

BOOL WINAPI MyCryptDecrypt(
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen
);

//====================================================================================

BOOL (WINAPI *pCryptEncrypt)(
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen,
  DWORD      dwBufLen
) = CryptEncrypt;

BOOL WINAPI MyCryptEncrypt(
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen,
  DWORD      dwBufLen
);

//====================================================================================

BOOL (WINAPI *pCryptDecryptMessage)(
  PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
  const BYTE                  *pbEncryptedBlob,
  DWORD                       cbEncryptedBlob,
  BYTE                        *pbDecrypted,
  DWORD                       *pcbDecrypted,
  PCCERT_CONTEXT              *ppXchgCert
) = CryptDecryptMessage;

BOOL WINAPI MyCryptDecryptMessage(
  PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
  const BYTE                  *pbEncryptedBlob,
  DWORD                       cbEncryptedBlob,
  BYTE                        *pbDecrypted,
  DWORD                       *pcbDecrypted,
  PCCERT_CONTEXT              *ppXchgCert
);

//====================================================================================

BOOL (WINAPI *pCryptEncryptMessage)(
  PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
  DWORD                       cRecipientCert,
  PCCERT_CONTEXT             rgpRecipientCert[],
  const BYTE                  *pbToBeEncrypted,
  DWORD                       cbToBeEncrypted,
  BYTE                        *pbEncryptedBlob,
  DWORD                       *pcbEncryptedBlob
) = CryptEncryptMessage;

BOOL WINAPI MyCryptEncryptMessage(
  PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
  DWORD                       cRecipientCert,
  PCCERT_CONTEXT              rgpRecipientCert[],
  const BYTE                  *pbToBeEncrypted,
  DWORD                       cbToBeEncrypted,
  BYTE                        *pbEncryptedBlob,
  DWORD                       *pcbEncryptedBlob
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

int (WINAPI *plisten)(
	SOCKET s,
	int backlog
) = listen;


int WINAPI MyListen(
	SOCKET s,
	int backlog
);

//====================================================================================

int (WINAPI *pconnect)(
	SOCKET s,
	const struct sockaddr *name,
	int namelen
) = connect;

int WINAPI MyConnect(
	SOCKET s,
	const struct sockaddr *name,
	int namelen
);

//====================================================================================

int (WINAPI *pbind)(
	SOCKET s,
	const struct sockaddr *addr,
	int namelen
) = bind;

int WINAPI MyBind(
	SOCKET s,
	const struct sockaddr *addr,
	int namelen
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
//====================================================================================

void* (__cdecl *pmemcpy)(
	void *dest,
	const void *src,
	size_t count
) = memcpy;

void* __cdecl MyMemcpy(
	void *dest,
	const void *src,
	size_t count
);

//====================================================================================

wchar_t* (__cdecl *pwmemcpy)(
	wchar_t *dest,
	const wchar_t *src,
	size_t count
) = wmemcpy;

wchar_t* __cdecl MyWmemcpy(
	wchar_t *dest,
	const wchar_t *src,
	size_t count
);

//====================================================================================

errno_t (__cdecl *pmemcpy_s)(
	void *dest,
	size_t destSize,
	const void *src,
	size_t count
) = memcpy_s;

errno_t __cdecl MyMemcpy_s(
	void *dest,
	size_t destSize,
	const void *src,
	size_t count
);

//====================================================================================

errno_t (__cdecl *pwmemcpy_s)(
	wchar_t *dest,
	size_t destSize,
	const wchar_t *src,
	size_t count
) = wmemcpy_s;

errno_t __cdecl MyWmemcpy_s(
	wchar_t *dest,
	size_t destSize,
	const wchar_t *src,
	size_t count
);

//====================================================================================

void* (__cdecl *pmemset)(
	void *dest,
	int c,
	size_t count
) = memset;

void* __cdecl MyMemset(
	void *dest,
	int c,
	size_t count
);

//====================================================================================

wchar_t* (__cdecl *pwmemset)(
	wchar_t *dest,
	wchar_t c,
	size_t count
) = wmemset;

wchar_t* __cdecl MyWmemset(
	wchar_t *dest,
	wchar_t c,
	size_t count
);

//====================================================================================

PVOID (__cdecl *pSecureZeroMemory)(
	PVOID  ptr,
	SIZE_T cnt
) = SecureZeroMemory;

PVOID __cdecl MySecureZeroMemory(
	PVOID  ptr,
	SIZE_T cnt
);

//====================================================================================

UINT (WINAPI *pWinExec)(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
) = WinExec;

UINT WINAPI MyWinExec(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
);

//====================================================================================
//====================================================================================

HRESULT(WINAPI *pURLDownloadToFile)(
	LPUNKNOWN            pCaller,
	LPCTSTR              szURL,
	LPCTSTR              szFileName,
	DWORD                dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	) = URLDownloadToFileW;

HRESULT WINAPI MyURLDownloadToFile(
	LPUNKNOWN            pCaller,
	LPCTSTR              szURL,
	LPCTSTR              szFileName,
	DWORD                dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
);

//====================================================================================

HINTERNET (WINAPI *pHttpOpenRequestA)(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR    *lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
	) = HttpOpenRequestA;

HINTERNET WINAPI MyHttpOpenRequestA(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR    *lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

//====================================================================================

HINTERNET(WINAPI *pHttpOpenRequestW)(
	HINTERNET hConnect,
	LPCWSTR    lpszVerb,
	LPCWSTR    lpszObjectName,
	LPCWSTR    lpszVersion,
	LPCWSTR    lpszReferrer,
	LPCWSTR    *lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
	) = HttpOpenRequestW;

HINTERNET WINAPI MyHttpOpenRequestW(
	HINTERNET hConnect,
	LPCWSTR    lpszVerb,
	LPCWSTR    lpszObjectName,
	LPCWSTR    lpszVersion,
	LPCWSTR    lpszReferrer,
	LPCWSTR    *lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

//====================================================================================

BOOL (WINAPI *pHttpSendRequestA)(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
	) = HttpSendRequestA;

BOOL WINAPI MyHttpSendRequestA(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
);

//====================================================================================

BOOL (WINAPI *pHttpSendRequestW)(
	HINTERNET hRequest,
	LPCWSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
) = HttpSendRequestW;

BOOL WINAPI MyHttpSendRequestW(
	HINTERNET hRequest,
	LPCWSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
);

//====================================================================================

HINTERNET (WINAPI *pInternetConnectA)(
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
) = InternetConnectA;

HINTERNET WINAPI MyInternetConnectA(
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
);

//====================================================================================

HINTERNET (WINAPI *pInternetConnectW)(
	HINTERNET     hInternet,
	LPCWSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCWSTR        lpszUserName,
	LPCWSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
	) = InternetConnectW;

HINTERNET WINAPI MyInternetConnectW(
	HINTERNET     hInternet,
	LPCWSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCWSTR        lpszUserName,
	LPCWSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
);

//====================================================================================

BOOL (WINAPI *pInternetCrackUrlA)(
	LPCSTR            lpszUrl,
	DWORD             dwUrlLength,
	DWORD             dwFlags,
	LPURL_COMPONENTSA lpUrlComponents
) = InternetCrackUrlA;

BOOL WINAPI MyInternetCrackUrlA(
	LPCSTR            lpszUrl,
	DWORD             dwUrlLength,
	DWORD             dwFlags,
	LPURL_COMPONENTSA lpUrlComponents
);

//====================================================================================

BOOL (WINAPI *pInternetCrackUrlW)(
	LPCWSTR            lpszUrl,
	DWORD             dwUrlLength,
	DWORD             dwFlags,
	LPURL_COMPONENTSW lpUrlComponents
	) = InternetCrackUrlW;

BOOL WINAPI MyInternetCrackUrlW(
	LPCWSTR            lpszUrl,
	DWORD             dwUrlLength,
	DWORD             dwFlags,
	LPURL_COMPONENTSW lpUrlComponents
);

//====================================================================================

HINTERNET (WINAPI *pInternetOpenA)(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
	) = InternetOpenA;

HINTERNET WINAPI MyInternetOpenA(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
);

//====================================================================================

HINTERNET(WINAPI *pInternetOpenW)(
	LPCWSTR lpszAgent,
	DWORD  dwAccessType,
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD  dwFlags
	) = InternetOpenW;

HINTERNET WINAPI MyInternetOpenW(
	LPCWSTR lpszAgent,
	DWORD  dwAccessType,
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD  dwFlags
);

//====================================================================================

HINTERNET (WINAPI *pInternetOpenUrlA)(
	HINTERNET hInternet,
	LPCSTR    lpszUrl,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
	) = InternetOpenUrlA;

HINTERNET WINAPI MyInternetOpenUrlA(
	HINTERNET hInternet,
	LPCSTR    lpszUrl,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

//====================================================================================

HINTERNET(WINAPI *pInternetOpenUrlW)(
	HINTERNET hInternet,
	LPCWSTR    lpszUrl,
	LPCWSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
	) = InternetOpenUrlW;

HINTERNET WINAPI MyInternetOpenUrlW(
	HINTERNET hInternet,
	LPCWSTR    lpszUrl,
	LPCWSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

//====================================================================================
