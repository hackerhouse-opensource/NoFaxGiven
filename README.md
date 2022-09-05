NoFaxGiven - Code Execution & Persistence in NETWORK SERVICE FAX Service
========================================================================
A fax routing extension is a DLL that adds routing functionality to the fax service. Multiple 
fax routing extensions can reside on one server. When the fax server receives a fax transmission, 
it routes the received document through each of the fax routing extensions in order of priority. 
A user sets the routing priority using the fax service administration application, a Microsoft 
Management Console (MMC) snap-in component. The FAX service runs manually when an application 
requests a connection to the FAX service, (such as when loading fxsadmin in MMC). On Desktops the
service is present but will timeout when attempting to set extensions as requires config & role. 
More on MSDN. Administrator rights are required to interact with the service by default, if a 
user has the FAX Config roles to the FAX service and is elevated then they may extend the FAX service. 
This exploit requires the FAX server role which is not available on workstations by default. It is
installed on Servers that enable Fax & Print Services.

Users in the FAX Group who have the FAX Config role can also add / remove extensions which maybe
configured with 3rd party FAX programs. FAX Config role is supplied to users in the local Administrator
or Domain Administrator group by default, additional users must have explicitly been defined in 
FAX service user configuration if using as part of a privilege escalation path in Active Directory.

Learn more:
https://docs.microsoft.com/en-us/previous-versions/windows/desktop/fax/-mfax-fax-routing-extension

We can also persist inside the FAX service - our DLL will be called each time the service is started, 
which is not automatically called on a reboot so would only offer persistence on servers that 
are actively using FAX features, it also offers an attacker an alternative pathway to SYSTEM from 
Administrator privileges as you can escalate from the Network Service to SYSTEM.

Extends the FAX service to execute any commands in c:\temp\run.bat once and cleans up the FXSSVC. Uses 
Fax Extension DLL with appropriate callbacks to start/stop FAX service reliably, the extension launches 
commands from bat file. You can prevent removal of the DLL for "persistence" purposes which will run the 
batch command file any time the FAX service is used, such as when opening, sending or recieving FAX. 

Compile this Project with Visual Studio 22, both x86 and x64 static binaries will be produced that 
require to be in the same directory. 

``` 
C:\Windows\system32>whoami
 nt authority\network service
 
 C:\Windows\system32>whoami /priv
  
 PRIVILEGES INFORMATION
 ----------------------
  
 Privilege Name                Description                               State
 ============================= ========================================= ========
 SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
 SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
 SeAuditPrivilege              Generate security audits                  Enabled
 SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
 SeImpersonatePrivilege        Impersonate a client after authentication Enabled
 SeCreateGlobalPrivilege       Create global objects                     Enabled
  
 ```