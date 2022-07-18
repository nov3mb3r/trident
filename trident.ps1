# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.  You may obtain a copy of the License at;
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and limitations under the License.

param(
[Parameter(Mandatory=$False)]
[Switch]$a
)

$banner = @"
____________________________________________   _________
___  __/__  __ \___  _/__  __ \__  ____/__  | / /__  __/
__  /  __  /_/ /__  / __  / / /_  __/  __   |/ /__  /   
_  /   _  _, _/__/ /  _  /_/ /_  /___  _  /|  / _  /    
/_/    /_/ |_| /___/  /_____/ /_____/  /_/ |_/  /_/     
   

   Triage & Identification for Incident Response

"@

<#
.NAME
TRIDENT

.SYNOPSIS
Automation for the identification and triage step of Incident Response procedure.

.EXAMPLE
    PS C:\> .\trident.ps1
        Simply run the script or provide the argument -a for advanced investigation 
#>

$banner
$ErrorActionPreference= 'silentlycontinue'
# Check for Admin Rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host 'You must run TRIDENT using elevated privileges session...'
    Exit 1
}

$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$cname = (gi env:\Computername).Value
Write-Host "Collecting data for $cname ($ip) | $(Get-Date -Format dd/MM/yyyy-H:mm:ss)"

$data = {
"==== GENERAL INFORMATION ===="
#Get-ComputerInfo | Format-List -Property CsDNSHostName, CsDomain, OsName, OsVersion, OsBuildNumber, OsArchitecture, OsUptime, OsLocalDateTime, TimeZone, OsSerialNumber, OsMuiLanguages, OsHotFixes, WindowsRegisteredOrganization, WindowsRegisteredOwner, WindowsSystemRoot, OsPagingFiles, CsManufacturer, CsModel, CsName, CsProcessors, CsNetworkAdapters, BiosBIOSVersion, BiosSeralNumber, BiosFirmwareType, CsDomainRole, OsStatus, OsSuites, LogonServer, DeviceGuardSmartStatus, DeviceGuardRequiredSecurityProperties, DeviceGuardAvailableSecurityProperties, DeviceGuardSecurityServicesConfigured, DeviceGuardSecurityServicesRunning, DeviceGuardCodeIntegrityPolicyEnforcementStatus, DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus
systeminfo
"----------------------------------------
"

"--- Group policy settings ---"
gpresult.exe -z
"----------------------------------------
"

"--- Encryption information ---"
manage-bde.exe -status
"----------------------------------------
"

"==== NETWORK INFORMATION ===="
"--- Active Network Interfaces ---"
Get-NetAdapter | ? status -eq "up" |  Get-NetIPAddress | Select IPAddress,InterfaceIndex, InterfaceAlias, AddressFamily,PrefixOrigin |Sort InterfaceAlias | Format-Table -Wrap
"----------------------------------------
"

"--- DNS Cache ---"
Get-DnsClientCache -Status 'Success' | Select Name, Data
"----------------------------------------
"

"--- Shared folders ---"
net use
"----------------------------------------
"

"--- Process Connections ---"
$nets = netstat -bano|select-string 'TCP|UDP'; 
foreach ($n in $nets)    
{
$p = $n -replace ' +',' ';
$nar = $p.Split(' ');
$pname = $(Get-Process -id $nar[-1]).Path;
$n -replace "$($nar[-1])","$($ppath) $($pname)";
}
"----------------------------------------
"

"==== PROCESS INFORMATION ===="
"--- Running processes ---"
tasklist /v /fo table /fi "STATUS ne Unknown"
"----------------------------------------
"

"--- Process List ---"
Get-Process -IncludeUserName | Format-Table -Property Name, Id, Path, UserName, Company, Handles, StartTime, HasExited -Wrap
"----------------------------------------
"

"--- Process Commandline ---"
Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine | Sort Name | Format-Table -Wrap
"----------------------------------------
"

"==== PERSISTENCE ===="
"--- Commands on Startup ---"
Get-CimInstance -Class Win32_StartupCommand | Format-Table -Property Name, Command, User, Location -Wrap
"----------------------------------------
"

"--- Scheduled Tasks ---"
(Get-ScheduledTask).Where({$_.State -ne "Disabled"}) | Sort TaskPath | Format-Table -Wrap
"----------------------------------------
"

"--- Services ---"
Get-WmiObject win32_service | Select-Object Name, PathName, StartName, StartMode, State, ProcessId | Sort PathName| Format-Table -Wrap
#Get-CimInstance -Class Win32_Service -Filter "Caption LIKE '%'" | Select-Object Name, PathName, ProcessId, StartMode, State | Format-Table
"----------------------------------------
"

"==== USER ACTIVITY ===="
"--- Recently used USB devices ---"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName
"----------------------------------------
"

"--- Recently modified files ---"
$RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File
$RecentFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName, LastWriteTime
"----------------------------------------
"

"--- PowerShell history ---"
history
"----------------------------------------
"

"--- Kerberos sessions ---"
klist sessions
"----------------------------------------
"

"--- SMB sessions ---"
Get-SmbSession
"----------------------------------------
"

"--- RDP sessions ---"
qwinsta /server:localhost
"----------------------------------------
"

if ($a -eq $true)
{
"==== ADVANCED INVESTIGATION ===="
"--- Total Process Instances ---"
Get-Process | Group-Object ProcessName | Select Count, Name | Sort Count -Descending
"----------------------------------------
"

"--- Prefetch files ---"
gci C:\Windows\Prefetch\ | Sort Name | Format-Table Name,CreationTime,LastWriteTime,LastAccessTime
"----------------------------------------
"

"--- DLL List ---"
gps | Format-List ProcessName, @{l="Modules";e={$_.Modules|Out-String}}
"----------------------------------------
"

"--- WMI ---"
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription | FT Consumer,Filter,__SERVER -wrap
"----------------------------------------
"

"--- WMI Filters ---"
Get-WmiObject -Class __EventFilter -Namespace root\subscription | FT Name, Query, PSComputerName -wrap
"----------------------------------------
"

"--- WMI Consumers ---"
Get-WmiObject -Class __EventConsumer -Namespace root\subscription | FT Name,ScriptingEngine,ScriptText -wrap
"----------------------------------------
"

"--- Windows Defender Exclusions ---"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
"----------------------------------------
"

"--- Named Pipes List ---"
Get-ChildItem -Path '\\.\pipe\' |  Sort Length | Format-Table FullName, Length, IsReadOnly, Exists, CreationTime, LastAccessTime
"----------------------------------------
"

}

}

& $data | Out-File -FilePath $pwd\TRIDENT_$cname.txt
Write-Host "Collection saved in $pwd\TRIDENT_$cname.txt" -ForegroundColor Green
