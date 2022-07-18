# TRIDENT
<img src="https://raw.githubusercontent.com/nov3mb3r/trident/master/logo.PNG" width="550">


[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

TRIDENT is a PowerShell script for fast triage and collection of evidence from forensic artifacts and volatile data, aimed to assist in the identification of compromise in Windows systems. The collected data will be stored inside a text file named after the hostname of the system.

## Breakdown of collection details

### General information
- Group policy settings
- Encryption information

### Network
- Active network interfaces
- DNS cache
- Shared folders
- Connections by spawned processes

### Process Information
- Running processes
- Process commandline

### Persistence
- Commands on Startup
- Scheduled tasks
- Services

### User account activity
- Recent USB devices
- Recent files
- PowerShell history
- Kerberos sessions
- SMB sessions
- RDP sessions

### Advanced
- Prefetch file information
- DLL List
- WMI filters and consumers
- Named pipes

## Usage
Using administrative privileges, just run the script from a PowerShell console
```powershell
PS >.\trident.ps1
```

For Advanced collection
```powershell
PS >.\trident.ps1 -a
```

## Example
![](https://raw.githubusercontent.com/nov3mb3r/trident/master/example.PNG)
