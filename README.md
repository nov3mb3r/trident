# TRIDENT
TRiage & IDENTification for incident response

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

TRIDENT is a PowerShell script for automated collection of evidence from forensic artifacts and volatile data, aimed to assist in the identification of compromise in Windows systems. The collected data will be stored inside a text file named after the hostname of the system.

## Breakdown of acquired evidence
### Network
- Active Network Interfaces
- DNS Cache
- Shared folders
- Connections by spawned processes

### Process Information
- Running processes
- Process Commandline

### Persistence
- Commands on Startup
- Scheduled Tasks
- Services

### Advanced
- Prefetch file information
- DLL List
- WMI filters and consumers
- Named pipes
- Kerberos sessions

## Usage
Using administrative privileges, just run the script from a PowerShell console:
```powershell
PS >.\trident.ps1
```
s
For Advanced collection
```powershell
PS >.\trident.ps1 -a
```

## Example

