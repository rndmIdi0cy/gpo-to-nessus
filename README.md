# gpo-to-nessus

This script will convert (most of) the output of a parsed GPO from Microsofts LGPO utility. 

## Requirements

Download LGPO from the Microsoft Security Compliance Toolkit [https://www.microsoft.com/en-us/download/details.aspx?id=55319]

Open a cmd prompt or powershell and go to the directory of the extraacted LGPO utility. Use the /m switch for machine or /u for user policy

```
> LGPO.exe /parse /m [path/to/gpo/registry.pol] >> lgpo.txt
```

## Usage

```
    Required
      -OutputFile           : Destination file path for the audit file
      -GPOSettingsFile      : Parsed GPO file from LGPO
    
    Optional
      -AuditVersion         : Set the audit file version
      -ADMLTempDB           : Set the temp
      -AuditDescription     : Set the audit file description
      -PolicyDefsFolder     : Folder path that contains the ADML files
      -ShowVerbose          : Show verbose messages
    Examples
      .\gpo_to_audit.ps1 -OutputFile 'C:\Temp\nessus_win_baseline.audit' -GPOSettingsFile 'C:\Temp\computers_gpo.txt'
      .\gpo_to_audit.ps1 -AuditVersion 2 -ShowVerbose
```
