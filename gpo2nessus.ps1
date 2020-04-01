<#
.SYNOPSIS
    Script to generate a Tenable Nessus compliance audit file from an export of 
    Windows Group Policy via LGPO.
.EXAMPLE
    .\create-nessusaudit.ps1 -OutputFile 'C:\windows_gpo.audit' -Version 2 -ADMLTempDB 'C:\temp_adml.xml'
.PARAMETER OutputFile
    The file path where the Nessus audit file will be saved to
.PARAMETER PolicyDefsFolder
    Folder location of the ADML Policy Definitions
.PARAMETER Version
    The revision number of the audit file
.PARAMETER ADMLTempDB
    The file path where to store the temporary ADML 'database'
.PARAMETER AuditDescription
    A short description for the purpose of the audit file
.PARAMETER ShowVerbose
    Enable Verbose output
.PARAMETER GPOSettingsFiles
    File path to an exported group policy from LGPO.exe
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false, HelpMessage = "The file and folder path to save the audit file to")]
    [string]
    $OutputFile = "$(Split-Path $MyInvocation.MyCommand.Path -Parent)\nessus_gpo.audit",

    [Parameter(Mandatory = $false, HelpMessage = "Location of the ADML templates")]
    [string]
    $PolicyDefsFolder = "C:\Windows\PolicyDefinitions\en-US\",

    [Parameter(Mandatory = $false, HelpMessage = "Versioning of the audit file")]
    [string]
    $AuditVersion = "1",

    [Parameter(Mandatory = $false, HelpMessage = "The file and folder path for the ADML temporary database")]
    [string]
    $ADMLTempDB = "$($ENV:Temp)\adml_temp_database.xml",

    [Parameter(Mandatory = $false, HelpMessage = "Short description of the audit file")]
    [string]
    $AuditDescription = "Verifies Windows machines are in-line with corporate baseline",

    [Parameter(Mandatory = $false, HelpMessage = "Verbose information")]
    [switch]
    $ShowVerbose,

    [Parameter(Mandatory = $false, HelpMessage = "Exported GPO from LGPO utility")]
    [string]
    $GPOSettingsFile
)


function Write-Success($msg) {
    Write-Host -ForegroundColor Green -NoNewline "[+] "
    Write-Host "$($msg)"
}


function Write-Status($msg) {
    Write-Host -ForegroundColor DarkBlue -NoNewline "[*] "
    Write-Host "$($msg)"
}


function Write-Error($msg) {
    Write-Host -ForegroundColor Red -NoNewline "[!] "
    Write-Host "$($msg)"
}


function Write-Failure($msg) {
    Write-Host -ForegroundColor Magenta -NoNewline "[-] "
    Write-Host "$($msg)"
}


function Write-Debug($msg) {
    Write-Host -ForegroundColor Yellow -NoNewLine "[DEBUG] "
    Write-Host "$($msg)"
}


function usage() {
    Write-Output "
    Usage:

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
    "
}

function New-ADMLDatabase($policydefs_folder, $db_file_path) {
    if (Test-Path $db_file_path) {
        Remove-Item -Path $db_file_path -Force
    }

    if (!(Test-Path $policydefs_folder)) {
        Write-Error "could not find the policy definitions folder: $($policydefs_folder)"
        exit
    }

    $adml_files = Get-ChildItem -Path $policydefs_folder -Filter *.adml | Select-Object Name
    
    if (($adml_files | Measure-Object).Count -eq 0) {
        Write-Error "could not find any ADML files, check path"
        exit
    }

    [xml]$doc = New-Object System.Xml.XmlDocument
    $declaration = $doc.CreateXmlDeclaration("1.0", "UTF-8", $null)
    $doc.AppendChild($declaration) | Out-Null
    $root = $doc.CreateNode("element", "stringTable", $null)

    foreach ($adml in $adml_files.Name) {
        [xml]$xml = Get-Content -Path "$($policydefs_folder)/$($adml)"
        $string_table = $xml.policyDefinitionResources.resources.stringTable.string

        foreach ($string in $string_table) {
            $sid = $string.id
            $description = $string.'#text'

            $element = $doc.CreateElement("string")
            $element.SetAttribute("id", $sid)
            $element.InnerText = "$($description)"
            $root.AppendChild($element) | Out-Null
        }
    }

    $doc.AppendChild($root) | Out-Null
    $doc.Save($db_file_path)

    if (Test-Path $db_file_path) {
        Write-Success "temp ADML database file created"
    }
    else {
        Write-Failure "could not create temporary ADML database file"
        exit
    }
}


function New-NessusAuditFile($adml_db, $output_file, $audit_version, $audit_description, $gpo_settings) {
    $check_type_start   =   "<check_type: `"Windows`" version:`"$($audit_version)`">"
    $check_type_end     =   "</check_type>"
    $group_policy_start =   "`t<group_policy: `"$($audit_description)`">"
    $group_policy_end   =   "`t</group_policy>"
    $custom_item_start  =   "`t<custom_item>"
    $custom_item_end    =   "`t</custom_item>"
    $counter = 0

    $audit_file = New-Item -Path $output_file -ItemType File
    Add-Content $audit_file $check_type_start
    Add-Content $audit_file $group_policy_start

    foreach ($setting in $gpo_settings) {
        if ($setting -match "^;") {
            continue
        }

        if ($setting -match "^$") {
            continue
        }

        if ($setting -eq "Computer") {
            $reg_hive = "`"HKLM"
        }

        if ($setting -eq "User") {
            $reg_hive = "`"HKCU"
        }

        if ($counter -eq 1) {
            $reg_key = "$($reg_hive)\$($setting)`""
        }
    
        if ($counter -eq 2) {
            $res_strings = $xmlDB.stringTable.string `
            | Select-Object id, '#text' `
            | Where-Object {
                $_.id -match "^.*" + [regex]::Escape($setting) + "`$"
            }
    
            if ($res_strings.id) {
                $description = $res_strings.'#text'
            }
            else {
                $description = $setting
            }
    
            $reg_item = "`"$setting`""
        }
    
        if ($counter -eq 3) {
            if ($setting -match "([^:]*):(.*)") {
                $value_type = "POLICY_$($matches[1])"
                if ($matches[1] -eq "SZ") {
                    $value_data = "`"$($matches[2])`""
                }
                else {
                    $value_data = $matches[2]
                }
            }
            elseif ($setting -match "(DELETE|DELETEALLVALUES|CREATEKEYS)") {
                Write-Status "Skipping $($reg_item) as the action is: $($matches[1])"
                $counter = 0
                continue
            }
            else {
                Write-status "Entirely not sure whats here"
                $counter = 0
                continue
            }
        }
    
        if ($counter -eq 3) {
            if ($ShowVerbose) {
                Write-Debug "created entry for $($reg_item)"
            }
            Add-Content $audit_file $custom_item_start
            Add-Content $audit_file "`t`ttype:`t`t`tREGISTRY_SETTING"
            Add-Content $audit_file "`tdescription:`t`t$($description.Trim())"
            Add-Content $audit_file "`t`tvalue_type:`t`t$value_type"
            Add-Content $audit_file "`t`tvalue_data`t`t$value_data"
            Add-Content $audit_file "`t`treg_key:`t`t$reg_key"
            Add-Content $audit_file "`t`treg_item:`t`t$reg_item"
            Add-Content $audit_file $custom_item_end
            $counter = 0
        }
        else {
            $counter++
        }
    }

    Add-Content $audit_file $group_policy_end
    Add-Content $audit_file $check_type_end
}

if ($OutputFile -and $GPOSettingsFile) {
    Write-Success "creating ADML 'database'"
    New-ADMLDatabase $PolicyDefsFolder $ADMLTempDB 

    [xml]$admlDB = Get-Content -Path $ADMLTempDB
    Write-Success 'loaded ADML database'

    $gpoSettings = (Get-Content -Path "computer_gpo_utf8.txt")

    Write-Success "creating audit file"
    if (Test-Path $OutputFile) {
        $doOverwrite = Read-Host "[?] audit file already exists, overwrite? [y/N]"

        if (($doOverwrite.ToLower() -eq "y") -or ($doOverwrite.ToLower() -eq "yes")) {
            Remove-Item -Path $OutputFile -Force
        }
        else {
            do {
                $OutputFile = Read-Host "[+] Enter file path to save audit file:"
            }
            while(!(Test-Path $OutputFile))
        }
    }

    New-NessusAuditFile $admlDB $OutputFile $Version $AuditDescription $gpoSettings

    Write-Success "finished"
    Write-Success "file saved to: $($OutputFile)"
}
else {
    Write-Error "missing required parameter"
    usage
    exit
}
