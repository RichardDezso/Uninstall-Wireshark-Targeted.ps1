
### Uninstall-Wireshark-Targeted.ps1
PowerShell script to uninstall Wireshark by **exact version**, **patterns**, or **minimum-version threshold**. Handles **MSI/EXE**, finds installs in **HKLM/HKCU (x64/x86)**, stops `wireshark`/`tshark`/`dumpcap`, optional **Npcap** removal, logs to file, optional **CSV** report.

## Requirements
- Windows PowerShell **5.1+** or PowerShell **7+**
- Run from an **elevated** console for machine-wide uninstalls
- Enable script execution for the current session:
  ```powershell
  Set-ExecutionPolicy -Scope Process Bypass
  Unblock-File .\automation\Uninstall-Wireshark-Targeted.ps1

# Dry run (no changes)
.\Uninstall-Wireshark-Targeted.ps1 -MinVersion 4.2.0 -WhatIf -Verbose

# Remove anything older than 4.2.0
.\Uninstall-Wireshark-Targeted.ps1 -MinVersion 4.2.0 -Verbose

# Remove specific versions
.\Uninstall-Wireshark-Targeted.ps1 -RemoveVersions 2.2.1,2.4.10 -Verbose

# Remove by pattern
.\Uninstall-Wireshark-Targeted.ps1 -RemoveVersionPatterns "2.2.*","3.0*" -Verbose

## Options

\-RemoveNpcap — also uninstall Npcap (stops the service).

\-ReportCsv — write a CSV of findings/actions, e.g. C:\\Temp\\ws-removal.csv.

\-LogPath — log file path (default: C:\\ProgramData\\WiresharkRemediation\\remove-wireshark.log).

\-Verbose — detailed progress.

\-WhatIf — dry run (no changes).
