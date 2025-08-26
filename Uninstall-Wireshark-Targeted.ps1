<#
.SYNOPSIS
  Remove Wireshark by explicit versions, wildcard patterns, or a minimum-version threshold.
  Searches HKLM/HKCU (x64 & x86 views), stops running processes, handles MSI/NSIS, optional Npcap removal,
  logs actions, and can export a CSV report.

.NOTES
  Run elevated. Test in non-prod. PowerShell 5.1+.
  Author: Richard Dezso

.PARAMETER RemoveVersions
  Exact versions to remove (e.g., 2.2.1, 3.4.7).

.PARAMETER RemoveVersionPatterns
  Wildcard patterns matched against DisplayVersion (e.g., "2.2.*","3.0*").

.PARAMETER MinVersion
  Used only if no explicit lists/patterns: removes anything strictly less than MinVersion.

.PARAMETER RemoveNpcap
  Also remove Npcap after Wireshark.

.PARAMETER LogPath
  Default: $env:ProgramData\WiresharkRemediation\remove-wireshark.log

.PARAMETER ReportCsv
  Optional CSV path to record findings/actions.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Version[]]$RemoveVersions = @(),
  [string[]]$RemoveVersionPatterns = @(),
  [Version]$MinVersion,
  [switch]$RemoveNpcap,
  [string]$LogPath   = "$env:ProgramData\WiresharkRemediation\remove-wireshark.log",
  [string]$ReportCsv
)

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
  param([string]$Message,[string]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line="$ts [$Level] $Message"
  Write-Host $line
  if ($LogPath) {
    $dir = Split-Path -Parent $LogPath
    if (-not (Test-Path $dir)) { New-Item -Force -ItemType Directory -Path $dir | Out-Null }
    Add-Content -Path $LogPath -Value $line
  }
}

function Get-UninstallEntries {
  param([string]$NameLike)
  $roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  foreach ($root in $roots) {
    if (Test-Path $root) {
      Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
        if ($p.DisplayName -and $p.DisplayName -like $NameLike) {
          [PSCustomObject]@{
            HivePath        = $_.PsPath
            DisplayName     = $p.DisplayName
            DisplayVersion  = $p.DisplayVersion
            UninstallString = $p.UninstallString
            InstallLocation = $p.InstallLocation
          }
        }
      }
    }
  }
}

function Stop-WiresharkProcesses {
  'Wireshark','tshark','dumpcap' | ForEach-Object {
    Get-Process -Name $_ -ErrorAction SilentlyContinue | ForEach-Object {
      Write-Log "Stopping process: $($_.ProcessName) (PID $($_.Id))"
      if ($PSCmdlet.ShouldProcess($_.ProcessName,'Stop-Process')) {
        try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
      }
    }
  }
}

function Parse-Version {
  param([string]$DisplayVersion)
  $norm = [regex]::Match($DisplayVersion,'\d+(\.\d+){1,3}').Value
  if ($norm) { try { return [Version]$norm } catch { return $null } }
  return $null
}

function Matches-ExplicitTarget {
  param([string]$DisplayVersion,[Version[]]$ExactVersions,[string[]]$Patterns)
  $v = Parse-Version -DisplayVersion $DisplayVersion
  if ($ExactVersions.Count -gt 0 -and $v) {
    if ($ExactVersions -contains $v) { return $true }
  }
  if ($Patterns.Count -gt 0) {
    foreach ($pat in $Patterns) { if ($DisplayVersion -like $pat) { return $true } }
  }
  return $false
}

function Invoke-SilentUninstall {
  param([string]$UninstallString,[string]$DisplayName)

  if (-not $UninstallString) {
    Write-Log "No UninstallString for $DisplayName" 'WARN'
    return @{ Success=$false; ExitCode=-1 }
  }

  $file=$null; $args=$null

  if ($UninstallString -match 'msiexec\.exe') {
    $guid = ($UninstallString | Select-String '{[0-9A-Fa-f-]+}').Matches.Value | Select-Object -First 1
    $file = "$env:SystemRoot\System32\msiexec.exe"
    $args = if ($guid) { "/x $guid /qn /norestart" } else { ($UninstallString -replace '(?i)/I','/x') + ' /qn /norestart' }
  } else {
    if ($UninstallString.StartsWith('"')) {
      $file = $UninstallString.Split('"')[1]
      $args = $UninstallString.Substring($file.Length + 2).Trim()
    } else {
      $file = $UninstallString.Split(' ')[0]
      $args = $UninstallString.Substring($file.Length).Trim()
    }
    if ($args -notmatch '(?i)(/S|/quiet|/qn)') { $args = "$args /S".Trim() }
  }

  Write-Log "Running uninstall: `"$file`" $args for $DisplayName"
  if ($PSCmdlet.ShouldProcess($DisplayName,'Uninstall')) {
    $p = Start-Process -FilePath $file -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
    $code = if ($p) { $p.ExitCode } else { -1 }
    Write-Log "$DisplayName uninstall exit code: $code"
    return @{ Success = ($code -eq 0); ExitCode = $code }
  }
  return @{ Success=$true; ExitCode=0 }
}

# --- Preflight ---
if (-not (Test-Admin)) { Write-Log "Not running as Administrator. Machine-wide uninstalls may fail." 'WARN' }

Write-Log "=== Wireshark targeted removal started ==="
$useExplicit = ($RemoveVersions.Count -gt 0) -or ($RemoveVersionPatterns.Count -gt 0)

$report = @()

# --- Find Wireshark installs ---
$apps = Get-UninstallEntries -NameLike '*Wireshark*'

if (-not $apps) {
  Write-Log "Wireshark not found."
} else {
  foreach ($app in $apps) {
    $disp = $app.DisplayVersion
    $ver  = Parse-Version -DisplayVersion $disp
    Write-Log "Found: $($app.DisplayName) | DisplayVersion='$disp' (parsed=$ver) | Hive='$($app.HivePath)'"

    $action = 'Skip'
    $exit   = $null
    $remove = $false

    if ($useExplicit) {
      $remove = Matches-ExplicitTarget -DisplayVersion $disp -ExactVersions $RemoveVersions -Patterns $RemoveVersionPatterns
      Write-Log "Version matches explicit list/patterns: $remove"
    } elseif ($MinVersion) {
      if ($ver -and ($ver -lt $MinVersion)) {
        $remove = $true
        Write-Log "Version $ver < MinVersion $MinVersion → mark for removal"
      } else {
        Write-Log "Version is >= MinVersion or unknown → skip"
      }
    } else {
      Write-Log "No RemoveVersions/Patterns or MinVersion provided → skip" 'WARN'
    }

    if ($remove) {
      Stop-WiresharkProcesses
      $res = Invoke-SilentUninstall -UninstallString $app.UninstallString -DisplayName $app.DisplayName
      $action = if ($res.Success) { 'Uninstalled' } else { 'Attempted-Uninstall-Failed' }
      $exit   = $res.ExitCode
    }

    $report += [pscustomobject]@{
      DisplayName     = $app.DisplayName
      DisplayVersion  = $disp
      ParsedVersion   = if ($ver) { $ver.ToString() } else { '' }
      HivePath        = $app.HivePath
      Action          = $action
      ExitCode        = $exit
      Timestamp       = (Get-Date)
    }
  }
}

# --- Optional: Npcap removal ---
if ($RemoveNpcap) {
  Write-Log "Npcap removal requested."
  $svc = Get-Service -Name 'npcap' -ErrorAction SilentlyContinue
  if ($svc) {
    Write-Log "Stopping service 'npcap'."
    if ($PSCmdlet.ShouldProcess('npcap','Stop-Service')) {
      try { Stop-Service -Name 'npcap' -Force -ErrorAction SilentlyContinue } catch {}
    }
  }
  $np = Get-UninstallEntries -NameLike '*Npcap*' | Select-Object -First 1
  if ($np) {
    $res = Invoke-SilentUninstall -UninstallString $np.UninstallString -DisplayName $np.DisplayName
    $report += [pscustomobject]@{
      DisplayName     = $np.DisplayName
      DisplayVersion  = $np.DisplayVersion
      ParsedVersion   = (Parse-Version -DisplayVersion $np.DisplayVersion)
      HivePath        = $np.HivePath
      Action          = if ($res.Success) { 'Uninstalled' } else { 'Attempted-Uninstall-Failed' }
      ExitCode        = $res.ExitCode
      Timestamp       = (Get-Date)
    }
  } else {
    Write-Log "Npcap not found."
  }
}


# --- Reporting ---
if ($ReportCsv) {
  $dir = Split-Path -Parent $ReportCsv
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  try {
    $report | Export-Csv -Path $ReportCsv -NoTypeInformation -Force -Encoding UTF8
    Write-Log "Wrote report to $ReportCsv"
  } catch {
    Write-Log ("Failed to write report to {0}: {1}" -f $ReportCsv, $_.Exception.Message) 'WARN'
  }
}

Write-Log "=== Wireshark targeted removal finished ==="
exit 0
