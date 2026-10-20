@echo off
setlocal
title KIK Windows 11 Security Check
echo Collecting information about your PC...

REM This BAT contains an embedded PowerShell script.
REM Edit the KB number in the PowerShell section below.
powershell.exe -NoLogo -NoProfile -Command "$p='%~f0'; $s=Get-Content -LiteralPath $p; $i=[Array]::IndexOf($s, ':POWERSHELL'); if ($i -lt 0) { throw 'PowerShell section not found.' }; $code=$s[($i+1)..($s.Length-1)] -join [Environment]::NewLine; & ([scriptblock]::Create($code))"
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo The check reported an error. Review the messages above.
pause
exit /b %RC%

:POWERSHELL
# ===================== CONFIGURATION =====================
# Replace this with the KB number your IT team requires.
# Example only: KB5060000 is NOT a recommendation for a current update.
$RequiredKB = 'KB5127648'

# Reports are saved in the current user's Documents folder.
# ========================================================

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Value,
        [string]$Notes = ''
    )
    $results.Add([pscustomobject]@{
        Check  = $Check
        Status = $Status
        Value  = $Value
        Notes  = $Notes
    })
}

function Get-RegistryUninstallEntries {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName }
    }
}

function Get-DefaultBrowserInfo {
    $progId = $null
    try {
        $progId = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -ErrorAction Stop).ProgId
    } catch {}
    $browser = switch -Regex ($progId) {
        'MSEdgeHTM' { 'Edge'; break }
        'ChromeHTML' { 'Chrome'; break }
        'FirefoxURL|FirefoxHTML' { 'Firefox'; break }
        default { 'Unknown' }
    }
    [pscustomobject]@{ ProgId = $progId; Browser = $browser }
}

function Get-ChromiumUblockStatus {
    param([string]$BrowserName, [string]$UserDataPath)

    if (-not (Test-Path -LiteralPath $UserDataPath)) {
        return [pscustomobject]@{ Status='UNKNOWN'; Value=''; Notes="$BrowserName profile folder not found." }
    }

    $profiles = @()
    $defaultProfile = Join-Path $UserDataPath 'Default'
    if (Test-Path -LiteralPath $defaultProfile) { $profiles += Get-Item -LiteralPath $defaultProfile }
    $profiles += Get-ChildItem -LiteralPath $UserDataPath -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^Profile \d+$' }

    $matches = @()
    $couldRead = $false
    foreach ($profile in $profiles) {
        $prefPath = Join-Path $profile.FullName 'Preferences'
        if (-not (Test-Path -LiteralPath $prefPath)) { continue }
        try {
            $prefs = Get-Content -LiteralPath $prefPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $settings = $prefs.extensions.settings
            if ($null -eq $settings) { continue }
            $couldRead = $true
            foreach ($prop in $settings.PSObject.Properties) {
                $ext = $prop.Value
                $name = [string]$ext.manifest.name
                $id = [string]$prop.Name
                if ($name -match '(?i)^ublock' -or $id -eq 'cjpalhdlnbpafiamejdnhcphjbkeiagm') {
                    $enabled = ($null -ne $ext.state -and [int]$ext.state -eq 1)
                    $displayName = if ($name) { $name } else { "uBlock (name not available; ID $id)" }
                    $matches += [pscustomobject]@{
                        Profile = $profile.Name
                        Name = $displayName
                        Enabled = $enabled
                    }
                }
            }
        } catch {
            # A browser may be running and its Preferences file may be locked or temporarily incomplete.
        }
    }

    if ($matches.Count -gt 0) {
        $enabledMatches = @($matches | Where-Object Enabled)
        $summary = ($matches | ForEach-Object {
            "$($_.Name) in $($_.Profile): " + $(if ($_.Enabled) {'enabled'} else {'not enabled'})
        }) -join '; '
        if ($enabledMatches.Count -gt 0) {
            return [pscustomobject]@{ Status='OK'; Value=$summary; Notes='Profiles found in browser data; browser may have multiple profiles.' }
        }
        return [pscustomobject]@{ Status='NOT OK'; Value=$summary; Notes='uBlock found, but not enabled in the examined profiles.' }
    }

    if ($couldRead) {
        return [pscustomobject]@{ Status='NOT OK'; Value='No enabled uBlock extension found'; Notes='The readable profiles contain no extension whose name starts with uBlock (or the known uBlock Origin ID).' }
    }
    return [pscustomobject]@{ Status='UNKNOWN'; Value=''; Notes='No usable extension data could be read. Close the browser and try again.' }
}

function Get-FirefoxUblockStatus {
    $base = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
    if (-not (Test-Path -LiteralPath $base)) {
        return [pscustomobject]@{ Status='UNKNOWN'; Value=''; Notes='Firefox profile folder not found.' }
    }
    $found = @()
    $couldRead = $false
    foreach ($profile in (Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
        $extFile = Join-Path $profile.FullName 'extensions.json'
        if (-not (Test-Path -LiteralPath $extFile)) { continue }
        try {
            $data = Get-Content -LiteralPath $extFile -Raw | ConvertFrom-Json
            $couldRead = $true
            foreach ($ext in $data.addons) {
                $name = [string]$ext.defaultLocale.name
                $id = [string]$ext.id
                if ($name -match '(?i)^ublock' -or $id -eq 'uBlock0@raymondhill.net') {
                    $active = [bool]$ext.active
                    $displayName = if ($name) { $name } else { "uBlock (name not available; ID $id)" }
                    $found += [pscustomobject]@{ Profile=$profile.Name; Name=$displayName; Active=$active }
                }
            }
        } catch {}
    }
    if ($found.Count -gt 0) {
        $summary = ($found | ForEach-Object {
            "$($_.Name) in $($_.Profile): " + $(if ($_.Active) {'enabled'} else {'not enabled'})
        }) -join '; '
        if (@($found | Where-Object Active).Count -gt 0) {
            return [pscustomobject]@{ Status='OK'; Value=$summary; Notes='Profile data read; multiple Firefox profiles are possible.' }
        }
        return [pscustomobject]@{ Status='NOT OK'; Value=$summary; Notes='uBlock found, but not enabled.' }
    }
    if ($couldRead) {
        return [pscustomobject]@{ Status='NOT OK'; Value='No enabled uBlock extension found'; Notes='No matching extension found in the readable Firefox profiles.' }
    }
    return [pscustomobject]@{ Status='UNKNOWN'; Value=''; Notes='Extension data not available.' }
}

function Get-AvProductState {
    param([uint32]$ProductState)
    $rtByte = ($ProductState -shr 8) -band 0xFF
    $sigByte = $ProductState -band 0xFF
    $enabled = ($rtByte -band 0xF0) -eq 0x10
    $signaturesCurrent = ($sigByte -band 0xF0) -eq 0x00
    return [pscustomobject]@{ Enabled = $enabled; SignaturesCurrent = $signaturesCurrent }
}

function Get-McAfeeStatus {
    param([array]$AvProducts)

    $mcafeeProducts = @($AvProducts | Where-Object { $_.displayName -match 'McAfee' })
    if ($mcafeeProducts.Count -eq 0) {
        return [pscustomobject]@{ Detected = $false; DisplayName = ''; InstalledProducts = ''; Version = ''; AllVersions = ''; DATVersion = ''; RealTimeEnabled = $null }
    }

    $displayName = ($mcafeeProducts | ForEach-Object { $_.displayName } | Where-Object { $_ } | Select-Object -Unique) -join '; '
    $productState = $mcafeeProducts[0].productState
    $avState = Get-AvProductState -ProductState $productState

    $installedProducts = @()
    try {
        $installedProducts = @(Get-RegistryUninstallEntries | Where-Object { $_.DisplayName -match 'McAfee' } |
            ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)".Trim() } | Select-Object -Unique)
    } catch {}

    $version = ''
    $allVersions = @()
    $datVersion = ''
    $realTimeEnabled = $null

    $regPaths = @(
        'HKLM:\SOFTWARE\McAfee\DesktopProtection',
        'HKLM:\SOFTWARE\WOW6432Node\McAfee\DesktopProtection',
        'HKLM:\SOFTWARE\McAfee\AVSolution\MCSHIELD',
        'HKLM:\SOFTWARE\WOW6432Node\McAfee\AVSolution\MCSHIELD',
        'HKLM:\SOFTWARE\McAfee\VirusScan\InstallSettings',
        'HKLM:\SOFTWARE\WOW6432Node\McAfee\VirusScan\InstallSettings',
        'HKLM:\SOFTWARE\McAfee\Endpoint Protection',
        'HKLM:\SOFTWARE\WOW6432Node\McAfee\Endpoint Protection',
        'HKLM:\SOFTWARE\McAfee\WebAdvisor',
        'HKLM:\SOFTWARE\WOW6432Node\McAfee\WebAdvisor',
        'HKLM:\SOFTWARE\McAfee\wps',
        'HKLM:\SOFTWARE\WOW6432Node\McAfee\wps'
    )
    foreach ($regPath in $regPaths) {
        try {
            $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
            foreach ($prop in @($props.ProductVersion, $props.Version, $props.FullVersion)) {
                if ($prop) {
                    $v = [string]$prop
                    if ($v -and $allVersions -notcontains $v) { $allVersions += $v }
                }
            }
            if (-not $datVersion -and $props.DATVersion) { $datVersion = [string]$props.DATVersion }
            if (-not $datVersion -and $props.DatVersion) { $datVersion = [string]$props.DatVersion }
        } catch {}
    }
    if ($allVersions.Count -gt 0) { $version = ($allVersions | Select-Object -Unique) -join '; ' }

    $shstatPaths = @(
        "${env:ProgramFiles}\McAfee\VirusScan Enterprise\shstat.exe",
        "${env:ProgramFiles(x86)}\McAfee\VirusScan Enterprise\shstat.exe",
        "${env:ProgramFiles}\McAfee\Endpoint Security\shstat.exe",
        "${env:ProgramFiles(x86)}\McAfee\Endpoint Security\shstat.exe"
    )
    foreach ($shstat in $shstatPaths) {
        if (-not (Test-Path -LiteralPath $shstat)) { continue }
        try {
            $output = & $shstat 2>$null
            if (-not $realTimeEnabled -and $output -match 'Access Scanning.*:\s*(\w+)') {
                $realTimeEnabled = $matches[1] -eq 'Enabled'
            }
            if (-not $version -and $output -match 'Version.*:\s*([\d.]+)') {
                $version = $matches[1]
            }
            if (-not $datVersion -and $output -match 'DAT.*:\s*([\d.]+)') {
                $datVersion = $matches[1]
            }
        } catch {}
    }

    return [pscustomobject]@{
        Detected = $true
        DisplayName = $displayName
        InstalledProducts = ($installedProducts -join '; ')
        Version = $version
        AllVersions = $version
        DATVersion = $datVersion
        RealTimeEnabled = $realTimeEnabled
        WscEnabled = $avState.Enabled
        WscSignaturesCurrent = $avState.SignaturesCurrent
        WscState = ('0x{0:X}' -f $productState)
    }
}

try {
    # Device name
    Add-Result 'Device name' 'OK' $env:COMPUTERNAME

    # Windows version / build
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $winValue = "$($os.Caption); version $($cv.DisplayVersion); build $($os.BuildNumber)"
    Add-Result 'Windows version' 'OK' $winValue 'Check that the device is using Windows 11.'

    # Antivirus products registered with Windows Security Center
    $avProducts = @()
    try {
        $avProducts = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
    } catch {}
    $avNames = @($avProducts | ForEach-Object { $_.displayName } | Where-Object { $_ } | Select-Object -Unique)
    if ($avNames.Count -gt 0) {
        Add-Result 'Antivirus registered' 'OK' ($avNames -join '; ') 'Windows Security Center lists these products; this alone does not prove that all protection functions work.'
    } else {
        Add-Result 'Antivirus registered' 'UNKNOWN' '' 'No antivirus product could be read via Windows Security Center.'
    }

    # Microsoft Defender details (available only where Defender cmdlets are available)
    $defenderAvailable = $false
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defenderAvailable = $true
        $defenderStatus = if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) {'OK'} else {'NOT OK'}
        Add-Result 'Microsoft Defender active and real-time protection' $defenderStatus "AntivirusEnabled=$($mp.AntivirusEnabled); RealTimeProtectionEnabled=$($mp.RealTimeProtectionEnabled)" 'With another primary antivirus, Defender may intentionally be in passive mode.'
        $sigDate = $mp.AntivirusSignatureLastUpdated
        if ($sigDate) {
            $sigStatus = if ((Get-Date) - $sigDate -le [TimeSpan]::FromDays(3)) {'OK'} else {'NOT OK'}
            Add-Result 'Last Defender virus definition update' $sigStatus ([string]$sigDate) 'OK means here: at most 3 days old; adjust the norm if necessary.'
        } else {
            Add-Result 'Last Defender virus definition update' 'UNKNOWN' '' 'Date not available.'
        }

        $threats = @()
        try { $threats = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.IsActive -eq $true }) } catch {}
        if ($threats.Count -eq 0) {
            Add-Result 'Active Microsoft Defender threats' 'OK' 'No active threats reported' 'This is no guarantee that the device is free of malware; the check depends on Defender and available rights.'
        } else {
            $names = @($threats | ForEach-Object { "$($_.ThreatName) (ID $($_.ThreatID))" }) -join '; '
            Add-Result 'Active Microsoft Defender threats' 'NOT OK' $names 'Check the notifications in Windows Security.'
        }
    } catch {
        Add-Result 'Microsoft Defender checks' 'UNKNOWN' '' 'Defender status could not be read; Defender may not be available or another antivirus is active.'
    }

    # McAfee details (when McAfee is the registered antivirus)
    $mcafee = Get-McAfeeStatus -AvProducts $avProducts
    if ($mcafee.Detected) {
        $mcafeeVersionValue = if ($mcafee.InstalledProducts) { $mcafee.InstalledProducts } elseif ($mcafee.AllVersions) { "McAfee $($mcafee.AllVersions)" } else { $mcafee.DisplayName }
        Add-Result 'McAfee installed products' 'OK' $mcafeeVersionValue 'Versions found in registry uninstall data; consumer McAfee products may not expose real-time protection or definition status via standard interfaces.'
        $mcafeeRtText = if ($mcafee.WscEnabled) {'enabled'} else {'disabled'}
        $mcafeeSigText = if ($mcafee.WscSignaturesCurrent) {'up to date'} else {'out of date'}
        $mcafeeValue = "Product=$($mcafee.DisplayName); real-time protection $mcafeeRtText; definitions $mcafeeSigText; DAT=$($mcafee.DATVersion)"
        $mcafeeStatus = if ($mcafee.WscEnabled) {'OK'} else {'NOT OK'}
        Add-Result 'McAfee antivirus enabled (Windows Security Center)' $mcafeeStatus $mcafeeValue 'Enabled state decoded from Windows Security Center productState. SignaturesCurrent reflects WSC freshness flag.'
        if ($mcafee.DATVersion) {
            Add-Result 'Last McAfee virus definition update' 'UNKNOWN' $mcafee.DATVersion 'DAT version retrieved; age check not available via standard cmdlets.'
        }
        Add-Result 'Active McAfee threats' 'UNKNOWN' '' 'Threat enumeration not available via standard cmdlets; check the McAfee console.'
    }

    # Required KB
    $kb = $RequiredKB.Trim().ToUpperInvariant()
    if ($kb -notmatch '^KB\d+$') {
        Add-Result 'Required Windows update' 'UNKNOWN' $RequiredKB 'Enter a valid KB number at the top of the script, e.g. KB1234567.'
    } else {
        $kbFound = $false
        try {
            $null = Get-HotFix -Id $kb -ErrorAction Stop
            $kbFound = $true
        } catch {}
        if (-not $kbFound) {
            # DISM can list packages not returned by Get-HotFix; this is a secondary check.
            try {
                $dismOutput = & dism.exe /Online /Get-Packages /Format:Table 2>$null
                if (($dismOutput -join "`n") -match [regex]::Escape($kb)) { $kbFound = $true }
            } catch {}
        }
        if ($kbFound) {
            Add-Result 'Required Windows update' 'OK' "$kb installed" 'Check via Get-HotFix and additional DISM. Some update forms are not shown in both sources.'
        } else {
            Add-Result 'Required Windows update' 'NOT OK' "$kb not found" 'Not found via Get-HotFix or DISM. Check manually via Windows Update history if needed; some updates are registered differently.'
        }
    }

    # BitLocker system drive
    try {
        $systemDrive = $env:SystemDrive
        $bl = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop
        $blStatus = [string]$bl.ProtectionStatus
        $blPercent = [string]$bl.EncryptionPercentage
        $blValue = "Drive=$systemDrive; VolumeStatus=$($bl.VolumeStatus); ProtectionStatus=$blStatus; EncryptionPercentage=$blPercent"
        if ($bl.ProtectionStatus -eq 'On' -and $bl.EncryptionPercentage -eq 100) {
            Add-Result 'BitLocker on system drive' 'OK' $blValue
        } elseif ($bl.ProtectionStatus -eq 'Off' -or $bl.EncryptionPercentage -lt 100) {
            Add-Result 'BitLocker on system drive' 'NOT OK' $blValue 'Check whether encryption and protection are required according to organizational policy.'
        } else {
            Add-Result 'BitLocker on system drive' 'UNKNOWN' $blValue 'Status could not be interpreted unambiguously.'
        }
    } catch {
        Add-Result 'BitLocker on system drive' 'UNKNOWN' '' 'BitLocker status not readable; permissions may be missing, BitLocker may not be available or another encryption method may be used.'
    }

    # Device Encryption (Windows Home alternative to BitLocker management)
    try {
        $sku = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).OperatingSystemSKU
        $secureBoot = $null
        try { $secureBoot = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop).UEFISecureBootEnabled } catch {}
        $devEnc = "$sku"
        if ($sku -eq 101) {
            $sbText = if ($secureBoot -eq 1) {'SecureBoot enabled'} elseif ($secureBoot -eq 0) {'SecureBoot disabled'} else {'SecureBoot state unknown'}
            $devEncValue = "Home edition (SKU $sku); $sbText. Device Encryption is the Home alternative to BitLocker management; check Settings - Privacy and security - Device encryption."
            Add-Result 'Device Encryption (Windows Home alternative)' 'UNKNOWN' $devEncValue 'BitLocker management is not available on Home; enable Device Encryption in Settings if supported by the hardware.'
        }
    } catch {}

    # Default browser and uBlock extension
    $browserInfo = Get-DefaultBrowserInfo
    if ($browserInfo.Browser -eq 'Unknown') {
        Add-Result 'Default browser' 'UNKNOWN' ([string]$browserInfo.ProgId) 'Browser not recognized via current user setting.'
        Add-Result 'uBlock extension enabled' 'UNKNOWN' '' 'Default browser not recognized.'
    } else {
        Add-Result 'Default browser' 'OK' "$($browserInfo.Browser) ($($browserInfo.ProgId))"
        $browserResult = $null
        switch ($browserInfo.Browser) {
            'Edge' {
                $browserResult = Get-ChromiumUblockStatus 'Edge' (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data')
            }
            'Chrome' {
                $browserResult = Get-ChromiumUblockStatus 'Chrome' (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data')
            }
            'Firefox' {
                $browserResult = Get-FirefoxUblockStatus
            }
        }
        Add-Result 'uBlock extension enabled' $browserResult.Status $browserResult.Value $browserResult.Notes
    }

    # Citrix Workspace app version
    $citrix = @(Get-RegistryUninstallEntries | Where-Object { $_.DisplayName -match 'Citrix Workspace' } |
        Sort-Object DisplayVersion -Descending)
    if ($citrix.Count -gt 0) {
        $versions = @($citrix | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" } | Select-Object -Unique)
        Add-Result 'Citrix Workspace version' 'OK' ($versions -join '; ') 'Version found in uninstall registry data; per-user or non-standard installations may be missing.'
    } else {
        Add-Result 'Citrix Workspace version' 'NOT APPLICABLE' 'Not found' 'Citrix Workspace does not appear to be installed for the examined registry locations.'
    }

    # Number of local Windows user accounts
    try {
        $localUsers = @(Get-LocalUser -ErrorAction Stop)
        Add-Result 'Number of local Windows users' 'OK' ([string]$localUsers.Count) 'Counts local accounts, including disabled accounts.'
    } catch {
        try {
            $localUsers = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
            Add-Result 'Number of local Windows users' 'OK' ([string]$localUsers.Count) 'Fallback via WMI; counts local accounts, including disabled accounts.'
        } catch {
            Add-Result 'Number of local Windows users' 'UNKNOWN' '' 'Local accounts could not be counted.'
        }
    }
} catch {
    Add-Result 'Script error' 'UNKNOWN' $_.Exception.Message 'An unexpected error interrupted part of the checks.'
}

# Save CSV locally
try {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if (-not $documents -or -not (Test-Path -LiteralPath $documents)) {
        $documents = $env:TEMP
    }
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $documents "WindowsSecurityCheck_$($env:COMPUTERNAME)_$timestamp.csv"
    $results | Export-Csv -LiteralPath $reportPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host 'Windows 11 security check completed.' -ForegroundColor Cyan
    Write-Host "Report: $reportPath"
    Write-Host ''
    $results | Format-Table Check, Status, Value -AutoSize -Wrap
    Write-Host ''
    Write-Host "Information saved as $reportPath. Email this file to the KIK." -ForegroundColor Cyan
} catch {
    Write-Host 'Report could not be saved.' -ForegroundColor Yellow
    $results | Format-Table Check, Status, Value -AutoSize -Wrap
    exit 1
}
