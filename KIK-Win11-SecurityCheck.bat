@echo off
setlocal
title KIK Windows 11 Security Check
echo Collecting information about your PC...

REM Floris Wiesman, Klinische Informatiekunde, Amsterdam UMC
REM This BAT contains an embedded PowerShell script.
REM Edit the KB number in the PowerShell section below.
set "KIK_SCRIPT_PATH=%~f0"
powershell.exe -NoLogo -NoProfile -Command "$p=$env:KIK_SCRIPT_PATH; $s=Get-Content -LiteralPath $p; $i=[Array]::IndexOf($s, ':POWERSHELL'); if ($i -lt 0) { throw 'PowerShell section not found.' }; $code=$s[($i+1)..($s.Length-1)] -join [Environment]::NewLine; & ([scriptblock]::Create($code))"
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

# This tool must inspect the physical endpoint, not a Citrix/OneView session.
if ($env:SESSIONNAME -match '(?i)^ICA-TCP' -or $env:CTXSESSIONID) {
    Write-Host 'Error: Do not run this tool in OneView. It is for laptops and PCs only.' -ForegroundColor Red
    exit 2
}

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Value,
        [string]$Notes = ''
    )
    $results.Add([pscustomobject]@{
        Check  = Protect-CsvValue $Check
        Status = Protect-CsvValue $Status
        Value  = Protect-CsvValue $Value
        Notes  = Protect-CsvValue $Notes
    })
}

function Protect-CsvValue {
    param([AllowNull()][string]$Value)
    if ($null -ne $Value -and $Value -match '^[=+\-@]') {
        return "'$Value"
    }
    return $Value
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
        'BraveHTML' { 'Brave'; break }
        'OperaStable' { 'Opera'; break }
        'ChromiumHTM' { 'Chromium'; break }
        'VivaldiHTM' { 'Vivaldi'; break }
        'FirefoxURL|FirefoxHTML' { 'Firefox'; break }
        default { 'Unknown' }
    }
    [pscustomobject]@{ ProgId = $progId; Browser = $browser }
}

function Get-ChromiumUblockStatus {
    param([string]$BrowserName, [string]$UserDataPath)

    $knownExtensionIds = @(
        'cjpalhdlnbpafiamejdnhcphjbkeiagm' # Chrome Web Store
        'odfafepnkmbhccpbejgmiehpchacaeak' # Microsoft Edge Add-ons
        'ddkjiahejlhfcafbddmgiahcphecmpfh' # uBlock Origin Lite
        'cimighlppcgcoapaliogpjjdehbnofhn' # Microsoft Edge uBlock Origin Lite
    )

    if (-not (Test-Path -LiteralPath $UserDataPath)) {
        return [pscustomobject]@{ Status='UNKNOWN'; Value=''; Notes="$BrowserName profile folder not found." }
    }

    $profiles = @()
    $defaultProfile = Join-Path $UserDataPath 'Default'
    if (Test-Path -LiteralPath $defaultProfile) { $profiles += Get-Item -LiteralPath $defaultProfile }
    $profiles += Get-ChildItem -LiteralPath $UserDataPath -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'Preferences') }
    $profiles = @($profiles | Sort-Object FullName -Unique)

    $matches = @()
    $couldRead = $false
    foreach ($profile in $profiles) {
        $prefPaths = @(
            (Join-Path $profile.FullName 'Preferences')
            (Join-Path $profile.FullName 'Secure Preferences')
        ) | Where-Object { Test-Path -LiteralPath $_ }
        foreach ($prefPath in $prefPaths) {
          try {
            $prefs = Get-Content -LiteralPath $prefPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $settings = $prefs.extensions.settings
            if ($null -eq $settings) { continue }
            $couldRead = $true
            foreach ($prop in $settings.PSObject.Properties) {
                $ext = $prop.Value
                $id = [string]$prop.Name
                if ($knownExtensionIds -contains $id) {
                    $name = [string]$ext.manifest.name
                    if ($ext.disable_reasons -is [array]) {
                        $hasDisableReason = $ext.disable_reasons.Count -gt 0
                    } elseif ($null -eq $ext.disable_reasons) {
                        $hasDisableReason = $false
                    } else {
                        $hasDisableReason = [int]$ext.disable_reasons -ne 0
                    }
                    # Chromium versions increasingly use disable_reasons as the
                    # authoritative state; the legacy state field can be stale.
                    $enabled = -not $hasDisableReason
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
    }

    if ($matches.Count -gt 0) {
        $enabledMatches = @($matches | Where-Object Enabled)
        $summary = ($matches | ForEach-Object {
            $stateText = if ($null -eq $_.Enabled) {'state unknown'} elseif ($_.Enabled) {'enabled'} else {'not enabled'}
            "$($_.Name) in $($_.Profile): $stateText"
        }) -join '; '
        if ($enabledMatches.Count -gt 0) {
            return [pscustomobject]@{ Status='OK'; Value=$summary; Notes='Profiles found in browser data; browser may have multiple profiles.' }
        }
        return [pscustomobject]@{ Status='NOT OK'; Value=$summary; Notes='uBlock found, but not enabled in the examined profiles.' }
    }

    if ($couldRead) {
        return [pscustomobject]@{ Status='NOT OK'; Value='No enabled uBlock extension found'; Notes='The readable profiles contain no recognized uBlock extension with a trusted browser-store ID.' }
    }
    return [pscustomobject]@{ Status='UNKNOWN'; Value=''; Notes='No usable extension data could be read. Close the browser and try again.' }
}

function Get-FirefoxUblockStatus {
    $firefoxRoot = Join-Path $env:APPDATA 'Mozilla\Firefox'
    $base = Join-Path $firefoxRoot 'Profiles'
    if (-not (Test-Path -LiteralPath $firefoxRoot)) {
        return [pscustomobject]@{ Status='UNKNOWN'; Value=''; Notes='Firefox profile folder not found.' }
    }
    $profilePaths = @()
    $profilesIni = Join-Path $firefoxRoot 'profiles.ini'
    if (Test-Path -LiteralPath $profilesIni) {
        $section = @{}
        foreach ($line in (Get-Content -LiteralPath $profilesIni -ErrorAction SilentlyContinue)) {
            if ($line -match '^\[Profile\d+\]$') {
                if ($section.Path) {
                    $profilePaths += if ($section.IsRelative -eq '1') { Join-Path $firefoxRoot $section.Path } else { $section.Path }
                }
                $section = @{}
            } elseif ($line -match '^(Path|IsRelative)=(.*)$') {
                $section[$matches[1]] = $matches[2]
            }
        }
        if ($section.Path) {
            $profilePaths += if ($section.IsRelative -eq '1') { Join-Path $firefoxRoot $section.Path } else { $section.Path }
        }
    }
    if (Test-Path -LiteralPath $base) {
        $profilePaths += @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName)
    }
    $profilePaths = @($profilePaths | Where-Object { $_ } | Select-Object -Unique)
    $found = @()
    $couldRead = $false
    foreach ($profilePath in $profilePaths) {
        $extFile = Join-Path $profilePath 'extensions.json'
        if (-not (Test-Path -LiteralPath $extFile)) { continue }
        try {
            $data = Get-Content -LiteralPath $extFile -Raw | ConvertFrom-Json
            $couldRead = $true
            foreach ($ext in $data.addons) {
                $id = [string]$ext.id
                if ($id -in @('uBlock0@raymondhill.net', 'uBOLite@raymondhill.net')) {
                    $name = [string]$ext.defaultLocale.name
                    $active = [bool]$ext.active
                    $displayName = if ($name) { $name } else { "uBlock (name not available; ID $id)" }
                    $found += [pscustomobject]@{ Profile=(Split-Path $profilePath -Leaf); Name=$displayName; Active=$active }
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
        return [pscustomobject]@{ Status='NOT OK'; Value='No enabled uBlock extension found'; Notes='No uBlock Origin extension with the trusted Firefox ID was found in the readable profiles.' }
    }
    return [pscustomobject]@{ Status='UNKNOWN'; Value=''; Notes='Extension data not available.' }
}

function Get-AvProductState {
    param([uint32]$ProductState)
    $rtByte = ($ProductState -shr 8) -band 0xFF
    $sigByte = $ProductState -band 0xFF
    $enabled = switch ($rtByte -band 0xF0) {
        0x10 { $true; break }
        0x00 { $false; break }
        default { $null }
    }
    $signaturesCurrent = switch ($sigByte -band 0xF0) {
        0x00 { $true; break }
        0x10 { $false; break }
        default { $null }
    }
    return [pscustomobject]@{ Enabled = $enabled; SignaturesCurrent = $signaturesCurrent }
}

function Get-McAfeeStatus {
    param([array]$AvProducts)

    $mcafeeProducts = @($AvProducts | Where-Object { $_.displayName -match 'McAfee' })
    if ($mcafeeProducts.Count -eq 0) {
        return [pscustomobject]@{ Detected = $false; DisplayName = ''; InstalledProducts = ''; Version = ''; AllVersions = ''; DATVersion = ''; RealTimeEnabled = $null }
    }

    $displayName = ($mcafeeProducts | ForEach-Object { $_.displayName } | Where-Object { $_ } | Select-Object -Unique) -join '; '
    $productStates = @($mcafeeProducts | ForEach-Object {
        $rawState = $_.productState
        $state = if ($null -eq $rawState -or [string]::IsNullOrWhiteSpace([string]$rawState)) {
            [pscustomobject]@{ Enabled = $null; SignaturesCurrent = $null }
        } else {
            Get-AvProductState -ProductState ([uint32]$rawState)
        }
        [pscustomobject]@{
            Product = $_.displayName
            State = $state
            RawState = $rawState
        }
    })
    $enabledStates = @($productStates | ForEach-Object { $_.State.Enabled } | Where-Object { $null -ne $_ })
    $signatureStates = @($productStates | ForEach-Object { $_.State.SignaturesCurrent } | Where-Object { $null -ne $_ })
    $wscEnabled = if (@($enabledStates | Where-Object { $_ }).Count -gt 0) { $true } elseif ($enabledStates.Count -eq $productStates.Count) { $false } else { $null }
    $wscSignaturesCurrent = if (@($signatureStates | Where-Object { $_ }).Count -gt 0) { $true } elseif ($signatureStates.Count -eq $productStates.Count) { $false } else { $null }

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
        WscEnabled = $wscEnabled
        WscSignaturesCurrent = $wscSignaturesCurrent
        WscState = (($productStates | ForEach-Object { '{0}: 0x{1:X}' -f $_.Product, $_.RawState }) -join '; ')
    }
}

try {
    # Device name
    Add-Result 'Device name' 'OK' $env:COMPUTERNAME

    # Windows version / build
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $winValue = "$($os.Caption); version $($cv.DisplayVersion); build $($os.BuildNumber)"
    $winStatus = if ($os.Caption -match '^Microsoft Windows 11\b') { 'OK' } else { 'NOT OK' }
    Add-Result 'Windows version' $winStatus $winValue 'The check requires a Microsoft Windows 11 client operating system.'

    # Antivirus products registered with Windows Security Center
    $avProducts = @()
    try {
        $avProducts = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
    } catch {}
    $avNames = @($avProducts | ForEach-Object { $_.displayName } | Where-Object { $_ } | Select-Object -Unique)
    if ($avNames.Count -gt 0) {
        Add-Result 'Antivirus registered' 'UNKNOWN' ($avNames -join '; ') 'Windows Security Center lists these products, but registration alone does not prove that protection is enabled or current.'
    } else {
        Add-Result 'Antivirus registered' 'UNKNOWN' '' 'No antivirus product could be read via Windows Security Center.'
    }

    # Microsoft Defender details (available only where Defender cmdlets are available)
    $defenderAvailable = $false
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defenderAvailable = $true
        $thirdPartyAv = @($avProducts | Where-Object { $_.displayName -and $_.displayName -notmatch '(?i)Microsoft Defender|Windows Defender' }).Count -gt 0
        if ($thirdPartyAv -and $mp.AMRunningMode -eq 'Passive') {
            $defenderStatus = 'NOT APPLICABLE'
            $defenderNote = 'Microsoft Defender is passive because another antivirus is registered as the primary product.'
        } else {
            $defenderStatus = if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) {'OK'} else {'NOT OK'}
            $defenderNote = 'With another primary antivirus, Defender may intentionally be in passive mode.'
        }
        Add-Result 'Microsoft Defender active and real-time protection' $defenderStatus "AntivirusEnabled=$($mp.AntivirusEnabled); RealTimeProtectionEnabled=$($mp.RealTimeProtectionEnabled); AMRunningMode=$($mp.AMRunningMode)" $defenderNote
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
        $mcafeeRtText = if ($null -eq $mcafee.WscEnabled) {'unknown'} elseif ($mcafee.WscEnabled) {'enabled'} else {'disabled'}
        $mcafeeSigText = if ($null -eq $mcafee.WscSignaturesCurrent) {'unknown'} elseif ($mcafee.WscSignaturesCurrent) {'up to date'} else {'out of date'}
        $mcafeeValue = "Product=$($mcafee.DisplayName); real-time protection $mcafeeRtText; definitions $mcafeeSigText; DAT=$($mcafee.DATVersion)"
        $mcafeeStatus = if ($null -eq $mcafee.WscEnabled) {'UNKNOWN'} elseif ($mcafee.WscEnabled) {'OK'} else {'NOT OK'}
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
        $packageCheckAvailable = $false
        try {
            $null = Get-HotFix -Id $kb -ErrorAction Stop
            $kbFound = $true
        } catch {}
        if (-not $kbFound) {
            # Get-WindowsPackage provides structured package state for updates that
            # are not exposed through Win32_QuickFixEngineering/Get-HotFix.
            try {
                $packages = @(Get-WindowsPackage -Online -ErrorAction Stop)
                $packageCheckAvailable = $true
                $kbPattern = "(?i)(^|[^A-Z0-9])$([regex]::Escape($kb))([^A-Z0-9]|$)"
                $kbFound = @($packages | Where-Object {
                    $_.PackageState -eq 'Installed' -and
                    ([string]$_.PackageName -match $kbPattern)
                }).Count -gt 0
            } catch {}
        }
        if (-not $kbFound -and -not $packageCheckAvailable) {
            # DISM /Format:List is a fallback for systems without the cmdlet.
            try {
                $dismText = (& dism.exe /English /Online /Get-Packages /Format:List 2>$null | Out-String)
                if ($dismText) {
                    $packageCheckAvailable = $true
                    $kbPattern = "(?i)(^|[^A-Z0-9])$([regex]::Escape($kb))([^A-Z0-9]|$)"
                    $packageBlocks = $dismText -split '(?m)(?=^Package Identity\s*:)' | Where-Object { $_ }
                    $kbFound = @($packageBlocks | Where-Object {
                        $_ -match '(?im)^State\s*:\s*Installed\s*$' -and $_ -match $kbPattern
                    }).Count -gt 0
                }
            } catch {}
        }
        if ($kbFound) {
            Add-Result 'Required Windows update' 'OK' "$kb installed" 'Checked Get-HotFix and structured Windows package state. This verifies the exact KB; a superseding update may require a separate baseline policy.'
        } elseif (-not $packageCheckAvailable) {
            Add-Result 'Required Windows update' 'UNKNOWN' "$kb could not be verified" 'Neither Get-HotFix nor structured Windows package inventory was available.'
        } else {
            Add-Result 'Required Windows update' 'NOT OK' "$kb not found" 'Not found as an installed package via Get-HotFix or structured Windows package inventory. A superseding update may require a separate baseline policy.'
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
            $systemDrive = $env:SystemDrive
            $volume = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$systemDrive'" -ErrorAction Stop
            $conversionText = switch ([int]$volume.ConversionStatus) {
                0 { 'Fully decrypted' }
                1 { 'Fully encrypted' }
                2 { 'Encryption in progress' }
                3 { 'Decryption in progress' }
                4 { 'Encryption paused' }
                5 { 'Decryption paused' }
                default { "Unknown ($($volume.ConversionStatus))" }
            }
            $protectionText = switch ([int]$volume.ProtectionStatus) {
                0 { 'off' }
                1 { 'on' }
                2 { 'unknown' }
                default { "unknown ($($volume.ProtectionStatus))" }
            }
            $devEncValue = "Home edition (SKU $sku); Drive=$systemDrive; ConversionStatus=$conversionText; ProtectionStatus=$protectionText; $sbText"
            if ([int]$volume.ConversionStatus -eq 1 -and [int]$volume.ProtectionStatus -eq 1) {
                Add-Result 'Device Encryption (Windows Home alternative)' 'OK' $devEncValue 'Encryption and protection reported by Win32_EncryptableVolume.'
            } elseif ([int]$volume.ConversionStatus -eq 0 -or [int]$volume.ProtectionStatus -eq 0) {
                Add-Result 'Device Encryption (Windows Home alternative)' 'NOT OK' $devEncValue 'Device Encryption is not fully enabled on the system drive.'
            } else {
                Add-Result 'Device Encryption (Windows Home alternative)' 'UNKNOWN' $devEncValue 'Device Encryption is transitioning or the status could not be interpreted.'
            }
        }
    } catch {
        if ($sku -eq 101) {
            Add-Result 'Device Encryption (Windows Home alternative)' 'UNKNOWN' '' 'Win32_EncryptableVolume could not report Device Encryption status; the feature may be unavailable or permissions may be missing.'
        }
    }

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
            'Brave' {
                $browserResult = Get-ChromiumUblockStatus 'Brave' (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data')
            }
            'Opera' {
                $browserResult = Get-ChromiumUblockStatus 'Opera' (Join-Path $env:APPDATA 'Opera Software\Opera Stable')
            }
            'Chromium' {
                $browserResult = Get-ChromiumUblockStatus 'Chromium' (Join-Path $env:LOCALAPPDATA 'Chromium\User Data')
            }
            'Vivaldi' {
                $browserResult = Get-ChromiumUblockStatus 'Vivaldi' (Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data')
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
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $reportPath = Join-Path $documents "WindowsSecurityCheck_$($env:COMPUTERNAME)_$timestamp.csv"
    $suffix = 1
    while (Test-Path -LiteralPath $reportPath) {
        $reportPath = Join-Path $documents "WindowsSecurityCheck_$($env:COMPUTERNAME)_$timestamp`_$suffix.csv"
        $suffix++
    }
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
