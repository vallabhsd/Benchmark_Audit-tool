function Handle-Output {
    param (
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        "$Message not satisfied." | Out-File -Append -FilePath "not_satisfied.txt"
    } else {
        "$Message satisfied." | Out-File -Append -FilePath "satisfied.txt"
    }
}
# 18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
function Check-PreventLockScreenSlideShowEnabled {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $regName = "NoLockScreenSlideshow"
    $expectedValue = 1

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoLockScreenSlideshow
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.1.1.2 Prevent enabling lock screen slide show is set to 'Enabled'."
}

# 18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'
function Check-AllowOnlineSpeechRecognitionDisabled {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    $regName = "AllowInputPersonalization"
    $expectedValue = 0

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowInputPersonalization
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.1.2.2 Allow users to enable online speech recognition services is set to 'Disabled'."
}

# 18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled'
function Check-AllowOnlineTipsDisabled {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $regName = "AllowOnlineTips"
    $expectedValue = 0

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowOnlineTips
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.1.3 Allow Online Tips is set to 'Disabled'."
}

# 18.4.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
function Check-ApplyUACRestrictionsLocalAccountsEnabled {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "LocalAccountTokenFilterPolicy"
    $expectedValue = 0

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.4.1 Apply UAC restrictions to local accounts on network logons is set to 'Enabled'."
}

# 18.4.2 (L1) Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'
function Check-ConfigureRPCPrivacyEnabled {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
    $regName = "RpcAuthnLevelPrivacyEnabled"
    $expectedValue = 1

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).RpcAuthnLevelPrivacyEnabled
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.4.2 Configure RPC packet level privacy setting for incoming connections is set to 'Enabled'."
}

# 18.4.3 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'
function Check-ConfigureSMBv1ClientDriver {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
    $regName = "Start"
    $expectedValue = 4

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).Start
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.4.3 Configure SMB v1 client driver is set to 'Enabled: Disable driver (recommended)'."
}

# 18.4.4 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'
function Check-ConfigureSMBv1ServerDisabled {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $regName = "SMB1"
    $expectedValue = 0

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).SMB1
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.4.4 Configure SMB v1 server is set to 'Disabled'."
}

# 18.4.5 (L1) Ensure 'Enable Certificate Padding' is set to 'Enabled'
function Check-EnableCertificatePadding {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
    $regName = "EnableCertPaddingCheck"
    $expectedValue = 1

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableCertPaddingCheck
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.4.5 Enable Certificate Padding is set to 'Enabled'."
}

# 18.4.6 (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
function Check-EnableSEHOP {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    $regName = "DisableExceptionChainValidation"
    $expectedValue = 0

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableExceptionChainValidation
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.4.6 Enable Structured Exception Handling Overwrite Protection (SEHOP) is set to 'Enabled'."
}

# 18.4.7 (L1) Ensure 'Turn on Data Execution Prevention (DEP) for Windows components' is set to 'Enabled'
function Check-TurnOnDEPForWindowsComponents {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $regName = "DataExecutionPrevention"
    $expectedValue = 1

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DataExecutionPrevention
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.4.7 Turn on Data Execution Prevention (DEP) for Windows components is set to 'Enabled'."
}

# 18.4.8 (L1) Ensure 'Turn on EMET protection for Outlook' is set to 'Enabled'
function Check-TurnOnEMETProtectionForOutlook {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security"
    $regName = "EnableEMETProtection"
    $expectedValue = 1

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableEMETProtection
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.4.8 Turn on EMET protection for Outlook is set to 'Enabled'."
}


# 18.5.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'
function Check-AutoAdminLogonDisabled {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regName = "AutoAdminLogon"
    $expectedValue = 0

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AutoAdminLogon
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.1 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'."
}

# 18.5.2 (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'
function Check-IPSourceRoutingProtection {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $regName = "DisableIPSourceRouting"
    $expectedValue = 2

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableIPSourceRouting
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.2 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'."
}

# 18.5.3 (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'
function Check-IPSourceRoutingProtectionIPv4 {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $regName = "DisableIPSourceRouting"
    $expectedValue = 2

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableIPSourceRouting
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.3 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'."
}



# 18.5.4 (L2) Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled'
function Check-DisableSavePassword {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
    $regName = "DisableSavePassword"
    $expectedValue = 1

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableSavePassword
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.4 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled'."
}


# 18.5.5 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
function Check-EnableICMPRedirect {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $regName = "EnableICMPRedirect"
    $expectedValue = 0

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableICMPRedirect
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.5 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'."
}


# 18.5.6 (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'
function Check-KeepAliveTime {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $regName = "KeepAliveTime"
    $expectedValue = 300000

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).KeepAliveTime
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.6 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'."
}
# 18.5.7 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
function Check-NoNameReleaseOnDemand {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $regName = "NoNameReleaseOnDemand"
    $expectedValue = 1

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoNameReleaseOnDemand
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.7 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'."
}
function Check-PerformRouterDiscovery {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $regName = "PerformRouterDiscovery"
    $expectedValue = 0

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).PerformRouterDiscovery
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.8 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled'."
}
# 18.5.9 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'
function Check-SafeDllSearchMode {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $regName = "SafeDllSearchMode"
    $expectedValue = 1

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).SafeDllSearchMode
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.9 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'."
}
function Check-ScreenSaverGracePeriod {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regName = "ScreenSaverGracePeriod"
    $expectedValue = 5

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).ScreenSaverGracePeriod
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.10 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds'."
}
function Check-TcpMaxDataRetransmissionsIPv6 {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
    $regName = "TcpMaxDataRetransmissions"
    $expectedValue = 3

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).TcpMaxDataRetransmissions
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.11 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
}
function Check-TcpMaxDataRetransmissionsIPv4 {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $regName = "TcpMaxDataRetransmissions"
    $expectedValue = 3

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).TcpMaxDataRetransmissions
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.12 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
}
function Check-SecurityLogWarningLevel {
    # Define the registry path and key
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
    $regName = "WarningLevel"
    $expectedValue = 90

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).WarningLevel
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.5.13 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'."
}
function Check-DNSOverHTTPS {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $regName = "DoHPolicy"
    $validValues = @(2, 3)  # 2 = Allow DoH, 3 = Require DoH

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DoHPolicy
    } else {
        $currentValue = $null
    }

    # Check if the current value is valid
    $isConfigCorrect = ($validValues -contains $currentValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.4.1 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher."
}
function Check-NetBIOSSettings {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $regName = "EnableNetbios"
    $validValues = @(0, 2)  # 0 or 2 = Disable NetBIOS name resolution on public networks

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableNetbios
    } else {
        $currentValue = $null
    }

    # Check if the current value is valid
    $isConfigCorrect = ($validValues -contains $currentValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.4.2 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'."
}
function Check-TurnOffMulticastNameResolution {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $regName = "EnableMulticast"
    $expectedValue = 0  # 0 = Disabled

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableMulticast
    } else {
        $currentValue = $null
    }

    # Check if the current value is as expected
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.4.3 'Turn off multicast name resolution' is set to 'Enabled'."
}
function Check-EnableFontProviders {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $regName = "EnableFontProviders"
    $expectedValue = 0  # 0 = Disabled

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableFontProviders
    } else {
        $currentValue = $null
    }

    # Check if the current value is as expected
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.5.1 'Enable Font Providers' is set to 'Disabled'."
}
function Check-EnableInsecureGuestLogons {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
    $regName = "AllowInsecureGuestAuth"
    $expectedValue = 0  # 0 = Disabled

    # Retrieve the current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowInsecureGuestAuth
    } else {
        $currentValue = $null
    }

    # Check if the current value is as expected
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.8.1 'Enable insecure guest logons' is set to 'Disabled'."
}
function Check-LLTDIOSettings {
    # Define the registry path and keys
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    $regKeys = @{
        "AllowLLTDIOOnDomain"        = 0
        "AllowLLTDIOOnPublicNet"     = 0
        "EnableLLTDIO"               = 0
        "ProhibitLLTDIOOnPrivateNet" = 0
    }

    # Check each registry key
    foreach ($key in $regKeys.Keys) {
        $expectedValue = $regKeys[$key]
        
        if (Test-Path $regPath) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $key -ErrorAction SilentlyContinue).$key
        } else {
            $currentValue = $null
        }

        # Check if the current value is as expected
        $isConfigCorrect = ($currentValue -eq $expectedValue)

        # Output result
        Handle-Output -Condition $isConfigCorrect -Message "18.6.9.1 '$key' is set to 'Disabled'."
    }
}
function Check-RSPNDRSettings {
    # Define the registry path and keys
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    $regKeys = @{
        "AllowRspndrOnDomain"        = 0
        "AllowRspndrOnPublicNet"     = 0
        "EnableRspndr"               = 0
        "ProhibitRspndrOnPrivateNet" = 0
    }

    # Check each registry key
    foreach ($key in $regKeys.Keys) {
        $expectedValue = $regKeys[$key]
        
        if (Test-Path $regPath) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $key -ErrorAction SilentlyContinue).$key
        } else {
            $currentValue = $null
        }

        # Check if the current value is as expected
        $isConfigCorrect = ($currentValue -eq $expectedValue)

        # Output result
        Handle-Output -Condition $isConfigCorrect -Message "18.6.9.2 '$key' is set to 'Disabled'."
    }
}
function Check-PeerNetworkingService {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
    $regKey = "Disabled"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regKey -ErrorAction SilentlyContinue).$regKey
    } else {
        $currentValue = $null
    }

    # Check if the current value is as expected
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.10.2 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'."
}

function Check-NetworkBridgePolicy {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $regKey = "NC_AllowNetBridge_NLA"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regKey -ErrorAction SilentlyContinue).$regKey
    } else {
        $currentValue = $null
    }

    # Check if the current value is as expected
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.11.2 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'."
}function Check-InternetConnectionSharingPolicy {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $regKey = "NC_ShowSharedAccessUI"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regKey -ErrorAction SilentlyContinue).$regKey
    } else {
        $currentValue = $null
    }

    # Check if the current value is as expected
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.11.3 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'."
}
function Check-RequireDomainUserElevation {
    # Define the registry path and key
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $regKey = "NC_StdDomainUserSetLocation"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regKey -ErrorAction SilentlyContinue).$regKey
    } else {
        $currentValue = $null
    }

    # Check if the current value is as expected
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.6.11.4 'Require domain users to elevate when setting a network's location' is set to 'Enabled'."
}


function Check-HardenedUNCPaths {
    # Define the registry paths and expected values
    $netlogonRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\NETLOGON"
    $sysvolRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\SYSVOL"
    $expectedValue = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"

    # Check if the registry paths exist
    $netlogonExists = Test-Path $netlogonRegPath
    $sysvolExists = Test-Path $sysvolRegPath

    # Get current values
    if ($netlogonExists) {
        $currentNetlogonValue = (Get-ItemProperty -Path $netlogonRegPath -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
    } else {
        $currentNetlogonValue = $null
    }

    if ($sysvolExists) {
        $currentSysvolValue = (Get-ItemProperty -Path $sysvolRegPath -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
    } else {
        $currentSysvolValue = $null
    }

    # Check if the current values are as expected
    $isNetlogonCorrect = ($currentNetlogonValue -eq $expectedValue)
    $isSysvolCorrect = ($currentSysvolValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition ($isNetlogonCorrect -and $isSysvolCorrect) -Message "18.6.14.1 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\", \"Require Integrity\", and \"Require Privacy\" set for all NETLOGON and SYSVOL shares'."
}
function Check-IPv6DisabledComponents {
    # Define the registry path and expected value
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
    $regName = "DisabledComponents"
    $expectedValue = 255

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    } else {
        $currentValue = $null
    }

    # Check if the current value matches the expected value
    $isCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isCorrect -Message "18.6.19.2.1 IPv6 is disabled with 'DisabledComponents' set to '0xff (255)'."
}

function Check-WCNSettings {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Check each registry value
        $keys = @(
            "EnableRegistrars",
            "DisableUPnPRegistrar",
            "DisableInBand802DOT11Registrar",
            "DisableFlashConfigRegistrar",
            "DisableWPDRegistrar"
        )

        $allCorrect = $true

        foreach ($key in $keys) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $key -ErrorAction SilentlyContinue).$key
            if ($currentValue -ne $expectedValue) {
                $allCorrect = $false
                Handle-Output -Condition $false -Message "18.6.20.1 WCN setting '$key' is not set to 'Disabled'."
            }
        }

        if ($allCorrect) {
            Handle-Output -Condition $true -Message "18.6.20.1 All WCN settings are set to 'Disabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.6.20.1 Registry path for WCN settings does not exist."
    }
}
function Check-WCNAccess {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
    $regName = "DisableWcnUi"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.6.20.2 WCN access setting '$regName' is not set to 'Enabled'."
        } else {
            Handle-Output -Condition $true -Message "18.6.20.2 WCN access setting '$regName' is set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.6.20.2 Registry path for WCN access settings does not exist."
    }
}
function Check-MinimizeConnections {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    $regName = "fMinimizeConnections"
    $expectedValue = 3

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.6.21.1 Minimize Connections setting '$regName' is not set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'."
        } else {
            Handle-Output -Condition $true -Message "18.6.21.1 Minimize Connections setting '$regName' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.6.21.1 Registry path for Minimize Connections settings does not exist."
    }
}
function Check-ProhibitNonDomainConnections {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    $regName = "fBlockNonDomain"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.6.21.2 Prohibit connection to non-domain networks setting '$regName' is not set to 'Enabled'."
        } else {
            Handle-Output -Condition $true -Message "18.6.21.2 Prohibit connection to non-domain networks setting '$regName' is set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.6.21.2 Registry path for Prohibit Non-Domain Connections settings does not exist."
    }
}
function Check-AutoConnectSettings {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    $regName = "AutoConnectAllowedOEM"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.6.23.2.1 AutoConnect settings '$regName' is not set to 'Disabled'."
        } else {
            Handle-Output -Condition $true -Message "18.6.23.2.1 AutoConnect settings '$regName' is set to 'Disabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.6.23.2.1 Registry path for AutoConnect settings does not exist."
    }
}
function Check-PrintSpoolerSettings {
    # Define the registry path and expected value
    $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
    $regName = "RegisterSpoolerRemoteRpcEndPoint"
    $expectedValue = 2

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.7.1 Print Spooler setting '$regName' is not set to 'Disabled'."
        } else {
            Handle-Output -Condition $true -Message "18.7.1 Print Spooler setting '$regName' is set to 'Disabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.1 Registry path for Print Spooler settings does not exist."
    }
}
function Check-RedirectionGuardSettings {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $regName = "RedirectionguardPolicy"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.7.2 Redirection Guard setting '$regName' is not set to 'Enabled: Redirection Guard Enabled'."
        } else {
            Handle-Output -Condition $true -Message "18.7.2 Redirection Guard setting '$regName' is set to 'Enabled: Redirection Guard Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.2 Registry path for Redirection Guard settings does not exist."
    }
}
function Check-RpcConnectionSettings {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
    $regName = "RpcUseNamedPipeProtocol"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.7.3 RPC connection setting '$regName' is not set to 'Enabled: RPC over TCP'."
        } else {
            Handle-Output -Condition $true -Message "18.7.3 RPC connection setting '$regName' is set to 'Enabled: RPC over TCP'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.3 Registry path for RPC connection settings does not exist."
    }
}
function Check-RpcAuthenticationSettings {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
    $regName = "RpcAuthentication"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.7.4 RPC authentication setting '$regName' is not set to 'Enabled: Default'."
        } else {
            Handle-Output -Condition $true -Message "18.7.4 RPC authentication setting '$regName' is set to 'Enabled: Default'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.4 Registry path for RPC authentication settings does not exist."
    }
}
function Check-RpcProtocolsSettings {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
    $regName = "RpcProtocols"
    $expectedValue = 5

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value matches the expected value
        if ($currentValue -ne $expectedValue) {
            Handle-Output -Condition $false -Message "18.7.5 RPC listener setting '$regName' is not set to 'Enabled: RPC over TCP'."
        } else {
            Handle-Output -Condition $true -Message "18.7.5 RPC listener setting '$regName' is set to 'Enabled: RPC over TCP'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.5 Registry path for RPC listener settings does not exist."
    }
}
function Check-RpcAuthenticationProtocol {
    # Define the registry path and expected values
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
    $regName = "ForceKerberosForRpc"
    $validValues = @(0, 1) # 0 for Negotiate, 1 for Kerberos or higher

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        # Check if the current value is within the valid range
        if ($currentValue -notin $validValues) {
            Handle-Output -Condition $false -Message "18.7.6 RPC listener setting '$regName' is not set to 'Enabled: Negotiate' or higher."
        } else {
            Handle-Output -Condition $true -Message "18.7.6 RPC listener setting '$regName' is set to 'Enabled: Negotiate' or higher."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.6 Registry path for RPC authentication protocol settings does not exist."
    }
}
function Check-RpcOverTcpPort {
    # Define the registry path and expected values
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
    $regName = "RpcTcpPort"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.7.7 RPC over TCP port is set to 'Enabled: 0'."
        } else {
            Handle-Output -Condition $false -Message "18.7.7 RPC over TCP port is not set to 'Enabled: 0'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.7 Registry path for RPC over TCP port does not exist."
    }
}
function Check-PrintDriverInstallationLimit {
    # Define the registry path and expected values
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $regName = "RestrictDriverInstallationToAdministrators"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.7.8 Limits print driver installation to Administrators is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.7.8 Limits print driver installation to Administrators is not set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.8 Registry path for limiting print driver installation to Administrators does not exist."
    }
}
function Check-QueueSpecificFilesProcessing {
    # Define the registry path and expected values
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $regName = "CopyFilesPolicy"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.7.9 Manage processing of Queue-specific files is set to 'Enabled: Limit Queue-specific files to Color profiles'."
        } else {
            Handle-Output -Condition $false -Message "18.7.9 Manage processing of Queue-specific files is not set to 'Enabled: Limit Queue-specific files to Color profiles'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.9 Registry path for managing processing of Queue-specific files does not exist."
    }
}
function Check-PointAndPrintRestrictions {
    # Define the registry path and expected value
    $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $regName = "NoWarningNoElevationOnInstall"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.7.10 Point and Print Restrictions are set to 'Enabled: Show warning and elevation prompt' for installing drivers for a new connection."
        } else {
            Handle-Output -Condition $false -Message "18.7.10 Point and Print Restrictions are not set to 'Enabled: Show warning and elevation prompt' for installing drivers for a new connection."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.10 Registry path for Point and Print Restrictions does not exist."
    }
}
function Check-PointAndPrintRestrictionsUpdate {
    # Define the registry path and expected value
    $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $regName = "UpdatePromptSettings"
    $expectedValue = 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.7.11 Point and Print Restrictions are set to 'Enabled: Show warning and elevation prompt' when updating drivers for an existing connection."
        } else {
            Handle-Output -Condition $false -Message "18.7.11 Point and Print Restrictions are not set to 'Enabled: Show warning and elevation prompt' when updating drivers for an existing connection."
        }
    } else {
        Handle-Output -Condition $false -Message "18.7.11 Registry path for Point and Print Restrictions does not exist."
    }
}
function Check-TurnOffNotificationsNetworkUsage {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    $regName = "NoCloudApplicationNotification"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.8.1.1 Turn off notifications network usage is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.8.1.1 Turn off notifications network usage is not set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.8.1.1 Registry path for Turn off notifications network usage does not exist."
    }
}
function Check-RemovePersonalizedWebsiteRecommendations {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $regName = "HideRecommendedPersonalizedSites"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.8.2 Remove Personalized Website Recommendations from the Start Menu is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.8.2 Remove Personalized Website Recommendations from the Start Menu is not set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.8.2 Registry path for Remove Personalized Website Recommendations does not exist."
    }
}
function Check-IncludeCmdLineInProcessCreationEvents {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $regName = "ProcessCreationIncludeCmdLine_Enabled"
    $expectedValue = 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.3.1 Include command line in process creation events is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.9.3.1 Include command line in process creation events is not set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.3.1 Registry path for Include command line in process creation events does not exist."
    }
}
function Check-EncryptionOracleRemediation {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
    $regName = "AllowEncryptionOracle"
    $expectedValue = 0  # 'Force Updated Clients' corresponds to a REG_DWORD value of 0

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.4.1 Encryption Oracle Remediation is set to 'Enabled: Force Updated Clients'."
        } else {
            Handle-Output -Condition $false -Message "18.9.4.1 Encryption Oracle Remediation is not set to 'Enabled: Force Updated Clients'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.4.1 Registry path for Encryption Oracle Remediation does not exist."
    }
}
function Check-RemoteHostDelegation {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
    $regName = "AllowProtectedCreds"
    $expectedValue = 1  # 'Enabled' corresponds to a REG_DWORD value of 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.4.2 Remote host allows delegation of non-exportable credentials is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.9.4.2 Remote host allows delegation of non-exportable credentials is not set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.4.2 Registry path for Remote host allows delegation of non-exportable credentials does not exist."
    }
}
function Check-VirtualizationBasedSecurity {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $regName = "EnableVirtualizationBasedSecurity"
    $expectedValue = 1  # 'Enabled' corresponds to a REG_DWORD value of 1

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.5.1 Turn On Virtualization Based Security is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.9.5.1 Turn On Virtualization Based Security is not set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.5.1 Registry path for Turn On Virtualization Based Security does not exist."
    }
}
function Check-PlatformSecurityLevel {
    # Define the registry path and expected values
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $regName = "RequirePlatformSecurityFeatures"
    $expectedValues = @(1, 3)  # '1' = Secure Boot, '3' = Secure Boot and DMA Protection

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected values
        if ($expectedValues -contains $currentValue) {
            Handle-Output -Condition $true -Message "18.9.5.2 Turn On Virtualization Based Security: Select Platform Security Level is set to 'Secure Boot' or higher."
        } else {
            Handle-Output -Condition $false -Message "18.9.5.2 Turn On Virtualization Based Security: Select Platform Security Level is not set to 'Secure Boot' or higher."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.5.2 Registry path for Platform Security Level does not exist."
    }
}
function Check-VirtualizationBasedProtectionCodeIntegrity {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $regName = "HypervisorEnforcedCodeIntegrity"
    $expectedValue = 1  # '1' = Enabled with UEFI lock

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.5.3 Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity is set to 'Enabled with UEFI lock'."
        } else {
            Handle-Output -Condition $false -Message "18.9.5.3 Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity is not set to 'Enabled with UEFI lock'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.5.3 Registry path for Virtualization Based Protection of Code Integrity does not exist."
    }
}
function Check-RequireUEFIMemoryAttributesTable {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $regName = "HVCIMATRequired"
    $expectedValue = 1  # '1' = True (checked)

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.5.4 Turn On Virtualization Based Security: Require UEFI Memory Attributes Table is set to 'True (checked)'."
        } else {
            Handle-Output -Condition $false -Message "18.9.5.4 Turn On Virtualization Based Security: Require UEFI Memory Attributes Table is not set to 'True (checked)'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.5.4 Registry path for Require UEFI Memory Attributes Table does not exist."
    }
}
function Check-CredentialGuardConfiguration {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $regName = "LsaCfgFlags"
    $expectedValue = 1  # '1' = Enabled with UEFI lock

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.5.5 Turn On Virtualization Based Security: Credential Guard Configuration is set to 'Enabled with UEFI lock'."
        } else {
            Handle-Output -Condition $false -Message "18.9.5.5 Turn On Virtualization Based Security: Credential Guard Configuration is not set to 'Enabled with UEFI lock'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.5.5 Registry path for Credential Guard Configuration does not exist."
    }
}
function Check-SecureLaunchConfiguration {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $regName = "ConfigureSystemGuardLaunch"
    $expectedValue = 1  # '1' = Enabled

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.5.6 Turn On Virtualization Based Security: Secure Launch Configuration is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.9.5.6 Turn On Virtualization Based Security: Secure Launch Configuration is not set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.5.6 Registry path for Secure Launch Configuration does not exist."
    }
}
function Check-KernelModeHardwareEnforcedStackProtection {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $regName = "ConfigureKernelShadowStacksLaunch"
    $expectedValue = 1  # '1' = Enabled in enforcement mode

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.5.7 Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection is set to 'Enabled: Enabled in enforcement mode'."
        } else {
            Handle-Output -Condition $false -Message "18.9.5.7 Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection is not set to 'Enabled: Enabled in enforcement mode'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.5.7 Registry path for Kernel-mode Hardware-enforced Stack Protection does not exist."
    }
}
function Check-PreventInstallationOfDevices {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    $regName = "DenyDeviceIDs"
    $expectedValue = 1  # '1' = Enabled

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the current value of the registry key
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

        # Compare the current value with the expected value
        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.9.7.1.1 Prevent installation of devices that match any of these device IDs is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.9.7.1.1 Prevent installation of devices that match any of these device IDs is not set to 'Enabled'."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.7.1.1 Registry path for Prevent installation of devices does not exist."
    }
}
function Check-PreventInstallationDeviceIDs {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
    $expectedValue = "PCI\CC_0C0A"  # Expected device ID

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get all values in the registry path
        $currentValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

        # Check if the expected value is present
        $valueExists = $currentValues.PSObject.Properties.Value -contains $expectedValue

        if ($valueExists) {
            Handle-Output -Condition $true -Message "18.9.7.1.2 Prevent installation of devices with ID 'PCI\CC_0C0A' is set correctly."
        } else {
            Handle-Output -Condition $false -Message "18.9.7.1.2 Prevent installation of devices with ID 'PCI\CC_0C0A' is not set correctly."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.7.1.2 Registry path for Prevent installation of devices does not exist."
    }
}
function Check-PreventInstallationDevicesRetroactive {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    $regValueName = "DenyDeviceIDsRetroactive"
    $expectedValue = 1  # True (checked)

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $currentValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the value is as expected
        $valueMatches = $currentValue.$regValueName -eq $expectedValue

        if ($valueMatches) {
            Handle-Output -Condition $true -Message "18.9.7.1.3 Prevent installation of devices retroactively is set to 'True'."
        } else {
            Handle-Output -Condition $false -Message "18.9.7.1.3 Prevent installation of devices retroactively is not set correctly."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.7.1.3 Registry path for Prevent installation of devices retroactively does not exist."
    }
}
function Check-PreventInstallationDeviceClasses {
    # Define the registry path and expected value
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    $regValueName = "DenyDeviceClasses"
    $expectedValue = 1  # Enabled

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $currentValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the value is as expected
        $valueMatches = $currentValue.$regValueName -eq $expectedValue

        if ($valueMatches) {
            Handle-Output -Condition $true -Message "18.9.7.1.4 Prevent installation of devices using drivers that match these device setup classes is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.9.7.1.4 Prevent installation of devices using drivers that match these device setup classes is not set correctly."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.7.1.4 Registry path for Prevent installation of devices using drivers that match these device setup classes does not exist."
    }
}
function Check-PreventInstallationDeviceSetupClasses {
    # Define the registry path and expected GUIDs
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    $regValueName = "DenyDeviceClasses"
    $expectedGuids = @(
        "{d48179be-ec20-11d1-b6b8-00c04fa372a7}", # IEEE 1394 devices (SBP2 Protocol Class)
        "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}", # IEEE 1394 devices (IEC-61883 Protocol Class)
        "{c06ff265-ae09-48f0-812c-16753d7cba83}", # IEEE 1394 devices (AVC Protocol Class)
        "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"  # IEEE 1394 Host Bus Controller Class
    )

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $currentValues = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        if ($currentValues) {
            $currentGuids = $currentValues.$regValueName -split ','

            # Compare the current GUIDs with expected GUIDs
            $guidMatches = $expectedGuids | ForEach-Object { $currentGuids -contains $_ }

            if ($guidMatches -contains $false) {
                Handle-Output -Condition $false -Message "18.9.7.1.5 Prevent installation of devices using drivers that match these device setup classes is not set correctly."
            } else {
                Handle-Output -Condition $true -Message "18.9.7.1.5 Prevent installation of devices using drivers that match these device setup classes is set to IEEE 1394 device setup classes."
            }
        } else {
            Handle-Output -Condition $false -Message "18.9.7.1.5 Registry value for Prevent installation of devices using drivers that match these device setup classes does not exist."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.7.1.5 Registry path for Prevent installation of devices using drivers that match these device setup classes does not exist."
    }
}
function Check-PreventInstallationDeviceSetupClassesRetroactive {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    $regValueName = "DenyDeviceClassesRetroactive"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the registry value exists and is set to True (1)
        if ($regValue -and $regValue.$regValueName -eq 1) {
            Handle-Output -Condition $true -Message "18.9.7.1.6 Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed is set to True (checked)."
        } else {
            Handle-Output -Condition $false -Message "18.9.7.1.6 Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed is not set correctly."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.7.1.6 Registry path for Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed does not exist."
    }
}
function Check-PreventDeviceMetadataRetrieval {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceMetadata"
    $regValueName = "PreventDeviceMetadataFromNetwork"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the registry value exists and is set to Enabled (1)
        if ($regValue -and $regValue.$regValueName -eq 1) {
            Handle-Output -Condition $true -Message "18.9.7.2 Prevent device metadata retrieval from the Internet is set to Enabled."
        } else {
            Handle-Output -Condition $false -Message "18.9.7.2 Prevent device metadata retrieval from the Internet is not set correctly."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.7.2 Registry path for Prevent device metadata retrieval from the Internet does not exist."
    }
}
function Check-BootStartDriverInitializationPolicy {
    # Define the registry path and value name
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
    $regValueName = "DriverLoadPolicy"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the registry value exists and is set to Enabled: Good, unknown and bad but critical (3)
        if ($regValue -and $regValue.$regValueName -eq 3) {
            Handle-Output -Condition $true -Message "18.9.13.1 Boot-Start Driver Initialization Policy is set to Enabled: Good, unknown and bad but critical."
        } else {
            Handle-Output -Condition $false -Message "18.9.13.1 Boot-Start Driver Initialization Policy is not set correctly."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.13.1 Registry path for Boot-Start Driver Initialization Policy does not exist."
    }
}
function Check-RegistryPolicyProcessing {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"
    $regValueName = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}:NoBackgroundPolicy"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the registry value exists and is set to 0 (Enabled: FALSE)
        if ($regValue -and $regValue.$regValueName -eq 0) {
            Handle-Output -Condition $true -Message "18.9.19.2 Configure registry policy processing is set to Enabled: FALSE."
        } else {
            Handle-Output -Condition $false -Message "18.9.19.2 Configure registry policy processing is not set to Enabled: FALSE."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.19.2 Registry path for Configure registry policy processing does not exist."
    }
}
function Check-RegistryPolicyProcessingChanges {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"
    $regValueName = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}:NoGPOListChanges"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the registry value exists and is set to 0 (Enabled: TRUE)
        if ($regValue -and $regValue.$regValueName -eq 0) {
            Handle-Output -Condition $true -Message "18.9.19.3 Configure registry policy processing is set to Enabled: TRUE."
        } else {
            Handle-Output -Condition $false -Message "18.9.19.3 Configure registry policy processing is not set to Enabled: TRUE."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.19.3 Registry path for Configure registry policy processing does not exist."
    }
}
function Check-SecurityPolicyProcessingBackground {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"
    $regValueName = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}:NoBackgroundPolicy"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the registry value exists and is set to 0 (Enabled: FALSE)
        if ($regValue -and $regValue.$regValueName -eq 0) {
            Handle-Output -Condition $true -Message "18.9.19.4 Configure security policy processing is set to Enabled: FALSE."
        } else {
            Handle-Output -Condition $false -Message "18.9.19.4 Configure security policy processing is not set to Enabled: FALSE."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.19.4 Registry path for Configure security policy processing does not exist."
    }
}
function Check-SecurityPolicyProcessing {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"
    $regValueName = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}:NoGPOListChanges"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the registry value exists and is set to 0 (Enabled: TRUE)
        if ($regValue -and $regValue.$regValueName -eq 0) {
            Handle-Output -Condition $true -Message "18.9.19.5 Configure security policy processing is set to Enabled: TRUE."
        } else {
            Handle-Output -Condition $false -Message "18.9.19.5 Configure security policy processing is not set to Enabled: TRUE."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.19.5 Registry path for Configure security policy processing does not exist."
    }
}
function Check-ContinueExperiences {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $regValueName = "EnableCdp"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the value from the registry
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue

        # Check if the registry value exists and is set to 0 (Disabled)
        if ($regValue -and $regValue.$regValueName -eq 0) {
            Handle-Output -Condition $true -Message "18.9.19.6 Continue experiences on this device is set to Disabled."
        } else {
            Handle-Output -Condition $false -Message "18.9.19.6 Continue experiences on this device is not set to Disabled."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.19.6 Registry path for Continue experiences on this device does not exist."
    }
}
function Check-TurnOffBackgroundRefreshOfGroupPolicy {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regValueName = "DisableBkGndGroupPolicy"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Check if the value exists
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
        
        # Check if the value does not exist (which means the policy is Disabled)
        if (-not $regValue) {
            Handle-Output -Condition $true -Message "18.9.19.7 Turn off background refresh of Group Policy is set to Disabled."
        } else {
            Handle-Output -Condition $false -Message "18.9.19.7 Turn off background refresh of Group Policy is not set to Disabled."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.19.7 Registry path for Turn off background refresh of Group Policy does not exist."
    }
}
function Check-TurnOffAccessToStore {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $regValueName = "NoUseStoreOpenWith"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Check if the value exists and is set to 1 (Enabled)
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
        
        if ($regValue.NoUseStoreOpenWith -eq 1) {
            Handle-Output -Condition $true -Message "18.9.20.1.1 Turn off access to the Store is set to Enabled."
        } else {
            Handle-Output -Condition $false -Message "18.9.20.1.1 Turn off access to the Store is not set to Enabled."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.20.1.1 Registry path for Turn off access to the Store does not exist."
    }
}
function Check-TurnOffDownloadPrintDriversOverHTTP {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $regValueName = "DisableWebPnPDownload"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Check if the value exists and is set to 1 (Enabled)
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
        
        if ($regValue.DisableWebPnPDownload -eq 1) {
            Handle-Output -Condition $true -Message "18.9.20.1.2 Turn off downloading of print drivers over HTTP is set to Enabled."
        } else {
            Handle-Output -Condition $false -Message "18.9.20.1.2 Turn off downloading of print drivers over HTTP is not set to Enabled."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.20.1.2 Registry path for Turn off downloading of print drivers over HTTP does not exist."
    }
}
function Check-TurnOffHandwritingDataSharing {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
    $regValueName = "PreventHandwritingDataSharing"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Check if the value exists and is set to 1 (Enabled)
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
        
        if ($regValue.PreventHandwritingDataSharing -eq 1) {
            Handle-Output -Condition $true -Message "18.9.20.1.3 Turn off handwriting personalization data sharing is set to Enabled."
        } else {
            Handle-Output -Condition $false -Message "18.9.20.1.3 Turn off handwriting personalization data sharing is not set to Enabled."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.20.1.3 Registry path for Turn off handwriting personalization data sharing does not exist."
    }
}
function Check-TurnOffHandwritingRecognitionErrorReporting {
    # Define the registry path and value name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
    $regValueName = "PreventHandwritingErrorReports"
    
    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Check if the value exists and is set to 1 (Enabled)
        $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
        
        if ($regValue.PreventHandwritingErrorReports -eq 1) {
            Handle-Output -Condition $true -Message "18.9.20.1.4 Turn off handwriting recognition error reporting is set to Enabled."
        } else {
            Handle-Output -Condition $false -Message "18.9.20.1.4 Turn off handwriting recognition error reporting is not set to Enabled."
        }
    } else {
        Handle-Output -Condition $false -Message "18.9.20.1.4 Registry path for Turn off handwriting recognition error reporting does not exist."
    }
}


#BREAK BREAK RBREAK REAKR AEKR AERK ARE EAR AERKA ER AER AKER AE RAE RAE RAER AKER AKR AK RAE R
function Check-PreventLockScreenSlideShowEnabled {
    # Registry path and key for the setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $regName = "NoLockScreenSlideshow"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoLockScreenSlideshow
    } else {
        $currentValue = $null
    }

    # Expected value for 'Enabled'
    $expectedValue = 1

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.1.1.2 Prevent enabling lock screen slide show is set to 'Enabled'."
}

# 18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'
function Check-AllowOnlineSpeechRecognitionDisabled {
    # Registry path and key for the setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    $regName = "AllowInputPersonalization"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowInputPersonalization
    } else {
        $currentValue = $null
    }

    # Expected value for 'Disabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.1.2.2 Allow users to enable online speech recognition services is set to 'Disabled'."
}

# 18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled'
function Check-AllowOnlineTipsDisabled {
    # Registry path and key for the setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $regName = "AllowOnlineTips"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowOnlineTips
    } else {
        $currentValue = $null
    }

    # Expected value for 'Disabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.1.3 Allow Online Tips is set to 'Disabled'."
}

# 18.4.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
function Check-ApplyUACRestrictionsLocalAccountsEnabled {
    # Registry path and key for the setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "LocalAccountTokenFilterPolicy"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
    } else {
        $currentValue = $null
    }

    # Expected value for 'Enabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.4.1 Apply UAC restrictions to local accounts on network logons is set to 'Enabled'."
}

# 18.4.2 (L1) Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'
function Check-ConfigureRPCPrivacyEnabled {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
    $regName = "RpcAuthnLevelPrivacyEnabled"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).RpcAuthnLevelPrivacyEnabled
    } else {
        $currentValue = $null
    }

    # Expected value for 'Enabled'
    $expectedValue = 1

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.4.2 Configure RPC packet level privacy setting for incoming connections is set to 'Enabled'."
}

# 18.4.3 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'
function Check-ConfigureSMBv1ClientDriver {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
    $regName = "Start"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).Start
    } else {
        $currentValue = $null
    }

    # Expected value for 'Disable driver (recommended)'
    $expectedValue = 4

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.4.3 Configure SMB v1 client driver is set to 'Enabled: Disable driver (recommended)'."
}

# 18.4.4 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'
function Check-ConfigureSMBv1ServerDisabled {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $regName = "SMB1"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).SMB1
    } else {
        $currentValue = $null
    }

    # Expected value for 'Disabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.4.4 Configure SMB v1 server is set to 'Disabled'."
}

# 18.4.5 (L1) Ensure 'Enable Certificate Padding' is set to 'Enabled'
function Check-EnableCertificatePadding {
    # Registry path and key for the setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
    $regName = "EnableCertPaddingCheck"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableCertPaddingCheck
    } else {
        $currentValue = $null
    }

    # Expected value for 'Enabled'
    $expectedValue = 1

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.4.5 Enable Certificate Padding is set to 'Enabled'."
}

# 18.4.6 (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
function Check-EnableSEHOP {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    $regName = "DisableExceptionChainValidation"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableExceptionChainValidation
    } else {
        $currentValue = $null
    }

    # Expected value for 'Enabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.4.6 Enable Structured Exception Handling Overwrite Protection (SEHOP) is set to 'Enabled'."
}

# 18.4.7 (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'
function Check-NetBTNodeTypePNode {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $regName = "NodeType"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NodeType
    } else {
        $currentValue = $null
    }

    # Expected value for 'P-node (recommended)'
    $expectedValue = 2

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.4.7 NetBT NodeType configuration is set to 'Enabled: P-node (recommended)'."
}

# 18.4.8 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'
function Check-WDigestAuthenticationDisabled {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $regName = "UseLogonCredential"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).UseLogonCredential
    } else {
        $currentValue = $null
    }

    # Expected value for 'Disabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.4.8 WDigest Authentication is set to 'Disabled'."
}

# 18.5.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'
function Check-AutoAdminLogonDisabled {
    # Registry path and key for the setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regName = "AutoAdminLogon"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AutoAdminLogon
    } else {
        $currentValue = $null
    }

    # Expected value for 'Disabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -ne $expectedValue) -Message "18.5.1 AutoAdminLogon is not set to 'Disabled'."
}

# 18.5.2 (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'
function Check-DisableIPSourceRouting {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $regName = "DisableIPSourceRouting"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableIPSourceRouting
    } else {
        $currentValue = $null
    }

    # Expected value for 'Highest protection, source routing is completely disabled'
    $expectedValue = 2

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.5.2 IP source routing protection level is set to 'Enabled: Highest protection, source routing is completely disabled'."
}

function Check-DisableIPSourceRoutingIPv4 {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $regName = "DisableIPSourceRouting"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableIPSourceRouting
    } else {
        $currentValue = $null
    }

    # Expected value for 'Highest protection, source routing is completely disabled'
    $expectedValue = 2

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.5.3 IP source routing protection level for IPv4 is set to 'Enabled: Highest protection, source routing is completely disabled'."
}

function Check-EnableICMPRedirect {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $regName = "EnableICMPRedirect"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableICMPRedirect
    } else {
        $currentValue = $null
    }

    # Expected value for 'Disabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.5.5 ICMP redirects to override OSPF generated routes is set to 'Disabled'."
}
#18.5.6 (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'
function Check-KeepAliveTime {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $regName = "KeepAliveTime"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).KeepAliveTime
    } else {
        $currentValue = $null
    }

    # Expected value for '300,000'
    $expectedValue = 300000

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.5.6 KeepAliveTime is set to '300,000 milliseconds (5 minutes)'."
}
function Check-NoNameReleaseOnDemand {
    # Registry path and key for the setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $regName = "NoNameReleaseOnDemand"

    # Check current registry value
    if (Test-Path $regPath) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoNameReleaseOnDemand
    } else {
        $currentValue = $null
    }

    # Expected value for 'Enabled'
    $expectedValue = 1

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.5.7 NoNameReleaseOnDemand is set to 'Enabled'."
}












Check-PreventLockScreenSlideShowEnabled
Check-AllowOnlineSpeechRecognitionDisabled
Check-AllowOnlineTipsDisabled
Check-ApplyUACRestrictionsLocalAccountsEnabled
Check-ConfigureRPCPrivacyEnabled
Check-ConfigureSMBv1ClientDriver
Check-ConfigureSMBv1ServerDisabled
Check-EnableCertificatePadding
Check-EnableSEHOP
Check-NetBTNodeTypePNode
Check-WDigestAuthenticationDisabled
Check-AutoAdminLogonDisabled
Check-DisableIPSourceRouting
Check-DisableIPSourceRoutingIPv4
Check-DisableSavePassword
Check-EnableICMPRedirect
Check-KeepAliveTime
Check-NoNameReleaseOnDemand








Check-PreventLockScreenSlideShowEnabled
Check-AllowOnlineSpeechRecognitionDisabled
Check-AllowOnlineTipsDisabled
Check-ApplyUACRestrictionsLocalAccountsEnabled
Check-ConfigureRPCPrivacyEnabled
Check-ConfigureSMBv1ClientDriver
Check-ConfigureSMBv1ServerDisabled
Check-EnableCertificatePadding
Check-EnableSEHOP
Check-TurnOnDEPForWindowsComponents
Check-TurnOnEMETProtectionForOutlook
Check-AutoAdminLogonDisabled
Check-IPSourceRoutingProtection
Check-IPSourceRoutingProtectionIPv4
Check-DisableSavePassword
Check-EnableICMPRedirect
Check-KeepAliveTime
Check-NoNameReleaseOnDemand
Check-PerformRouterDiscovery
Check-SafeDllSearchMode
Check-ScreenSaverGracePeriod
Check-TcpMaxDataRetransmissionsIPv6
Check-TcpMaxDataRetransmissionsIPv4
Check-SecurityLogWarningLevel
Check-DNSOverHTTPS
Check-NetBIOSSettings
Check-TurnOffMulticastNameResolution
Check-EnableFontProviders
Check-EnableInsecureGuestLogons
Check-LLTDIOSettings
Check-RSPNDRSettings
Check-PeerNetworkingService
Check-NetworkBridgePolicy
Check-InternetConnectionSharingPolicy
Check-RequireDomainUserElevation
Check-HardenedUNCPaths
Check-IPv6DisabledComponents
Check-WCNSettings
Check-WCNAccess
Check-MinimizeConnections
Check-ProhibitNonDomainConnections
Check-AutoConnectSettings
Check-PrintSpoolerSettings
Check-RedirectionGuardSettings
Check-RpcConnectionSettings
Check-RpcAuthenticationSettings
Check-RpcProtocolsSettings
Check-RpcOverTcpPort
Check-PrintDriverInstallationLimit
Check-QueueSpecificFilesProcessing
Check-PointAndPrintRestrictions
Check-PointAndPrintRestrictionsUpdate
Check-TurnOffNotificationsNetworkUsage
Check-RemovePersonalizedWebsiteRecommendations
Check-IncludeCmdLineInProcessCreationEvents
Check-EncryptionOracleRemediation
Check-RemoteHostDelegation
Check-VirtualizationBasedSecurity
Check-PlatformSecurityLevel
Check-VirtualizationBasedProtectionCodeIntegrity
Check-RequireUEFIMemoryAttributesTable
Check-CredentialGuardConfiguration
Check-SecureLaunchConfiguration
Check-KernelModeHardwareEnforcedStackProtection
Check-PreventInstallationOfDevices
Check-PreventInstallationDeviceIDs
Check-PreventInstallationDevicesRetroactive
Check-PreventInstallationDeviceClasses
Check-PreventInstallationDeviceSetupClasses
Check-PreventInstallationDeviceSetupClassesRetroactive
Check-PreventDeviceMetadataRetrieval
Check-BootStartDriverInitializationPolicy
Check-RegistryPolicyProcessing
Check-RegistryPolicyProcessingChanges
Check-SecurityPolicyProcessingBackground
Check-SecurityPolicyProcessing
Check-ContinueExperiences
Check-TurnOffBackgroundRefreshOfGroupPolicy
Check-TurnOffAccessToStore
Check-TurnOffDownloadPrintDriversOverHTTP
Check-TurnOffHandwritingDataSharing
Check-TurnOffHandwritingRecognitionErrorReporting
