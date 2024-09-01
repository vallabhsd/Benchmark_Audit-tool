# Function to handle output based on conditions
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

# 18.10.56.3.2.1 (L2) Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled'
function Ensure-RDPConnectionDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fDenyTSConnections"

    # Check if the registry path exists
    if (-not (Test-Path -Path $regPath)) {
        "Registry path $regPath does not exist." | Out-File -Append -FilePath "errors.txt"
        return
    }

    # Initialize currentValue
    $currentValue = $null

    # Try to get the current value of the registry key
    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fDenyTSConnections
    } catch {
        "Property $regName does not exist at $regPath." | Out-File -Append -FilePath "errors.txt"
    }

    # Expected value for 'Disabled'
    $expectedValue = 1

    # Handle output based on the presence and value of the property
    if ($currentValue -eq $null) {
        Handle-Output -Condition $false -Message "18.10.56.3.2.1 Allow users to connect remotely by using Remote Desktop Services (property missing)"
    } elseif ($currentValue -ne $expectedValue) {
        Handle-Output -Condition $false -Message "18.10.56.3.2.1 Allow users to connect remotely by using Remote Desktop Services (value mismatch)"
    } else {
        Handle-Output -Condition $true -Message "18.10.56.3.2.1 Allow users to connect remotely by using Remote Desktop Services"
    }
}

# 18.10.56.3.3.1 (L2) Ensure 'Allow UI Automation redirection' is set to 'Disabled'
function Ensure-AllowUIAutomationRedirectionDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "EnableUiaRedirection"
    $expectedValue = 0

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableUiaRedirection

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable UI Automation redirection
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableUiaRedirection
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.56.3.3.1 Allow UI Automation redirection is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.56.3.3.1 Allow UI Automation redirection is already set to 'Disabled'."
    }
}


# 18.10.56.3.3.2 (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'
function Ensure-DoNotAllowCOMPortRedirectionEnabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fDisableCcm"
    $expectedValue = 1

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fDisableCcm

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 1 to enable the policy
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fDisableCcm
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.56.3.3.2 Do not allow COM port redirection is set to 'Enabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.56.3.3.2 Do not allow COM port redirection is already set to 'Enabled'."
    }
}


# 18.10.56.3.3.3 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'
function Check-DoNotAllowDriveRedirection {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fDisableCdm"
    $expectedValue = 1

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fDisableCdm

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.3.3 Do not allow drive redirection is set to 'Enabled'."
}


# 18.10.56.3.3.4 (L2) Ensure 'Do not allow location redirection' is set to 'Enabled'
function Check-DoNotAllowLocationRedirection {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fDisableLocationRedir"
    $expectedValue = 1

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fDisableLocationRedir

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.3.4 Do not allow location redirection is set to 'Enabled'."
}

# 18.10.56.3.3.5 (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
function Check-DoNotAllowLPTPortRedirection {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fDisableLPT"
    $expectedValue = 1

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fDisableLPT

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.3.5 Do not allow LPT port redirection is set to 'Enabled'."
}

# 18.10.56.3.3.6 (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
function Check-DoNotAllowPNPDeviceRedirection {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fDisablePNPRedir"
    $expectedValue = 1

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fDisablePNPRedir

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.3.6 Do not allow supported Plug and Play device redirection is set to 'Enabled'."
}

# 18.10.56.3.3.7 (L2) Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled'
function Check-DoNotAllowWebAuthnRedirection {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fDisableWebAuthn"
    $expectedValue = 1

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fDisableWebAuthn

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.3.7 Do not allow WebAuthn redirection is set to 'Enabled'."
}

# 18.10.56.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'
function Check-AlwaysPromptForPassword {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fPromptForPassword"
    $expectedValue = 1

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fPromptForPassword

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.9.1 Always prompt for password upon connection is set to 'Enabled'."
}

# 18.10.56.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'
function Check-RequireSecureRPCCommunication {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fEncryptRPCTraffic"
    $expectedValue = 1

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).fEncryptRPCTraffic

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.9.2 Require secure RPC communication is set to 'Enabled'."
}

# 18.10.56.3.9.3 (L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'
function Check-RequireSpecificSecurityLayer {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "SecurityLayer"
    $expectedValue = 2  # 2 corresponds to SSL/TLS

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).SecurityLayer

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.9.3 Require use of specific security layer for remote (RDP) connections is set to 'Enabled: SSL'."
}

# 18.10.56.3.9.4 (L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
function Check-RequireUserAuthentication {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "UserAuthentication"
    $expectedValue = 1  # 1 corresponds to Enabled

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).UserAuthentication

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.56.3.9.4 Require user authentication for remote connections by using Network Level Authentication is set to 'Enabled'."
}

# 18.10.56.3.9.5 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
function Ensure-ClientConnectionEncryptionLevel {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "MinEncryptionLevel"
    $expectedValue = 3  # 3 corresponds to High Level

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MinEncryptionLevel

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 3 to enforce High Level encryption
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MinEncryptionLevel
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.56.3.9.5 Set client connection encryption level is set to 'Enabled: High Level'."
    } else {
        Handle-Output -Condition $true -Message "18.10.56.3.9.5 Set client connection encryption level is already set to 'Enabled: High Level'."
    }
}

# 18.10.56.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'
function Ensure-IdleSessionTimeLimit {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "MaxIdleTime"
    $maxIdleTime = 900000  # 15 minutes in milliseconds
    $neverValue = 0

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MaxIdleTime

    if ($currentValue -eq $neverValue) {
        # Set registry value to 15 minutes if it is currently set to Never
        Set-ItemProperty -Path $regPath -Name $regName -Value $maxIdleTime -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MaxIdleTime
        Handle-Output -Condition ($newValue -le $maxIdleTime -and $newValue -ne $neverValue) -Message "18.10.56.3.10.1 Set time limit for active but idle Remote Desktop Services sessions is set to '15 minutes or less, but not Never (0)'."
    } elseif ($currentValue -gt $maxIdleTime -or $currentValue -eq $neverValue) {
        # Ensure the value does not exceed 15 minutes or is not set to Never
        Set-ItemProperty -Path $regPath -Name $regName -Value $maxIdleTime -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MaxIdleTime
        Handle-Output -Condition ($newValue -le $maxIdleTime -and $newValue -ne $neverValue) -Message "18.10.56.3.10.1 Set time limit for active but idle Remote Desktop Services sessions is set to '15 minutes or less, but not Never (0)'."
    } else {
        Handle-Output -Condition $true -Message "18.10.56.3.10.1 Set time limit for active but idle Remote Desktop Services sessions is already set to '15 minutes or less, but not Never (0)'."
    }
}

# 18.10.56.3.10.2 (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'
function Ensure-DisconnectedSessionTimeLimit {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "MaxDisconnectionTime"
    $timeLimit = 60000  # 1 minute in milliseconds

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MaxDisconnectionTime

    if ($currentValue -ne $timeLimit) {
        # Set registry value to 1 minute
        Set-ItemProperty -Path $regPath -Name $regName -Value $timeLimit -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MaxDisconnectionTime
        Handle-Output -Condition ($newValue -eq $timeLimit) -Message "18.10.56.3.10.2 Set time limit for disconnected sessions is set to '1 minute'."
    } else {
        Handle-Output -Condition $true -Message "18.10.56.3.10.2 Set time limit for disconnected sessions is already set to '1 minute'."
    }
}

# 18.10.56.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
function Ensure-DeleteTempDirsOnExitDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "DeleteTempDirsOnExit"
    $expectedValue = 0  # Disabled

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DeleteTempDirsOnExit

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable the policy
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DeleteTempDirsOnExit
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.56.3.11.1 Do not delete temp folders upon exit is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.56.3.11.1 Do not delete temp folders upon exit is already set to 'Disabled'."
    }
}

# 18.10.57.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
function Ensure-PreventDownloadingOfEnclosuresEnabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
    $regName = "DisableEnclosureDownload"
    $expectedValue = 1  # Enabled

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableEnclosureDownload

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 1 to enable the policy
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableEnclosureDownload
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.57.1 Prevent downloading of enclosures is set to 'Enabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.57.1 Prevent downloading of enclosures is already set to 'Enabled'."
    }
}

# 18.10.58.2 (L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'
function Ensure-AllowCloudSearchDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $regName = "AllowCloudSearch"
    $expectedValue = 0  # Disable Cloud Search

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowCloudSearch
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable cloud search
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowCloudSearch
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.58.2 Allow Cloud Search is set to 'Enabled: Disable Cloud Search'."
    } else {
        Handle-Output -Condition $true -Message "18.10.58.2 Allow Cloud Search is already set to 'Enabled: Disable Cloud Search'."
    }
}

# 18.10.58.3 (L1) Ensure 'Allow Cortana' is set to 'Disabled'
function Ensure-AllowCortanaDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $regName = "AllowCortana"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowCortana
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable Cortana
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowCortana
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.58.3 Allow Cortana is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.58.3 Allow Cortana is already set to 'Disabled'."
    }
}

# 18.10.58.4 (L1) Ensure 'Allow Cortana above lock screen' is set to 'Disabled'
function Ensure-AllowCortanaAboveLockDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $regName = "AllowCortanaAboveLock"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowCortanaAboveLock
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable Cortana above lock screen
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowCortanaAboveLock
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.58.4 Allow Cortana above lock screen is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.58.4 Allow Cortana above lock screen is already set to 'Disabled'."
    }
}

# 18.10.58.5 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
function Ensure-AllowIndexingEncryptedFilesDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $regName = "AllowIndexingEncryptedStoresOrItems"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowIndexingEncryptedStoresOrItems
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable indexing of encrypted files
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowIndexingEncryptedStoresOrItems
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.58.5 Allow indexing of encrypted files is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.58.5 Allow indexing of encrypted files is already set to 'Disabled'."
    }
}

# 18.10.58.6 (L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
function Ensure-AllowSearchAndCortanaToUseLocationDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $regName = "AllowSearchToUseLocation"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowSearchToUseLocation
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable location access for search and Cortana
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowSearchToUseLocation
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.58.6 Allow search and Cortana to use location is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.58.6 Allow search and Cortana to use location is already set to 'Disabled'."
    }
}

# 18.10.58.7 (L2) Ensure 'Allow search highlights' is set to 'Disabled'
function Ensure-AllowSearchHighlightsDisabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $regName = "EnableDynamicContentInWSB"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableDynamicContentInWSB
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable search highlights
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableDynamicContentInWSB
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.58.7 Allow search highlights is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.58.7 Allow search highlights is already set to 'Disabled'."
    }
}

# 18.10.62.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
function Ensure-TurnOffKMSClientOnlineAVSValidation {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
    $regName = "NoGenTicket"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoGenTicket
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 1 to enable turning off KMS Client Online AVS Validation
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoGenTicket
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.62.1 Turn off KMS Client Online AVS Validation is set to 'Enabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.62.1 Turn off KMS Client Online AVS Validation is already set to 'Enabled'."
    }
}

# 18.10.65.1 (L2) Ensure 'Disable all apps from Microsoft Store' is set to 'Disabled'
function Ensure-DisableAllAppsFromMicrosoftStore {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    $regName = "DisableStoreApps"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableStoreApps
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 0 to disable disabling all apps from Microsoft Store
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableStoreApps
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.65.1 Disable all apps from Microsoft Store is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.65.1 Disable all apps from Microsoft Store is already set to 'Disabled'."
    }
}

# 18.10.65.2 (L1) Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled'
function Ensure-OnlyDisplayPrivateStore {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    $regName = "RequirePrivateStoreOnly"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).RequirePrivateStoreOnly
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 1 to enable only displaying the private store
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).RequirePrivateStoreOnly
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.65.2 Only display the private store within the Microsoft Store is set to 'Enabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.65.2 Only display the private store within the Microsoft Store is already set to 'Enabled'."
    }
}

# 18.10.65.3 (L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'
function Ensure-AutoDownloadUpdates {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    $regName = "AutoDownload"
    $expectedValue = 4  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AutoDownload
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 4 to disable automatic download and installation
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AutoDownload
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.65.3 Turn off Automatic Download and Install of updates is set to 'Disabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.65.3 Turn off Automatic Download and Install of updates is already set to 'Disabled'."
    }
}

# 18.10.65.4 (L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'
function Ensure-TurnOffOSUpgradeOffer {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    $regName = "DisableOSUpgrade"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableOSUpgrade
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 1 to disable the offer to update to the latest version of Windows
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableOSUpgrade
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.65.4 Turn off the offer to update to the latest version of Windows is set to 'Enabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.65.4 Turn off the offer to update to the latest version of Windows is already set to 'Enabled'."
    }
}

# 18.10.65.5 (L2) Ensure 'Turn off the Store application' is set to 'Enabled'
function Ensure-TurnOffStoreApp {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    $regName = "RemoveWindowsStore"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).RemoveWindowsStore
    }

    if ($currentValue -ne $expectedValue) {
        # Set registry value to 1 to turn off the Store application
        if (-not $keyExists) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -ErrorAction SilentlyContinue

        # Verify the change
        $newValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).RemoveWindowsStore
        Handle-Output -Condition ($newValue -eq $expectedValue) -Message "18.10.65.5 Turn off the Store application is set to 'Enabled'."
    } else {
        Handle-Output -Condition $true -Message "18.10.65.5 Turn off the Store application is already set to 'Enabled'."
    }
}

# Function to check if 'Allow widgets' is set to 'Disabled'
function Check-AllowWidgets {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
    $regName = "AllowNewsAndInterests"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowNewsAndInterests
    }

    # Check and handle output
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.71.1 Allow widgets is set to 'Disabled'."
}

# Function to ensure 'Automatic Data Collection' is set to 'Enabled'
function Ensure-AutomaticDataCollection {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
    $regName = "CaptureThreatWindow"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).CaptureThreatWindow
    }

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.75.1.1 Automatic Data Collection is set to 'Enabled'."
}

# 18.10.75.1.2 (L1) Ensure 'Notify Malicious' is set to 'Enabled'
function Ensure-NotifyMalicious {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
    $regName = "NotifyMalicious"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NotifyMalicious
    }

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.75.1.2 Notify Malicious is set to 'Enabled'."
}

# 18.10.75.1.3 (L1) Ensure 'Notify Password Reuse' is set to 'Enabled'
function Ensure-NotifyPasswordReuse {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
    $regName = "NotifyPasswordReuse"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NotifyPasswordReuse
    }

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.75.1.3 Notify Password Reuse is set to 'Enabled'."
}

# 18.10.75.1.4 (L1) Ensure 'Notify Unsafe App' is set to 'Enabled'
function Ensure-NotifyUnsafeApp {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
    $regName = "NotifyUnsafeApp"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NotifyUnsafeApp
    }

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.75.1.4 Notify Unsafe App is set to 'Enabled'."
}

# 18.10.75.1.5 (L1) Ensure 'Service Enabled' is set to 'Enabled'
function Ensure-ServiceEnabled {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
    $regName = "ServiceEnabled"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).ServiceEnabled
    }

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.75.1.5 Service Enabled is set to 'Enabled'."
}

# 18.10.75.2.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'
function Ensure-WindowsDefenderSmartScreen {
    # Registry paths and keys for the policy settings
    $regPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $regName1 = "EnableSmartScreen"
    $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $regName2 = "ShellSmartScreenLevel"
    
    $expectedValue1 = 1  # Enabled
    $expectedValue2 = "Block"  # Warn and prevent bypass

    # Check if the registry keys exist and get the current values
    $keyExists1 = Test-Path -Path $regPath1
    $keyExists2 = Test-Path -Path $regPath2

    $currentValue1 = $null
    $currentValue2 = $null

    if ($keyExists1) {
        $currentValue1 = (Get-ItemProperty -Path $regPath1 -Name $regName1 -ErrorAction SilentlyContinue).EnableSmartScreen
    }

    if ($keyExists2) {
        $currentValue2 = (Get-ItemProperty -Path $regPath2 -Name $regName2 -ErrorAction SilentlyContinue).ShellSmartScreenLevel
    }

    # Check conditions and output results
    $condition1 = ($currentValue1 -eq $expectedValue1)
    $condition2 = ($currentValue2 -eq $expectedValue2)

    Handle-Output -Condition $condition1 -Message "18.10.75.2.1 Configure Windows Defender SmartScreen EnableSmartScreen is set to 'Enabled'."
    Handle-Output -Condition $condition2 -Message "18.10.75.2.1 Configure Windows Defender SmartScreen ShellSmartScreenLevel is set to 'Warn and prevent bypass'."
}

# 18.10.77.1 (L1) Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'
function Ensure-DisableGameRecording {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
    $regName = "AllowGameDVR"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowGameDVR
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.77.1 Windows Game Recording and Broadcasting is set to 'Disabled'."
}

# 18.10.78.1 (L1) Ensure 'Enable ESS with Supported Peripherals' is set to 'Enabled: 1'
function Ensure-EnableESS {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics"
    $regName = "EnableESSwithSupportedPeripherals"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableESSwithSupportedPeripherals
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.78.1 Enable ESS with Supported Peripherals is set to 'Enabled: 1'."
}

# 18.10.79.1 (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'
function Ensure-DisableSuggestedAppsInInkWorkspace {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    $regName = "AllowSuggestedAppsInWindowsInkWorkspace"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowSuggestedAppsInWindowsInkWorkspace
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.79.1 Allow suggested apps in Windows Ink Workspace is set to 'Disabled'."
}

# 18.10.79.2 (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'
function Ensure-AllowWindowsInkWorkspace {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    $regName = "AllowWindowsInkWorkspace"
    $expectedValues = @(0, 1)  # Disabled or Enabled: On, but disallow access above lock

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowWindowsInkWorkspace
    }

    # Check condition and output result
    Handle-Output -Condition ($expectedValues -contains $currentValue) -Message "18.10.79.2 Allow Windows Ink Workspace is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'."
}

# 18.10.80.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled'
function Ensure-AllowUserControlOverInstalls {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $regName = "EnableUserControl"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableUserControl
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.80.1 Allow user control over installs is set to 'Disabled'."
}

# 18.10.80.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'
function Ensure-AlwaysInstallWithElevatedPrivileges {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $regName = "AlwaysInstallElevated"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AlwaysInstallElevated
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.80.2 Always install with elevated privileges is set to 'Disabled'."
}

# 18.10.80.3 (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'
function Ensure-PreventIESecurityPromptForInstallerScripts {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $regName = "SafeForScripting"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).SafeForScripting
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.80.3 Prevent Internet Explorer security prompt for Windows Installer scripts is set to 'Disabled'."
}

# 18.10.81.1 (L1) Ensure 'Enable MPR notifications for the system' is set to 'Disabled'
function Ensure-EnableMPRNotifications {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "EnableMPR"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableMPR
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.81.1 Enable MPR notifications for the system is set to 'Disabled'."
}

# 18.10.81.2 (L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'
function Ensure-AutomaticRestartSignOn {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "DisableAutomaticRestartSignOn"
    $expectedValue = 1  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableAutomaticRestartSignOn
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.81.2 Sign-in and lock last interactive user automatically after a restart is set to 'Disabled'."
}

# 18.10.86.1 (L2) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'
function Ensure-ScriptBlockLogging {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $regName = "EnableScriptBlockLogging"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.86.1 Turn on PowerShell Script Block Logging is set to 'Enabled'."
}

# 18.10.86.2 (L2) Ensure 'Turn on PowerShell Transcription' is set to 'Enabled'
function Ensure-PowerShellTranscription {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $regName = "EnableTranscription"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).EnableTranscription
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.86.2 Turn on PowerShell Transcription is set to 'Enabled'."
}

# 18.10.88.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'
function Ensure-AllowBasicAuthentication {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    $regName = "AllowBasic"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowBasic
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.88.1.1 Allow Basic authentication is set to 'Disabled'."
}

# 18.10.88.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
function Ensure-AllowUnencryptedTraffic {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    $regName = "AllowUnencryptedTraffic"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowUnencryptedTraffic
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.88.1.2 Allow unencrypted traffic is set to 'Disabled'."
}

# 18.10.88.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'
function Ensure-DisallowDigestAuthentication {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    $regName = "AllowDigest"
    $expectedValue = 0  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowDigest
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.88.1.3 Disallow Digest authentication is set to 'Enabled'."
}

# 18.10.88.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'
function Ensure-AllowBasicAuthentication {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $regName = "AllowBasic"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowBasic
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.88.2.1 Allow Basic authentication is set to 'Disabled'."
}

# 18.10.88.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'
function Ensure-AllowRemoteServerManagement {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $regName = "AllowAutoConfig"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowAutoConfig
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.88.2.2 Allow remote server management through WinRM is set to 'Disabled'."
}

# 18.10.88.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
function Ensure-AllowUnencryptedTraffic {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $regName = "AllowUnencryptedTraffic"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowUnencryptedTraffic
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.88.2.3 Allow unencrypted traffic is set to 'Disabled'."
}

# 18.10.88.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
function Ensure-DisallowRunAs {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $regName = "DisableRunAs"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableRunAs
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.88.2.4 Disallow WinRM from storing RunAs credentials is set to 'Enabled'."
}

# 18.10.89.1 (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'
function Ensure-AllowRemoteShellAccess {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"
    $regName = "AllowRemoteShellAccess"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowRemoteShellAccess
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.89.1 Allow Remote Shell Access is set to 'Disabled'."
}

# 18.10.90.1 (L1) Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled'
function Ensure-AllowClipboardSharingWithSandbox {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"
    $regName = "AllowClipboardRedirection"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowClipboardRedirection
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.90.1 Allow clipboard sharing with Windows Sandbox is set to 'Disabled'."
}

# 18.10.90.2 (L1) Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled'
function Ensure-AllowNetworkingInSandbox {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"
    $regName = "AllowNetworking"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowNetworking
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.90.2 Allow networking in Windows Sandbox is set to 'Disabled'."
}

# 18.10.91.2.1 (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'
function Ensure-PreventUsersFromModifyingSettings {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
    $regName = "DisallowExploitProtectionOverride"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisallowExploitProtectionOverride
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.91.2.1 Prevent users from modifying settings is set to 'Enabled'."
}

# 18.10.92.1.1 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
function Ensure-NoAutoRestartWithLoggedOnUsers {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $regName = "NoAutoRebootWithLoggedOnUsers"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.92.1.1 No auto-restart with logged on users for scheduled automatic updates installations is set to 'Disabled'."
}

# 18.10.92.2.1 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'
function Ensure-ConfigureAutomaticUpdates {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $regName = "NoAutoUpdate"
    $expectedValue = 0  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoAutoUpdate
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -ne $expectedValue) -Message "18.10.92.2.1 Configure Automatic Updates is set to 'Enabled'."
}

# 18.10.92.2.2 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
function Ensure-ScheduledInstallDay {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $regName = "ScheduledInstallDay"
    $expectedValue = 0  # Every day

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).ScheduledInstallDay
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -ne $expectedValue) -Message "18.10.92.2.2 Configure Automatic Updates: Scheduled install day is set to '0 - Every day'."
}

# 18.10.92.2.3 (L1) Ensure 'Enable features introduced via servicing that are off by default' is set to 'Disabled'
function Ensure-EnableFeaturesIntroducedViaServicing {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $regName = "AllowTemporaryEnterpriseFeatureControl"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowTemporaryEnterpriseFeatureControl
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -ne $expectedValue) -Message "18.10.92.2.3 Enable features introduced via servicing that are off by default is set to 'Disabled'."
}

# 18.10.92.2.4 (L1) Ensure 'Remove access to “Pause updates” feature' is set to 'Enabled'
function Ensure-RemoveAccessToPauseUpdatesFeature {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $regName = "SetDisablePauseUXAccess"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).SetDisablePauseUXAccess
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -ne $expectedValue) -Message "18.10.92.2.4 Remove access to 'Pause updates' feature is set to 'Enabled'."
}

# 18.10.92.4.1 (L1) Ensure 'Manage preview builds' is set to 'Disabled'
function Ensure-ManagePreviewBuilds {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $regName = "ManagePreviewBuildsPolicyValue"
    $expectedValue = 1  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).ManagePreviewBuildsPolicyValue
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -ne $expectedValue) -Message "18.10.92.4.1 Manage preview builds is set to 'Disabled'."
}

# 18.10.92.4.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'
function Ensure-PreviewBuildsFeatureUpdates {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $regName1 = "DeferFeatureUpdates"
    $regName2 = "DeferFeatureUpdatesPeriodInDays"
    $expectedValue1 = 1  # Enabled
    $expectedValue2 = 180 # 180 days or more

    # Check if the registry key exists and get the current values
    $keyExists = Test-Path -Path $regPath
    $currentValue1 = $null
    $currentValue2 = $null

    if ($keyExists) {
        $currentValue1 = (Get-ItemProperty -Path $regPath -Name $regName1 -ErrorAction SilentlyContinue).DeferFeatureUpdates
        $currentValue2 = (Get-ItemProperty -Path $regPath -Name $regName2 -ErrorAction SilentlyContinue).DeferFeatureUpdatesPeriodInDays
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue1 -ne $expectedValue1 -or $currentValue2 -lt $expectedValue2) -Message "18.10.92.4.2 Select when Preview Builds and Feature Updates are received is set to 'Enabled: 180 or more days'."
}

# 18.10.92.4.3 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
function Ensure-QualityUpdates {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $regName1 = "DeferQualityUpdates"
    $regName2 = "DeferQualityUpdatesPeriodInDays"
    $expectedValue1 = 1  # Enabled
    $expectedValue2 = 0  # 0 days

    # Check if the registry key exists and get the current values
    $keyExists = Test-Path -Path $regPath
    $currentValue1 = $null
    $currentValue2 = $null

    if ($keyExists) {
        $currentValue1 = (Get-ItemProperty -Path $regPath -Name $regName1 -ErrorAction SilentlyContinue).DeferQualityUpdates
        $currentValue2 = (Get-ItemProperty -Path $regPath -Name $regName2 -ErrorAction SilentlyContinue).DeferQualityUpdatesPeriodInDays
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue1 -ne $expectedValue1 -or $currentValue2 -ne $expectedValue2) -Message "18.10.92.4.3 Select when Quality Updates are received is set to 'Enabled: 0 days'."
}

# 18.10.92.4.4 (L1) Ensure 'Enable optional updates' is set to 'Disabled'
function Ensure-OptionalUpdates {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $regName = "AllowOptionalContent"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AllowOptionalContent
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "18.10.92.4.4 Enable optional updates is set to 'Disabled'."
}

# 19.5.1.1 (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
function Ensure-ToastNotificationsOnLockScreen {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    $regName = "NoToastApplicationNotificationOnLockScreen"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoToastApplicationNotificationOnLockScreen
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.5.1.1 Turn off toast notifications on the lock screen is set to 'Enabled'."
}

# 19.6.6.1.1 (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
function Ensure-HelpExperienceImprovement {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Policies\Microsoft\Assistance\Client\1.0"
    $regName = "NoImplicitFeedback"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoImplicitFeedback
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.6.6.1.1 Turn off Help Experience Improvement Program is set to 'Enabled'."
}

# 19.7.5.1 (L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
function Ensure-ZoneInformationPreservation {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    $regName = "SaveZoneInformation"
    $expectedValue = 2  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).SaveZoneInformation
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.5.1 Do not preserve zone information in file attachments is set to 'Disabled'."
}

# 19.7.5.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
function Ensure-AntivirusNotification {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    $regName = "ScanWithAntiVirus"
    $expectedValue = 3  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).ScanWithAntiVirus
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.5.2 Notify antivirus programs when opening attachments is set to 'Enabled'."
}

# 19.7.8.1 (L1) Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'
function Ensure-WindowsSpotlightDisabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Policies\Microsoft\Windows\CloudContent"
    $regName = "ConfigureWindowsSpotlight"
    $expectedValue = 2  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).ConfigureWindowsSpotlight
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.8.1 Configure Windows spotlight on lock screen is set to 'Disabled'."
}

# 19.7.8.2 (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
function Ensure-DisableThirdPartySuggestionsEnabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Policies\Microsoft\Windows\CloudContent"
    $regName = "DisableThirdPartySuggestions"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableThirdPartySuggestions
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.8.2 Do not suggest third-party content in Windows spotlight is set to 'Enabled'."
}

# 19.7.8.3 (L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'
function Ensure-DisableTailoredExperiencesWithDiagnosticDataEnabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Policies\Microsoft\Windows\CloudContent"
    $regName = "DisableTailoredExperiencesWithDiagnosticData"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableTailoredExperiencesWithDiagnosticData
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.8.3 Do not use diagnostic data for tailored experiences is set to 'Enabled'."
}

# 19.7.8.4 (L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'
function Ensure-TurnOffAllWindowsSpotlightFeaturesEnabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Policies\Microsoft\Windows\CloudContent"
    $regName = "DisableWindowsSpotlightFeatures"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableWindowsSpotlightFeatures
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.8.4 Turn off all Windows spotlight features is set to 'Enabled'."
}

# 19.7.8.5 (L1) Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'
function Ensure-TurnOffSpotlightCollectionOnDesktopEnabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $regName = "DisableSpotlightCollectionOnDesktop"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).DisableSpotlightCollectionOnDesktop
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.8.5 Turn off Spotlight collection on Desktop is set to 'Enabled'."
}

# 19.7.26.1 (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
function Ensure-PreventFileSharingWithinProfileEnabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $regName = "NoInplaceSharing"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).NoInplaceSharing
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.26.1 Prevent users from sharing files within their profile is set to 'Enabled'."
}

# 19.7.38.1 (L1) Ensure 'Turn off Windows Copilot' is set to 'Enabled'
function Ensure-TurnOffWindowsCopilotEnabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    $regName = "TurnOffWindowsCopilot"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).TurnOffWindowsCopilot
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.38.1 Turn off Windows Copilot is set to 'Enabled'."
}

# 19.7.42.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'
function Ensure-AlwaysInstallWithElevatedPrivilegesDisabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Policies\Microsoft\Windows\Installer"
    $regName = "AlwaysInstallElevated"
    $expectedValue = 0  # Disabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).AlwaysInstallElevated
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.42.1 Always install with elevated privileges is set to 'Disabled'."
}

# 19.7.44.2.1 (L2) Ensure 'Prevent Codec Download' is set to 'Enabled'
function Ensure-PreventCodecDownloadEnabled {
    # Registry path and key for the policy setting
    $userSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
    $regPath = "HKU:\$userSID\Software\Policies\Microsoft\WindowsMediaPlayer"
    $regName = "PreventCodecDownload"
    $expectedValue = 1  # Enabled

    # Check if the registry key exists and get the current value
    $keyExists = Test-Path -Path $regPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).PreventCodecDownload
    }

    # Check condition and output result
    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "19.7.44.2.1 Prevent Codec Download is set to 'Enabled'."
}

# Call the audit function
Ensure-PreventCodecDownloadEnabled

# Call the audit function
Ensure-AlwaysInstallWithElevatedPrivilegesDisabled

# Call the audit function
Ensure-TurnOffWindowsCopilotEnabled

# Call the audit function
Ensure-PreventFileSharingWithinProfileEnabled

# Call the audit function
Ensure-TurnOffSpotlightCollectionOnDesktopEnabled

# Call the audit function
Ensure-TurnOffAllWindowsSpotlightFeaturesEnabled

# Call the audit function
Ensure-DisableTailoredExperiencesWithDiagnosticDataEnabled

# Call the audit function
Ensure-DisableThirdPartySuggestionsEnabled

# Call the audit function
Ensure-WindowsSpotlightDisabled

# Call the audit function
Ensure-AntivirusNotification

# Call the audit function
Ensure-ZoneInformationPreservation

# Call the audit function
Ensure-HelpExperienceImprovement

# Call the audit function
Ensure-ToastNotificationsOnLockScreen

# Call the audit function
Ensure-OptionalUpdates

# Call the audit function
Ensure-QualityUpdates

# Call the audit function
Ensure-PreviewBuildsFeatureUpdates

# Call the audit function
Ensure-ManagePreviewBuilds

# Call the audit function
Ensure-RemoveAccessToPauseUpdatesFeature

# Call the audit function
Ensure-EnableFeaturesIntroducedViaServicing

# Call the audit function
Ensure-ScheduledInstallDay

# Call the audit function
Ensure-ConfigureAutomaticUpdates

# Call the audit function
Ensure-NoAutoRestartWithLoggedOnUsers

# Call the audit function
Ensure-PreventUsersFromModifyingSettings

# Call the audit function
Ensure-AllowNetworkingInSandbox

# Call the audit function
Ensure-AllowClipboardSharingWithSandbox

# Call the audit function
Ensure-AllowRemoteShellAccess

# Call the audit function
Ensure-DisallowRunAs

# Call the audit function
Ensure-AllowUnencryptedTraffic

# Call the audit function
Ensure-AllowRemoteServerManagement

# Call the audit function
Ensure-AllowBasicAuthentication

# Call the audit function
Ensure-DisallowDigestAuthentication

# Call the audit function
Ensure-AllowUnencryptedTraffic

# Call the audit function
Ensure-AllowBasicAuthentication

# Call the audit function
Ensure-PowerShellTranscription

# Call the audit function
Ensure-ScriptBlockLogging

# Call the audit function
Ensure-AutomaticRestartSignOn

# Call the audit function
Ensure-EnableMPRNotifications

# Call the audit function
Ensure-PreventIESecurityPromptForInstallerScripts

# Call the audit function
Ensure-AlwaysInstallWithElevatedPrivileges

# Call the audit function
Ensure-AllowUserControlOverInstalls

# Call the audit function
Ensure-AllowWindowsInkWorkspace

# Call the audit function
Ensure-DisableSuggestedAppsInInkWorkspace

# Call the audit function
Ensure-EnableESS

# Call the audit function
Ensure-DisableGameRecording

# Call the audit function
Ensure-WindowsDefenderSmartScreen

# Call the audit function
Ensure-ServiceEnabled

# Call the audit function
Ensure-NotifyUnsafeApp

# Call the audit function
Ensure-NotifyPasswordReuse

# Call the audit function
Ensure-NotifyMalicious

# Call the audit function
Ensure-AutomaticDataCollection

# Call the check Allow widgets function
Check-AllowWidgets

# Call the audit and remediation function
Ensure-IdleSessionTimeLimit

# Call the audit and remediation function
Ensure-TurnOffStoreApp

# Call the audit and remediation function
Ensure-TurnOffOSUpgradeOffer

# Call the audit and remediation function
Ensure-AutoDownloadUpdates

# Call the audit and remediation function
Ensure-OnlyDisplayPrivateStore

# Call the audit and remediation function
Ensure-DisableAllAppsFromMicrosoftStore

# Call the audit and remediation function
Ensure-TurnOffKMSClientOnlineAVSValidation

# Call the audit and remediation function
Ensure-AllowSearchHighlightsDisabled

# Call the audit and remediation function
Ensure-AllowSearchAndCortanaToUseLocationDisabled

# Call the audit and remediation function
Ensure-AllowIndexingEncryptedFilesDisabled

# Call the audit and remediation function
Ensure-AllowCortanaAboveLockDisabled

# Call the audit and remediation function
Ensure-AllowCortanaDisabled

# Call the audit and remediation function
Ensure-AllowCloudSearchDisabled

# Call the audit and remediation function
Ensure-PreventDownloadingOfEnclosuresEnabled

# Call the audit and remediation function
Ensure-DeleteTempDirsOnExitDisabled

# Call the audit and remediation function
Ensure-DisconnectedSessionTimeLimit

# Call the audit and remediation function
Ensure-ClientConnectionEncryptionLevel

# Call the check function
Check-RequireUserAuthentication

# Call the check function
Check-RequireSpecificSecurityLayer

# Call the check function
Check-RequireSecureRPCCommunication

# Call the check function
Check-AlwaysPromptForPassword

# Call the check function
Check-DoNotAllowWebAuthnRedirection

# Call the check function
Check-DoNotAllowPNPDeviceRedirection

# Call the check function
Check-DoNotAllowLPTPortRedirection

# Call the check function
Check-DoNotAllowLocationRedirection

# Call the check function
Check-DoNotAllowDriveRedirection

# Call the audit and remediation function
Ensure-DoNotAllowCOMPortRedirectionEnabled

# Call the audit and remediation function
Ensure-AllowUIAutomationRedirectionDisabled

# Call the audit function
Ensure-RDPConnectionDisabled

