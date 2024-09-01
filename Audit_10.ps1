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

# 18.10.9.2.17 (BL) Ensure 'Require additional authentication at startup: Configure TPM startup key:' is set to 'Enabled: Do not allow startup key with TPM'
function Check-TpmStartupKeyConfiguration {
    # Registry path and key for TPM startup key configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "UseTPMKey"

    # Expected value for 'Do not allow startup key with TPM' is 0
    $expectedValue = 0

    try {
        # Check current TPM startup key configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).UseTPMKey

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.2.17 Require additional authentication at startup: Configure TPM startup key is set to 'Enabled: Do not allow startup key with TPM'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.2.17 Require additional authentication at startup: Configure TPM startup key is not set to 'Enabled: Do not allow startup key with TPM'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.2.17 Error occurred while checking TPM startup key configuration: $_"
    }
}

# 18.10.9.2.18 (BL) Ensure 'Require additional authentication at startup: Configure TPM startup key and PIN:' is set to 'Enabled: Do not allow startup key and PIN with TPM'
function Check-TpmStartupKeyPinConfiguration {
    # Registry path and key for TPM startup key and PIN configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "UseTPMKeyPIN"

    # Expected value for 'Do not allow startup key and PIN with TPM' is 0
    $expectedValue = 0

    try {
        # Check current TPM startup key and PIN configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).UseTPMKeyPIN

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.2.18 Require additional authentication at startup: Configure TPM startup key and PIN is set to 'Enabled: Do not allow startup key and PIN with TPM'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.2.18 Require additional authentication at startup: Configure TPM startup key and PIN is not set to 'Enabled: Do not allow startup key and PIN with TPM'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.2.18 Error occurred while checking TPM startup key and PIN configuration: $_"
    }
}

# 18.10.9.3.2 (BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled'
function Check-BitLockerRecoveryConfiguration {
    # Registry path and key for BitLocker recovery configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVRecovery"
    $expectedValue = 1

    try {
        # Check current BitLocker recovery configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVRecovery

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.2 Choose how BitLocker-protected removable drives can be recovered is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.2 Choose how BitLocker-protected removable drives can be recovered is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.2 Error occurred while checking BitLocker recovery configuration: $_"
    }
}

# 18.10.9.3.3 (BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'
function Check-BitLockerRecoveryAgent {
    # Registry path and key for BitLocker recovery agent configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVManageDRA"
    $expectedValue = 1

    try {
        # Check current BitLocker recovery agent configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVManageDRA

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.3 Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent is set to 'Enabled: True'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.3 Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent is not set to 'Enabled: True'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.3 Error occurred while checking BitLocker recovery agent configuration: $_"
    }
}

# 18.10.9.3.5 (BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'
function Check-BitLockerRecoveryKey {
    # Registry path and key for BitLocker recovery key configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVRecoveryKey"
    $expectedValue = 0

    try {
        # Check current BitLocker recovery key configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVRecoveryKey

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.5 Choose how BitLocker-protected removable drives can be recovered: Recovery Key is set to 'Enabled: Do not allow 256-bit recovery key'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.5 Choose how BitLocker-protected removable drives can be recovered: Recovery Key is not set to 'Enabled: Do not allow 256-bit recovery key'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.5 Error occurred while checking BitLocker recovery key configuration: $_"
    }
}

# 18.10.9.3.6 (BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'
function Check-BitLockerOmitRecoveryOptions {
    # Registry path and key for BitLocker omit recovery options configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVHideRecoveryPage"
    $expectedValue = 1

    try {
        # Check current BitLocker omit recovery options configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVHideRecoveryPage

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.6 Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard is set to 'Enabled: True'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.6 Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard is not set to 'Enabled: True'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.6 Error occurred while checking BitLocker omit recovery options configuration: $_"
    }
}

# 18.10.9.3.7 (BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False'
function Check-BitLockerADDSBackup {
    # Registry path and key for BitLocker AD DS backup configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVActiveDirectoryBackup"
    $expectedValue = 0

    try {
        # Check current BitLocker AD DS backup configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVActiveDirectoryBackup

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.7 Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives is set to 'Enabled: False'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.7 Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives is not set to 'Enabled: False'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.7 Error occurred while checking BitLocker AD DS backup configuration: $_"
    }
}

# 18.10.9.3.8 (BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages'
function Check-BitLockerADDSBackupInfo {
    # Registry path and key for BitLocker AD DS backup information configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVActiveDirectoryInfoToStore"
    $expectedValue = 1

    try {
        # Check current BitLocker AD DS backup information configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVActiveDirectoryInfoToStore

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.8 Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS is set to 'Enabled: Backup recovery passwords and key packages'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.8 Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS is not set to 'Enabled: Backup recovery passwords and key packages'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.8 Error occurred while checking BitLocker AD DS backup information configuration: $_"
    }
}

# 18.10.9.3.9 (BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False'
function Check-BitLockerADDSBackupRequirement {
    # Registry path and key for BitLocker AD DS backup requirement configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVRequireActiveDirectoryBackup"
    $expectedValue = 0

    try {
        # Check current BitLocker AD DS backup requirement configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVRequireActiveDirectoryBackup

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.9 Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives is set to 'Enabled: False'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.9 Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives is not set to 'Enabled: False'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.9 Error occurred while checking BitLocker AD DS backup requirement configuration: $_"
    }
}

# 18.10.9.3.10 (BL) Ensure 'Configure use of hardware-based encryption for removable data drives' is set to 'Disabled'
function Check-BitLockerHardwareEncryption {
    # Registry path and key for BitLocker hardware-based encryption configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVHardwareEncryption"
    $expectedValue = 0

    try {
        # Check current BitLocker hardware-based encryption configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVHardwareEncryption

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.10 Configure use of hardware-based encryption for removable data drives is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.10 Configure use of hardware-based encryption for removable data drives is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.10 Error occurred while checking BitLocker hardware-based encryption configuration: $_"
    }
}

# 18.10.9.3.11 (BL) Ensure 'Configure use of passwords for removable data drives' is set to 'Disabled'
function Check-BitLockerUseOfPasswords {
    # Registry path and key for BitLocker use of passwords configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVPassphrase"
    $expectedValue = 0

    try {
        # Check current BitLocker use of passwords configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVPassphrase

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.11 Configure use of passwords for removable data drives is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.11 Configure use of passwords for removable data drives is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.11 Error occurred while checking BitLocker use of passwords configuration: $_"
    }
}

# 18.10.9.3.12 (BL) Ensure 'Configure use of smart cards on removable data drives' is set to 'Enabled'
function Check-BitLockerUseOfSmartCards {
    # Registry path and key for BitLocker use of smart cards configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVAllowUserCert"
    $expectedValue = 1

    try {
        # Check current BitLocker use of smart cards configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVAllowUserCert

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.12 Configure use of smart cards on removable data drives is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.12 Configure use of smart cards on removable data drives is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.12 Error occurred while checking BitLocker use of smart cards configuration: $_"
    }
}

# 18.10.9.3.13 (BL) Ensure 'Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives' is set to 'Enabled: True'
function Check-BitLockerRequireSmartCards {
    # Registry path and key for BitLocker smart card enforcement
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $regName = "RDVEnforceUserCert"
    $expectedValue = 1

    try {
        # Check current BitLocker smart card enforcement configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVEnforceUserCert

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.13 Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives is set to 'Enabled: True'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.13 Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives is not set to 'Enabled: True'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.13 Error occurred while checking BitLocker use of smart cards enforcement: $_"
    }
}

# 18.10.9.3.14 (BL) Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'
function Check-BitLockerDenyWriteAccess {
    # Registry path and key for BitLocker deny write access
    $regPath = "HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
    $regName = "RDVDenyWriteAccess"
    $expectedValue = 1

    try {
        # Check current BitLocker deny write access configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RDVDenyWriteAccess

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.9.3.14 Deny write access to removable drives not protected by BitLocker is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.9.3.14 Deny write access to removable drives not protected by BitLocker is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.9.3.14 Error occurred while checking BitLocker deny write access: $_"
    }
}

# Function to check 'Disable new DMA devices when this computer is locked'
Function Check-BitLockerDisableDMANewDevices {
    param (
        [string]$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE",
        [string]$RegistryKey = "DisableExternalDMAUnderLock",
        [int]$ExpectedValue = 1
    )
    
    try {
        # Check if registry path exists
        Write-Output "Checking registry path: $RegistryPath"
        if (Test-Path $RegistryPath) {
            Write-Output "Registry path exists. Checking key: $RegistryKey"
            $actualValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryKey -ErrorAction SilentlyContinue
            
            if ($null -ne $actualValue) {
                Write-Output "Registry key value retrieved: $($actualValue.$RegistryKey)"
                if ($actualValue.$RegistryKey -eq $ExpectedValue) {
                    Handle-Output -Condition $true -FunctionName "Check-BitLockerDisableDMANewDevices 18.10.9.4 satisfied"
                } else {
                    Handle-Output -Condition $false -FunctionName "Check-BitLockerDisableDMANewDevices 18.10.9.4 not_satisfied"
                }
            } else {
                Handle-Output -Condition $false -FunctionName "Check-BitLockerDisableDMANewDevices 18.10.9.4 not_satisfied" -Message "Registry key not found or empty."
            }
        } else {
            Handle-Output -Condition $false -FunctionName "Check-BitLockerDisableDMANewDevices 18.10.9.4 not_satisfied" -Message "Registry path not found."
        }
    } catch {
        Handle-Output -Condition $false -FunctionName "Check-BitLockerDisableDMANewDevices 18.10.9.4 not_satisfied" -Message "Error occurred while checking BitLocker DMA setting: $_"
    }
}

# Function to check 'Allow Use of Camera'
Function Check-AllowCamera {
    param (
        [string]$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Camera",
        [string]$RegistryKey = "AllowCamera",
        [int]$ExpectedValue = 0
    )
    
    try {
        # Check if registry path exists
        Write-Output "Checking registry path: $RegistryPath"
        if (Test-Path $RegistryPath) {
            Write-Output "Registry path exists. Checking key: $RegistryKey"
            $actualValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryKey -ErrorAction SilentlyContinue
            
            if ($null -ne $actualValue) {
                Write-Output "Registry key value retrieved: $($actualValue.$RegistryKey)"
                if ($actualValue.$RegistryKey -eq $ExpectedValue) {
                    Handle-Output -Condition $true -FunctionName "Check-AllowCamera 18.10.10.1 satisfied"
                } else {
                    Handle-Output -Condition $false -FunctionName "Check-AllowCamera 18.10.10.1 not_satisfied"
                }
            } else {
                Handle-Output -Condition $false -FunctionName "Check-AllowCamera 18.10.10.1 not_satisfied" -Message "Registry key not found or empty."
            }
        } else {
            Handle-Output -Condition $false -FunctionName "Check-AllowCamera 18.10.10.1 not_satisfied" -Message "Registry path not found."
        }
    } catch {
        Handle-Output -Condition $false -FunctionName "Check-AllowCamera 18.10.10.1 not_satisfied" -Message "Error occurred while checking camera setting: $_"
    }
}
# Function to check 'Turn off cloud consumer account state content'
function Check-TurnOffCloudConsumerAccountStateContent {
    # Registry path and key for cloud consumer account state content
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $regName = "DisableConsumerAccountStateContent"
    $expectedValue = 1

    try {
        # Check current setting for cloud consumer account state content
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableConsumerAccountStateContent

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.12.1 Turn off cloud consumer account state content is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.12.1 Turn off cloud consumer account state content is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.12.1 Error occurred while checking cloud consumer account state content setting: $_"
    }
}
# Function to check 'Turn off cloud optimized content'
function Check-TurnOffCloudOptimizedContent {
    # Registry path and key for cloud optimized content
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $regName = "DisableCloudOptimizedContent"
    $expectedValue = 1

    try {
        # Check current setting for cloud optimized content
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableCloudOptimizedContent

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.12.2 Turn off cloud optimized content is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.12.2 Turn off cloud optimized content is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.12.2 Error occurred while checking cloud optimized content setting: $_"
    }
}
# Function to check 'Turn off Microsoft consumer experiences'
function Check-TurnOffMicrosoftConsumerExperiences {
    # Registry path and key for Microsoft consumer experiences
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $regName = "DisableWindowsConsumerFeatures"
    $expectedValue = 1

    try {
        # Check current setting for Microsoft consumer experiences
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableWindowsConsumerFeatures

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.12.3 Turn off Microsoft consumer experiences is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.12.3 Turn off Microsoft consumer experiences is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.12.3 Error occurred while checking Microsoft consumer experiences setting: $_"
    }
}
# Function to check 'Require PIN for pairing'
function Check-RequirePinForPairing {
    # Registry path and key for Require PIN for pairing
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect"
    $regName = "RequirePinForPairing"
    $expectedValues = @(1, 2)  # 1 = Enabled: First Time, 2 = Enabled: Always

    try {
        # Check current setting for Require PIN for pairing
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).RequirePinForPairing

        if ($expectedValues -contains $currentValue) {
            Handle-Output -Condition $true -Message "18.10.13.1 Require PIN for pairing is set to 'Enabled: First Time' or 'Enabled: Always'."
        } else {
            Handle-Output -Condition $false -Message "18.10.13.1 Require PIN for pairing is not set to 'Enabled: First Time' or 'Enabled: Always'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.13.1 Error occurred while checking Require PIN for pairing setting: $_"
    }
}
# Function to check 'Do not display the password reveal button'
function Check-DisablePasswordReveal {
    # Registry path and key for Disable Password Reveal button
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI"
    $regName = "DisablePasswordReveal"
    $expectedValue = 1  # Enabled

    try {
        # Check current setting for Disable Password Reveal button
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisablePasswordReveal

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.14.1 Do not display the password reveal button is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.14.1 Do not display the password reveal button is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.14.1 Error occurred while checking Disable Password Reveal button setting: $_"
    }
}
# Function to check 'Enumerate administrator accounts on elevation'
function Check-EnumerateAdminAccountsOnElevation {
    # Registry path and key for Enumerate Administrator accounts on elevation
    $regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
    $regName = "EnumerateAdministrators"
    $expectedValue = 0  # Disabled

    try {
        # Check current setting for Enumerate Administrator accounts on elevation
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnumerateAdministrators

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.14.2 Enumerate administrator accounts on elevation is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.14.2 Enumerate administrator accounts on elevation is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.14.2 Error occurred while checking Enumerate Administrator accounts on elevation setting: $_"
    }
}

# Function to check 'Prevent the use of security questions for local accounts'
function Check-PreventLocalAccountSecurityQuestions {
    # Registry path and key for Prevent the use of security questions for local accounts
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $regName = "NoLocalPasswordResetQuestions"
    $expectedValue = 1  # Enabled

    try {
        # Check current setting for Prevent the use of security questions for local accounts
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).NoLocalPasswordResetQuestions

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.14.3 Prevent the use of security questions for local accounts is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.14.3 Prevent the use of security questions for local accounts is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.14.3 Error occurred while checking Prevent the use of security questions for local accounts setting: $_"
    }
}
# Function to check 'Allow Diagnostic Data'
function Check-AllowDiagnosticData {
    # Registry path and key for Allow Diagnostic Data
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $regName = "AllowTelemetry"

    # Expected values for 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data' are 0 or 1
    $validValues = @(0, 1)

    try {
        # Check current setting for Allow Diagnostic Data
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).AllowTelemetry

        if ($validValues -contains $currentValue) {
            Handle-Output -Condition $true -Message "18.10.15.1 Allow Diagnostic Data is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'."
        } else {
            Handle-Output -Condition $false -Message "18.10.15.1 Allow Diagnostic Data is not set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.15.1 Error occurred while checking Allow Diagnostic Data setting: $_"
    }
}
# Function to check 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service'
function Check-AuthenticatedProxyUsage {
    # Registry path and key for Authenticated Proxy usage
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $regName = "DisableEnterpriseAuthProxy"

    # Expected value for 'Enabled: Disable Authenticated Proxy usage' is 1
    $expectedValue = 1

    try {
        # Check current setting for Authenticated Proxy usage
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableEnterpriseAuthProxy

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.15.2 Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service is set to 'Enabled: Disable Authenticated Proxy usage'."
        } else {
            Handle-Output -Condition $false -Message "18.10.15.2 Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service is not set to 'Enabled: Disable Authenticated Proxy usage'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.15.2 Error occurred while checking Authenticated Proxy usage setting: $_"
    }
}
# Function to check 'Disable OneSettings Downloads'
function Check-DisableOneSettingsDownloads {
    # Registry path and key for OneSettings Downloads
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $regName = "DisableOneSettingsDownloads"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current setting for OneSettings Downloads
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableOneSettingsDownloads

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.15.3 Disable OneSettings Downloads is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.15.3 Disable OneSettings Downloads is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.15.3 Error occurred while checking OneSettings Downloads setting: $_"
    }
}
# Function to check 'Do not show feedback notifications'
function Check-DoNotShowFeedbackNotifications {
    # Registry path and key for feedback notifications
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $regName = "DoNotShowFeedbackNotifications"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current setting for feedback notifications
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DoNotShowFeedbackNotifications

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.15.4 Do not show feedback notifications is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.15.4 Do not show feedback notifications is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.15.4 Error occurred while checking feedback notifications setting: $_"
    }
}
# Function to check 'Enable OneSettings Auditing'
function Check-EnableOneSettingsAuditing {
    # Registry path and key for OneSettings auditing
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $regName = "EnableOneSettingsAuditing"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current setting for OneSettings auditing
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnableOneSettingsAuditing

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.15.5 Enable OneSettings Auditing is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.15.5 Enable OneSettings Auditing is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.15.5 Error occurred while checking OneSettings Auditing setting: $_"
    }
}

# Function to check 'Limit Diagnostic Log Collection'
function Check-LimitDiagnosticLogCollection {
    # Registry path and key for Limit Diagnostic Log Collection
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $regName = "LimitDiagnosticLogCollection"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current setting for Limit Diagnostic Log Collection
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LimitDiagnosticLogCollection

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.15.6 Limit Diagnostic Log Collection is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.15.6 Limit Diagnostic Log Collection is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.15.6 Error occurred while checking Limit Diagnostic Log Collection setting: $_"
    }
}

# Function to check 'Limit Dump Collection'
function Check-LimitDumpCollection {
    # Registry path and key for Limit Dump Collection
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $regName = "LimitDumpCollection"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current setting for Limit Dump Collection
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LimitDumpCollection

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.15.7 Limit Dump Collection is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.15.7 Limit Dump Collection is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.15.7 Error occurred while checking Limit Dump Collection setting: $_"
    }
}
# Function to check 'Toggle user control over Insider builds'
function Check-ToggleUserControlOverInsiderBuilds {
    # Registry path and key for Toggle User Control Over Insider Builds
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
    $regName = "AllowBuildPreview"

    # Expected value for 'Disabled' is 0
    $expectedValue = 0

    try {
        # Check current setting for Toggle User Control Over Insider Builds
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).AllowBuildPreview

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.15.8 Toggle user control over Insider builds is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.15.8 Toggle user control over Insider builds is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.15.8 Error occurred while checking Toggle user control over Insider builds setting: $_"
    }
}

# Function to check 'Download Mode' setting
function Check-DownloadMode {
    # Registry path and key for Download Mode
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    $regName = "DODownloadMode"

    # The value representing 'Enabled: Internet' is 3
    $internetValue = 3

    try {
        # Check current setting for Download Mode
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DODownloadMode

        if ($currentValue -ne $internetValue) {
            Handle-Output -Condition $true -Message "18.10.16.1 Download Mode is NOT set to 'Enabled: Internet'."
        } else {
            Handle-Output -Condition $false -Message "18.10.16.1 Download Mode is set to 'Enabled: Internet'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.16.1 Error occurred while checking Download Mode setting: $_"
    }
}

# Function to check 'Enable App Installer' setting
function Check-EnableAppInstaller {
    # Registry path and key for Enable App Installer
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
    $regName = "EnableAppInstaller"

    # The value representing 'Disabled' is 0
    $disabledValue = 0

    try {
        # Check current setting for Enable App Installer
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnableAppInstaller

        if ($currentValue -eq $disabledValue) {
            Handle-Output -Condition $true -Message "18.10.17.1 Enable App Installer is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.17.1 Enable App Installer is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.17.1 Error occurred while checking Enable App Installer setting: $_"
    }
}
# Function to check 'Enable App Installer Experimental Features' setting
function Check-EnableAppInstallerExperimentalFeatures {
    # Registry path and key for Enable App Installer Experimental Features
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
    $regName = "EnableExperimentalFeatures"

    # The value representing 'Disabled' is 0
    $disabledValue = 0

    try {
        # Check current setting for Enable App Installer Experimental Features
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnableExperimentalFeatures

        if ($currentValue -eq $disabledValue) {
            Handle-Output -Condition $true -Message "18.10.17.2 Enable App Installer Experimental Features is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.17.2 Enable App Installer Experimental Features is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.17.2 Error occurred while checking Enable App Installer Experimental Features setting: $_"
    }
}
# Function to check 'Enable App Installer Hash Override' setting
function Check-EnableAppInstallerHashOverride {
    # Registry path and key for Enable App Installer Hash Override
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
    $regName = "EnableHashOverride"

    # The value representing 'Disabled' is 0
    $disabledValue = 0

    try {
        # Check current setting for Enable App Installer Hash Override
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnableHashOverride

        if ($currentValue -eq $disabledValue) {
            Handle-Output -Condition $true -Message "18.10.17.3 Enable App Installer Hash Override is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.17.3 Enable App Installer Hash Override is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.17.3 Error occurred while checking Enable App Installer Hash Override setting: $_"
    }
}

# Function to check 'Enable App Installer ms-appinstaller protocol' setting
function Check-EnableAppInstallerMSAppInstallerProtocol {
    # Registry path and key for Enable App Installer ms-appinstaller protocol
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
    $regName = "EnableMSAppInstallerProtocol"

    # The value representing 'Disabled' is 0
    $disabledValue = 0

    try {
        # Check current setting for Enable App Installer ms-appinstaller protocol
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnableMSAppInstallerProtocol

        if ($currentValue -eq $disabledValue) {
            Handle-Output -Condition $true -Message "18.10.17.4 Enable App Installer ms-appinstaller protocol is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.17.4 Enable App Installer ms-appinstaller protocol is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.17.4 Error occurred while checking Enable App Installer ms-appinstaller protocol setting: $_"
    }
}

# Function to check 'Application: Control Event Log behavior when the log file reaches its maximum size' setting
function Check-ApplicationEventLogBehavior {
    # Registry path and key for Event Log behavior
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
    $regName = "Retention"

    # The value representing 'Disabled' is 0
    $disabledValue = "0"

    try {
        # Check current setting for Event Log behavior
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Retention

        if ($currentValue -eq $disabledValue) {
            Handle-Output -Condition $true -Message "18.10.25.1.1 Application Event Log behavior when the log file reaches its maximum size is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.25.1.1 Application Event Log behavior when the log file reaches its maximum size is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.25.1.1 Error occurred while checking Application Event Log behavior setting: $_"
    }
}

# Function to check 'Application: Specify the maximum log file size (KB)' setting
function Check-ApplicationMaxLogFileSize {
    # Registry path and key for maximum log file size
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
    $regName = "MaxSize"

    # The minimum value representing '32,768 or greater'
    $minimumValue = 32768

    try {
        # Check current setting for maximum log file size
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).MaxSize

        if ($currentValue -ge $minimumValue) {
            Handle-Output -Condition $true -Message "18.10.25.1.2 Application maximum log file size is set to '32,768 or greater'."
        } else {
            Handle-Output -Condition $false -Message "18.10.25.1.2 Application maximum log file size is not set to '32,768 or greater'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.25.1.2 Error occurred while checking Application maximum log file size setting: $_"
    }
}

# Function to check 'Security: Control Event Log behavior when the log file reaches its maximum size' setting
function Check-SecurityEventLogBehavior {
    # Registry path and key for event log behavior
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
    $regName = "Retention"

    # The expected value representing 'Disabled'
    $expectedValue = "0"

    try {
        # Check current setting for event log behavior
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Retention

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.25.2.1 Security event log behavior is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.25.2.1 Security event log behavior is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.25.2.1 Error occurred while checking Security event log behavior setting: $_"
    }
}
# Function to check 'Security: Specify the maximum log file size (KB)' setting
function Check-SecurityMaxLogFileSize {
    # Registry path and key for maximum log file size
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
    $regName = "MaxSize"

    # The minimum expected value representing 'Enabled: 196,608 or greater'
    $minimumValue = 196608

    try {
        # Check current setting for maximum log file size
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).MaxSize

        if ($currentValue -ge $minimumValue) {
            Handle-Output -Condition $true -Message "18.10.25.2.2 Security maximum log file size is set to '196,608 KB or greater'."
        } else {
            Handle-Output -Condition $false -Message "18.10.25.2.2 Security maximum log file size is not set to '196,608 KB or greater'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.25.2.2 Error occurred while checking Security maximum log file size setting: $_"
    }
}

# Function to check 'Setup: Control Event Log behavior when the log file reaches its maximum size' setting
function Check-SetupEventLogBehavior {
    # Registry path and key for event log behavior when log file reaches max size
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
    $regName = "Retention"

    # The expected value representing 'Disabled'
    $expectedValue = "0"

    try {
        # Check current setting for event log behavior
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Retention

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.25.3.1 Setup event log behavior is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.25.3.1 Setup event log behavior is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.25.3.1 Error occurred while checking Setup event log behavior setting: $_"
    }
}

# Call the functions to check the configurations
Check-TpmStartupKeyConfiguration
Check-TpmStartupKeyPinConfiguration
Check-BitLockerRecoveryConfiguration
Check-BitLockerRecoveryAgent
Check-BitLockerRecoveryKey
Check-BitLockerOmitRecoveryOptions
Check-BitLockerADDSBackup
Check-BitLockerADDSBackupInfo
Check-BitLockerADDSBackupRequirement
Check-BitLockerHardwareEncryption
Check-BitLockerUseOfPasswords
Check-BitLockerUseOfSmartCards
Check-BitLockerRequireSmartCards
Check-BitLockerDenyWriteAccess
Check-BitLockerDisableDMANewDevices
Check-AllowCamera
Check-TurnOffCloudConsumerAccountStateContent
Check-TurnOffCloudOptimizedContent
Check-TurnOffMicrosoftConsumerExperiences
Check-RequirePinForPairing
Check-DisablePasswordReveal
Check-EnumerateAdminAccountsOnElevation
Check-PreventLocalAccountSecurityQuestions
Check-AllowDiagnosticData
Check-AuthenticatedProxyUsage
Check-DisableOneSettingsDownloads
Check-DoNotShowFeedbackNotifications
Check-EnableOneSettingsAuditing
Check-LimitDiagnosticLogCollection
Check-LimitDumpCollection
Check-ToggleUserControlOverInsiderBuilds
Check-DownloadMode
Check-EnableAppInstaller
Check-EnableAppInstallerExperimentalFeatures
Check-EnableAppInstallerHashOverride
Check-EnableAppInstallerMSAppInstallerProtocol
Check-ApplicationEventLogBehavior
Check-ApplicationMaxLogFileSize
Check-SecurityEventLogBehavior
Check-SecurityMaxLogFileSize
Check-SetupEventLogBehavior