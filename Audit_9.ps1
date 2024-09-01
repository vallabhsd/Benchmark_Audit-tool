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
# Function to check 'Allow Custom SSPs and APs to be loaded into LSASS'
function Ensure-AllowCustomSSPsAPs {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $valueName = "AllowCustomSSPsAPs"
    $expectedValue = 0

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.26.1 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'."
}

# Function to check 'Configures LSASS to run as a protected process'
function Ensure-LSASSProtectedProcess {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $valueName = "RunAsPPL"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.26.2 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'."
}

# Function to check 'Disallow copying of user input methods to the system account for sign-in'
function Ensure-DisallowUserInputCopy {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International"
    $valueName = "BlockUserInputMethodsForSignIn"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.27.1 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'."
}

# Function to check 'Block user from showing account details on sign-in'
function Ensure-BlockAccountDetailsOnSignin {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $valueName = "BlockUserFromShowingAccountDetailsOnSignin"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.28.1 'Block user from showing account details on sign-in' is set to 'Enabled'."
}

# Function to check 'Do not display network selection UI'
function Ensure-DoNotDisplayNetworkSelectionUI {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $valueName = "DontDisplayNetworkSelectionUI"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.28.2 'Do not display network selection UI' is set to 'Enabled'."
}

# Function to check 'Do not enumerate connected users on domain-joined computers'
function Ensure-DoNotEnumerateConnectedUsers {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $valueName = "DontEnumerateConnectedUsers"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.28.3 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'."
}

# Function to check 'Enumerate local users on domain-joined computers'
function Ensure-EnumerateLocalUsers {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $valueName = "EnumerateLocalUsers"
    $expectedValue = 0

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.28.4 'Enumerate local users on domain-joined computers' is set to 'Disabled'."
}

# Function to check 'Turn off app notifications on the lock screen'
function Ensure-TurnOffAppNotificationsOnLockScreen {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $valueName = "DisableLockScreenAppNotifications"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.28.5 'Turn off app notifications on the lock screen' is set to 'Enabled'."
}

# Function to check 'Turn off picture password sign-in'
function Ensure-TurnOffPicturePasswordSignIn {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $valueName = "BlockDomainPicturePassword"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.28.6 'Turn off picture password sign-in' is set to 'Enabled'."
}

# Function to check 'Require a password when a computer wakes (on battery)'
function Ensure-RequirePasswordOnWakeOnBattery {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    $valueName = "DCSettingIndex"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.33.6.5 'Require a password when a computer wakes (on battery)' is set to 'Enabled'."
}

# Function to check 'Require a password when a computer wakes (plugged in)'
function Ensure-RequirePasswordOnWakePluggedIn {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    $valueName = "ACSettingIndex"
    $expectedValue = 1

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.33.6.6 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'."
}

# Function to check 'Configure Solicited Remote Assistance'
function Ensure-SolicitedRemoteAssistance {
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $valueName = "fAllowToGetHelp"
    $expectedValue = 0

    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    Handle-Output -Condition $isConfigCorrect -Message "18.9.33.8 'Configure Solicited Remote Assistance' is set to 'Disabled'."
}

# Function to check the BitLocker recovery information policy
function Ensure-BitLockerRecoveryInformation {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "FDVRequireActiveDirectoryBackup"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.1.9 (BL) Ensure 'Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False'."
}

# Call the check function
Ensure-BitLockerRecoveryInformation
# Function to check the hardware-based encryption policy
function Ensure-HardwareEncryptionDisabled {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "FDVHardwareEncryption"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.1.10 (BL) Ensure 'Configure use of hardware-based encryption for fixed data drives' is set to 'Disabled'."
}

# Call the check function
Ensure-HardwareEncryptionDisabled
# Function to check the use of passwords for fixed data drives policy
function Ensure-PasswordsForFixedDrivesDisabled {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "FDVPassphrase"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.1.11 (BL) Ensure 'Configure use of passwords for fixed data drives' is set to 'Disabled'."
}

# Call the check function
Ensure-PasswordsForFixedDrivesDisabled
# Function to check the use of smart cards on fixed data drives policy
function Ensure-SmartCardsForFixedDrivesEnabled {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "FDVAllowUserCert"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.1.12 (BL) Ensure 'Configure use of smart cards on fixed data drives' is set to 'Enabled'."
}

# Call the check function
Ensure-SmartCardsForFixedDrivesEnabled
# Function to check the enhanced PINs for startup policy
function Ensure-EnhancedPINsForStartupEnabled {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "UseEnhancedPin"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.1 (BL) Ensure 'Allow enhanced PINs for startup' is set to 'Enabled'."
}

# Call the check function
Ensure-EnhancedPINsForStartupEnabled
# Function to check Secure Boot for integrity validation policy
function Ensure-SecureBootForIntegrityValidationEnabled {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSAllowSecureBootForIntegrity"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.2 (BL) Ensure 'Allow Secure Boot for integrity validation' is set to 'Enabled'."
}

# Call the check function
Ensure-SecureBootForIntegrityValidationEnabled
# Function to check BitLocker recovery policy for operating system drives
function Ensure-BitLockerRecoveryOptionsEnabled {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSRecover"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.3 (BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled'."
}

# Call the check function
Ensure-BitLockerRecoveryOptionsEnabled
# Function to check if BitLocker requires a 48-digit recovery password
function Ensure-Require48DigitRecoveryPassword {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSRecoveryPassword"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.5 (BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password'."
}

# Call the check function
Ensure-Require48DigitRecoveryPassword
# Function to check if 256-bit recovery key is not allowed
function Ensure-No256BitRecoveryKey {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSRecoveryKey"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.6 (BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'."
}

# Call the check function
Ensure-No256BitRecoveryKey
# Function to check if recovery options page is omitted
function Ensure-HideRecoveryPage {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSHideRecoveryPage"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.7 (BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'."
}

# Call the check function
Ensure-HideRecoveryPage
# Function to check if BitLocker recovery information is saved to AD DS
function Ensure-ADDSBackup {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSActiveDirectoryBackup"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.8 (BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True'."
}

# Call the check function
Ensure-ADDSBackup
# Function to check the configuration of storage of BitLocker recovery information to AD DS
function Ensure-ADDSStorage {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSActiveDirectoryInfoToStore"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.9 (BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'."
}

# Call the check function
Ensure-ADDSStorage
# Function to check if BitLocker requires AD DS backup before enabling
function Ensure-RequireADBackup {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSRequireActiveDirectoryBackup"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.10 (BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives' is set to 'Enabled: True'."
}

# Call the check function
Ensure-RequireADBackup
# Function to check if hardware-based encryption is disabled
function Ensure-HardwareEncryptionDisabled {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSHardwareEncryption"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.11 (BL) Ensure 'Configure use of hardware-based encryption for operating system drives' is set to 'Disabled'."
}

# Call the check function
Ensure-HardwareEncryptionDisabled
# Function to check if the use of passwords for operating system drives is disabled
function Ensure-PasswordsDisabled {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "OSPassphrase"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.12 (BL) Ensure 'Configure use of passwords for operating system drives' is set to 'Disabled'."
}

# Call the check function
Ensure-PasswordsDisabled
# Function to check if additional authentication at startup is required
function Ensure-AdditionalAuthAtStartup {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "UseAdvancedStartup"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.13 (BL) Ensure 'Require additional authentication at startup' is set to 'Enabled'."
}

# Call the check function
Ensure-AdditionalAuthAtStartup
# Function to check if BitLocker requires a TPM
function Ensure-RequireTPMForBitLocker {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "EnableBDEWithNoTPM"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.14 (BL) Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False'."
}

# Call the check function
Ensure-RequireTPMForBitLocker
# Function to check if TPM is disabled for BitLocker
function Ensure-DisableTPMForBitLocker {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "UseTPM"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.15 (BL) Ensure 'Require additional authentication at startup: Configure TPM startup:' is set to 'Enabled: Do not allow TPM'."
}

# Call the check function
Ensure-DisableTPMForBitLocker
# Function to check if TPM startup PIN is required for BitLocker
function Ensure-RequireTPMPINForBitLocker {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "UseTPMPIN"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 1

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.16 (BL) Ensure 'Require additional authentication at startup: Configure TPM startup PIN:' is set to 'Enabled: Require startup PIN with TPM'."
}

# Call the check function
Ensure-RequireTPMPINForBitLocker
# Function to check if TPM startup key is not allowed
function Ensure-TPMKeyNotAllowed {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
    $valueName = "UseTPMKey"

    # Retrieve the current value from the registry
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    # Define the expected value
    $expectedValue = 0

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "18.10.9.2.17 (BL) Ensure 'Require additional authentication at startup: Configure TPM startup key:' is set to 'Enabled: Do not allow startup key with TPM'."
}

# Call the check function
Ensure-TPMKeyNotAllowed
# Execute all checks
Ensure-AllowCustomSSPsAPs
Ensure-LSASSProtectedProcess
Ensure-DisallowUserInputCopy
Ensure-BlockAccountDetailsOnSignin
Ensure-DoNotDisplayNetworkSelectionUI
Ensure-DoNotEnumerateConnectedUsers
Ensure-EnumerateLocalUsers
Ensure-TurnOffAppNotificationsOnLockScreen
Ensure-TurnOffPicturePasswordSignIn
Ensure-RequirePasswordOnWakeOnBattery
Ensure-RequirePasswordOnWakePluggedIn
Ensure-SolicitedRemoteAssistance
Ensure-EnableRPCClientAuth
Ensure-RestrictUnauthenticatedRPCClients
Ensure-DisableMSDTInteractiveCommunication
Ensure-EnumerateAdminAccountsOnElevation
Ensure-TurnOffConsumerExperiences
Ensure-AllowWindowsInkWorkspace
Ensure-RequirePinForPairing
Ensure-AlwaysInstallWithElevatedPrivileges
Ensure-TurnOffPrintingOverHTTP
Ensure-TurnOffWindowsSpotlightOnSettings
Ensure-DoNotSuggestThirdPartyContentInSpotlight
Ensure-DoNotUseDiagnosticDataForTailoredExperiences
