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
# 2.2.37 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
function Ensure-RestoreFilesAndDirectories {
    # Define the policy name
    $policyName = "Restore files and directories"

    # Retrieve the current policy settings
    $policySettings = (Get-LocalGroupPolicy -PolicyName $policyName).UserRightsAssignment

    # Define the expected group
    $expectedGroup = "Administrators"

    # Check if the expected group is in the policy settings
    $isConfigCorrect = $policySettings -contains $expectedGroup

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.37 Restore files and directories is set to 'Administrators'."
}

# 2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators, Users'
function Ensure-ShutDownTheSystem {
    # Define the policy name
    $policyName = "Shut down the system"

    # Retrieve the current policy settings
    $policySettings = (Get-LocalGroupPolicy -PolicyName $policyName).UserRightsAssignment

    # Define the expected groups
    $expectedGroups = @("Administrators", "Users")

    # Check if all expected groups are in the policy settings
    $isConfigCorrect = $expectedGroups | ForEach-Object { $policySettings -contains $_ } -and $true

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.38 Shut down the system is set to 'Administrators, Users'."
}

# 2.2.39 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
function Ensure-TakeOwnershipOfFilesOrObjects {
    # Define the policy name
    $policyName = "Take ownership of files or other objects"

    # Retrieve the current policy settings
    $policySettings = (Get-LocalGroupPolicy -PolicyName $policyName).UserRightsAssignment

    # Define the expected group
    $expectedGroup = "Administrators"

    # Check if the expected group is in the policy settings
    $isConfigCorrect = $policySettings -contains $expectedGroup

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.39 Take ownership of files or other objects is set to 'Administrators'."
}

# 2.3.1.1 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
function Ensure-BlockMicrosoftAccounts {
    # Define the registry path and value name
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryValueName = "NoConnectedUser"

    # Retrieve the current registry value
    $registryValue = Get-ItemPropertyValue -Path $registryPath -Name $registryValueName

    # Define the expected value
    $expectedValue = 3

    # Check if the registry value matches the expected value
    $isConfigCorrect = $registryValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.1.1 Accounts: Block Microsoft accounts is set to 'Users can't add or log on with Microsoft accounts'."
}

# 2.3.1.2 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'
function Ensure-GuestAccountStatus {
    # Define the account name
    $accountName = "Guest"

    # Retrieve the current account status
    $accountStatus = Get-LocalUser -Name $accountName

    # Check if the account is disabled
    $isConfigCorrect = $accountStatus.Enabled -eq $false

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.1.2 Accounts: Guest account status is set to 'Disabled'."
}

# 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
function Ensure-ForceAuditPolicySubcategorySettingsOverride {
    # Define the registry path and value name
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryValueName = "SCENoApplyLegacyAuditPolicy"

    # Retrieve the current registry value
    $registryValue = Get-ItemPropertyValue -Path $registryPath -Name $registryValueName

    # Define the expected value
    $expectedValue = 1

    # Check if the registry value matches the expected value
    $isConfigCorrect = $registryValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.2.1 Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is set to 'Enabled'."
}
# 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
function Ensure-ShutDownIfUnableToLogSecurityAudits {
    # Define the registry path and value name
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryValueName = "CrashOnAuditFail"

    # Retrieve the current registry value
    $registryValue = Get-ItemPropertyValue -Path $registryPath -Name $registryValueName

    # Define the expected value
    $expectedValue = 0

    # Check if the registry value matches the expected value
    $isConfigCorrect = $registryValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.2.2 Audit: Shut down system immediately if unable to log security audits is set to 'Disabled'."
}

# 2.3.4.1 (L2) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
function Ensure-PreventUsersFromInstallingPrinterDrivers {
    # Define the registry path and value name
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
    $registryValueName = "AddPrinterDrivers"

    # Retrieve the current registry value
    $registryValue = Get-ItemPropertyValue -Path $registryPath -Name $registryValueName

    # Define the expected value
    $expectedValue = 1

    # Check if the registry value matches the expected value
    $isConfigCorrect = $registryValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.4.1 Devices: Prevent users from installing printer drivers is set to 'Enabled'."
}

# 2.3.7.1 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
function Ensure-DoNotRequireCTRLALTDEL {
    # Define the registry path and value
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $expectedValue = 0

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name "DisableCAD" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableCAD"

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.7.1 Interactive logon: Do not require CTRL+ALT+DEL is set to 'Disabled'."
}

# 2.3.7.2 (L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'
function Ensure-DoNotDisplayLastSignedIn {
    # Define the registry path and value
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $expectedValue = 1

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DontDisplayLastUserName"

    # Check if the current value matches the expected value
    $isConfigCorrect = ($currentValue -eq $expectedValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.7.2 Interactive logon: Don't display last signed-in is set to 'Enabled'."
}


# 2.3.7.3 (BL) Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'
function Ensure-MachineAccountLockoutThreshold {
    # Define the registry path and expected range
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryKey = "MaxDevicePasswordFailedAttempts"
    $minValue = 1
    $maxValue = 10

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is within the expected range
    $isConfigCorrect = ($currentValue -ge $minValue -and $currentValue -le $maxValue -and $currentValue -ne 0)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.7.3 Interactive logon: Machine account lockout threshold is set to '10 or fewer invalid logon attempts, but not 0'."
}

# 2.3.7.4 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
function Ensure-MachineInactivityLimit {
    # Define the registry path and expected range
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryKey = "InactivityTimeoutSecs"
    $minValue = 1
    $maxValue = 900

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is within the expected range
    $isConfigCorrect = ($currentValue -ge $minValue -and $currentValue -le $maxValue -and $currentValue -ne 0)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.7.4 Interactive logon: Machine inactivity limit is set to '900 or fewer second(s), but not 0'."
}

# 2.3.7.5 (L1) Configure 'Interactive logon: Message text for users attempting to log on'
function Ensure-MessageTextForLogon {
    # Define the registry path and key
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryKey = "LegalNoticeText"

    # Define the expected text message
    $expectedMessage = "This is a corporate computer. Unauthorized access is prohibited. All activities are monitored and logged."

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value matches the expected message
    $isConfigCorrect = $currentValue -eq $expectedMessage

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.7.5 Interactive logon: Message text for users attempting to log on is configured as expected."
}
# 2.3.7.6 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
function Ensure-MessageTitleForLogon {
    # Define the registry path and key
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryKey = "LegalNoticeCaption"

    # Define the expected title text
    $expectedTitle = "Unauthorized Access Prohibited"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value matches the expected title
    $isConfigCorrect = $currentValue -eq $expectedTitle

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.7.6 Interactive logon: Message title for users attempting to log on is configured as expected."
}

# 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
function Ensure-PasswordExpiryWarning {
    # Define the registry path and key
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $registryKey = "PasswordExpiryWarning"

    # Define the acceptable range for the warning period
    $minDays = 5
    $maxDays = 14

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is within the acceptable range
    $isConfigCorrect = $currentValue -ge $minDays -and $currentValue -le $maxDays

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.7.7 Interactive logon: Prompt user to change password before expiration is set to between 5 and 14 days."
}

# 2.3.7.8 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
function Ensure-SmartCardRemovalBehavior {
    # Define the registry path and key
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $registryKey = "ScRemoveOption"

    # Define acceptable values
    $acceptableValues = @("1", "2", "3")

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is within acceptable values
    $isConfigCorrect = $acceptableValues -contains $currentValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.7.8 Interactive logon: Smart card removal behavior is set to 'Lock Workstation' or higher."
}

# 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
function Ensure-MicrosoftNetworkClientDigitallySignCommunications {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $registryKey = "RequireSecuritySignature"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is set to '1' (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.8.1 Microsoft network client: Digitally sign communications (always) is set to 'Enabled'."
}

# 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
function Ensure-MicrosoftNetworkClientDigitallySignCommunicationsIfServerAgrees {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $registryKey = "EnableSecuritySignature"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is set to '1' (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.8.2 Microsoft network client: Digitally sign communications (if server agrees) is set to 'Enabled'."
}

# 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
function Ensure-MicrosoftNetworkClientSendUnencryptedPasswordToThirdPartySMBServers {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $registryKey = "EnablePlainTextPassword"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is set to '0' (Disabled)
    $isConfigCorrect = $currentValue -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.8.3 Microsoft network client: Send unencrypted password to third-party SMB servers is set to 'Disabled'."
}

# 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'
function Ensure-MicrosoftNetworkServerIdleTimeBeforeSuspendingSession {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    $registryKey = "AutoDisconnect"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 15 or less
    $isConfigCorrect = $currentValue -le 15

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.9.1 Microsoft network server: Amount of idle time required before suspending session is set to '15 or fewer minute(s)'."
}

# 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
function Ensure-MicrosoftNetworkServerDigitallySignCommunicationsAlways {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    $registryKey = "RequireSecuritySignature"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 1 (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.9.2 Microsoft network server: Digitally sign communications (always) is set to 'Enabled'."
}

# 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
function Ensure-MicrosoftNetworkServerDigitallySignCommunicationsIfClientAgrees {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    $registryKey = "EnableSecuritySignature"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 1 (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.9.3 Microsoft network server: Digitally sign communications (if client agrees) is set to 'Enabled'."
}

# 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
function Ensure-MicrosoftNetworkServerDisconnectClientsWhenLogonHoursExpire {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    $registryKey = "enableforcedlogoff"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 1 (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.9.4 Microsoft network server: Disconnect clients when logon hours expire is set to 'Enabled'."
}

# 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
function Ensure-MicrosoftNetworkServerSPNTargetNameValidationLevel {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    $registryKey = "SMBServerNameHardeningLevel"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 1 or higher
    $isConfigCorrect = $currentValue -ge 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.9.5 Microsoft network server: Server SPN target name validation level is set to 'Accept if provided by client' or higher."
}

# 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
function Ensure-NetworkAccessAllowAnonymousSIDNameTranslation {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "RestrictAnonymousSAM"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 1 (Disabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.1 Network access: Allow anonymous SID/Name translation is set to 'Disabled'."
}

# 2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
function Ensure-NetworkAccessNoAnonymousSAMEnumeration {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "RestrictAnonymousSAM"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 1 (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.2 Network access: Do not allow anonymous enumeration of SAM accounts is set to 'Enabled'."
}

# 2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
function Ensure-NetworkAccessNoAnonymousSAMAndSharesEnumeration {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "RestrictAnonymous"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 1 (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.3 Network access: Do not allow anonymous enumeration of SAM accounts and shares is set to 'Enabled'."
}

# 2.3.10.4 (L1) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
function Ensure-NetworkAccessNoStorageOfCredentials {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "DisableDomainCreds"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 1 (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.4 Network access: Do not allow storage of passwords and credentials for network authentication is set to 'Enabled'."
}

# 2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
function Ensure-NetworkAccessNoEveryonePermissionsForAnonymous {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "EveryoneIncludesAnonymous"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is 0 (Disabled)
    $isConfigCorrect = $currentValue -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.5 Network access: Let Everyone permissions apply to anonymous users is set to 'Disabled'."
}

# 2.3.10.6 (L1) Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'
function Ensure-NetworkAccessNoAnonymousNamedPipes {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    $registryKey = "NullSessionPipes"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the current value is empty (None)
    $isConfigCorrect = [string]::IsNullOrEmpty($currentValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.6 Network access: Named Pipes that can be accessed anonymously is set to 'None'."
}

# 2.3.10.7 (L1) Ensure 'Network access: Remotely accessible registry paths' is configured
function Ensure-NetworkAccessRemotelyAccessibleRegistryPaths {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
    $registryKey = "Machine"

    # Define the expected registry paths
    $expectedPaths = @(
        "System\CurrentControlSet\Control\ProductOptions",
        "System\CurrentControlSet\Control\Server Applications",
        "Software\Microsoft\Windows NT\CurrentVersion"
    )

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Convert the current value to an array of paths
    $currentPaths = $currentValue -split "`n"

    # Check if all expected paths are present in the current paths
    $isConfigCorrect = $expectedPaths | ForEach-Object { $_ -in $currentPaths } | Where-Object { -not $_ } | Measure-Object | Select-Object -ExpandProperty Count -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.7 Network access: Remotely accessible registry paths is configured as expected."
}

# 2.3.10.8 (L1) Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured
function Ensure-NetworkAccessRemotelyAccessibleRegistryPathsAndSubPaths {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
    $registryKey = "Machine"

    # Define the expected registry paths
    $expectedPaths = @(
        "System\CurrentControlSet\Control\Print\Printers",
        "System\CurrentControlSet\Services\Eventlog",
        "Software\Microsoft\OLAP Server",
        "Software\Microsoft\Windows NT\CurrentVersion\Print",
        "Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "System\CurrentControlSet\Control\ContentIndex",
        "System\CurrentControlSet\Control\Terminal Server",
        "System\CurrentControlSet\Control\Terminal Server\UserConfig",
        "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
        "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
        "System\CurrentControlSet\Services\SysmonLog"
    )

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Convert the current value to an array of paths
    $currentPaths = $currentValue -split "`n"

    # Check if all expected paths are present in the current paths
    $isConfigCorrect = $expectedPaths | ForEach-Object { $_ -in $currentPaths } | Where-Object { -not $_ } | Measure-Object | Select-Object -ExpandProperty Count -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.8 Network access: Remotely accessible registry paths and sub-paths is configured as expected."
}

# 2.3.10.9 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
function Ensure-NetworkAccessRestrictAnonymousAccess {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    $registryKey = "RestrictNullSessAccess"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the registry value is set to 1
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.9 Network access: Restrict anonymous access to Named Pipes and Shares is set to 'Enabled'."
}

# 2.3.10.10 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'
function Ensure-NetworkAccessRestrictRemoteSAM {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "restrictremotesam"
    $expectedValue = "O:BAG:BAD:(A;;RC;;;BA)" # Value for Administrators: Remote Access: Allow

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the registry value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.10 Network access: Restrict clients allowed to make remote calls to SAM is set to 'Administrators: Remote Access: Allow'."
}

# 2.3.10.11 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
function Ensure-NetworkAccessSharesAnonymous {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    $registryKey = "NullSessionShares"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the registry value is empty (i.e., None)
    $isConfigCorrect = [string]::IsNullOrEmpty($currentValue)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.11 Network access: Shares that can be accessed anonymously is set to 'None'."
}

# 2.3.10.12 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
function Ensure-NetworkAccessSharingModel {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "ForceGuest"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the registry value is set to 0 (Classic model)
    $isConfigCorrect = $currentValue -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.10.12 Network access: Sharing and security model for local accounts is set to 'Classic - local users authenticate as themselves'."
}

# 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
function Ensure-AllowLocalSystemIdentityForNTLM {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "UseMachineId"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the registry value is set to 1 (Enabled)
    $isConfigCorrect = $currentValue -eq 1

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.1 Network security: Allow Local System to use computer identity for NTLM is set to 'Enabled'."
}

# 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
function Ensure-AllowLocalSystemNullSessionFallback {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $registryKey = "AllowNullSessionFallback"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the registry value is set to 0 (Disabled)
    $isConfigCorrect = $currentValue -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.2 Network security: Allow LocalSystem NULL session fallback is set to 'Disabled'."
}

# 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
function Ensure-AllowPKU2UOnlineID {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
    $registryKey = "AllowOnlineID"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the registry value is set to 0 (Disabled)
    $isConfigCorrect = $currentValue -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.3 Network Security: Allow PKU2U authentication requests to this computer to use online identities is set to 'Disabled'."
}

# 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
function Ensure-KerberosEncryptionTypes {
    # Define the registry path and key
    $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $registryKey = "SupportedEncryptionTypes"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Define the expected registry value (2147483640 corresponds to AES128_HMAC_SHA1, AES256_HMAC_SHA1, and Future encryption types)
    $expectedValue = 2147483640

    # Check if the registry value is set to the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.4 Network Security: Configure encryption types allowed for Kerberos is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'."
}

# 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
function Ensure-NoLMHashStored {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "NoLMHash"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Define the expected registry value (1 corresponds to Enabled)
    $expectedValue = 1

    # Check if the registry value is set to the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.5 Network Security: Do not store LAN Manager hash value on next password change is set to 'Enabled'."
}

# 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
function Ensure-ForceLogoffWhenLogonHoursExpire {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "ForceLogoffWhenHoursExpire"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Define the expected registry value (1 corresponds to Enabled)
    $expectedValue = 1

    # Check if the registry value is set to the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.6 Network security: Force logoff when logon hours expire is set to 'Enabled'."
}

# 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
function Ensure-LANManagerAuthenticationLevel {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryKey = "LmCompatibilityLevel"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Define the expected registry value (5 corresponds to 'Send NTLMv2 response only. Refuse LM & NTLM')
    $expectedValue = 5

    # Check if the registry value is set to the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.7 Network security: LAN Manager authentication level is set to 'Send NTLMv2 response only. Refuse LM & NTLM'."
}

# 2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
function Ensure-LDAPClientSigningRequirements {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\LDAP"
    $registryKey = "LDAPClientIntegrity"

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Define the expected registry value (1 corresponds to 'Negotiate signing')
    $expectedValue = 1

    # Check if the registry value is set to the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.8 Network security: LDAP client signing requirements is set to 'Negotiate signing' or higher."
}

# 2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
function Ensure-NTLMMinClientSec {
    # Define the registry path and key
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $registryKey = "NTLMMinClientSec"

    # Define the expected registry value (537395200 corresponds to 'Require NTLMv2 session security, Require 128-bit encryption')
    $expectedValue = 537395200

    # Retrieve the current registry value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $registryKey

    # Check if the registry value is set to the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.9 Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
}

# Function to ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set correctly
function Ensure-MinimumSessionSecurityForNTLMSSPServers {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $registryValueName = "NTLMMinServerSec"
    $expectedValue = 537395200

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName).$registryValueName

    # Check if the current value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.10 Minimum session security for NTLM SSP based servers is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
}

# Function to ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set correctly
function Ensure-RestrictNTLMAuditIncomingTraffic {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $registryValueName = "AuditReceivingNTLMTraffic"
    $expectedValue = 2

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName).$registryValueName

    # Check if the current value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.11 Restrict NTLM: Audit Incoming NTLM Traffic is set to 'Enable auditing for all accounts'."
}

# Function to ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set correctly
function Ensure-RestrictNTLMOutgoingTraffic {
    # Define the registry path and expected values
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $registryValueName = "RestrictSendingNTLMTraffic"
    $expectedValues = @(1, 2)  # 1 for 'Audit all', 2 for 'Deny all'

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName).$registryValueName

    # Check if the current value matches any of the expected values
    $isConfigCorrect = $expectedValues -contains $currentValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.11.12 Restrict NTLM: Outgoing NTLM traffic to remote servers is set to 'Audit all' or higher."
}

# Function to ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set correctly
function Ensure-ForceStrongKeyProtection {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"
    $registryValueName = "ForceKeyProtection"
    $expectedValue = 1  # 'User is prompted when the key is first used' or higher

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

    # Check if the current value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.14.1 System cryptography: Force strong key protection for user keys stored on the computer is set to 'User is prompted when the key is first used' or higher."
}

# Function to ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set correctly
function Ensure-RequireCaseInsensitivity {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
    $registryValueName = "ObCaseInsensitive"
    $expectedValue = 1  # Enabled

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

    # Check if the current value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.15.1 System objects: Require case insensitivity for non-Windows subsystems is set to 'Enabled'."
}

# Function to ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set correctly
function Ensure-StrengthenDefaultPermissions {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $registryValueName = "ProtectionMode"
    $expectedValue = 1  # Enabled

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

    # Check if the current value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.15.2 System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links) is set to 'Enabled'."
}

# Function to ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set correctly
function Ensure-AdminApprovalModeForBuiltInAdmin {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryValueName = "FilterAdministratorToken"
    $expectedValue = 1  # Enabled

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

    # Check if the current value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.17.1 User Account Control: Admin Approval Mode for the Built-in Administrator account is set to 'Enabled'."
}

# Function to ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set correctly
function Ensure-ElevationPromptBehaviorForAdmins {
    # Define the registry path and expected values
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryValueName = "ConsentPromptBehaviorAdmin"
    $expectedValues = @(1, 2)  # Prompt for consent on the secure desktop (1) or Prompt for credentials on the secure desktop (2)

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

    # Check if the current value matches any of the expected values
    $isConfigCorrect = $expectedValues -contains $currentValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.17.2 User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to 'Prompt for consent on the secure desktop' or higher."
}


Ensure-ElevationPromptBehaviorForAdmins
Ensure-AdminApprovalModeForBuiltInAdmin
Ensure-StrengthenDefaultPermissions
Ensure-RequireCaseInsensitivity
Ensure-ForceStrongKeyProtection
Ensure-RestrictNTLMOutgoingTraffic
Ensure-RestrictNTLMAuditIncomingTraffic
Ensure-MinimumSessionSecurityForNTLMSSPServers
Ensure-NTLMMinClientSec
Ensure-LDAPClientSigningRequirements
Ensure-LANManagerAuthenticationLevel
Ensure-ForceLogoffWhenLogonHoursExpire
Ensure-NoLMHashStored
Ensure-KerberosEncryptionTypes
Ensure-AllowPKU2UOnlineID
Ensure-AllowLocalSystemNullSessionFallback
Ensure-AllowLocalSystemIdentityForNTLM
Ensure-NetworkAccessSharingModel
Ensure-NetworkAccessSharesAnonymous
Ensure-NetworkAccessRestrictRemoteSAM
Ensure-NetworkAccessRestrictAnonymousAccess
Ensure-NetworkAccessRemotelyAccessibleRegistryPathsAndSubPaths
Ensure-NetworkAccessRemotelyAccessibleRegistryPaths
Ensure-NetworkAccessNoAnonymousNamedPipes
Ensure-NetworkAccessNoEveryonePermissionsForAnonymous
Ensure-NetworkAccessNoAnonymousSAMAndSharesEnumeration
Ensure-NetworkAccessNoAnonymousSAMEnumeration
Ensure-NetworkAccessAllowAnonymousSIDNameTranslation
Ensure-MicrosoftNetworkServerSPNTargetNameValidationLevel
Ensure-MicrosoftNetworkServerDisconnectClientsWhenLogonHoursExpire
Ensure-MicrosoftNetworkServerDigitallySignCommunicationsIfClientAgrees
Ensure-MicrosoftNetworkServerDigitallySignCommunicationsAlways
Ensure-MicrosoftNetworkServerIdleTimeBeforeSuspendingSession
Ensure-MicrosoftNetworkClientSendUnencryptedPasswordToThirdPartySMBServer
Ensure-MicrosoftNetworkClientDigitallySignCommunicationsIfServerAgrees
Ensure-MicrosoftNetworkClientDigitallySignCommunications
Ensure-SmartCardRemovalBehaviorEnsure-PasswordExpiryWarning
Ensure-MessageTitleForLogon
Ensure-MessageTextForLogon
Ensure-MachineInactivityLimit
Ensure-MachineAccountLockoutThreshold
Ensure-DoNotDisplayLastSignedIn
Ensure-PreventUsersFromInstallingPrinterDrivers
Ensure-ShutDownIfUnableToLogSecurityAudits
Ensure-ForceAuditPolicySubcategorySettingsOverride
Ensure-RestoreFilesAndDirectories
Ensure-ShutDownTheSystem
Ensure-TakeOwnershipOfFilesOrObjects
Ensure-BlockMicrosoftAccounts
Ensure-GuestAccountStatus
Ensure-DoNotRequireCTRLALTDEL
