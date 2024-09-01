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
# 2.2.19 (L1) Ensure 'Deny log on locally' includes 'Guests'
function Ensure-DenyLogOnLocally {
    # Define the policy name
    $policyName = "Deny log on locally"

    # Retrieve the current policy settings
    $policySettings = (Get-LocalGroupPolicy -PolicyName $policyName).UserRightsAssignment

    # Define the expected group
    $expectedGroup = "Guests"

    # Check if the expected group is in the policy settings
    $isConfigCorrect = $policySettings -contains $expectedGroup

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.19 Deny log on locally includes 'Guests'."
}

# Call the check function
Ensure-DenyLogOnLocally

# 2.2.21 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
function Ensure-TrustedForDelegation {
    # Define the policy name
    $policyName = "Enable computer and user accounts to be trusted for delegation"

    # Retrieve the current policy settings
    $policySettings = Get-LocalGroupPolicy -PolicyName $policyName

    # Define the expected state
    $expectedState = "No One"

    # Check if the current state matches the expected state
    $isConfigCorrect = ($policySettings -eq $expectedState)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.21 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'."
}

# Call the check function
Ensure-TrustedForDelegation

# 2.2.21 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
function Ensure-TrustedForDelegation {
    # Define the policy name
    $policyName = "Enable computer and user accounts to be trusted for delegation"

    # Retrieve the current policy settings
    $policySettings = Get-LocalGroupPolicy -PolicyName $policyName

    # Define the expected state
    $expectedState = "No One"

    # Check if the current state matches the expected state
    $isConfigCorrect = ($policySettings -eq $expectedState)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.21 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'."
}

# Call the check function
Ensure-TrustedForDelegation

# 2.2.22 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
function Ensure-ForceShutdownFromRemoteSystem {
    # Define the policy name
    $policyName = "Force shutdown from a remote system"

    # Retrieve the current policy settings
    $policySettings = Get-LocalGroupPolicy -PolicyName $policyName

    # Define the expected state
    $expectedState = "Administrators"

    # Check if the current state matches the expected state
    $isConfigCorrect = ($policySettings -eq $expectedState)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.22 'Force shutdown from a remote system' is set to 'Administrators'."
}

# Call the check function
Ensure-ForceShutdownFromRemoteSystem

# 2.2.23 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
function Ensure-GenerateSecurityAudits {
    # Define the policy name
    $policyName = "Generate security audits"

    # Retrieve the current policy settings
    $policySettings = Get-LocalGroupPolicy -PolicyName $policyName

    # Define the expected state
    $expectedState = @("LOCAL SERVICE", "NETWORK SERVICE")

    # Check if the current state matches the expected state
    $isConfigCorrect = $expectedState -eq $policySettings

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.23 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'."
}

# Call the check function
Ensure-GenerateSecurityAudits

# 2.2.24 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
function Ensure-ImpersonateClientAfterAuthentication {
    # Define the policy name
    $policyName = "Impersonate a client after authentication"

    # Retrieve the current policy settings
    $policySettings = Get-LocalUserRightsAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")

    # Check if the current state matches the expected state
    $isConfigCorrect = $expectedState -eq $policySettings

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.24 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'."
}

# Call the check function
Ensure-ImpersonateClientAfterAuthentication

# 2.2.25 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'
function Ensure-IncreaseSchedulingPriority {
    # Define the policy name
    $policyName = "Increase scheduling priority"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = @("Administrators", "Window Manager\Window Manager Group")

    # Check if the current state matches the expected state
    $isConfigCorrect = ($expectedState | ForEach-Object { $_ -in $policySettings }) -and ($policySettings | ForEach-Object { $_ -in $expectedState })

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.25 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'."
}

# Call the check function
Ensure-IncreaseSchedulingPriority

# 2.2.26 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
function Ensure-LoadAndUnloadDeviceDrivers {
    # Define the policy name
    $policyName = "Load and unload device drivers"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = @("Administrators")

    # Check if the current state matches the expected state
    $isConfigCorrect = ($expectedState | ForEach-Object { $_ -in $policySettings }) -and ($policySettings | ForEach-Object { $_ -in $expectedState })

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.26 'Load and unload device drivers' is set to 'Administrators'."
}

# Call the check function
Ensure-LoadAndUnloadDeviceDrivers

# 2.2.27 (L1) Ensure 'Lock pages in memory' is set to 'No One'
function Ensure-LockPagesInMemory {
    # Define the policy name
    $policyName = "Lock pages in memory"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = @("No One")

    # Check if the current state matches the expected state
    $isConfigCorrect = ($expectedState | ForEach-Object { $_ -in $policySettings }) -and ($policySettings | ForEach-Object { $_ -in $expectedState })

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.27 'Lock pages in memory' is set to 'No One'."
}

# Call the check function
Ensure-LockPagesInMemory

# 2.2.28 (L2) Ensure 'Log on as a batch job' is set to 'Administrators'
function Ensure-LogOnAsBatchJob {
    # Define the policy name
    $policyName = "Log on as a batch job"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = @("Administrators")

    # Check if the current state matches the expected state
    $isConfigCorrect = ($expectedState | ForEach-Object { $_ -in $policySettings }) -and ($policySettings | ForEach-Object { $_ -in $expectedState })

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.28 'Log on as a batch job' is set to 'Administrators'."
}

# Call the check function
Ensure-LogOnAsBatchJob

# 2.2.29 (L2) Configure 'Log on as a service'
function Ensure-LogOnAsService {
    # Define the policy name
    $policyName = "Log on as a service"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected states
    $expectedStates = @("NT VIRTUAL MACHINE\Virtual Machines", "WDAGUtilityAccount")

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = ($expectedStates -contains $policySettings -or $policySettings.Count -eq 0)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.29 'Log on as a service' is configured as recommended."
}

# Call the check function
Ensure-LogOnAsService

# 2.2.30 (L1) Ensure 'Manage auditing and security log'
function Ensure-ManageAuditingAndSecurityLog {
    # Define the policy name
    $policyName = "Manage auditing and security log"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = "Administrators"

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = ($policySettings -contains $expectedState)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.30 'Manage auditing and security log' is configured as recommended."
}

# Call the check function
Ensure-ManageAuditingAndSecurityLog

# 2.2.31 (L1) Ensure 'Modify an object label'
function Ensure-ModifyObjectLabel {
    # Define the policy name
    $policyName = "Modify an object label"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = "No One"

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = ($policySettings -contains $expectedState)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.31 'Modify an object label' is configured as recommended."
}

# Call the check function
Ensure-ModifyObjectLabel

# 2.2.32 (L1) Ensure 'Modify firmware environment values'
function Ensure-ModifyFirmwareEnvironmentValues {
    # Define the policy name
    $policyName = "Modify firmware environment values"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = "Administrators"

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = ($policySettings -contains $expectedState)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.32 'Modify firmware environment values' is configured as recommended."
}

# Call the check function
Ensure-ModifyFirmwareEnvironmentValues

# 2.2.33 (L1) Ensure 'Perform volume maintenance tasks'
function Ensure-PerformVolumeMaintenanceTasks {
    # Define the policy name
    $policyName = "Perform volume maintenance tasks"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = "Administrators"

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = ($policySettings -contains $expectedState)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.33 'Perform volume maintenance tasks' is configured as recommended."
}

# Call the check function
Ensure-PerformVolumeMaintenanceTasks

# 2.2.34 (L1) Ensure 'Profile single process'
function Ensure-ProfileSingleProcess {
    # Define the policy name
    $policyName = "Profile single process"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = "Administrators"

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = ($policySettings -contains $expectedState)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.34 'Profile single process' is configured as recommended."
}

# Call the check function
Ensure-ProfileSingleProcess

# 2.2.35 (L1) Ensure 'Profile system performance'
function Ensure-ProfileSystemPerformance {
    # Define the policy name
    $policyName = "Profile system performance"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedStates = @("Administrators", "NT SERVICE\WdiServiceHost")

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = $expectedStates | ForEach-Object { $policySettings -contains $_ } -and ($expectedStates.Count -eq $policySettings.Count)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.35 'Profile system performance' is configured as recommended."
}

# Call the check function
Ensure-ProfileSystemPerformance

# 2.2.36 (L1) Ensure 'Replace a process level token'
function Ensure-ReplaceProcessLevelToken {
    # Define the policy name
    $policyName = "Replace a process level token"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedStates = @("LOCAL SERVICE", "NETWORK SERVICE")

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = $expectedStates | ForEach-Object { $policySettings -contains $_ } -and ($expectedStates.Count -eq $policySettings.Count)

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.36 'Replace a process level token' is configured as recommended."
}

# Call the check function
Ensure-ReplaceProcessLevelToken

# 2.2.37 (L1) Ensure 'Restore files and directories'
function Ensure-RestoreFilesAndDirectories {
    # Define the policy name
    $policyName = "Restore files and directories"

    # Retrieve the current policy settings
    $policySettings = Get-UserRightAssignment -PolicyName $policyName

    # Define the expected state
    $expectedState = "Administrators"

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = $policySettings -contains $expectedState

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.37 'Restore files and directories' is configured as recommended."
}

# Call the check function
Ensure-RestoreFilesAndDirectories


# 2.2.39 (L1) Ensure 'Take ownership of files or other objects'
function Ensure-TakeOwnership {
    # Define the policy name
    $policyName = "Take ownership of files or other objects"

    # Retrieve the current policy settings
    $policySettings = Get-PolicySetting -PolicyName $policyName

    # Define the expected state
    $expectedState = "Administrators"

    # Determine if the policy state matches the expected configuration
    $isConfigCorrect = $expectedState -in $policySettings

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.39 'Take ownership of files or other objects' is configured as recommended."
}

# 2.3.1.1 (L1) Ensure 'Accounts: Block Microsoft accounts'
function Ensure-BlockMicrosoftAccounts {
    # Define the registry path and value name
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "NoConnectedUser"
    $expectedValue = 3

    # Check the registry setting
    $isConfigCorrect = Check-RegistrySetting -RegistryPath $registryPath -ValueName $valueName -ExpectedValue $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.3.1.1 'Accounts: Block Microsoft accounts' is configured as recommended."
}

# Call the check function
Ensure-BlockMicrosoftAccounts


# Function to check if the Guest account is disabled
function Check-GuestAccountStatus {
    # Define the Guest account name
    $guestAccountName = "Guest"

    # Get the guest account status
    $guestAccount = Get-LocalUser -Name $guestAccountName -ErrorAction SilentlyContinue

    # Check if the account is disabled
    return $guestAccount -and $guestAccount.Enabled -eq $false
}

# 2.3.1.2 (L1) Ensure 'Accounts: Guest account status'
function Ensure-GuestAccountStatus {
    # Check the guest account status
    $isAccountDisabled = Check-GuestAccountStatus

    # Output result
    Handle-Output -Condition $isAccountDisabled -Message "2.3.1.2 'Accounts: Guest account status' is set to Disabled."
}

# Call the check function
Ensure-GuestAccountStatus

# Function to check the 'Limit local account use of blank passwords to console logon only' policy
function Check-LimitBlankPasswordUse {
    # Define the registry path and value
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $regName = "LimitBlankPasswordUse"

    # Get the registry value
    $regValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue

    # Check if the value is set to 1
    return $regValue -and $regValue.LimitBlankPasswordUse -eq 1
}

# 2.3.1.3 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only'
function Ensure-LimitBlankPasswordUse {
    # Check the policy setting
    $isPolicyEnabled = Check-LimitBlankPasswordUse

    # Output result
    Handle-Output -Condition $isPolicyEnabled -Message "2.3.1.3 'Accounts: Limit local account use of blank passwords to console logon only' is set to Enabled."
}

# Call the check function
Ensure-LimitBlankPasswordUse

# Function to check the 'Rename administrator account' policy
function Check-RenameAdministratorAccount {
    # Define the default administrator name
    $defaultAdminName = "Administrator"

    # Get the local user account with the name 'Administrator'
    $adminAccount = Get-LocalUser -Name $defaultAdminName -ErrorAction SilentlyContinue

    # Check if the default admin account exists
    if ($adminAccount) {
        return $false
    } else {
        return $true
    }
}

# 2.3.1.4 (L1) Ensure 'Accounts: Rename administrator account'
function Ensure-RenameAdministratorAccount {
    # Check if the administrator account has been renamed
    $isAccountRenamed = Check-RenameAdministratorAccount

    # Output result
    Handle-Output -Condition $isAccountRenamed -Message "2.3.1.4 'Accounts: Rename administrator account' is configured properly."
}

# Call the check function
Ensure-RenameAdministratorAccount

# Function to check the 'Rename guest account' policy
function Check-RenameGuestAccount {
    # Define the default guest account name
    $defaultGuestName = "Guest"

    # Get the local user account with the name 'Guest'
    $guestAccount = Get-LocalUser -Name $defaultGuestName -ErrorAction SilentlyContinue

    # Check if the default guest account exists
    if ($guestAccount) {
        return $false
    } else {
        return $true
    }
}

# 2.3.1.5 (L1) Ensure 'Accounts: Rename guest account'
function Ensure-RenameGuestAccount {
    # Check if the guest account has been renamed
    $isAccountRenamed = Check-RenameGuestAccount

    # Output result
    Handle-Output -Condition $isAccountRenamed -Message "2.3.1.5 'Accounts: Rename guest account' is configured properly."
}

# Call the check function
Ensure-RenameGuestAccount

# Function to check the 'Audit: Force audit policy subcategory settings' policy
function Check-ForceAuditPolicySubcategorySettings {
    # Define the registry path and value
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $regName = "SCENoApplyLegacyAuditPolicy"
    
    # Check if the registry key exists and its value
    if (Test-Path $regPath) {
        $regValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        if ($regValue -and $regValue.$regName -eq 1) {
            return $true
        }
    }
    return $false
}

# 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings'
function Ensure-ForceAuditPolicySubcategorySettings {
    # Check if the policy is configured to Enabled
    $isPolicyEnabled = Check-ForceAuditPolicySubcategorySettings

    # Output result
    Handle-Output -Condition $isPolicyEnabled -Message "2.3.2.1 'Audit: Force audit policy subcategory settings' is configured properly."
}

# Call the check function
Ensure-ForceAuditPolicySubcategorySettings

# Function to check the 'Audit: Shut down system immediately if unable to log security audits' policy
function Check-AuditShutDownSystem {
    # Define the registry path and value
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $regName = "CrashOnAuditFail"
    
    # Check if the registry key exists and its value
    if (Test-Path $regPath) {
        $regValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        if ($regValue -and $regValue.$regName -eq 0) {
            return $true
        }
    }
    return $false
}

# 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits'
function Ensure-AuditShutDownSystem {
    # Check if the policy is configured to Disabled
    $isPolicyDisabled = Check-AuditShutDownSystem

    # Output result
    Handle-Output -Condition $isPolicyDisabled -Message "2.3.2.2 'Audit: Shut down system immediately if unable to log security audits' is configured properly."
}

# Call the check function
Ensure-AuditShutDownSystem

# Function to check the 'Devices: Prevent users from installing printer drivers' policy
function Check-PreventPrinterDriverInstallation {
    # Define the registry path and value
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
    $regName = "AddPrinterDrivers"
    
    # Check if the registry key exists and its value
    if (Test-Path $regPath) {
        $regValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        if ($regValue -and $regValue.$regName -eq 1) {
            return $true
        }
    }
    return $false
}

# 2.3.4.1 (L2) Ensure 'Devices: Prevent users from installing printer drivers'
function Ensure-PreventPrinterDriverInstallation {
    # Check if the policy is configured to Enabled
    $isPolicyEnabled = Check-PreventPrinterDriverInstallation

    # Output result
    Handle-Output -Condition $isPolicyEnabled -Message "2.3.4.1 'Devices: Prevent users from installing printer drivers' is configured properly."
}

# Call the check function
Ensure-PreventPrinterDriverInstallation
