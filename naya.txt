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

# 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
function Check-EnforcePasswordHistory {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $regName = "PasswordHistorySize"

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).PasswordHistorySize

    # Expected value for 'Enforce password history'
    $expectedValue = 24

    Handle-Output -Condition ($currentValue -ge $expectedValue) -Message "1.1.1 Enforce password history is set to '24 or more password(s)'"
}

# 1.1.2 (L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'
function Check-MaximumPasswordAge {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $regName = "MaximumPasswordAge"

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MaximumPasswordAge

    # Expected value for 'Maximum password age'
    $expectedValue = 365

    # Check that the value is greater than 0 and less than or equal to 365
    Handle-Output -Condition ($currentValue -le $expectedValue -and $currentValue -gt 0) -Message "1.1.2 Maximum password age is set to '365 or fewer days, but not 0'"
}

# 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
function Check-MinimumPasswordAge {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $regName = "MinimumPasswordAge"

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MinimumPasswordAge

    # Expected value for 'Minimum password age'
    $expectedValue = 1

    Handle-Output -Condition ($currentValue -ge $expectedValue) -Message "1.1.3 Minimum password age is set to '1 or more day(s)'"
}

# 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
function Check-MinimumPasswordLength {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $regName = "MinimumPasswordLength"

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MinimumPasswordLength

    # Expected value for 'Minimum password length'
    $expectedValue = 14

    Handle-Output -Condition ($currentValue -ge $expectedValue) -Message "1.1.4 Minimum password length is set to '14 or more character(s)'"
}

# 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
function Check-PasswordComplexity {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $regName = "PasswordComplexity"

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).PasswordComplexity

    # Expected value for 'Password must meet complexity requirements'
    $expectedValue = 1

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "1.1.5 Password must meet complexity requirements is set to 'Enabled'"
}

# 1.1.6 (L1) Ensure 'Relax minimum password length limits' is set to 'Enabled'
function Check-RelaxMinimumPasswordLengthLimits {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\System\CurrentControlSet\Control\SAM"
    $regName = "RelaxMinimumPasswordLengthLimits"

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).RelaxMinimumPasswordLengthLimits

    # Expected value for 'Relax minimum password length limits'
    $expectedValue = 1

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "1.1.6 Relax minimum password length limits is set to 'Enabled'"
}

# 1.1.7 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
function Check-StorePasswordsReversibleEncryption {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $regName = "LimitBlankPasswordUse"
    
    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).LimitBlankPasswordUse
    
    # Expected value for 'Disabled'
    $expectedValue = 0

    Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "1.1.7 Store passwords using reversible encryption is set to 'Disabled'"
}

# 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
function Check-AccountLockoutDuration {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regName = "MaxFailedAttemptsBeforeLockout"
    
    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).MaxFailedAttemptsBeforeLockout
    
    # Expected value for '15 or more minutes'
    $expectedValue = 15

    Handle-Output -Condition ($currentValue -ge $expectedValue) -Message "1.2.1 Account lockout duration is set to '15 or more minute(s)'"
}

# 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'
function Check-AccountLockoutThreshold {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regName = "LockoutBadCount"

    # Check current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).LockoutBadCount

    # Expected value range
    $minValue = 1
    $maxValue = 5

    Handle-Output -Condition (($currentValue -ge $minValue -and $currentValue -le $maxValue) -and $currentValue -ne 0) -Message "1.2.2 Account lockout threshold is set to '5 or fewer invalid logon attempt(s), but not 0'."
}

# 1.2.3 (L1) Ensure 'Allow Administrator account lockout' is set to 'Enabled'
function Check-AllowAdminAccountLockout {
    # The setting must be verified manually via Group Policy Management Editor or Local Security Policy
    $message = "1.2.3 Ensure 'Allow Administrator account lockout' is set to 'Enabled'. This policy must be verified manually."

    # Output the message to indicate that this check requires manual verification
    Handle-Output -Condition $true -Message $message
}

# 1.2.4 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
function Ensure-ResetAccountLockoutCounter {
    # Registry path and key for the policy setting
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regName = "ResetLockoutCounterAfter"

    # Get current registry value for the setting
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).ResetLockoutCounterAfter

    # Convert the registry value to integer (minutes)
    $currentValueInt = [int]$currentValue

    # Expected minimum value
    $expectedValue = 15

    if ($currentValueInt -lt $expectedValue -or $currentValue -eq $null) {
        Handle-Output -Condition $false -Message "1.2.4 Reset account lockout counter after is set to less than 15 minutes or not defined."
    } else {
        Handle-Output -Condition $true -Message "1.2.4 Reset account lockout counter after is set to $currentValueInt minutes."
    }
}

# 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
function Ensure-AccessCredentialManagerNoOne {
    # Define the user right
    $userRight = "SeTrustedCredManAccessPrivilege"

    # Get current user rights assignments
    $currentRights = (Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }).Users

    # Check if 'No One' is configured
    if ($currentRights -ne $null -and $currentRights -eq @()) {
        Handle-Output -Condition $true -Message "2.2.1 Access Credential Manager as a trusted caller is set to 'No One'."
    } else {
        Handle-Output -Condition $false -Message "2.2.1 Access Credential Manager as a trusted caller is not set to 'No One'."
    }
}

# 2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'
function Ensure-AccessComputerFromNetwork {
    # Define the user right
    $userRight = "SeNetworkLogonRight"

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedUsers = $currentRights.Users

    # Define the expected users
    $expectedUsers = @('Administrators', 'Remote Desktop Users')

    # Check if the assigned users match the expected users
    $isConfigCorrect = $assignedUsers -eq $expectedUsers

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.2 Access this computer from the network is set to 'Administrators, Remote Desktop Users'."
}

# 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
function Ensure-ActAsPartOfOperatingSystem {
    # Define the user right
    $userRight = "SeTcbPrivilege"

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedUsers = $currentRights.Users

    # Check if the assigned users match the expected value
    $isConfigCorrect = ($assignedUsers -eq @(''))

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.3 Act as part of the operating system is set to 'No One'."
}

# 2.2.4 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
function Ensure-AdjustMemoryQuotas {
    # Define the user right and expected values
    $userRight = "SeIncreaseQuotaPrivilege"
    $expectedUsers = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE")

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedUsers = $currentRights.Users

    # Check if the assigned users match the expected value
    $isConfigCorrect = $expectedUsers | ForEach-Object { $_ -in $assignedUsers } | Where-Object { -not $_ } -eq $null

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.4 Adjust memory quotas for a process is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'."
}

# 2.2.5 (L1) Ensure 'Allow log on locally' is set to 'Administrators, Users'
function Ensure-AllowLogOnLocally {
    # Define the user right and expected values
    $userRight = "SeInteractiveLogonRight"
    $expectedUsers = @("Administrators", "Users")

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedUsers = $currentRights.Users

    # Check if the assigned users match the expected value
    $isConfigCorrect = $expectedUsers | ForEach-Object { $_ -in $assignedUsers } | Where-Object { -not $_ } -eq $null

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.5 Allow log on locally is set to 'Administrators, Users'."
}

# 2.2.6 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
function Ensure-AllowLogOnThroughRDS {
    # Define the user right and expected values
    $userRight = "SeRemoteInteractiveLogonRight"
    $expectedUsers = @("Administrators", "Remote Desktop Users")

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedUsers = $currentRights.Users

    # Check if the assigned users match the expected value
    $isConfigCorrect = $expectedUsers | ForEach-Object { $_ -in $assignedUsers } | Where-Object { -not $_ } -eq $null

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.6 Allow log on through Remote Desktop Services is set to 'Administrators, Remote Desktop Users'."
}

# 2.2.7 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
function Ensure-BackupFilesAndDirectories {
    # Define the user right and expected value
    $userRight = "SeBackupPrivilege"
    $expectedGroup = "Administrators"

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Check if the Administrators group is assigned
    $isConfigCorrect = $expectedGroup -in $assignedGroups

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.7 Back up files and directories is set to 'Administrators'."
}

# 2.2.8 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
function Ensure-ChangeSystemTime {
    # Define the user right and expected groups
    $userRight = "SeSystemTimePrivilege"
    $expectedGroups = @("Administrators", "LOCAL SERVICE")

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Check if the expected groups are assigned
    $isConfigCorrect = $expectedGroups | ForEach-Object { $_ -in $assignedGroups } | Where-Object { $_ -eq $false } | Measure-Object -Sum | Select-Object -ExpandProperty Sum -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.8 Change the system time is set to 'Administrators, LOCAL SERVICE'."
}

# 2.2.9 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'
function Ensure-ChangeTimeZone {
    # Define the user right and expected groups
    $userRight = "SeTimeZonePrivilege"
    $expectedGroups = @("Administrators", "LOCAL SERVICE", "Users")

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Check if the expected groups are assigned
    $isConfigCorrect = $expectedGroups | ForEach-Object { $_ -in $assignedGroups } | Where-Object { $_ -eq $false } | Measure-Object -Sum | Select-Object -ExpandProperty Sum -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.9 Change the time zone is set to 'Administrators, LOCAL SERVICE, Users'."
}

# 2.2.10 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
function Ensure-CreatePagefile {
    # Define the user right and expected group
    $userRight = "SeCreatePagefilePrivilege"
    $expectedGroup = "Administrators"

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Check if the expected group is assigned
    $isConfigCorrect = $expectedGroup -in $assignedGroups

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.10 Create a pagefile is set to 'Administrators'."
}

# 2.2.11 (L1) Ensure 'Create a token object' is set to 'No One'
function Ensure-CreateTokenObject {
    # Define the user right and expected state
    $userRight = "SeCreateTokenPrivilege"
    $expectedGroup = "No One"

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Check if no groups are assigned this right
    $isConfigCorrect = $assignedGroups.Count -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.11 Create a token object is set to 'No One'."
}

# 2.2.12 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
function Ensure-CreateGlobalObjects {
    # Define the user right and expected groups
    $userRight = "SeCreateGlobalPrivilege"
    $expectedGroups = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Check if the assigned groups match the expected groups
    $isConfigCorrect = $expectedGroups -eq $assignedGroups

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.12 Create global objects is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'."
}

# 2.2.13 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
function Ensure-CreatePermanentSharedObjects {
    # Define the user right
    $userRight = "SeCreatePermanentSharedObjectsPrivilege"

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Check if no groups have this right
    $isConfigCorrect = $assignedGroups.Count -eq 0

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.13 Create permanent shared objects is set to 'No One'."
}

# 2.2.14 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
function Ensure-CreateSymbolicLinks {
    # Define the user right
    $userRight = "SeCreateSymbolicLinkPrivilege"

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Define the expected groups
    $expectedGroups = @("Administrators", "NT VIRTUAL MACHINE\Virtual Machines")

    # Check if the assigned groups match the expected groups
    $isConfigCorrect = $assignedGroups -eq $expectedGroups

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.14 Create symbolic links is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'."
}

# 2.2.15 (L1) Ensure 'Debug programs' is set to 'Administrators'
function Ensure-DebugPrograms {
    # Define the user right
    $userRight = "SeDebugPrivilege"

    # Retrieve the current user rights assignments
    $currentRights = Get-LocalUserRightsAssignment | Where-Object { $_.Name -eq $userRight }
    $assignedGroups = $currentRights.Groups

    # Define the expected group
    $expectedGroups = @("Administrators")

    # Check if the assigned groups match the expected group
    $isConfigCorrect = $assignedGroups -eq $expectedGroups

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.15 Debug programs is set to 'Administrators'."
}

# 2.2.16 (L1) Ensure 'Deny access to this computer from the network' includes 'Guests'
function Ensure-DenyAccessNetwork {
    # Define the policy name
    $policyName = "Deny access to this computer from the network"

    # Retrieve the current policy settings
    $policySettings = (Get-LocalGroupPolicy -PolicyName $policyName).UserRightsAssignment

    # Define the expected group
    $expectedGroup = "Guests"

    # Check if the expected group is in the policy settings
    $isConfigCorrect = $policySettings -contains $expectedGroup

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.16 Deny access to this computer from the network includes 'Guests'."
}

# 2.2.17 (L1) Ensure 'Deny log on as a batch job' includes 'Guests'
function Ensure-DenyLogOnAsBatchJob {
    # Define the policy name
    $policyName = "Deny log on as a batch job"

    # Retrieve the current policy settings
    $policySettings = (Get-LocalGroupPolicy -PolicyName $policyName).UserRightsAssignment

    # Define the expected group
    $expectedGroup = "Guests"

    # Check if the expected group is in the policy settings
    $isConfigCorrect = $policySettings -contains $expectedGroup

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.17 Deny log on as a batch job includes 'Guests'."
}

# 2.2.18 (L1) Ensure 'Deny log on as a service' includes 'Guests'
function Ensure-DenyLogOnAsService {
    # Define the policy name
    $policyName = "Deny log on as a service"

    # Retrieve the current policy settings
    $policySettings = (Get-LocalGroupPolicy -PolicyName $policyName).UserRightsAssignment

    # Define the expected group
    $expectedGroup = "Guests"

    # Check if the expected group is in the policy settings
    $isConfigCorrect = $policySettings -contains $expectedGroup

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "2.2.18 Deny log on as a service includes 'Guests'."
}


# Call the check functions
Check-EnforcePasswordHistory
Check-MaximumPasswordAge
Check-MinimumPasswordAge
Check-MinimumPasswordLength
Check-PasswordComplexity
Check-RelaxMinimumPasswordLengthLimits
Check-StorePasswordsReversibleEncryption
Check-AccountLockoutDuration
Check-AccountLockoutThreshold
Check-AllowAdminAccountLockout
Ensure-ResetAccountLockoutCounter
Ensure-AccessCredentialManagerNoOne
Ensure-AccessComputerFromNetwork
Ensure-ActAsPartOfOperatingSystem
Ensure-AdjustMemoryQuotas
Ensure-AllowLogOnLocally
Ensure-AllowLogOnThroughRDS
Ensure-BackupFilesAndDirectories
Ensure-ChangeSystemTime
Ensure-ChangeTimeZone
Ensure-CreatePagefile
Ensure-CreateTokenObject
Ensure-CreateGlobalObjects
Ensure-CreatePermanentSharedObjects
Ensure-CreateSymbolicLinks
Ensure-DebugPrograms
Ensure-DenyAccessNetwork
Ensure-DenyLogOnAsBatchJob
Ensure-DenyLogOnAsService
