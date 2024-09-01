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

# 9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
function Check-WindowsFirewallDomainProfileState {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $regName = "EnableFirewall"
    $expectedValue = 1

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnableFirewall
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "9.1.1 Windows Firewall: Domain: Firewall state is set to 'On (recommended)'."
    } catch {
        Handle-Output -Condition $false -Message "9.1.1 Error occurred while checking Windows Firewall: Domain: Firewall state: $_"
    }
}

# 9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
function Check-WindowsFirewallDomainInboundConnections {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $regName = "DefaultInboundAction"
    $expectedValue = 1

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DefaultInboundAction
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "9.1.2 Windows Firewall: Domain: Inbound connections is set to 'Block (default)'."
    } catch {
        Handle-Output -Condition $false -Message "9.1.2 Error occurred while checking Windows Firewall: Domain: Inbound connections: $_"
    }
}

# 9.1.3 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
function Check-WindowsFirewallDomainDisplayNotification {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $regName = "DisableNotifications"
    $expectedValue = 1

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableNotifications
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "9.1.3 Windows Firewall: Domain: Settings: Display a notification is set to 'No'."
    } catch {
        Handle-Output -Condition $false -Message "9.1.3 Error occurred while checking Windows Firewall: Domain: Settings: Display a notification: $_"
    }
}

# 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'
function Check-WindowsFirewallDomainLoggingName {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $regName = "LogFilePath"
    $expectedValue = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogFilePath
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "9.1.4 Windows Firewall: Domain: Logging: Name is set to '$expectedValue'."
    } catch {
        Handle-Output -Condition $false -Message "9.1.4 Error occurred while checking Windows Firewall: Domain: Logging: Name: $_"
    }
}

# 9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
function Check-WindowsFirewallDomainLoggingSizeLimit {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $regName = "LogFileSize"
    $expectedValue = 16384

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogFileSize
        Handle-Output -Condition ($currentValue -ge $expectedValue) -Message "9.1.5 Windows Firewall: Domain: Logging: Size limit (KB) is set to '16,384 KB or greater'."
    } catch {
        Handle-Output -Condition $false -Message "9.1.5 Error occurred while checking Windows Firewall: Domain: Logging: Size limit (KB): $_"
    }
}

# 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
function Check-WindowsFirewallDomainLoggingDroppedPackets {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $regName = "LogDroppedPackets"
    $expectedValue = 1

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogDroppedPackets
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "9.1.6 Windows Firewall: Domain: Logging: Log dropped packets is set to 'Yes'."
    } catch {
        Handle-Output -Condition $false -Message "9.1.6 Error occurred while checking Windows Firewall: Domain: Logging: Log dropped packets: $_"
    }
}

# 9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
function Check-WindowsFirewallDomainLoggingSuccessfulConnections {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $regName = "LogSuccessfulConnections"
    $expectedValue = 1

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogSuccessfulConnections
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "9.1.7 Windows Firewall: Domain: Logging: Log successful connections is set to 'Yes'."
    } catch {
        Handle-Output -Condition $false -Message "9.1.7 Error occurred while checking Windows Firewall: Domain: Logging: Log successful connections: $_"
    }
}


# 9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
function Check-WindowsFirewallPrivateProfileState {
    # Registry path and key for the Windows Firewall private profile state
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $regName = "EnableFirewall"

    # Expected value for 'On (recommended)' is 1
    $expectedValue = 1

    try {
        # Check current firewall state for the private profile
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnableFirewall

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.2.1 Windows Firewall: Private: Firewall state is set to 'On (recommended)'."
        } else {
            Handle-Output -Condition $false -Message "9.2.1 Windows Firewall: Private: Firewall state is not set to 'On (recommended)'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.2.1 Error occurred while checking Windows Firewall: Private: Firewall state: $_"
    }
}

# 9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
function Check-WindowsFirewallPrivateProfileInboundConnections {
    # Registry path and key for the Windows Firewall private profile inbound connections
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $regName = "DefaultInboundAction"

    # Expected value for 'Block (default)' is 1
    $expectedValue = 1

    try {
        # Check current inbound connections setting for the private profile
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DefaultInboundAction

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.2.2 Windows Firewall: Private: Inbound connections are set to 'Block (default)'."
        } else {
            Handle-Output -Condition $false -Message "9.2.2 Windows Firewall: Private: Inbound connections are not set to 'Block (default)'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.2.2 Error occurred while checking Windows Firewall: Private: Inbound connections: $_"
    }
}

# 9.2.3 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
function Check-WindowsFirewallPrivateProfileNotification {
    # Registry path and key for the Windows Firewall private profile notification settings
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $regName = "DisableNotifications"

    # Expected value for 'No' is 1
    $expectedValue = 1

    try {
        # Check current notification setting for the private profile
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableNotifications

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.2.3 Windows Firewall: Private: Settings: Display a notification is set to 'No'."
        } else {
            Handle-Output -Condition $false -Message "9.2.3 Windows Firewall: Private: Settings: Display a notification is not set to 'No'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.2.3 Error occurred while checking Windows Firewall: Private: Settings: Display a notification: $_"
    }
}

# 9.2.4 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'
function Check-WindowsFirewallPrivateProfileLogFilePath {
    # Registry path and key for the Windows Firewall private profile logging file path
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $regName = "LogFilePath"

    # Expected value for the log file path
    $expectedValue = "$env:SystemRoot\System32\logfiles\firewall\privatefw.log"

    try {
        # Check current log file path setting for the private profile
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogFilePath

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.2.4 Windows Firewall: Private: Logging: Name is set to '$expectedValue'."
        } else {
            Handle-Output -Condition $false -Message "9.2.4 Windows Firewall: Private: Logging: Name is not set to '$expectedValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.2.4 Error occurred while checking Windows Firewall: Private: Logging: Name: $_"
    }
}

# 9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
function Check-WindowsFirewallPrivateProfileLogSizeLimit {
    # Registry path and key for the log file size limit
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $regName = "LogFileSize"

    # Expected value for 16,384 KB
    $expectedValue = 16384

    try {
        # Check current log file size limit
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogFileSize

        if ($currentValue -ge $expectedValue) {
            Handle-Output -Condition $true -Message "9.2.5 Windows Firewall Private Profile Log Size Limit is set to '$currentValue' KB or greater."
        } else {
            Handle-Output -Condition $false -Message "9.2.5 Windows Firewall Private Profile Log Size Limit is set to '$currentValue' KB, which is less than the recommended '16,384' KB."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.2.5 Error occurred while checking Windows Firewall Private Profile Log Size Limit: $_"
    }
}

# 9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
function Check-WindowsFirewallPrivateProfileLogDroppedPackets {
    # Registry path and key for logging dropped packets
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $regName = "LogDroppedPackets"

    # Expected value for 'Yes' is 1
    $expectedValue = 1

    try {
        # Check current log dropped packets setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogDroppedPackets

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.2.6 Windows Firewall Private Profile Logging for Dropped Packets is set to 'Yes'."
        } else {
            Handle-Output -Condition $false -Message "9.2.6 Windows Firewall Private Profile Logging for Dropped Packets is not set to 'Yes'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.2.6 Error occurred while checking Windows Firewall Private Profile Logging for Dropped Packets: $_"
    }
}

# 9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
function Check-WindowsFirewallPrivateProfileLogSuccessfulConnections {
    # Registry path and key for logging successful connections
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $regName = "LogSuccessfulConnections"

    # Expected value for 'Yes' is 1
    $expectedValue = 1

    try {
        # Check current log successful connections setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogSuccessfulConnections

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.2.7 Windows Firewall Private Profile Logging for Successful Connections is set to 'Yes'."
        } else {
            Handle-Output -Condition $false -Message "9.2.7 Windows Firewall Private Profile Logging for Successful Connections is not set to 'Yes'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.2.7 Error occurred while checking Windows Firewall Private Profile Logging for Successful Connections: $_"
    }
}


# 9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
function Check-WindowsFirewallPublicProfileFirewallState {
    # Registry path and key for firewall state
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $regName = "EnableFirewall"

    # Expected value for 'On (recommended)' is 1
    $expectedValue = 1

    try {
        # Check current firewall state
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).EnableFirewall

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.1 Windows Firewall Public Profile Firewall State is set to 'On (recommended)'."
        } else {
            Handle-Output -Condition $false -Message "9.3.1 Windows Firewall Public Profile Firewall State is not set to 'On (recommended)'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.1 Error occurred while checking Windows Firewall Public Profile Firewall State: $_"
    }
}

# 9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
function Check-WindowsFirewallPublicProfileInboundConnections {
    # Registry path and key for inbound connections
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $regName = "DefaultInboundAction"

    # Expected value for 'Block (default)' is 1
    $expectedValue = 1

    try {
        # Check current inbound connections setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DefaultInboundAction

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.2 Windows Firewall Public Profile Inbound Connections are set to 'Block (default)'."
        } else {
            Handle-Output -Condition $false -Message "9.3.2 Windows Firewall Public Profile Inbound Connections are not set to 'Block (default)'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.2 Error occurred while checking Windows Firewall Public Profile Inbound Connections: $_"
    }
}

# 9.3.3 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
function Check-WindowsFirewallPublicProfileDisplayNotification {
    # Registry path and key for display notification
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $regName = "DisableNotifications"

    # Expected value for 'No' is 1
    $expectedValue = 1

    try {
        # Check current display notification setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableNotifications

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.3 Windows Firewall Public Profile Display Notifications are set to 'No'."
        } else {
            Handle-Output -Condition $false -Message "9.3.3 Windows Firewall Public Profile Display Notifications are not set to 'No'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.3 Error occurred while checking Windows Firewall Public Profile Display Notifications: $_"
    }
}

# 9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
function Check-WindowsFirewallPublicProfileApplyLocalFirewallRules {
    # Registry path and key for apply local firewall rules
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $regName = "AllowLocalPolicyMerge"

    # Expected value for 'No' is 0
    $expectedValue = 0

    try {
        # Check current apply local firewall rules setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).AllowLocalPolicyMerge

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.4 Windows Firewall Public Profile Apply Local Firewall Rules is set to 'No'."
        } else {
            Handle-Output -Condition $false -Message "9.3.4 Windows Firewall Public Profile Apply Local Firewall Rules is not set to 'No'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.4 Error occurred while checking Windows Firewall Public Profile Apply Local Firewall Rules: $_"
    }
}

# 9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
function Check-WindowsFirewallPublicProfileApplyLocalConnectionSecurityRules {
    # Registry path and key for apply local connection security rules
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $regName = "AllowLocalIPsecPolicyMerge"

    # Expected value for 'No' is 0
    $expectedValue = 0

    try {
        # Check current apply local connection security rules setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).AllowLocalIPsecPolicyMerge

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.5 Windows Firewall Public Profile Apply Local Connection Security Rules is set to 'No'."
        } else {
            Handle-Output -Condition $false -Message "9.3.5 Windows Firewall Public Profile Apply Local Connection Security Rules is not set to 'No'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.5 Error occurred while checking Windows Firewall Public Profile Apply Local Connection Security Rules: $_"
    }
}

# 9.3.6 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'
function Check-WindowsFirewallPublicProfileLogName {
    # Registry path and key for log name
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $regName = "LogFilePath"

    # Expected value for log name
    $expectedValue = "$env:SystemRoot\System32\logfiles\firewall\publicfw.log"

    try {
        # Check current log name setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogFilePath

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.6 Windows Firewall Public Profile Logging Name is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'."
        } else {
            Handle-Output -Condition $false -Message "9.3.6 Windows Firewall Public Profile Logging Name is not set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.6 Error occurred while checking Windows Firewall Public Profile Logging Name: $_"
    }
}

# 9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
function Check-WindowsFirewallPublicProfileLogSizeLimit {
    # Registry path and key for log size limit
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $regName = "LogFileSize"

    # Expected value for size limit
    $expectedValue = 16384

    try {
        # Check current log size limit setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogFileSize

        if ($currentValue -ge $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.7 Windows Firewall Public Profile Logging Size Limit is set to '16,384 KB or greater'."
        } else {
            Handle-Output -Condition $false -Message "9.3.7 Windows Firewall Public Profile Logging Size Limit is not set to '16,384 KB or greater'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.7 Error occurred while checking Windows Firewall Public Profile Logging Size Limit: $_"
    }
}

# 9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
function Check-WindowsFirewallPublicProfileLogDroppedPackets {
    # Registry path and key for log dropped packets
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $regName = "LogDroppedPackets"

    # Expected value for 'Yes' is 1
    $expectedValue = 1

    try {
        # Check current log dropped packets setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogDroppedPackets

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.8 Windows Firewall Public Profile Logging Log Dropped Packets is set to 'Yes'."
        } else {
            Handle-Output -Condition $false -Message "9.3.8 Windows Firewall Public Profile Logging Log Dropped Packets is not set to 'Yes'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.8 Error occurred while checking Windows Firewall Public Profile Logging Log Dropped Packets: $_"
    }
}

# 9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
function Check-WindowsFirewallPublicProfileLogSuccessfulConnections {
    # Registry path and key for log successful connections
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $regName = "LogSuccessfulConnections"

    # Expected value for 'Yes' is 1
    $expectedValue = 1

    try {
        # Check current log successful connections setting
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LogSuccessfulConnections

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "9.3.9 Windows Firewall Public Profile Logging Log Successful Connections is set to 'Yes'."
        } else {
            Handle-Output -Condition $false -Message "9.3.9 Windows Firewall Public Profile Logging Log Successful Connections is not set to 'Yes'. Current value: '$currentValue'."
        }
    } catch {
        Handle-Output -Condition $false -Message "9.3.9 Error occurred while checking Windows Firewall Public Profile Logging Log Successful Connections: $_"
    }
}


# Call the functions to check Windows Firewall Domain Profile settings
Check-WindowsFirewallDomainProfileState
Check-WindowsFirewallDomainInboundConnections
Check-WindowsFirewallDomainDisplayNotification
Check-WindowsFirewallDomainLoggingName
Check-WindowsFirewallDomainLoggingSizeLimit
Check-WindowsFirewallDomainLoggingDroppedPackets
Check-WindowsFirewallDomainLoggingSuccessfulConnections
Check-WindowsFirewallPrivateProfileState
Check-WindowsFirewallPrivateProfileInboundConnections
Check-WindowsFirewallPrivateProfileNotification
Check-WindowsFirewallPrivateProfileLogFilePath
Check-WindowsFirewallPrivateProfileLogSizeLimit
Check-WindowsFirewallPrivateProfileLogDroppedPackets
Check-WindowsFirewallPrivateProfileLogSuccessfulConnections
Check-WindowsFirewallPublicProfileFirewallState
Check-WindowsFirewallPublicProfileInboundConnections
Check-WindowsFirewallPublicProfileDisplayNotification
Check-WindowsFirewallPublicProfileApplyLocalFirewallRules
Check-WindowsFirewallPublicProfileApplyLocalConnectionSecurityRules
Check-WindowsFirewallPublicProfileLogName
Check-WindowsFirewallPublicProfileLogSizeLimit
Check-WindowsFirewallPublicProfileLogDroppedPackets
Check-WindowsFirewallPublicProfileLogSuccessfulConnections