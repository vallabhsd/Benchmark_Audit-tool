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

# 18.10.25.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
function Check-LogFileSizeConfiguration {
    # Registry path and key for maximum log file size configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog"
    $regName = "Setup:MaxSize"

    # Expected minimum value for maximum log file size is 32768 KB (32 MB)
    $expectedValue = 32768

    try {
        # Check current maximum log file size configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).MaxSize

        if ($currentValue -ge $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.25.3.2 Setup: Specify the maximum log file size (KB) is set to 'Enabled: 32,768 or greater'."
        } else {
            Handle-Output -Condition $false -Message "18.10.25.3.2 Setup: Specify the maximum log file size (KB) is not set to 'Enabled: 32,768 or greater'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.25.3.2 Error occurred while checking maximum log file size configuration: $_"
    }
}

# 18.10.25.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
function Check-EventLogBehaviorConfiguration {
    # Registry path and key for event log behavior configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog"
    $regName = "System:Retention"

    # Expected value for 'Disabled' is 0
    $expectedValue = 0

    try {
        # Check current event log behavior configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Retention

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.25.4.1 System: Control Event Log behavior when the log file reaches its maximum size is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.25.4.1 System: Control Event Log behavior when the log file reaches its maximum size is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.25.4.1 Error occurred while checking event log behavior configuration: $_"
    }
}
# 18.10.25.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
function Check-MaxLogFileSizeConfiguration {
    # Registry path and key for maximum log file size configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog"
    $regName = "System:MaxSize"

    # Expected minimum value for maximum log file size is 32768 KB (32 MB)
    $expectedValue = 32768

    try {
        # Check current maximum log file size configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).MaxSize

        if ($currentValue -ge $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.25.4.2 System: Specify the maximum log file size (KB) is set to 'Enabled: 32,768 or greater'."
        } else {
            Handle-Output -Condition $false -Message "18.10.25.4.2 System: Specify the maximum log file size (KB) is not set to 'Enabled: 32,768 or greater'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.25.4.2 Error occurred while checking maximum log file size configuration: $_"
    }
}
# 18.10.28.2 (L2) Ensure 'Turn off account-based insights, recent, favorite, and recommended files in File Explorer' is set to 'Enabled'
function Check-TurnOffAccountBasedInsightsConfiguration {
    # Registry path and key for account-based insights configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $regName = "DisableGraphRecentItems"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current account-based insights configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableGraphRecentItems

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.28.2 Turn off account-based insights, recent, favorite, and recommended files in File Explorer is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.28.2 Turn off account-based insights, recent, favorite, and recommended files in File Explorer is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.28.2 Error occurred while checking account-based insights configuration: $_"
    }
}

# 18.10.28.3 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
function Check-TurnOffDataExecutionPreventionConfiguration {
    # Registry path and key for Data Execution Prevention configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $regName = "NoDataExecutionPrevention"

    # Expected value for 'Disabled' is 0
    $expectedValue = 0

    try {
        # Check current Data Execution Prevention configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).NoDataExecutionPrevention

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.28.3 Turn off Data Execution Prevention for Explorer is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.28.3 Turn off Data Execution Prevention for Explorer is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.28.3 Error occurred while checking Data Execution Prevention configuration: $_"
    }
}

# 18.10.28.4 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
function Check-TurnOffHeapTerminationOnCorruptionConfiguration {
    # Registry path and key for heap termination on corruption configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $regName = "NoHeapTerminationOnCorruption"

    # Expected value for 'Disabled' is 0
    $expectedValue = 0

    try {
        # Check current heap termination on corruption configuration
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).NoHeapTerminationOnCorruption

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.28.4 Turn off heap termination on corruption is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.28.4 Turn off heap termination on corruption is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.28.4 Error occurred while checking heap termination on corruption configuration: $_"
    }
}
# 18.10.28.5 (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
function Check-ShellProtocolProtectedMode {
    # Registry path and key for shell protocol protected mode
    $regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $regName = "PreXPSP2ShellProtocolBehavior"

    # Expected value for 'Disabled' is 0
    $expectedValue = 0

    try {
        # Check current setting for shell protocol protected mode
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).PreXPSP2ShellProtocolBehavior

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.28.5 Turn off shell protocol protected mode is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.28.5 Turn off shell protocol protected mode is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.28.5 Error occurred while checking shell protocol protected mode setting: $_"
    }
}
# 18.10.36.1 (L2) Ensure 'Turn off location' is set to 'Enabled'
function Check-TurnOffLocation {
    # Registry path and key for turn off location
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    $regName = "DisableLocation"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current setting for turn off location
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableLocation

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.36.1 Turn off location is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.36.1 Turn off location is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.36.1 Error occurred while checking turn off location setting: $_"
    }
}
# 18.10.40.1 (L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
function Check-AllowMessageServiceCloudSync {
    # Registry path and key for message service cloud sync
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging"
    $regName = "AllowMessageSync"

    # Expected value for 'Disabled' is 0
    $expectedValue = 0

    try {
        # Check current setting for message service cloud sync
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).AllowMessageSync

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.40.1 Allow Message Service Cloud Sync is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.40.1 Allow Message Service Cloud Sync is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.40.1 Error occurred while checking Allow Message Service Cloud Sync setting: $_"
    }
}
# 18.10.41.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'
function Check-BlockConsumerMicrosoftAccountAuth {
    # Registry path and key for block consumer Microsoft account user authentication
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
    $regName = "DisableUserAuth"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current setting for block consumer Microsoft account user authentication
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).DisableUserAuth

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.41.1 Block all consumer Microsoft account user authentication is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.41.1 Block all consumer Microsoft account user authentication is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.41.1 Error occurred while checking block consumer Microsoft account user authentication setting: $_"
    }
}

# 18.10.42.5.1 (L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'
function Check-LocalSettingOverrideForMAPS {
    # Registry path and key for local setting override for reporting to Microsoft MAPS
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    $regName = "LocalSettingOverrideSpynetReporting"

    # Expected value for 'Disabled' is 0
    $expectedValue = 0

    try {
        # Check current setting for local setting override for reporting to Microsoft MAPS
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).LocalSettingOverrideSpynetReporting

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.42.5.1 Configure local setting override for reporting to Microsoft MAPS is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.42.5.1 Configure local setting override for reporting to Microsoft MAPS is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.42.5.1 Error occurred while checking local setting override for reporting to Microsoft MAPS setting: $_"
    }
}

# 18.10.42.5.2 (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'
function Check-JoinMicrosoftMAPS {
    # Registry path and key for join Microsoft MAPS
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    $regName = "SpynetReporting"

    # Expected value for 'Disabled' is 0 (or registry key does not exist)
    $expectedValue = 0

    try {
        # Check current setting for join Microsoft MAPS
        if (Test-Path -Path "$regPath\$regName") {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).SpynetReporting
        } else {
            $currentValue = $null
        }

        if ($currentValue -eq $expectedValue -or $currentValue -eq $null) {
            Handle-Output -Condition $true -Message "18.10.42.5.2 Join Microsoft MAPS is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.42.5.2 Join Microsoft MAPS is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.42.5.2 Error occurred while checking join Microsoft MAPS setting: $_"
    }
}

# 18.10.42.6.1.1 (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'
function Check-ConfigureASRRules {
    # Registry path and key for Attack Surface Reduction rules
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
    $regName = "ExploitGuard_ASR_Rules"

    # Expected value for 'Enabled' is 1
    $expectedValue = 1

    try {
        # Check current setting for Attack Surface Reduction rules
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).ExploitGuard_ASR_Rules

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "18.10.42.6.1.1 Configure Attack Surface Reduction rules is set to 'Enabled'."
        } else {
            Handle-Output -Condition $false -Message "18.10.42.6.1.1 Configure Attack Surface Reduction rules is not set to 'Enabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "18.10.42.6.1.1 Error occurred while checking Configure Attack Surface Reduction rules setting: $_"
    }
}



# Call the functions to check the configurations
Check-TpmStartupKeyConfiguration
Check-LogFileSizeConfiguration
Check-EventLogBehaviorConfiguration
Check-MaxLogFileSizeConfiguration
Check-TurnOffAccountBasedInsightsConfiguration
Check-TurnOffDataExecutionPreventionConfiguration
Check-TurnOffHeapTerminationOnCorruptionConfiguration
Check-ShellProtocolProtectedMode
Check-TurnOffLocation
Check-AllowMessageServiceCloudSync
Check-BlockConsumerMicrosoftAccountAuth
Check-LocalSettingOverrideForMAPS
Check-JoinMicrosoftMAPS
Check-ConfigureASRRules

