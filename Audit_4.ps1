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

# Function to ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'
function Ensure-BTAGServiceDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

    # Check if the current value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.1 Bluetooth Audio Gateway Service (BTAGService) is set to 'Disabled'."
}

# Function to ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'
function Ensure-BluetoothSupportServiceDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Retrieve the current registry value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

    # Check if the current value matches the expected value
    $isConfigCorrect = $currentValue -eq $expectedValue

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.2 Bluetooth Support Service (bthserv) is set to 'Disabled'."
}

# Function to ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'
function Ensure-ComputerBrowserServiceDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist, so it is considered "Not Installed"
        $isConfigCorrect = $true
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.3 Computer Browser (Browser) service is set to 'Disabled' or 'Not Installed'."
}

# Function to ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'
function Ensure-MapsBrokerServiceDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist
        $isConfigCorrect = $false
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.4 Downloaded Maps Manager (MapsBroker) service is set to 'Disabled'."
}

# Run the audit function
Ensure-MapsBrokerServiceDisabled

# Function to ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'
function Ensure-GeolocationServiceDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist
        $isConfigCorrect = $false
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.5 Geolocation Service (lfsvc) is set to 'Disabled'."
}

# Function to ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'
function Ensure-IISAdminServiceDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist, indicating that the service is not installed
        $isConfigCorrect = $true
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.6 IIS Admin Service (IISADMIN) is set to 'Disabled' or 'Not Installed'."
}

# Function to ensure 'Infrared Monitor Service (irmon)' is set to 'Disabled' or 'Not Installed'
function Ensure-InfraredMonitorServiceDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\irmon"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist, indicating that the service is not installed
        $isConfigCorrect = $true
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.7 Infrared Monitor Service (irmon) is set to 'Disabled' or 'Not Installed'."
}

# Function to ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'
function Ensure-LLTDServiceDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist, indicating that the service is not installed
        $isConfigCorrect = $true
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.8 Link-Layer Topology Discovery Mapper (lltdsvc) is set to 'Disabled'."
}

# Function to ensure 'LxssManager (LxssManager)' is set to 'Disabled'
function Ensure-LxssManagerDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist, indicating that the service is not installed
        $isConfigCorrect = $true
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.9 LxssManager (LxssManager) is set to 'Disabled' or 'Not Installed'."
}

# Function to ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled'
function Ensure-FTPSVCDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist, indicating that the service is not installed
        $isConfigCorrect = $true
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.10 Microsoft FTP Service (FTPSVC) is set to 'Disabled' or 'Not Installed'."
}

# Function to ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'
function Ensure-MSiSCSIDisabled {
    # Define the registry path and expected value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"
    $registryValueName = "Start"
    $expectedValue = 4  # Disabled

    # Check if the registry path exists
    if (Test-Path -Path $registryPath) {
        # Retrieve the current registry value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

        # Check if the current value matches the expected value
        $isConfigCorrect = $currentValue -eq $expectedValue
    } else {
        # Registry path does not exist, indicating that the service is not installed
        $isConfigCorrect = $true
    }

    # Output result
    Handle-Output -Condition $isConfigCorrect -Message "5.11 Microsoft iSCSI Initiator Service (MSiSCSI) is set to 'Disabled'."
}

# Run the audit function
Ensure-MSiSCSIDisabled
Ensure-FTPSVCDisabled
Ensure-LxssManagerDisabled
Ensure-LLTDServiceDisabled
Ensure-InfraredMonitorServiceDisabled
Ensure-IISAdminServiceDisabled
Ensure-GeolocationServiceDisabled
Ensure-ComputerBrowserServiceDisabled
Ensure-BluetoothSupportServiceDisabled
