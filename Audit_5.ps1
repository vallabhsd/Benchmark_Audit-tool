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

# 5.1 (L2) Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'
function Check-BluetoothAudioGatewayServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.1 Bluetooth Audio Gateway Service (BTAGService) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.1 Bluetooth Audio Gateway Service (BTAGService) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.1 Error occurred while checking Bluetooth Audio Gateway Service (BTAGService): $_"
    }
}

# 5.2 (L2) Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'
function Check-BluetoothSupportServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.2 Bluetooth Support Service (bthserv) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.2 Bluetooth Support Service (bthserv) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.2 Error occurred while checking Bluetooth Support Service (bthserv): $_"
    }
}

# 5.3 (L1) Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'
function Check-ComputerBrowserServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        if (Test-Path -Path $regPath) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

            if ($currentValue -eq $expectedValue) {
                Handle-Output -Condition $true -Message "5.3 Computer Browser (Browser) is set to 'Disabled'."
            } else {
                Handle-Output -Condition $false -Message "5.3 Computer Browser (Browser) is not set to 'Disabled'."
            }
        } else {
            Handle-Output -Condition $true -Message "5.3 Computer Browser (Browser) is not installed."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.3 Error occurred while checking Computer Browser (Browser): $_"
    }
}

# 5.4 (L2) Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'
function Check-DownloadedMapsManagerDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.4 Downloaded Maps Manager (MapsBroker) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.4 Downloaded Maps Manager (MapsBroker) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.4 Error occurred while checking Downloaded Maps Manager (MapsBroker): $_"
    }
}

# 5.5 (L2) Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'
function Check-GeolocationServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.5 Geolocation Service (lfsvc) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.5 Geolocation Service (lfsvc) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.5 Error occurred while checking Geolocation Service (lfsvc): $_"
    }
}

# 5.6 (L1) Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'
function Check-IISAdminServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        if (Test-Path -Path $regPath) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

            if ($currentValue -eq $expectedValue) {
                Handle-Output -Condition $true -Message "5.6 IIS Admin Service (IISADMIN) is set to 'Disabled'."
            } else {
                Handle-Output -Condition $false -Message "5.6 IIS Admin Service (IISADMIN) is not set to 'Disabled'."
            }
        } else {
            Handle-Output -Condition $true -Message "5.6 IIS Admin Service (IISADMIN) is not installed."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.6 Error occurred while checking IIS Admin Service (IISADMIN): $_"
    }
}

# 5.7 (L1) Ensure 'Infrared monitor service (irmon)' is set to 'Disabled' or 'Not Installed'
function Check-InfraredMonitorServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\irmon"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        if (Test-Path -Path $regPath) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

            if ($currentValue -eq $expectedValue) {
                Handle-Output -Condition $true -Message "5.7 Infrared monitor service (irmon) is set to 'Disabled'."
            } else {
                Handle-Output -Condition $false -Message "5.7 Infrared monitor service (irmon) is not set to 'Disabled'."
            }
        } else {
            Handle-Output -Condition $true -Message "5.7 Infrared monitor service (irmon) is not installed."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.7 Error occurred while checking Infrared monitor service (irmon): $_"
    }
}

# 5.8 (L2) Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'
function Check-LinkLayerTopologyDiscoveryMapperDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.8 Link-Layer Topology Discovery Mapper (lltdsvc) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.8 Link-Layer Topology Discovery Mapper (lltdsvc) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.8 Error occurred while checking Link-Layer Topology Discovery Mapper (lltdsvc): $_"
    }
}

# 5.9 (L1) Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'
function Check-LxssManagerDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        if (Test-Path -Path $regPath) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

            if ($currentValue -eq $expectedValue) {
                Handle-Output -Condition $true -Message "5.9 LxssManager (LxssManager) is set to 'Disabled'."
            } else {
                Handle-Output -Condition $false -Message "5.9 LxssManager (LxssManager) is not set to 'Disabled'."
            }
        } else {
            Handle-Output -Condition $true -Message "5.9 LxssManager (LxssManager) is not installed."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.9 Error occurred while checking LxssManager (LxssManager): $_"
    }
}

# 5.10 (L1) Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'
function Check-MicrosoftFTPServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        if (Test-Path -Path $regPath) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

            if ($currentValue -eq $expectedValue) {
                Handle-Output -Condition $true -Message "5.10 Microsoft FTP Service (FTPSVC) is set to 'Disabled'."
            } else {
                Handle-Output -Condition $false -Message "5.10 Microsoft FTP Service (FTPSVC) is not set to 'Disabled'."
            }
        } else {
            Handle-Output -Condition $true -Message "5.10 Microsoft FTP Service (FTPSVC) is not installed."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.10 Error occurred while checking Microsoft FTP Service (FTPSVC): $_"
    }
}

# 5.11 (L2) Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'
function Check-MicrosoftiSCSIInitiatorServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.11 Microsoft iSCSI Initiator Service (MSiSCSI) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.11 Microsoft iSCSI Initiator Service (MSiSCSI) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.11 Error occurred while checking Microsoft iSCSI Initiator Service (MSiSCSI): $_"
    }
}

# 5.12 (L1) Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'
function Check-OpenSSHSSHServerDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\sshd"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        if (Test-Path -Path $regPath) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

            if ($currentValue -eq $expectedValue) {
                Handle-Output -Condition $true -Message "5.12 OpenSSH SSH Server (sshd) is set to 'Disabled'."
            } else {
                Handle-Output -Condition $false -Message "5.12 OpenSSH SSH Server (sshd) is not set to 'Disabled'."
            }
        } else {
            Handle-Output -Condition $true -Message "5.12 OpenSSH SSH Server (sshd) is not installed."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.12 Error occurred while checking OpenSSH SSH Server (sshd): $_"
    }
}

# 5.13 (L2) Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'
function Check-PNRPSVCDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.13 Peer Name Resolution Protocol (PNRPsvc) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.13 Peer Name Resolution Protocol (PNRPsvc) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.13 Error occurred while checking Peer Name Resolution Protocol (PNRPsvc): $_"
    }
}

# 5.14 (L2) Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'
function Check-P2PSVCDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.14 Peer Networking Grouping (p2psvc) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.14 Peer Networking Grouping (p2psvc) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.14 Error occurred while checking Peer Networking Grouping (p2psvc): $_"
    }
}
# 5.15 (L2) Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'
function Check-P2PIMSvcDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.15 Peer Networking Identity Manager (p2pimsvc) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.15 Peer Networking Identity Manager (p2pimsvc) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.15 Error occurred while checking Peer Networking Identity Manager (p2pimsvc): $_"
    }
}
# 5.16 (L2) Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'
function Check-PNRPAutoRegDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.16 PNRP Machine Name Publication Service (PNRPAutoReg) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.16 PNRP Machine Name Publication Service (PNRPAutoReg) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.16 Error occurred while checking PNRP Machine Name Publication Service (PNRPAutoReg): $_"
    }
}

# 5.17 (L2) Ensure 'Print Spooler (Spooler)' is set to 'Disabled'
function Check-PrintSpoolerDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.17 Print Spooler (Spooler) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.17 Print Spooler (Spooler) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.17 Error occurred while checking Print Spooler (Spooler): $_"
    }
}

# 5.18 (L2) Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'
function Check-ProblemReportsAndSolutionsDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.18 Problem Reports and Solutions Control Panel Support (wercplsupport) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.18 Problem Reports and Solutions Control Panel Support (wercplsupport) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.18 Error occurred while checking Problem Reports and Solutions Control Panel Support (wercplsupport): $_"
    }
}

# 5.19 (L2) Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'
function Check-RemoteAccessAutoConnectionManagerDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.19 Remote Access Auto Connection Manager (RasAuto) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.19 Remote Access Auto Connection Manager (RasAuto) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.19 Error occurred while checking Remote Access Auto Connection Manager (RasAuto): $_"
    }
}

# 5.20 (L2) Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'
function Check-RemoteDesktopConfigurationDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.20 Remote Desktop Configuration (SessionEnv) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.20 Remote Desktop Configuration (SessionEnv) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.20 Error occurred while checking Remote Desktop Configuration (SessionEnv): $_"
    }
}

# 5.21 (L2) Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'
function Check-RemoteDesktopServicesDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.21 Remote Desktop Services (TermService) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.21 Error occurred while checking Remote Desktop Services (TermService): $_"
    }
}

# 5.22 (L2) Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'
function Check-RemoteDesktopServicesUserModePortRedirectorDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.22 Remote Desktop Services UserMode Port Redirector (UmRdpService) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.22 Error occurred while checking Remote Desktop Services UserMode Port Redirector (UmRdpService): $_"
    }
}

# 5.23 (L1) Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'
function Check-RPCLocatorDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.23 Remote Procedure Call (RPC) Locator (RpcLocator) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.23 Error occurred while checking Remote Procedure Call (RPC) Locator (RpcLocator): $_"
    }
}

# 5.24 (L2) Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'
function Check-RemoteRegistryDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.24 Remote Registry (RemoteRegistry) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.24 Error occurred while checking Remote Registry (RemoteRegistry): $_"
    }
}

# 5.25 (L1) Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'
function Check-RoutingAndRemoteAccessDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.25 Routing and Remote Access (RemoteAccess) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.25 Error occurred while checking Routing and Remote Access (RemoteAccess): $_"
    }
}

# 5.26 (L2) Ensure 'Server (LanmanServer)' is set to 'Disabled'
function Check-ServerDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.26 Server (LanmanServer) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.26 Error occurred while checking Server (LanmanServer): $_"
    }
}

# 5.27 (L1) Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'
function Check-SimpleTCPIPServicesDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.27 Simple TCP/IP Services (simptcp) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.27 Error occurred while checking Simple TCP/IP Services (simptcp): $_"
    }
}

# 5.28 (L2) Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed'
function Check-SNMPServiceDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.28 SNMP Service (SNMP) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.28 Error occurred while checking SNMP Service (SNMP): $_"
    }
}

# 5.29 (L1) Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed'
function Check-SpecialAdministrationConsoleHelperDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.29 Special Administration Console Helper (sacsvr) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.29 Error occurred while checking Special Administration Console Helper (sacsvr): $_"
    }
}

# 5.30 (L1) Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'
function Check-SSDPDiscoveryDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.30 SSDP Discovery (SSDPSRV) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.30 Error occurred while checking SSDP Discovery (SSDPSRV): $_"
    }
}

# 5.31 (L1) Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'
function Check-UPnPDeviceHostDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.31 UPnP Device Host (upnphost) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.31 Error occurred while checking UPnP Device Host (upnphost): $_"
    }
}

# 5.32 (L1) Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'
function Check-WebManagementServiceDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.32 Web Management Service (WMSvc) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.32 Error occurred while checking Web Management Service (WMSvc): $_"
    }
}

# 5.33 (L2) Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled'
function Check-WindowsErrorReportingServiceDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.33 Windows Error Reporting Service (WerSvc) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.33 Error occurred while checking Windows Error Reporting Service (WerSvc): $_"
    }
}

# 5.34 (L2) Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled'
function Check-WindowsEventCollectorDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.34 Windows Event Collector (Wecsvc) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.34 Error occurred while checking Windows Event Collector (Wecsvc): $_"
    }
}

# 5.35 (L1) Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'
function Check-WindowsMediaPlayerNetworkSharingServiceDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.35 Windows Media Player Network Sharing Service (WMPNetworkSvc) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.35 Error occurred while checking Windows Media Player Network Sharing Service (WMPNetworkSvc): $_"
    }
}

# 5.36 (L1) Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'
function Check-WindowsMobileHotspotServiceDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.36 Windows Mobile Hotspot Service (icssvc) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.36 Error occurred while checking Windows Mobile Hotspot Service (icssvc): $_"
    }
}

# 5.37 (L2) Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled'
function Check-WindowsPushNotificationsSystemServiceDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.37 Windows Push Notifications System Service (WpnService) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.37 Error occurred while checking Windows Push Notifications System Service (WpnService): $_"
    }
}

# 5.38 (L2) Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled'
function Check-WindowsPushToInstallServiceDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.38 Windows PushToInstall Service (PushToInstall) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.38 Error occurred while checking Windows PushToInstall Service (PushToInstall): $_"
    }
}

# 5.39 (L2) Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'
function Check-WindowsRemoteManagementDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.39 Windows Remote Management (WinRM) is set to 'Disabled'."
    } catch {
        Handle-Output -Condition $false -Message "5.39 Error occurred while checking Windows Remote Management (WinRM): $_"
    }
}

# 5.40 (L1) Ensure 'World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed'
function Check-WorldWideWebPublishingServiceDisabled {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"
    $regName = "Start"
    $expectedValue = 4

    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start
        Handle-Output -Condition ($currentValue -eq $expectedValue) -Message "5.40 World Wide Web Publishing Service (W3SVC) is set to 'Disabled' or 'Not Installed'."
    } catch {
        Handle-Output -Condition $false -Message "5.40 Error occurred while checking World Wide Web Publishing Service (W3SVC): $_"
    }
}




# 5.41 (L1) Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'
function Check-XboxAccessoryManagementServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.41 Xbox Accessory Management Service (XboxGipSvc) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.41 Xbox Accessory Management Service (XboxGipSvc) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.41 Error occurred while checking Xbox Accessory Management Service (XboxGipSvc): $_"
    }
}

# 5.42 (L1) Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'
function Check-XboxLiveAuthManagerDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.42 Xbox Live Auth Manager (XblAuthManager) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.42 Xbox Live Auth Manager (XblAuthManager) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.42 Error occurred while checking Xbox Live Auth Manager (XblAuthManager): $_"
    }
}

# 5.43 (L1) Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'
function Check-XboxLiveGameSaveDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.43 Xbox Live Game Save (XblGameSave) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.43 Xbox Live Game Save (XblGameSave) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.43 Error occurred while checking Xbox Live Game Save (XblGameSave): $_"
    }
}

# 5.44 (L1) Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'
function Check-XboxLiveNetworkingServiceDisabled {
    # Registry path and key for the service startup type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"
    $regName = "Start"

    # Expected value for 'Disabled' is 4
    $expectedValue = 4

    try {
        # Check current service startup type
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).Start

        if ($currentValue -eq $expectedValue) {
            Handle-Output -Condition $true -Message "5.44 Xbox Live Networking Service (XboxNetApiSvc) is set to 'Disabled'."
        } else {
            Handle-Output -Condition $false -Message "5.44 Xbox Live Networking Service (XboxNetApiSvc) is not set to 'Disabled'."
        }
    } catch {
        Handle-Output -Condition $false -Message "5.44 Error occurred while checking Xbox Live Networking Service (XboxNetApiSvc): $_"
    }
}


# Call the functions to check each service
Check-BluetoothAudioGatewayServiceDisabled
Check-BluetoothSupportServiceDisabled
Check-ComputerBrowserServiceDisabled
Check-DownloadedMapsManagerDisabled
Check-GeolocationServiceDisabled
Check-IISAdminServiceDisabled
Check-InfraredMonitorServiceDisabled
Check-LinkLayerTopologyDiscoveryMapperDisabled
Check-LxssManagerDisabled
Check-MicrosoftFTPServiceDisabled
Check-MicrosoftiSCSIInitiatorServiceDisabled
Check-OpenSSHSSHServerDisabled
Check-PNRPSVCDisabled
Check-P2PSVCDisabled
Check-P2PIMSvcDisabled
Check-PNRPAutoRegDisabled
Check-PrintSpoolerDisabled
Check-ProblemReportsAndSolutionsDisabled
Check-RemoteAccessAutoConnectionManagerDisabled
Check-RemoteDesktopConfigurationDisabled
Check-RemoteDesktopServicesDisabled
Check-RemoteDesktopServicesUserModePortRedirectorDisabled
Check-RPCLocatorDisabled
Check-RemoteRegistryDisabled
Check-RoutingAndRemoteAccessDisabled
Check-ServerDisabled
Check-SimpleTCPIPServicesDisabled
Check-SNMPServiceDisabled
Check-SpecialAdministrationConsoleHelperDisabled
Check-SSDPDiscoveryDisabled
Check-UPnPDeviceHostDisabled
Check-WebManagementServiceDisabled
Check-WindowsErrorReportingServiceDisabled
Check-WindowsEventCollectorDisabled
Check-WindowsMediaPlayerNetworkSharingServiceDisabled
Check-WindowsMobileHotspotServiceDisabled
Check-WindowsPushNotificationsSystemServiceDisabled
Check-WindowsPushToInstallServiceDisabled
Check-WindowsRemoteManagementDisabled
Check-WorldWideWebPublishingServiceDisabled
Check-XboxAccessoryManagementServiceDisabled
Check-XboxLiveAuthManagerDisabled
Check-XboxLiveGameSaveDisabled
Check-XboxLiveNetworkingServiceDisabled