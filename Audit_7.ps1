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

# 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
function Check-AuditCredentialValidation {
    try {
        # Get current audit policy for Credential Validation
        $auditPolicy = auditpol /get /subcategory:"Credential Validation"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.1.1 Audit Credential Validation is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.1.1 Audit Credential Validation is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.1.1 Error occurred while checking Audit Credential Validation: $_"
    }
}

# 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
function Check-AuditApplicationGroupManagement {
    try {
        # Get current audit policy for Application Group Management
        $auditPolicy = auditpol /get /subcategory:"Application Group Management"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.2.1 Audit Application Group Management is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.2.1 Audit Application Group Management is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.2.1 Error occurred while checking Audit Application Group Management: $_"
    }
}

# 17.2.2 (L1) Ensure 'Audit Security Group Management' is set to include 'Success'
function Check-AuditSecurityGroupManagement {
    try {
        # Get current audit policy for Security Group Management
        $auditPolicy = auditpol /get /subcategory:"Security Group Management"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.2.2 Audit Security Group Management is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.2.2 Audit Security Group Management is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.2.2 Error occurred while checking Audit Security Group Management: $_"
    }
}

# 17.2.3 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
function Check-AuditUserAccountManagement {
    try {
        # Get current audit policy for User Account Management
        $auditPolicy = auditpol /get /subcategory:"User Account Management"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.2.3 Audit User Account Management is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.2.3 Audit User Account Management is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.2.3 Error occurred while checking Audit User Account Management: $_"
    }
}

# 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to include 'Success'
function Check-AuditPNPActivity {
    try {
        # Get current audit policy for PNP Activity
        $auditPolicy = auditpol /get /subcategory:"PNP Activity"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.3.1 Audit PNP Activity is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.3.1 Audit PNP Activity is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.3.1 Error occurred while checking Audit PNP Activity: $_"
    }
}

# 17.3.2 (L1) Ensure 'Audit Process Creation' is set to include 'Success'
function Check-AuditProcessCreation {
    try {
        # Get current audit policy for Process Creation
        $auditPolicy = auditpol /get /subcategory:"Process Creation"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.3.2 Audit Process Creation is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.3.2 Audit Process Creation is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.3.2 Error occurred while checking Audit Process Creation: $_"
    }
}

# 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to include 'Failure'
function Check-AuditAccountLockout {
    try {
        # Get current audit policy for Account Lockout
        $auditPolicy = auditpol /get /subcategory:"Account Lockout"

        if ($auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.5.1 Audit Account Lockout is set to include 'Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.5.1 Audit Account Lockout is not set to include 'Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.5.1 Error occurred while checking Audit Account Lockout: $_"
    }
}

# 17.5.2 (L1) Ensure 'Audit Group Membership' is set to include 'Success'
function Check-AuditGroupMembership {
    try {
        # Get current audit policy for Group Membership
        $auditPolicy = auditpol /get /subcategory:"Group Membership"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.5.2 Audit Group Membership is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.5.2 Audit Group Membership is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.5.2 Error occurred while checking Audit Group Membership: $_"
    }
}

# 17.5.3 (L1) Ensure 'Audit Logoff' is set to include 'Success'
function Check-AuditLogoff {
    try {
        # Get current audit policy for Logoff
        $auditPolicy = auditpol /get /subcategory:"Logoff"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.5.3 Audit Logoff is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.5.3 Audit Logoff is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.5.3 Error occurred while checking Audit Logoff: $_"
    }
}

# 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
function Check-AuditLogon {
    try {
        # Get current audit policy for Logon
        $auditPolicy = auditpol /get /subcategory:"Logon"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.5.4 Audit Logon is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.5.4 Audit Logon is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.5.4 Error occurred while checking Audit Logon: $_"
    }
}

# 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
function Check-AuditOtherLogonLogoffEvents {
    try {
        # Get current audit policy for Other Logon/Logoff Events
        $auditPolicy = auditpol /get /subcategory:"Other Logon/Logoff Events"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.5.5 Audit Other Logon/Logoff Events is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.5.5 Audit Other Logon/Logoff Events is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.5.5 Error occurred while checking Audit Other Logon/Logoff Events: $_"
    }
}

# 17.5.6 (L1) Ensure 'Audit Special Logon' is set to include 'Success'
function Check-AuditSpecialLogon {
    try {
        # Get current audit policy for Special Logon
        $auditPolicy = auditpol /get /subcategory:"Special Logon"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.5.6 Audit Special Logon is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.5.6 Audit Special Logon is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.5.6 Error occurred while checking Audit Special Logon: $_"
    }
}

# 17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'
function Check-AuditDetailedFileShare {
    try {
        # Get current audit policy for Detailed File Share
        $auditPolicy = auditpol /get /subcategory:"Detailed File Share"

        if ($auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.6.1 Audit Detailed File Share is set to include 'Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.6.1 Audit Detailed File Share is not set to include 'Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.6.1 Error occurred while checking Audit Detailed File Share: $_"
    }
}

# 17.6.2 (L1) Ensure 'Audit File Share' is set to 'Success and Failure'
function Check-AuditFileShare {
    try {
        # Get current audit policy for File Share
        $auditPolicy = auditpol /get /subcategory:"File Share"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.6.2 Audit File Share is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.6.2 Audit File Share is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.6.2 Error occurred while checking Audit File Share: $_"
    }
}

# 17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
function Check-AuditOtherObjectAccessEvents {
    try {
        # Get current audit policy for Other Object Access Events
        $auditPolicy = auditpol /get /subcategory:"Other Object Access Events"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.6.3 Audit Other Object Access Events is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.6.3 Audit Other Object Access Events is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.6.3 Error occurred while checking Audit Other Object Access Events: $_"
    }
}

# 17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'
function Check-AuditRemovableStorage {
    try {
        # Get current audit policy for Removable Storage
        $auditPolicy = auditpol /get /subcategory:"Removable Storage"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.6.4 Audit Removable Storage is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.6.4 Audit Removable Storage is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.6.4 Error occurred while checking Audit Removable Storage: $_"
    }
}

# 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success'
function Check-AuditPolicyChange {
    try {
        # Get current audit policy for Audit Policy Change
        $auditPolicy = auditpol /get /subcategory:"Audit Policy Change"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.7.1 Audit Policy Change is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.7.1 Audit Policy Change is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.7.1 Error occurred while checking Audit Policy Change: $_"
    }
}

# 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success'
function Check-AuditAuthenticationPolicyChange {
    try {
        # Get current audit policy for Authentication Policy Change
        $auditPolicy = auditpol /get /subcategory:"Authentication Policy Change"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.7.2 Audit Authentication Policy Change is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.7.2 Audit Authentication Policy Change is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.7.2 Error occurred while checking Authentication Policy Change: $_"
    }
}

# 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success'
function Check-AuditAuthorizationPolicyChange {
    try {
        # Get current audit policy for Authorization Policy Change
        $auditPolicy = auditpol /get /subcategory:"Authorization Policy Change"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.7.3 Audit Authorization Policy Change is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.7.3 Audit Authorization Policy Change is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.7.3 Error occurred while checking Authorization Policy Change: $_"
    }
}

# 17.7.4 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
function Check-AuditMPSSVCRuleLevelPolicyChange {
    try {
        # Get current audit policy for MPSSVC Rule-Level Policy Change
        $auditPolicy = auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.7.4 Audit MPSSVC Rule-Level Policy Change is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.7.4 Audit MPSSVC Rule-Level Policy Change is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.7.4 Error occurred while checking MPSSVC Rule-Level Policy Change: $_"
    }
}

# 17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'
function Check-AuditOtherPolicyChangeEvents {
    try {
        # Get current audit policy for Other Policy Change Events
        $auditPolicy = auditpol /get /subcategory:"Other Policy Change Events"

        if ($auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.7.5 Audit Other Policy Change Events is set to include 'Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.7.5 Audit Other Policy Change Events is not set to include 'Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.7.5 Error occurred while checking Other Policy Change Events: $_"
    }
}

# 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
function Check-AuditSensitivePrivilegeUse {
    try {
        # Get current audit policy for Sensitive Privilege Use
        $auditPolicy = auditpol /get /subcategory:"Sensitive Privilege Use"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.8.1 Audit Sensitive Privilege Use is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.8.1 Audit Sensitive Privilege Use is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.8.1 Error occurred while checking Sensitive Privilege Use: $_"
    }
}

# 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
function Check-AuditIPsecDriver {
    try {
        # Get current audit policy for IPsec Driver
        $auditPolicy = auditpol /get /subcategory:"IPsec Driver"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.9.1 Audit IPsec Driver is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.9.1 Audit IPsec Driver is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.9.1 Error occurred while checking IPsec Driver: $_"
    }
}

# 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
function Check-AuditOtherSystemEvents {
    try {
        # Get current audit policy for Other System Events
        $auditPolicy = auditpol /get /subcategory:"Other System Events"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.9.2 Audit Other System Events is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.9.2 Audit Other System Events is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.9.2 Error occurred while checking Other System Events: $_"
    }
}

# 17.9.3 (L1) Ensure 'Audit Security State Change' is set to include 'Success'
function Check-AuditSecurityStateChange {
    try {
        # Get current audit policy for Security State Change
        $auditPolicy = auditpol /get /subcategory:"Security State Change"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.9.3 Audit Security State Change is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.9.3 Audit Security State Change is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.9.3 Error occurred while checking Security State Change: $_"
    }
}

# 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to include 'Success'
function Check-AuditSecuritySystemExtension {
    try {
        # Get current audit policy for Security System Extension
        $auditPolicy = auditpol /get /subcategory:"Security System Extension"

        if ($auditPolicy -match "Success") {
            Handle-Output -Condition $true -Message "17.9.4 Audit Security System Extension is set to include 'Success'."
        } else {
            Handle-Output -Condition $false -Message "17.9.4 Audit Security System Extension is not set to include 'Success'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.9.4 Error occurred while checking Security System Extension: $_"
    }
}

# 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
function Check-AuditSystemIntegrity {
    try {
        # Get current audit policy for System Integrity
        $auditPolicy = auditpol /get /subcategory:"System Integrity"

        if ($auditPolicy -match "Success" -and $auditPolicy -match "Failure") {
            Handle-Output -Condition $true -Message "17.9.5 Audit System Integrity is set to 'Success and Failure'."
        } else {
            Handle-Output -Condition $false -Message "17.9.5 Audit System Integrity is not set to 'Success and Failure'. Current setting: '$auditPolicy'."
        }
    } catch {
        Handle-Output -Condition $false -Message "17.9.5 Error occurred while checking System Integrity: $_"
    }
}

# Execute all checks
Check-AuditCredentialValidation
Check-AuditApplicationGroupManagement
Check-AuditSecurityGroupManagement
Check-AuditUserAccountManagement
Check-AuditPNPActivity
Check-AuditProcessCreation
Check-AuditAccountLockout
Check-AuditGroupMembership
Check-AuditLogoff
Check-AuditLogon
Check-AuditOtherLogonLogoffEvents
Check-AuditSpecialLogon
Check-AuditDetailedFileShare
Check-AuditFileShare
Check-AuditOtherObjectAccessEvents
Check-AuditRemovableStorage
Check-AuditPolicyChange
Check-AuditAuthenticationPolicyChange
Check-AuditAuthorizationPolicyChange
Check-AuditMPSSVCRuleLevelPolicyChange
Check-AuditOtherPolicyChangeEvents
Check-AuditSensitivePrivilegeUse
Check-AuditIPsecDriver
Check-AuditOtherSystemEvents
Check-AuditSecurityStateChange
Check-AuditSecuritySystemExtension
Check-AuditSystemIntegrity