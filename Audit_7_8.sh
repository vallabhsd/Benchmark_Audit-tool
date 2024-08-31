#!/bin/bash
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}
function check_ip_forwarding() {
  # Execute the command to check IP forwarding
  output=$(sysctl net.ipv4.ip_forward)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.1.1 Disable IP Forwarding"
}

# Call the function to check IP forwarding
check_ip_forwarding


function check_send_packet_redirects() {
  # Execute the commands to check send packet redirects
  output1=$(sysctl net.ipv4.conf.all.send_redirects)
  output2=$(sysctl net.ipv4.conf.default.send_redirects)

  # Use the handle_output function to check the output and write the result
  handle_output "$output1 $output2" "7.1.2 Disable Send Packet Redirects"
}

# Call the function to check send packet redirects
check_send_packet_redirects
function check_source_routed_packet_acceptance() {
  # Execute the commands to check source routed packet acceptance
  output1=$(sysctl net.ipv4.conf.all.accept_source_route)
  output2=$(sysctl net.ipv4.conf.default.accept_source_route)

  # Use the handle_output function to check the output and write the result
  handle_output "$output1 $output2" "7.2.1 Disable Source Routed Packet Acceptance"
}

# Call the function to check source routed packet acceptance
check_source_routed_packet_acceptance

function check_icmp_redirect_acceptance() {
  # Execute the commands to check ICMP redirect acceptance
  output1=$(sysctl net.ipv4.conf.all.accept_redirects)
  output2=$(sysctl net.ipv4.conf.default.accept_redirects)

  # Combine the outputs for evaluation
  combined_output="$output1 $output2"

  # Use the handle_output function to check the output and write the result
  handle_output "$combined_output" "7.2.2 Disable ICMP Redirect Acceptance"
}

# Call the function to check ICMP redirect acceptance
check_icmp_redirect_acceptance

function check_secure_icmp_redirect_acceptance() {
  # Execute the commands to check secure ICMP redirect acceptance
  output1=$(sysctl net.ipv4.conf.all.secure_redirects)
  output2=$(sysctl net.ipv4.conf.default.secure_redirects)

  # Use the handle_output function to check the output and write the result
  handle_output "$output1" "$output2" "7.2.3 Disable Secure ICMP Redirect Acceptance"
}

# Call the function to check secure ICMP redirect acceptance
check_secure_icmp_redirect_acceptance

function check_log_suspicious_packets() {
  # Execute the commands to check log suspicious packets
  output1=$(sysctl net.ipv4.conf.all.log_martians)
  output2=$(sysctl net.ipv4.conf.default.log_martians)

  # Use the handle_output function to check the output and write the result
  handle_output "$output1 $output2" "7.2.4 Log Suspicious Packets"
}

# Call the function to check log suspicious packets
check_log_suspicious_packets

function check_ignore_broadcast_requests() {
  # Execute the command to check ignore broadcast requests
  output=$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.2.5 Enable Ignore Broadcast Requests"
}

# Call the function to check ignore broadcast requests
check_ignore_broadcast_requests

function check_bad_error_message_protection() {
  # Execute the command to check bad error message protection
  output=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.2.6 Enable Bad Error Message Protection"
}

# Call the function to check bad error message protection
check_bad_error_message_protection

function check_rfc_recommended_source_route_validation() {
  # Execute the commands to check RFC-recommended source route validation
  output1=$(sysctl net.ipv4.conf.all.rp_filter)
  output2=$(sysctl net.ipv4.conf.default.rp_filter)

  # Use the handle_output function to check the output and write the result
  handle_output "$output1 $output2" "7.2.7 Enable RFC-recommended Source Route Validation"
}

# Call the function to check RFC-recommended source route validation
check_rfc_recommended_source_route_validation

function check_tcp_syncookies_enabled() {
  # Execute the command to check TCP SYN cookies enablement
  output=$(sysctl net.ipv4.tcp_syncookies)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.2.8 Enable TCP SYN Cookies"
}

# Call the function to check TCP SYN cookies enablement
check_tcp_syncookies_enabled
function check_ipv6_router_advertisements() {
  # Execute the commands to check IPv6 router advertisements
  output1=$(sysctl net.ipv6.conf.all.accept_ra)
  output2=$(sysctl net.ipv6.conf.default.accept_ra)

  # Combine the outputs for evaluation
  combined_output="$output1 $output2"

  # Use the handle_output function to check the output and write the result
  handle_output "$combined_output" "7.3.1 Disable IPv6 Router Advertisements"
}

# Call the function to check IPv6 router advertisements
check_ipv6_router_advertisements


function check_ipv6_redirect_acceptance_default() {
  # Execute the command to check IPv6 redirect acceptance for the default interface
  output=$(sysctl net.ipv6.conf.default.accept_redirects)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.3.2 Disable IPv6 Redirect Acceptance (1)"
}

# Call the function to check IPv6 redirect acceptance for the default interface
check_ipv6_redirect_acceptance_default

function check_ipv6_redirect_acceptance() {
  # Execute the command to check IPv6 redirect acceptance
  output=$(sysctl net.ipv6.conf.all.accept_redirects)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.3.2 Disable IPv6 Redirect Acceptance"
}

# Call the function to check IPv6 redirect acceptance
check_ipv6_redirect_acceptance
function check_ipv6_redirect_acceptance_default() {
  # Execute the command to check IPv6 redirect acceptance for the default interface
  output=$(sysctl net.ipv6.conf.default.accept_redirects)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.3.2 Disable IPv6 Redirect Acceptance (1)"
}

# Call the function to check IPv6 redirect acceptance for the default interface
check_ipv6_redirect_acceptance_default

# Function to check if IPv6 is enabled
function check_ipv6_disabled() {
    # Execute the command to list network interfaces and IPv6 addresses
    output=$(ip addr | grep inet6)

    # Use the handle_output function to check the output and write the result
    handle_output "$output" "7.3.3 Disable IPv6"
}

# Call the function to check IPv6 status
check_ipv6_disabled
function check_tcp_wrappers_installed() {
  # Check if the package is installed
  output=$(dpkg -l tcpd)

  # If the package is not found, try installing it
  if [[ -z "$output" ]]; then
    sudo apt-get install tcpd -y
    output=$(dpkg -l tcpd)
  fi

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.4 Install TCP Wrappers"
}

# Call the function to check TCP Wrappers installation
check_tcp_wrappers_installed
function check_hosts_allow_exists() {
  # Check if the file exists
  output=$(cat /etc/hosts.allow)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.4.2 Create /etc/hosts.allow"
}

# Call the function to check /etc/hosts.allow existence
check_hosts_allow_exists
function check_hosts_allow_permissions() {
  # Execute the command to check permissions
  output=$(ls -l /etc/hosts.allow)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.4.3 Verify Permissions on /etc/hosts.allow"
}

# Call the function to check /etc/hosts.allow permissions
check_hosts_allow_permissions
function check_hosts_deny_content() {
  # Execute the command to check the content
  output=$(grep "ALL: ALL" /etc/hosts.deny)

  # Check if the output is empty
  if [[ -z "$output" ]]; then
    handle_output "" "7.4.4 Create /etc/hosts.deny"
  else
    handle_output "$output" "7.4.4 Create /etc/hosts.deny"
  fi
}

# Call the function to check /etc/hosts.deny content
check_hosts_deny_content
function check_hosts_deny_permissions() {
  # Execute the command to check permissions
  output=$(ls -l /etc/hosts.deny)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.4.5 Verify Permissions on /etc/hosts.deny"
}

# Call the function to check /etc/hosts.deny permissions
check_hosts_deny_permissions
function check_dccp_disabled() {
  # Execute the command to check for the "install dccp /bin/true" line
  output=$(grep "install dccp /bin/true" /etc/modprobe.d/CIS.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.5.1 Disable DCCP"
}

# Call the function to check DCCP disablement
check_dccp_disabled
function check_sctp_disabled() {
  # Execute the command to check for the "install sctp /bin/true" line
  output=$(grep "install sctp /bin/true" /etc/modprobe.d/CIS.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.5.2 Disable SCTP"
}

# Call the function to check SCTP disablement
check_sctp_disabled
function check_rds_disabled() {
  # Execute the command to check for the "install rds /bin/true" line
  output=$(grep "install rds /bin/true" /etc/modprobe.d/CIS.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.5.3 Disable RDS"
}

# Call the function to check RDS disablement
check_rds_disabled
function check_tipc_disabled() {
  # Execute the command to check for the "install tipc /bin/true" line
  output=$(grep "install tipc /bin/true" /etc/modprobe.d/CIS.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.5.4 Disable TIPC"
}

# Call the function to check TIPC disablement
check_tipc_disabled
function check_tipc_disabled() {
  # Execute the command to check for the "install tipc /bin/true" line
  output=$(grep "install tipc /bin/true" /etc/modprobe.d/CIS.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.5.4 Disable TIPC"
}

# Call the function to check TIPC disablement
check_tipc_disabled
function handle_output() {
  if [[ "$1" =~ "state down" ]]; then
    echo "$2 satisfied." >> satisfied.txt
  else
    echo "$2 not satisfied." >> not_satisfied.txt
  fi
}

# Function to check if wireless interfaces are deactivated
function check_wireless_interfaces_deactivated() {
  # Execute the command to list network interfaces
  output=$(ifconfig -a)

  # Check if all wireless interfaces are down
  if [[ "$output" =~ "wlan.*state down" ]]; then
    handle_output "$output" "7.6 Deactivate Wireless Interfaces"
  else
    handle_output "" "7.6 Deactivate Wireless Interfaces"
  fi
}

# Call the function to check wireless interfaces deactivation
check_wireless_interfaces_deactivated
function check_firewall_active() {
  # Execute the command to check firewall status
  output=$(ufw status)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "7.7 Ensure Firewall is Active"
}

# Call the function to check firewall status
check_firewall_active
function check_audit_log_storage_size() {
  # Execute the command to check for the "max_log_file" parameter
  output=$(grep "max_log_file" /etc/audit/auditd.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.1.1 Configure Audit Log Storage Size"
}

# Call the function to check audit log storage size configuration
check_audit_log_storage_size
function check_audit_log_full_action() {
  # Execute the command to check for the specified parameters
  output=$(grep -E "space_left_action=email|action_mail_acct=root|admin_space_left_action=halt" /etc/audit/auditd.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.1.2 Disable System on Audit Log Full"
}

# Call the function to check audit log full action configuration
check_audit_log_full_action
function check_audit_log_retention_policy() {
  # Execute the command to check for the "max_log_file_action" parameter
  output=$(grep "max_log_file_action=keep_logs" /etc/audit/auditd.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.1.3 Keep All Auditing Information"
}

# Call the function to check audit log retention policy
check_audit_log_retention_policy

function check_auditd_installed() {
  # Execute the command to check if auditd is installed
  output=$(dpkg -s auditd)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.2 Install and Enable auditd Service"
}

# Call the function to check auditd service installation
check_auditd_installed
function check_auditd_service_enabled() {
  # Execute the command to list service scripts
  output=$(ls /etc/rc*.d/S*auditd)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.2 Install and Enable auditd Service"
}

# Call the function to check auditd service enablement
check_auditd_service_enabled

function check_auditd_early_enablement() {
  # Execute the command to check for the "audit=1" parameter in the kernel command line
  output=$(grep "linux" /boot/grub/grub.cfg)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.3 Enable Auditing for Processes That Start Prior to auditd"
}

# Call the function to check auditd early enablement
check_auditd_early_enablement

function check_audit_rule_time_change() {
  # Execute the command to check for the audit rule
  output=$(grep "time-change" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.4 Record Events That Modify Date and Time Information"
}

# Call the function to check audit rule for time-change events
check_audit_rule_time_change
function check_audit_rule_user_group_info() {
  # Execute the command to check for the audit rule
  output=$(grep "identity" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.5 Record Events That Modify User/Group Information"
}

# Call the function to check audit rule for user/group information
check_audit_rule_user_group_info
function check_audit_rule_network_env() {
  # Execute the command to check for the audit rule
  output=$(grep "system-locale" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.6 Record Events That Modify the System's Network Environment"
}

# Call the function to check audit rule for network environment changes
check_audit_rule_network_env
function check_audit_rule_mac_changes() {
  # Execute the command to check for the audit rule
  output=$(grep "MAC-policy" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.7 Record Events That Modify the System's Mandatory Access Controls"
}

# Call the function to check audit rule for MAC changes
check_audit_rule_mac_changes
function check_audit_rule_login_logout() {
  # Execute the command to check for the audit rule
  output=$(grep "logins" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.8 Collect Login and Logout Events"
}

# Call the function to check audit rule for login/logout events
check_audit_rule_login_logout
function check_audit_rule_session_initiation() {
  # Execute the command to check for the audit rule
  output=$(grep "session" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.9 Collect Session Initiation Information"
}

# Call the function to check audit rule for session initiation information
check_audit_rule_session_initiation
function check_audit_rule_discretionary_access_control() {
  # Execute the command to check for the audit rule
  output=$(grep "perm_mod" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.10 Collect Discretionary Access Control Permission Modification Events"
}

# Call the function to check audit rule for discretionary access control permission modification events
check_audit_rule_discretionary_access_control
function check_audit_rule_unsuccessful_access_attempts() {
  # Execute the command to check for the audit rule
  output=$(grep "access" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.11 Collect Unsuccessful Unauthorized Access Attempts to Files"
}

# Call the function to check audit rule for unsuccessful unauthorized access attempts to files
check_audit_rule_unsuccessful_access_attempts
function check_audit_rule_privileged_commands() {
  # Execute the command to check for the audit rule
  output=$(find / -perm /6000 -type f 2>/dev/null | while read -r file; do grep -H "$file" /var/log/audit/audit.log; done)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.12 Collect Use of Privileged Commands"
}

# Call the function to check audit rule for privileged command usage
check_audit_rule_privileged_commands
function check_audit_rule_successful_file_system_mounts() {
  # Execute the command to check for the audit rule
  output=$(grep "mounts" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.13 Collect Successful File System Mounts"
}

# Call the function to check audit rule for successful file system mounts
check_audit_rule_successful_file_system_mounts
function check_audit_rule_file_deletion() {
  # Execute the command to check for the audit rule
  output=$(grep "delete" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.14 Collect File Deletion Events by User"
}

# Call the function to check audit rule for file deletion events
check_audit_rule_file_deletion
function check_audit_rule_system_administration_scope() {
  # Execute the command to check for the audit rule
  output=$(grep "scope" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.15 Collect Changes to System Administration Scope"
}

# Call the function to check audit rule for changes to system administration scope
check_audit_rule_system_administration_scope
function check_audit_rule_system_administration_actions() {
  # Execute the command to check for the audit rule
  output=$(grep "actions" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.16 Collect System Administrator Actions"
}

# Call the function to check audit rule for system administrator actions
check_audit_rule_system_administration_actions
function check_audit_rule_kernel_module_events() {
  # Execute the command to check for the audit rule
  output=$(grep "modules" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.17 Collect Kernel Module Loading and Unloading"
}

# Call the function to check audit rule for kernel module loading and unloading events
check_audit_rule_kernel_module_events
function check_audit_rule_kernel_module_events() {
  # Execute the command to check for the audit rule
  output=$(grep "modules" /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.17 Collect Kernel Module Loading and Unloading"
}

# Call the function to check audit rule for kernel module loading and unloading events
check_audit_rule_kernel_module_events
function check_audit_configuration_immutability() {
  # Execute the command to check the last line of /etc/audit/audit.rules
  output=$(tail -n 1 /etc/audit/audit.rules)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.1.18 Make the Audit Configuration Immutable"
}

# Call the function to check audit configuration immutability
check_audit_configuration_immutability
function check_rsyslog_installed() {
  # Execute the command to check rsyslog package status
  output=$(dpkg -s rsyslog)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.2.1 Install the rsyslog package"
}

# Call the function to check rsyslog package installation
check_rsyslog_installed
function check_rsyslog_service_active() {
  # Execute the command to check rsyslog service configuration
  output=$(initctl show-config rsyslog)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.2.2 Ensure the rsyslog Service is Activated"
}

# Call the function to check rsyslog service activation
check_rsyslog_service_active
function check_rsyslog_configuration() {
  # Execute the command to list the contents of /var/log/
  output=$(ls -l /var/log/)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.2.3 Configure /etc/rsyslog.conf"
}

# Call the function to check rsyslog configuration
check_rsyslog_configuration
function check_rsyslog_log_file_permissions() {
  # Execute the command to check the contents of /var/log/auth.log
  output=$(ls -l /var/log/auth.log)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.2.4 Create and Set Permissions on rsyslog Log Files"
}

# Call the function to check rsyslog log file permissions
check_rsyslog_log_file_permissions
function check_rsyslog_remote_logging() {
  # Execute the command to grep the configuration file
  output=$(grep "^.[^I][^I]*@" /etc/rsyslog.conf)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.2.5 Configure rsyslog to Send Logs to a Remote Log Host"
}

# Call the function to check remote logging configuration
check_rsyslog_remote_logging
function check_rsyslog_remote_message_acceptance() {
  # Execute the command to grep the configuration file
  output=$(grep '$ModLoad imtcp.so' /etc/rsyslog.conf)

  # Check if the line exists and if there are further restrictions on connections
  if [[ -z "$output" ]]; then
    # Line not found, no TCP listener configured - satisfied
    handle_output "$output" "8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts"
  else
    # Line found, need to check for additional configuration
    restricted=$(grep -E '^InputTCPServerRun [0-9]+$' /etc/rsyslog.conf | wc -l)
    if [[ $restricted -gt 0 ]]; then
      # Additional configuration restricts connections - satisfied
      handle_output "$output" "8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts"
    else
      # TCP listener configured without restrictions - not satisfied
      handle_output "$output" "8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts - Not Satisfied"
    fi
  fi
}

# Call the function to check remote message acceptance configuration
check_rsyslog_remote_message_acceptance
function check_rsyslog_remote_message_acceptance1() {
  # Execute the command to grep the configuration file
  output=$(grep '$InputTCPServerRun' /etc/rsyslog.conf)

  # Check if the line exists and if it matches the expected format
  if [[ "$output" =~ "$InputTCPServerRun 514" ]]; then
    handle_output "$output" "8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts"
  else
    handle_output "" "8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts"
  fi
}

# Call the function to check remote message acceptance configuration
check_rsyslog_remote_message_acceptance1

function check_aide_installed() {
  # Execute the command to check AIDE package status
  output=$(dpkg -s aide)


  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.3.1 Install AIDE"
}

# Call the function to check AIDE installation
check_aide_installed

function check_aide_periodic_execution() {
  # Execute the command to check crontab entries
  output=$(crontab -u root -l)

  # Use the handle_output function to check the output and write the result
  handle_output "$output" "8.3.2 Implement Periodic Execution of File Integrity"
}