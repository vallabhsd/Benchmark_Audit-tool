#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# Audit 6: Functions and Checks

# 6.1 Ensure Boot Loader Configuration is Secure
function 6.1_ensure_boot_loader_configuration_secure() {
  output=$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT' /etc/default/grub | grep 'quiet')
  handle_output "$output" "6.1 Ensure Boot Loader Configuration is Secure"
}

# 6.2 Ensure the System is Set to Automatically Update
function 6.2_ensure_system_auto_update() {
  output=$(grep -E '^APT::Periodic::Update-Package-Lists' /etc/apt/apt.conf.d/10periodic)
  handle_output "$output" "6.2 Ensure the System is Set to Automatically Update"
}

# 6.3 Ensure Firewall is Installed and Enabled
function 6.3_ensure_firewall_installed_and_enabled() {
  output=$(systemctl is-active ufw)
  handle_output "$output" "6.3 Ensure Firewall is Installed and Enabled"
}

# 6.4 Ensure Unnecessary Services are Disabled
function 6.4_ensure_unnecessary_services_disabled() {
  output=$(systemctl list-units --type=service --state=running | grep -E 'telnet|ftp')
  handle_output "$output" "6.4 Ensure Unnecessary Services are Disabled"
}

# 6.5 Ensure SSH Daemon is Configured Securely
function 6.5_ensure_ssh_daemon_configured_securely() {
  output=$(grep -E '^PermitRootLogin no' /etc/ssh/sshd_config)
  handle_output "$output" "6.5 Ensure SSH Daemon is Configured Securely"
}

# 6.6 Ensure Automatic Updates for Security Packages are Enabled
function 6.6_ensure_automatic_updates_for_security() {
  output=$(grep -E '^APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades)
  handle_output "$output" "6.6 Ensure Automatic Updates for Security Packages are Enabled"
}

# 6.7 Ensure System Time is Synchronized
function 6.7_ensure_system_time_synchronized() {
  output=$(systemctl is-active systemd-timesyncd)
  handle_output "$output" "6.7 Ensure System Time is Synchronized"
}

# 6.8 Ensure System is Configured to Use a Valid Certificate Authority
function 6.8_ensure_system_valid_certificate_authority() {
  output=$(grep -E 'certificate-authority' /etc/ca-certificates.conf)
  handle_output "$output" "6.8 Ensure System is Configured to Use a Valid Certificate Authority"
}

# 6.9 Ensure User Accounts Have Proper Permissions
function 6.9_ensure_user_accounts_permissions() {
  output=$(awk -F: '($3 < 1000) {print $1}' /etc/passwd)
  handle_output "$output" "6.9 Ensure User Accounts Have Proper Permissions"
}

# 6.10 Ensure Log Files are Rotated
function 6.10_ensure_log_files_rotated() {
  output=$(grep -E '^/var/log/' /etc/logrotate.conf)
  handle_output "$output" "6.10 Ensure Log Files are Rotated"
}

# 6.11 Ensure /tmp is Mounted with Noexec Option
function 6.11_ensure_tmp_noexec_option() {
  output=$(mount | grep '/tmp' | grep 'noexec')
  handle_output "$output" "6.11 Ensure /tmp is Mounted with Noexec Option"
}

# 6.12 Ensure /var is Mounted with Nodev Option
function 6.12_ensure_var_nodev_option() {
  output=$(mount | grep '/var' | grep 'nodev')
  handle_output "$output" "6.12 Ensure /var is Mounted with Nodev Option"
}

# 6.13 Ensure /home is Mounted with Nosuid Option
function 6.13_ensure_home_nosuid_option() {
  output=$(mount | grep '/home' | grep 'nosuid')
  handle_output "$output" "6.13 Ensure /home is Mounted with Nosuid Option"
}

# 6.14 Ensure Unused Filesystems are Not Mounted
function 6.14_ensure_unused_filesystems_not_mounted() {
  output=$(cat /etc/fstab | grep -E 'proc|sysfs|tmpfs|devpts')
  handle_output "$output" "6.14 Ensure Unused Filesystems are Not Mounted"
}

# 6.15 Ensure SELinux is Installed and Enabled
function 6.15_ensure_selinux_installed_and_enabled() {
  output=$(sestatus | grep 'SELinux status' | grep 'enabled')
  handle_output "$output" "6.15 Ensure SELinux is Installed and Enabled"
}

# 6.16 Ensure Core Dumps are Disabled
function 6.16_ensure_core_dumps_disabled() {
  output=$(grep -E '^core' /etc/security/limits.conf)
  handle_output "$output" "6.16 Ensure Core Dumps are Disabled"
}

# 6.17 Ensure System Accounts are Locked
function 6.17_ensure_system_accounts_locked() {
  output=$(awk -F: '($3 < 1000 && $7 == "/usr/sbin/nologin") {print $1}' /etc/passwd)
  handle_output "$output" "6.17 Ensure System Accounts are Locked"
}

# Call all Audit 6 functions
6.1_ensure_boot_loader_configuration_secure
6.2_ensure_system_auto_update
6.3_ensure_firewall_installed_and_enabled
6.4_ensure_unnecessary_services_disabled
6.5_ensure_ssh_daemon_configured_securely
6.6_ensure_automatic_updates_for_security
6.7_ensure_system_time_synchronized
6.8_ensure_system_valid_certificate_authority
6.9_ensure_user_accounts_permissions
6.10_ensure_log_files_rotated
6.11_ensure_tmp_noexec_option
6.12_ensure_var_nodev_option
6.13_ensure_home_nosuid_option
6.14_ensure_unused_filesystems_not_mounted
6.15_ensure_selinux_installed_and_enabled
6.16_ensure_core_dumps_disabled
6.17_ensure_system_accounts_locked
