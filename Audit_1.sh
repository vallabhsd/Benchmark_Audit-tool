#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# Audit 1: Functions and Checks

# 1.1 Install Updates, Patches and Additional Security Software
function 1.1_check_updates_and_security() {
  sudo apt-get update
  output=$(sudo apt-get --just-print upgrade)
  handle_output "$output" "1.1 Install Updates, Patches and Additional Security Software"
}

# 1.2 Configure Automatic Updates
function 1.2_configure_automatic_updates() {
  output=$(grep "^APT::Periodic::Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades)
  handle_output "$output" "1.2 Configure Automatic Updates"
}

# 1.3 Disable the Login Service (if not needed)
function 1.3_disable_login_service() {
  output=$(systemctl is-enabled login | grep "disabled")
  handle_output "$output" "1.3 Disable the Login Service"
}

# 1.4 Ensure sudo commands use tty
function 1.4_ensure_sudo_uses_tty() {
  output=$(grep -E '^[^#]*Defaults[[:space:]]+requiretty' /etc/sudoers)
  handle_output "$output" "1.4 Ensure sudo commands use tty"
}

# 1.5 Restrict core dumps
function 1.5_restrict_core_dumps() {
  output=$(grep -E '^[^#]*hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf)
  handle_output "$output" "1.5 Restrict core dumps"
}

# 1.6 Configure SELinux
function 1.6_configure_selinux() {
  output=$(sestatus | grep "enabled")
  handle_output "$output" "1.6 Configure SELinux"
}

# 1.7 Configure AppArmor
function 1.7_configure_apparmor() {
  output=$(apparmor_status | grep "profiles are in enforce mode")
  handle_output "$output" "1.7 Configure AppArmor"
}

# 1.8 Verify Time Synchronization is in use
function 1.8_verify_time_sync() {
  output=$(timedatectl | grep "NTP synchronized: yes")
  handle_output "$output" "1.8 Verify Time Synchronization is in use"
}

# 1.9 Disable unused filesystems
function 1.9_disable_unused_filesystems() {
  output=$(lsmod | grep "cramfs\|freevxfs\|jffs2\|hfs\|hfsplus\|squashfs\|udf")
  handle_output "$output" "1.9 Disable unused filesystems"
}

# 1.10 Ensure no legacy services are running
function 1.10_no_legacy_services() {
  output=$(chkconfig --list 2>/dev/null | egrep 'xinetd|telnet|rsh|rlogin|rexec')
  handle_output "$output" "1.10 Ensure no legacy services are running"
}

# Call all Audit 1 functions
1.1_check_updates_and_security
1.2_configure_automatic_updates
1.3_disable_login_service
1.4_ensure_sudo_uses_tty
1.5_restrict_core_dumps
1.6_configure_selinux
1.7_configure_apparmor
1.8_verify_time_sync
1.9_disable_unused_filesystems
1.10_no_legacy_services
