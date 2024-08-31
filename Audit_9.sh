#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# 9.1.2 Set User/Group Owner and Permission on /etc/crontab (Scored)
function 9.1.2_check_crontab_permissions() {
  output=$(stat -c "%a %u %g" /etc/crontab | egrep ".00 0 0")
  handle_output "$output" "9.1.2 Set User/Group Owner and Permission on /etc/crontab (Scored)"
}

# 9.1.3 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)
function 9.1.3_check_cron_hourly_permissions() {
  output=$(stat -c "%a %u %g" /etc/cron.hourly | egrep ".00 0 0")
  handle_output "$output" "9.1.3 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)"
}

# 9.1.4 Set User/Group Owner and Permission on /etc/cron.daily (Scored)
function 9.1.4_check_cron_daily_permissions() {
  output=$(stat -c "%a %u %g" /etc/cron.daily | egrep ".00 0 0")
  handle_output "$output" "9.1.4 Set User/Group Owner and Permission on /etc/cron.daily (Scored)"
}

# 9.1.5 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)
function 9.1.5_check_cron_weekly_permissions() {
  output=$(stat -c "%a %u %g" /etc/cron.weekly | egrep ".00 0 0")
  handle_output "$output" "9.1.5 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)"
}

# 9.1.6 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)
function 9.1.6_check_cron_monthly_permissions() {
  output=$(stat -c "%a %u %g" /etc/cron.monthly | egrep ".00 0 0")
  handle_output "$output" "9.1.6 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)"
}

# 9.1.7 Set User/Group Owner and Permission on /etc/cron.d (Scored)
function 9.1.7_check_cron_d_permissions() {
  output=$(stat -c "%a %u %g" /etc/cron.d | egrep ".00 0 0")
  handle_output "$output" "9.1.7 Set User/Group Owner and Permission on /etc/cron.d (Scored)"
}

# 9.1.8 Restrict at/cron to Authorized Users (Scored)
function 9.1.8_restrict_cron_at_users() {
  output1=$(ls -l /etc/cron.deny)
  output2=$(ls -l /etc/at.deny)
  output3=$(ls -l /etc/cron.allow | grep "^-rw------- 1 root root")
  output4=$(ls -l /etc/at.allow | grep "^-rw------- 1 root root")

  handle_output "$output1" "9.1.8 Restrict at/cron to Authorized Users (cron.deny)"
  handle_output "$output2" "9.1.8 Restrict at/cron to Authorized Users (at.deny)"
  handle_output "$output3" "9.1.8 Restrict at/cron to Authorized Users (cron.allow)"
  handle_output "$output4" "9.1.8 Restrict at/cron to Authorized Users (at.allow)"
}

# 9.2.1 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)
function 9.2.1_check_pam_cracklib() {
  output=$(grep "pam_cracklib.so" /etc/pam.d/common-password | grep "retry=3" | grep "minlen=14" | grep "dcredit=-1" | grep "ucredit=-1" | grep "ocredit=-1" | grep "lcredit=-1")
  handle_output "$output" "9.2.1 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)"
}

# 9.2.2 Set Lockout for Failed Password Attempts (Not Scored)
function 9.2.2_check_lockout_for_failed_attempts() {
  output=$(grep "pam_tally2.so" /etc/pam.d/login | grep "auth required" | grep "onerr=fail" | grep "audit silent" | grep "deny=5" | grep "unlock_time=900")
  handle_output "$output" "9.2.2 Set Lockout for Failed Password Attempts (Not Scored)"
}

# 9.2.3 Limit Password Reuse (Scored)
function 9.2.3_check_password_reuse_limit() {
  output=$(grep "remember=5" /etc/pam.d/common-password | grep "pam_unix.so")
  handle_output "$output" "9.2.3 Limit Password Reuse (Scored)"
}

# 9.3.1 Set SSH Protocol to 2 (Scored)
function 9.3.1_check_ssh_protocol() {
  output=$(grep "^Protocol" /etc/ssh/sshd_config | grep "Protocol 2")
  handle_output "$output" "9.3.1 Set SSH Protocol to 2 (Scored)"
}

# 9.3.2 Set LogLevel to INFO (Scored)
function 9.3.2_check_ssh_loglevel() {
  output=$(grep "^LogLevel" /etc/ssh/sshd_config | grep "LogLevel INFO")
  handle_output "$output" "9.3.2 Set LogLevel to INFO (Scored)"
}

# 9.3.3 Set Permissions on /etc/ssh/sshd_config (Scored)
function 9.3.3_check_ssh_config_permissions() {
  output=$(ls -l /etc/ssh/sshd_config | grep "^-rw------- 1 root root")
  handle_output "$output" "9.3.3 Set Permissions on /etc/ssh/sshd_config (Scored)"
}

# 9.3.4 Disable SSH X11 Forwarding (Scored)
function 9.3.4_check_ssh_x11_forwarding() {
  output=$(grep "^X11Forwarding" /etc/ssh/sshd_config | grep "X11Forwarding no")
  handle_output "$output" "9.3.4 Disable SSH X11 Forwarding (Scored)"
}

# 9.3.5 Set SSH MaxAuthTries to 4 or Less (Scored)
function 9.3.5_check_ssh_max_auth_tries() {
  output=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | grep "MaxAuthTries 4")
  handle_output "$output" "9.3.5 Set SSH MaxAuthTries to 4 or Less (Scored)"
}


# 9.3.6 Set SSH IgnoreRhosts to Yes (Scored)
function 9.3.6_check_ssh_ignore_rhosts() {
  output=$(grep "^IgnoreRhosts" /etc/ssh/sshd_config | grep "IgnoreRhosts yes")
  handle_output "$output" "9.3.6 Set SSH IgnoreRhosts to Yes (Scored)"
}

# 9.3.7 Set SSH HostbasedAuthentication to No (Scored)
function 9.3.7_check_ssh_hostbased_authentication() {
  output=$(grep "^HostbasedAuthentication" /etc/ssh/sshd_config | grep "HostbasedAuthentication no")
  handle_output "$output" "9.3.7 Set SSH HostbasedAuthentication to No (Scored)"
}

# 9.3.8 Disable SSH Root Login (Scored)
function 9.3.8_check_ssh_root_login() {
  output=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | grep "PermitRootLogin no")
  handle_output "$output" "9.3.8 Disable SSH Root Login (Scored)"
}

# 9.3.9 Set SSH PermitEmptyPasswords to No (Scored)
function 9.3.9_check_ssh_permit_empty_passwords() {
  output=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | grep "PermitEmptyPasswords no")
  handle_output "$output" "9.3.9 Set SSH PermitEmptyPasswords to No (Scored)"
}

# 9.3.10 Do Not Allow Users to Set Environment Options (Scored)
function 9.3.10_check_ssh_user_environment() {
  output=$(grep "^PermitUserEnvironment" /etc/ssh/sshd_config | grep "PermitUserEnvironment no")
  handle_output "$output" "9.3.10 Do Not Allow Users to Set Environment Options (Scored)"
}

# 9.3.11 Use Only Approved Cipher in Counter Mode (Scored)
function 9.3.11_check_ssh_ciphers() {
  output=$(grep "^Ciphers" /etc/ssh/sshd_config | grep "Ciphers aes128-ctr,aes192-ctr,aes256-ctr")
  handle_output "$output" "9.3.11 Use Only Approved Cipher in Counter Mode (Scored)"
}

# 9.3.12 Set Idle Timeout Interval for User Login (Scored)
function 9.3.12_check_ssh_idle_timeout() {
  interval_output=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config | grep "ClientAliveInterval 300")
  count_output=$(grep "^ClientAliveCountMax" /etc/ssh/sshd_config | grep "ClientAliveCountMax 0")
  if [[ -z "$interval_output" ]] || [[ -z "$count_output" ]]; then
    echo "9.3.12 Set Idle Timeout Interval for User Login (Scored) not satisfied." >> not_satisfied.txt
  else
    echo "9.3.12 Set Idle Timeout Interval for User Login (Scored) satisfied." >> satisfied.txt
  fi
}

# 9.3.13 Limit Access via SSH (Scored)
function 9.3.13_check_ssh_limit_access() {
  allow_users_output=$(grep "^AllowUsers" /etc/ssh/sshd_config)
  allow_groups_output=$(grep "^AllowGroups" /etc/ssh/sshd_config)
  deny_users_output=$(grep "^DenyUsers" /etc/ssh/sshd_config)
  deny_groups_output=$(grep "^DenyGroups" /etc/ssh/sshd_config)
  if [[ -z "$allow_users_output" && -z "$allow_groups_output" && -z "$deny_users_output" && -z "$deny_groups_output" ]]; then
    echo "9.3.13 Limit Access via SSH (Scored) not satisfied." >> not_satisfied.txt
  else
    echo "9.3.13 Limit Access via SSH (Scored) satisfied." >> satisfied.txt
  fi
}

# 9.3.14 Set SSH Banner (Scored)
function 9.3.14_check_ssh_banner() {
  output=$(grep "^Banner" /etc/ssh/sshd_config | grep -E "Banner /etc/issue|Banner /etc/issue.net")
  handle_output "$output" "9.3.14 Set SSH Banner (Scored)"
}


# 9.4 Restrict Root Login to System Console (Not Scored)
function 9.4_check_restrict_root_console() {
  output=$(cat /etc/securetty)
  if [[ -z "$output" ]]; then
    echo "9.4 Restrict Root Login to System Console (Not Scored) not satisfied." >> not_satisfied.txt
  else
    echo "9.4 Restrict Root Login to System Console (Not Scored) satisfied." >> satisfied.txt
  fi
}


# 9.5 Restrict Access to the su Command (Scored)
function 9.5_check_restrict_su_command() {
  pam_wheel_output=$(grep "pam_wheel.so" /etc/pam.d/su | grep "auth required pam_wheel.so use_uid")
  wheel_group_output=$(grep "^wheel" /etc/group | grep "wheel:x:10:root")
  if [[ -z "$pam_wheel_output" ]] || [[ -z "$wheel_group_output" ]]; then
    echo "9.5 Restrict Access to the su Command (Scored) not satisfied." >> not_satisfied.txt
  else
    echo "9.5 Restrict Access to the su Command (Scored) satisfied." >> satisfied.txt
  fi
}


# Main script execution
9.1.2_check_crontab_permissions
9.1.3_check_cron_hourly_permissions
9.1.4_check_cron_daily_permissions
9.1.5_check_cron_weekly_permissions
9.1.6_check_cron_monthly_permissions
9.1.7_check_cron_d_permissions
9.1.8_restrict_cron_at_users
9.2.1_check_pam_cracklib
9.2.2_check_lockout_for_failed_attempts
9.2.3_check_password_reuse_limit
9.3.1_check_ssh_protocol
9.3.2_check_ssh_loglevel
9.3.3_check_ssh_config_permissions
9.3.4_check_ssh_x11_forwarding
9.3.5_check_ssh_max_auth_tries
9.3.6_check_ssh_ignore_rhosts
9.3.7_check_ssh_hostbased_authentication
9.3.8_check_ssh_root_login
9.3.9_check_ssh_permit_empty_passwords
9.3.10_check_ssh_user_environment
9.3.11_check_ssh_ciphers
9.3.12_check_ssh_idle_timeout
9.3.13_check_ssh_limit_access
9.3.14_check_ssh_banner
9.4_check_restrict_root_console
9.5_check_restrict_su_command


echo "Review complete. Check 'satisfied.txt' and 'not_satisfied.txt' for details."
