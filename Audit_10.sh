#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# 10.1.1 Set Password Expiration Days (Scored)
function 10.1.1_check_password_expiration_days() {
  pass_max_days_output=$(grep "^PASS_MAX_DAYS" /etc/login.defs | grep "PASS_MAX_DAYS 90")
  if [[ -z "$pass_max_days_output" ]]; then
    echo "10.1.1 Set Password Expiration Days (Scored) not satisfied." >> not_satisfied.txt
  else
    echo "10.1.1 Set Password Expiration Days (Scored) satisfied." >> satisfied.txt
  fi
}

# 10.1.2 Set Password Change Minimum Number of Days (Scored)
function 10.1.2_check_password_change_min_days() {
  pass_min_days_output=$(grep "^PASS_MIN_DAYS" /etc/login.defs | grep "PASS_MIN_DAYS 7")
  if [[ -z "$pass_min_days_output" ]]; then
    echo "10.1.2 Set Password Change Minimum Number of Days (Scored) not satisfied." >> not_satisfied.txt
  else
    echo "10.1.2 Set Password Change Minimum Number of Days (Scored) satisfied." >> satisfied.txt
  fi
}

# 10.1.3 Set Password Expiring Warning Days (Scored)
function 10.1.3_check_password_expiring_warning_days() {
  pass_warn_age_output=$(grep "^PASS_WARN_AGE" /etc/login.defs | grep "PASS_WARN_AGE 7")
  if [[ -z "$pass_warn_age_output" ]]; then
    echo "10.1.3 Set Password Expiring Warning Days (Scored) not satisfied." >> not_satisfied.txt
  else
    echo "10.1.3 Set Password Expiring Warning Days (Scored) satisfied." >> satisfied.txt
  fi
}

# 10.2 Disable System Accounts (Scored)
function 10.2_check_disable_system_accounts() {
  system_accounts_output=$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}')
  if [[ -z "$system_accounts_output" ]]; then
    echo "10.2 Disable System Accounts (Scored) satisfied." >> satisfied.txt
  else
    echo "10.2 Disable System Accounts (Scored) not satisfied." >> not_satisfied.txt
  fi
}

# 10.3 Set Default Group for root Account (Scored)
function 10.3_check_default_group_root() {
  root_gid_output=$(grep "^root:" /etc/passwd | cut -f4 -d: | grep "0")
  handle_output "$root_gid_output" "10.3 Set Default Group for root Account (Scored)"
}

# 10.4 Set Default umask for Users (Scored)
function 10.4_check_default_umask() {
  umask_output=$(grep "^UMASK" /etc/login.defs | grep "UMASK 077")
  handle_output "$umask_output" "10.4 Set Default umask for Users (Scored)"
}

# 10.5 Lock Inactive User Accounts (Scored)
function 10.5_check_lock_inactive_accounts() {
  inactive_output=$(useradd -D | grep "INACTIVE=35")
  handle_output "$inactive_output" "10.5 Lock Inactive User Accounts (Scored)"
}

# Main script execution
10.1.1_check_password_expiration_days
10.1.2_check_password_change_min_days
10.1.3_check_password_expiring_warning_days
10.2_check_disable_system_accounts
10.3_check_default_group_root
10.4_check_default_umask
10.5_check_lock_inactive_accounts


echo "Review complete. Check 'satisfied.txt' and 'not_satisfied.txt' for details."
