#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# Audit 3: Functions and Checks

# 3.1 Set Password Expiration Days
function 3.1_set_password_expiration_days() {
  output=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}' | grep -E "^[0-9]{1,3}$")
  handle_output "$output" "3.1 Set Password Expiration Days"
}

# 3.2 Set Password Minimum Days
function 3.2_set_password_minimum_days() {
  output=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}' | grep -E "^[0-9]{1,3}$")
  handle_output "$output" "3.2 Set Password Minimum Days"
}

# 3.3 Set Password Expiry Warning Days
function 3.3_set_password_expiry_warning_days() {
  output=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}' | grep -E "^[0-9]{1,3}$")
  handle_output "$output" "3.3 Set Password Expiry Warning Days"
}

# 3.4 Ensure Inactive Password Lock is 30 Days or Less
function 3.4_ensure_inactive_password_lock() {
  output=$(useradd -D | grep "^INACTIVE" | grep -E "[0-9]+" | awk -F= '{print $2}')
  handle_output "$output" "3.4 Ensure Inactive Password Lock is 30 Days or Less"
}

# 3.5 Ensure All Users' Home Directories Exist
function 3.5_ensure_users_home_directories_exist() {
  output=$(awk -F: '{ print $1 " " $6 }' /etc/passwd | while read user dir; do if [ ! -d "$dir" ]; then echo $user; fi; done)
  handle_output "$output" "3.5 Ensure All Users' Home Directories Exist"
}

# 3.6 Ensure All Users' Home Directories are Owned by the User
function 3.6_ensure_home_directories_owned_by_user() {
  output=$(awk -F: '{ print $1 " " $6 }' /etc/passwd | while read user dir; do if [ -d "$dir" ]; then owner=$(ls -ld $dir | awk '{print $3}'); if [ "$owner" != "$user" ]; then echo $user; fi; fi; done)
  handle_output "$output" "3.6 Ensure All Users' Home Directories are Owned by the User"
}

# 3.7 Ensure No Duplicate UIDs Exist
function 3.7_ensure_no_duplicate_uids() {
  output=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
  handle_output "$output" "3.7 Ensure No Duplicate UIDs Exist"
}

# 3.8 Ensure No Duplicate GIDs Exist
function 3.8_ensure_no_duplicate_gids() {
  output=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
  handle_output "$output" "3.8 Ensure No Duplicate GIDs Exist"
}

# 3.9 Ensure No Duplicate Usernames Exist
function 3.9_ensure_no_duplicate_usernames() {
  output=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
  handle_output "$output" "3.9 Ensure No Duplicate Usernames Exist"
}

# 3.10 Ensure No Duplicate Group Names Exist
function 3.10_ensure_no_duplicate_groupnames() {
  output=$(awk -F: '{print $1}' /etc/group | sort | uniq -d)
  handle_output "$output" "3.10 Ensure No Duplicate Group Names Exist"
}

# Call all Audit 3 functions
3.1_set_password_expiration_days
3.2_set_password_minimum_days
3.3_set_password_expiry_warning_days
3.4_ensure_inactive_password_lock
3.5_ensure_users_home_directories_exist
3.6_ensure_home_directories_owned_by_user
3.7_ensure_no_duplicate_uids
3.8_ensure_no_duplicate_gids
3.9_ensure_no_duplicate_usernames
3.10_ensure_no_duplicate_groupnames
