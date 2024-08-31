#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# Audit 4: Functions and Checks

# 4.1 Ensure Permissions on /etc/passwd are Configured
function 4.1_ensure_permissions_on_etc_passwd() {
  output=$(stat -L -c "%a %u %g" /etc/passwd | grep "644 0 0")
  handle_output "$output" "4.1 Ensure Permissions on /etc/passwd are Configured"
}

# 4.2 Ensure Permissions on /etc/shadow are Configured
function 4.2_ensure_permissions_on_etc_shadow() {
  output=$(stat -L -c "%a %u %g" /etc/shadow | grep "0 0 0")
  handle_output "$output" "4.2 Ensure Permissions on /etc/shadow are Configured"
}

# 4.3 Ensure Permissions on /etc/group are Configured
function 4.3_ensure_permissions_on_etc_group() {
  output=$(stat -L -c "%a %u %g" /etc/group | grep "644 0 0")
  handle_output "$output" "4.3 Ensure Permissions on /etc/group are Configured"
}

# 4.4 Ensure Permissions on /etc/gshadow are Configured
function 4.4_ensure_permissions_on_etc_gshadow() {
  output=$(stat -L -c "%a %u %g" /etc/gshadow | grep "0 0 0")
  handle_output "$output" "4.4 Ensure Permissions on /etc/gshadow are Configured"
}

# 4.5 Ensure Permissions on /etc/passwd- are Configured
function 4.5_ensure_permissions_on_etc_passwd_dash() {
  output=$(stat -L -c "%a %u %g" /etc/passwd- | grep "600 0 0")
  handle_output "$output" "4.5 Ensure Permissions on /etc/passwd- are Configured"
}

# 4.6 Ensure Permissions on /etc/shadow- are Configured
function 4.6_ensure_permissions_on_etc_shadow_dash() {
  output=$(stat -L -c "%a %u %g" /etc/shadow- | grep "0 0 0")
  handle_output "$output" "4.6 Ensure Permissions on /etc/shadow- are Configured"
}

# 4.7 Ensure Permissions on /etc/group- are Configured
function 4.7_ensure_permissions_on_etc_group_dash() {
  output=$(stat -L -c "%a %u %g" /etc/group- | grep "600 0 0")
  handle_output "$output" "4.7 Ensure Permissions on /etc/group- are Configured"
}

# 4.8 Ensure Permissions on /etc/gshadow- are Configured
function 4.8_ensure_permissions_on_etc_gshadow_dash() {
  output=$(stat -L -c "%a %u %g" /etc/gshadow- | grep "0 0 0")
  handle_output "$output" "4.8 Ensure Permissions on /etc/gshadow- are Configured"
}

# Call all Audit 4 functions
4.1_ensure_permissions_on_etc_passwd
4.2_ensure_permissions_on_etc_shadow
4.3_ensure_permissions_on_etc_group
4.4_ensure_permissions_on_etc_gshadow
4.5_ensure_permissions_on_etc_passwd_dash
4.6_ensure_permissions_on_etc_shadow_dash
4.7_ensure_permissions_on_etc_group_dash
4.8_ensure_permissions_on_etc_gshadow_dash
