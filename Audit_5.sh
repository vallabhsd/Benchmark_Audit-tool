#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# Audit 5: Functions and Checks

# 5.1 Ensure No Unowned Files or Directories Exist
function 5.1_ensure_no_unowned_files_or_directories() {
  output=$(find / -nouser -o -nogroup 2>/dev/null)
  handle_output "$output" "5.1 Ensure No Unowned Files or Directories Exist"
}

# 5.2 Ensure No World Writable Files Exist
function 5.2_ensure_no_world_writable_files() {
  output=$(find / -type f -perm -0002 ! -type l -exec ls -ld {} \; 2>/dev/null)
  handle_output "$output" "5.2 Ensure No World Writable Files Exist"
}

# 5.3 Ensure No World Writable Directories Exist
function 5.3_ensure_no_world_writable_directories() {
  output=$(find / -type d -perm -0007 ! -type l -exec ls -ld {} \; 2>/dev/null)
  handle_output "$output" "5.3 Ensure No World Writable Directories Exist"
}

# 5.4 Ensure Sticky Bit is Set on World Writable Directories
function 5.4_ensure_sticky_bit_set_on_world_writable_directories() {
  output=$(find / -type d -perm -1000 -exec ls -ld {} \; 2>/dev/null)
  handle_output "$output" "5.4 Ensure Sticky Bit is Set on World Writable Directories"
}

# 5.5 Ensure All Users Have a Home Directory
function 5.5_ensure_all_users_have_home_directory() {
  output=$(awk -F: '($6 == "" || $6 == "/nonexistent") {print $1}' /etc/passwd)
  handle_output "$output" "5.5 Ensure All Users Have a Home Directory"
}

# 5.6 Ensure All Users Have a Valid Shell
function 5.6_ensure_all_users_have_valid_shell() {
  output=$(awk -F: '($7 !~ /\/(bash|sh|dash|zsh)$/) {print $1}' /etc/passwd)
  handle_output "$output" "5.6 Ensure All Users Have a Valid Shell"
}

# Call all Audit 5 functions
5.1_ensure_no_unowned_files_or_directories
5.2_ensure_no_world_writable_files
5.3_ensure_no_world_writable_directories
5.4_ensure_sticky_bit_set_on_world_writable_directories
5.5_ensure_all_users_have_home_directory
5.6_ensure_all_users_have_valid_shell
