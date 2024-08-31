#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# 12.1 Verify Permissions on /etc/passwd (Scored)
function 12.1_verify_passwd_permissions() {
  passwd_permissions=$(ls -l /etc/passwd | awk '{print $1}')
  if [[ "$passwd_permissions" == "-rw-r--r--" ]]; then
    echo "12.1 Verify Permissions on /etc/passwd (Scored) satisfied." >> satisfied.txt
  else
    echo "12.1 Verify Permissions on /etc/passwd (Scored) not satisfied." >> not_satisfied.txt
    chmod 644 /etc/passwd
  fi
}

# 12.2 Verify Permissions on /etc/shadow (Scored)
function 12.2_verify_shadow_permissions() {
  shadow_permissions=$(ls -l /etc/shadow | awk '{print $1}')
  if [[ "$shadow_permissions" == "-rw-r-----" ]]; then
    echo "12.2 Verify Permissions on /etc/shadow (Scored) satisfied." >> satisfied.txt
  else
    echo "12.2 Verify Permissions on /etc/shadow (Scored) not satisfied." >> not_satisfied.txt
    chmod o-rwx,g-rw /etc/shadow
  fi
}

# 12.3 Verify Permissions on /etc/group (Scored)
function 12.3_verify_group_permissions() {
  group_permissions=$(ls -l /etc/group | awk '{print $1}')
  if [[ "$group_permissions" == "-rw-r--r--" ]]; then
    echo "12.3 Verify Permissions on /etc/group (Scored) satisfied." >> satisfied.txt
  else
    echo "12.3 Verify Permissions on /etc/group (Scored) not satisfied." >> not_satisfied.txt
    chmod 644 /etc/group
  fi
}

# 12.4 Verify User/Group Ownership on /etc/passwd (Scored)
function 12.4_verify_passwd_ownership() {
  passwd_owner=$(ls -l /etc/passwd | awk '{print $3":"$4}')
  if [[ "$passwd_owner" == "root:root" ]]; then
    echo "12.4 Verify User/Group Ownership on /etc/passwd (Scored) satisfied." >> satisfied.txt
  else
    echo "12.4 Verify User/Group Ownership on /etc/passwd (Scored) not satisfied." >> not_satisfied.txt
    chown root:root /etc/passwd
  fi
}

# 12.5 Verify User/Group Ownership on /etc/shadow (Scored)
function 12.5_verify_shadow_ownership() {
  shadow_owner=$(ls -l /etc/shadow | awk '{print $3":"$4}')
  if [[ "$shadow_owner" == "root:shadow" || "$shadow_owner" == "root:root" ]]; then
    echo "12.5 Verify User/Group Ownership on /etc/shadow (Scored) satisfied." >> satisfied.txt
  else
    echo "12.5 Verify User/Group Ownership on /etc/shadow (Scored) not satisfied." >> not_satisfied.txt
    chown root:shadow /etc/shadow
  fi
}

# 12.6 Verify User/Group Ownership on /etc/group (Scored)
function 12.6_verify_group_ownership() {
  group_owner=$(ls -l /etc/group | awk '{print $3":"$4}')
  if [[ "$group_owner" == "root:root" ]]; then
    echo "12.6 Verify User/Group Ownership on /etc/group (Scored) satisfied." >> satisfied.txt
  else
    echo "12.6 Verify User/Group Ownership on /etc/group (Scored) not satisfied." >> not_satisfied.txt
    chown root:root /etc/group
  fi
}

# 12.7 Find World Writable Files (Not Scored)
function 12.7_find_world_writable_files() {
  world_writable_files=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print)
  if [[ -n "$world_writable_files" ]]; then
    echo "12.7 Find World Writable Files (Not Scored) found files." >> not_satisfied.txt
    echo "$world_writable_files" >> world_writable_files.txt
  else
    echo "12.7 Find World Writable Files (Not Scored) no files found." >> satisfied.txt
  fi
}

# 12.8 Find Un-owned Files and Directories (Scored)
function 12.8_find_unowned_files() {
  unowned_files=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser -ls)
  if [[ -n "$unowned_files" ]]; then
    echo "12.8 Find Un-owned Files and Directories (Scored) found files." >> not_satisfied.txt
    echo "$unowned_files" >> unowned_files.txt
  else
    echo "12.8 Find Un-owned Files and Directories (Scored) no files found." >> satisfied.txt
  fi
}

# 12.9 Find Un-grouped Files and Directories (Scored)
function 12.9_find_ungrouped_files() {
  ungrouped_files=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup -ls)
  if [[ -n "$ungrouped_files" ]]; then
    echo "12.9 Find Un-grouped Files and Directories (Scored) found files." >> not_satisfied.txt
    echo "$ungrouped_files" >> ungrouped_files.txt
  else
    echo "12.9 Find Un-grouped Files and Directories (Scored) no files found." >> satisfied.txt
  fi
}

# 12.10 Find SUID System Executables (Not Scored)
function 12.10_find_suid_executables() {
  suid_executables=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)
  if [[ -n "$suid_executables" ]]; then
    echo "12.10 Find SUID System Executables (Not Scored) found executables." >> not_satisfied.txt
    echo "$suid_executables" >> suid_executables.txt
  else
    echo "12.10 Find SUID System Executables (Not Scored) no executables found." >> satisfied.txt
  fi
}

# 12.11 Find SGID System Executables (Not Scored)
function 12.11_find_sgid_executables() {
  sgid_executables=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print)
  if [[ -n "$sgid_executables" ]]; then
    echo "12.11 Find SGID System Executables (Not Scored) found executables." >> not_satisfied.txt
    echo "$sgid_executables" >> sgid_executables.txt
  else
    echo "12.11 Find SGID System Executables (Not Scored) no executables found." >> satisfied.txt
  fi
}

# Main script execution
12.1_verify_passwd_permissions
12.2_verify_shadow_permissions
12.3_verify_group_permissions
12.4_verify_passwd_ownership
12.5_verify_shadow_ownership
12.6_verify_group_ownership
12.7_find_world_writable_files
12.8_find_unowned_files
12.9_find_ungrouped_files
12.10_find_suid_executables
12.11_find_sgid_executables


echo "Review complete. Check 'satisfied.txt' and 'not_satisfied.txt' for details."
