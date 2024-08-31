#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# 13.1 Ensure Password Fields are Not Empty (Scored)
function 13.1_verify_password_fields() {
  empty_passwords=$(cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}')
  handle_output "$empty_passwords" "13.1 Ensure Password Fields are Not Empty (Scored)"
  if [[ -n "$empty_passwords" ]]; then
    echo "$empty_passwords" >> empty_passwords.txt
    for user in $(echo "$empty_passwords" | awk '{print $1}'); do
      passwd -l $user
    done
  fi
}

# 13.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)
function 13.2_verify_passwd_plus_entries() {
  plus_entries=$(grep '^+:' /etc/passwd)
  handle_output "$plus_entries" "13.2 Verify No Legacy \"+\" Entries Exist in /etc/passwd File (Scored)"
  if [[ -n "$plus_entries" ]]; then
    echo "$plus_entries" >> passwd_plus_entries.txt
    sed -i '/^+:/d' /etc/passwd
  fi
}

# 13.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)
function 13.3_verify_shadow_plus_entries() {
  plus_entries=$(grep '^+:' /etc/shadow)
  handle_output "$plus_entries" "13.3 Verify No Legacy \"+\" Entries Exist in /etc/shadow File (Scored)"
  if [[ -n "$plus_entries" ]]; then
    echo "$plus_entries" >> shadow_plus_entries.txt
    sed -i '/^+:/d' /etc/shadow
  fi
}

# 13.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)
function 13.4_verify_group_plus_entries() {
  plus_entries=$(grep '^+:' /etc/group)
  handle_output "$plus_entries" "13.4 Verify No Legacy \"+\" Entries Exist in /etc/group File (Scored)"
  if [[ -n "$plus_entries" ]]; then
    echo "$plus_entries" >> group_plus_entries.txt
    sed -i '/^+:/d' /etc/group
  fi
}

# 13.5 Verify No UID 0 Accounts Exist Other Than root (Scored)
function 13.5_verify_uid_0_accounts() {
  uid_0_accounts=$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }')
  handle_output "$uid_0_accounts" "13.5 Verify No UID 0 Accounts Exist Other Than root (Scored)"
  if [[ -n "$uid_0_accounts" && "$uid_0_accounts" != "root" ]]; then
    echo "$uid_0_accounts" >> uid_0_accounts.txt
    for account in $(echo "$uid_0_accounts"); do
      userdel $account
    done
  fi
}

# 13.6 Ensure root PATH Integrity (Scored)
function 13.6_verify_root_path_integrity() {
  path=$(echo $PATH)
  empty_dir=$(echo $PATH | grep '::')
  trailing_colon=$(echo $PATH | grep ':$')
  if [[ -n "$empty_dir" || -n "$trailing_colon" ]]; then
    echo "13.6 Ensure root PATH Integrity (Scored) not satisfied." >> not_satisfied.txt
  else
    echo "13.6 Ensure root PATH Integrity (Scored) satisfied." >> satisfied.txt
  fi

  IFS=':' read -r -a path_array <<< "$PATH"
  for dir in "${path_array[@]}"; do
    if [[ "$dir" == "." ]]; then
      echo "PATH contains ." >> not_satisfied.txt
    elif [[ -d "$dir" ]]; then
      dirperm=$(ls -ldH "$dir" | cut -f1 -d" ")
      if [[ "$(echo $dirperm | cut -c6)" != "-" ]]; then
        echo "Group Write permission set on directory $dir" >> not_satisfied.txt
      fi
      if [[ "$(echo $dirperm | cut -c9)" != "-" ]]; then
        echo "Other Write permission set on directory $dir" >> not_satisfied.txt
      fi
      if [[ "$(ls -ldH "$dir" | awk '{print $3}')" != "root" ]]; then
        echo "$dir is not owned by root" >> not_satisfied.txt
      fi
    else
      echo "$dir is not a directory" >> not_satisfied.txt
    fi
  done
}

# 13.7 Check Permissions on User Home Directories (Scored)
function 13.7_verify_home_directory_permissions() {
  home_dirs=$(cat /etc/passwd | grep -vE '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }')
  for dir in $home_dirs; do
    if [[ -d "$dir" ]]; then
      dirperm=$(ls -ld "$dir" | cut -f1 -d" ")
      if [[ "$(echo $dirperm | cut -c6)" != "-" ]]; then
        echo "Group Write permission set on directory $dir" >> not_satisfied.txt
      fi
      if [[ "$(echo $dirperm | cut -c8)" != "-" ]]; then
        echo "Other Read permission set on directory $dir" >> not_satisfied.txt
      fi
      if [[ "$(echo $dirperm | cut -c9)" != "-" ]]; then
        echo "Other Write permission set on directory $dir" >> not_satisfied.txt
      fi
      if [[ "$(echo $dirperm | cut -c10)" != "-" ]]; then
        echo "Other Execute permission set on directory $dir" >> not_satisfied.txt
      fi
    fi
  done
}

# 13.8 Check User Dot File Permissions (Scored)
function 13.8_verify_dot_file_permissions() {
  home_dirs=$(cat /etc/passwd | grep -vE '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }')
  for dir in $home_dirs; do
    for file in $dir/.[A-Za-z0-9]*; do
      if [[ -f "$file" && ! -h "$file" ]]; then
        fileperm=$(ls -ld "$file" | cut -f1 -d" ")
        if [[ "$(echo $fileperm | cut -c6)" != "-" ]]; then
          echo "Group Write permission set on file $file" >> not_satisfied.txt
        fi
        if [[ "$(echo $fileperm | cut -c9)" != "-" ]]; then
          echo "Other Write permission set on file $file" >> not_satisfied.txt
        fi
      fi
    done
  done
}

# 13.9 Check Permissions on User .netrc Files (Scored)
function 13.9_verify_netrc_permissions() {
  home_dirs=$(cat /etc/passwd | grep -vE '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }')
  for dir in $home_dirs; do
    for file in $dir/.netrc; do
      if [[ -f "$file" && ! -h "$file" ]]; then
        fileperm=$(ls -ld "$file" | cut -f1 -d" ")
        if [[ "$(echo $fileperm | cut -c5)" != "-" ]]; then
          echo "Group Read set on $file" >> not_satisfied.txt
        fi
        if [[ "$(echo $fileperm | cut -c6)" != "-" ]]; then
          echo "Group Write set on $file" >> not_satisfied.txt
        fi
        if [[ "$(echo $fileperm | cut -c7)" != "-" ]]; then
          echo "Group Execute set on $file" >> not_satisfied.txt
        fi
        if [[ "$(echo $fileperm | cut -c8)" != "-" ]]; then
          echo "Other Read set on $file" >> not_satisfied.txt
        fi
        if [[ "$(echo $fileperm | cut -c9)" != "-" ]]; then
          echo "Other Write set on $file" >> not_satisfied.txt
        fi
        if [[ "$(echo $fileperm | cut -c10)" != "-" ]]; then
          echo "Other Execute set on $file" >> not_satisfied.txt
        fi
      fi
    done
  done
}

# 13.10 Check for Presence of User .rhosts Files (Scored)
function 13.10_verify_rhosts_files() {
  home_dirs=$(cat /etc/passwd | grep -vE '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }')
  for dir in $home_dirs; do
    for file in $dir/.rhosts; do
      if [[ -f "$file" && ! -h "$file" ]]; then
        echo ".rhosts file in $dir" >> not_satisfied.txt
      fi
    done
  done
}

# 13.11 Check Groups in /etc/passwd (Scored)
function 13.11_verify_groups_in_passwd() {
  for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
    grep -q -P "^.*?:[^:]*:$i:" /etc/group
    if [ $? -ne 0 ]; then
      echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> not_satisfied.txt
    fi
  done
}

# 13.12 Check That Users Are Assigned Valid Home Directories (Scored)
function 13.12_verify_home_directories() {
  cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
    if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" -a $user != "nobody" ]; then
      echo "The home directory ($dir) of user $user does not exist." >> not_satisfied.txt
    fi
  done
}

# 13.13 Check User Home Directory Ownership (Scored)
function 13.13_verify_home_directory_ownership() {
  cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
    if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
      owner=$(stat -L -c "%U" "$dir")
      if [ "$owner" != "$user" ]; then
        echo "The home directory ($dir) of user $user is owned by $owner." >> not_satisfied.txt
      fi
    fi
  done
}

# 13.14 Check for Duplicate UIDs (Scored)
function 13.14_check_duplicate_uids() {
  /bin/cat /etc/passwd | /usr/bin/cut -f3 -d":" | /usr/bin/sort -n | /usr/bin/uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
      users=`/usr/bin/awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | /usr/bin/xargs`
      echo "Duplicate UID ($2): ${users}" >> not_satisfied.txt
    fi
  done
}

# 13.15 Check for Duplicate GIDs (Scored)
function 13.15_check_duplicate_gids() {
  /bin/cat /etc/group | /usr/bin/cut -f3 -d":" | /usr/bin/sort -n | /usr/bin/uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
      grps=`/usr/bin/awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
      echo "Duplicate GID ($2): ${grps}" >> not_satisfied.txt
    fi
  done
}

# 13.16 Check for Duplicate User Names (Scored)
function 13.16_check_duplicate_usernames() {
  cat /etc/passwd | /usr/bin/cut -f1 -d":" | /usr/bin/sort -n | /usr/bin/uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
      uids=`/usr/bin/awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
      echo "Duplicate User Name ($2): ${uids}" >> not_satisfied.txt
    fi
  done
}

# 13.17 Check for Duplicate Group Names (Scored)
function 13.17_check_duplicate_groupnames() {
  cat /etc/group | /usr/bin/cut -f1 -d":" | /usr/bin/sort -n | /usr/bin/uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
      gids=`/usr/bin/awk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
      echo "Duplicate Group Name ($2): ${gids}" >> not_satisfied.txt
    fi
  done
}

# 13.18 Check for Presence of User .netrc Files (Scored)
function 13.18_check_netrc_files() {
  home_dirs=$(cat /etc/passwd | grep -vE '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }')
  for dir in $home_dirs; do
    for file in $dir/.netrc; do
      if [[ -f "$file" && ! -h "$file" ]]; then
        echo ".netrc file $file exists" >> not_satisfied.txt
      fi
    done
  done
}

# 13.19 Check for Presence of User .forward Files (Scored)
function 13.19_check_forward_files() {
  home_dirs=$(cat /etc/passwd | grep -vE '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }')
  for dir in $home_dirs; do
    for file in $dir/.forward; do
      if [[ -f "$file" && ! -h "$file" ]]; then
        echo ".forward file $file exists" >> not_satisfied.txt
      fi
    done
  done
}

# 13.20 Ensure shadow group is empty (Scored)
function 13.20_ensure_shadow_group_empty() {
  shadow_gid=$(grep ^shadow /etc/group | cut -d: -f3)
  if [[ -n "$shadow_gid" ]]; then
    users_in_shadow=$(awk -F: -v gid="$shadow_gid" '($4 == gid) { print $1 }' /etc/passwd)
    if [[ -n "$users_in_shadow" ]]; then
      echo "Users with shadow group as primary group: $users_in_shadow" >> not_satisfied.txt
    fi
  fi
}

# Run all functions
13.1_verify_password_fields
13.2_verify_passwd_plus_entries
13.3_verify_shadow_plus_entries
13.4_verify_group_plus_entries
13.5_verify_uid_0_accounts
13.6_verify_root_path_integrity
13.7_verify_home_directory_permissions
13.8_verify_dot_file_permissions
13.9_verify_netrc_permissions
13.10_verify_rhosts_files
13.11_verify_groups_in_passwd
13.12_verify_home_directories
13.13_verify_home_directory_ownership
13.14_check_duplicate_uids
13.15_check_duplicate_gids
13.16_check_duplicate_usernames
13.17_check_duplicate_groupnames
13.18_check_netrc_files
13.19_check_forward_files
13.20_ensure_shadow_group_empty

echo "Review complete. Check 'satisfied.txt' and 'not_satisfied.txt' for details."
