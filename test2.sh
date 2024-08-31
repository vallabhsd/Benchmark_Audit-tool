#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# Function to check for updates and security software
function 1.1_check_updates_and_security() {
  sudo apt-get update

  output=$(sudo apt-get --just-print upgrade)

  handle_output "$output" "1.1 Install Updates, Patches and Additional Security Software"
}

# Function to check for a separate /tmp partition
function 2.1_check_tmp_partition() {
  output=$(grep "[[:space:]]/tmp[[:space:]]" /etc/fstab)

  handle_output "$output" "2.1 Create Separate Partition for /tmp"
}

# Function to check for nodev option in /tmp
function 2.2_check_tmp_nodev() {
  fstab_output=$(grep /tmp /etc/fstab | grep nodev)
  mount_output=$(mount | grep /tmp | grep nodev)

  handle_output "$fstab_output$mount_output" "2.2 Set nodev option for /tmp Partition"
}

# Function to check for nosuid option in /tmp
function 2.3_check_tmp_nosuid() {
  fstab_output=$(grep /tmp /etc/fstab | grep nosuid)
  mount_output=$(mount | grep /tmp | grep nosuid)

  handle_output "$fstab_output$mount_output" "2.3 Set nosuid option for /tmp Partition"
}

# Function to check for noexec option in /tmp
function 2.4_check_tmp_noexec() {
  fstab_output=$(grep /tmp /etc/fstab | grep noexec)
  mount_output=$(mount | grep /tmp | grep noexec)

  handle_output "$fstab_output$mount_output" "2.4 Set noexec option for /tmp Partition"
}

# Function to check for a separate /var partition
function 2.5_check_var_partition() {
  output=$(grep "[[:space:]]/var[[:space:]]" /etc/fstab)

  handle_output "$output" "2.5 Create Separate Partition for /var"
}

# Function to check for a bind mount of /var/tmp to /tmp
function 2.6_check_var_tmp_bind_mount() {
  fstab_output=$(grep -e "^/tmp" /etc/fstab | grep /var/tmp)
  mount_output=$(mount | grep -e "^/tmp" | grep /var/tmp)

  handle_output "$fstab_output$mount_output" "2.6 Bind Mount the /var/tmp directory to /tmp"
}

# Function to check for a separate /var/log partition
function 2.7_check_var_log_partition() {
  output=$(grep "[[:space:]]/var/log[[:space:]]" /etc/fstab)

  handle_output "$output" "2.7 Create Separate Partition for /var/log"
}

# Function to check for a separate /var/log/audit partition
function 2.8_check_var_log_audit_partition() {
  output=$(grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab)

  handle_output "$output" "2.8 Create Separate Partition for /var/log/audit"
}

# Function to check for a separate /home partition (Scored)
function 2.9_check_home_partition() {
  output=$(grep "[[:space:]]/home[[:space:]]" /etc/fstab)

  handle_output "$output" "2.9 Create Separate Partition for /home (Scored)"
}

# Function to check for nodev option in /home
function 2.10_check_home_nodev() {
  fstab_output=$(grep /home /etc/fstab | grep nodev)
  mount_output=$(mount | grep /home | grep nodev)

  handle_output "$fstab_output$mount_output" "2.10 Add nodev option to /home Partition"
}

# Function to check for nodev option in removable media partitions
function 2.11_check_removable_media_nodev() {
  removable_media_mountpoints=("/media/cdrom" "/media/usb" "/media/floppy" "/media/dvdrom")  # Add more mountpoints as needed

  for mountpoint in "${removable_media_mountpoints[@]}"; do
    fstab_output=$(grep "$mountpoint" /etc/fstab | grep nodev)
    mount_output=$(mount | grep "$mountpoint" | grep nodev)

    if [[ -z "$fstab_output" || -z "$mount_output" ]]; then
      echo "2.11 Add nodev option to Removable Media Partitions not satisfied." >> not_satisfied.txt
      break
    fi
  done

  if [[ -z "$fstab_output" || -z "$mount_output" ]]; then
    echo "2.11 Add nodev option to Removable Media Partitions satisfied." >> satisfied.txt
  fi
}

# Main script execution
1.1_check_updates_and_security
2.1_check_tmp_partition
2.2_check_tmp_nodev
2.3_check_tmp_nosuid
2.4_check_tmp_noexec
2.5_check_var_partition
2.6_check_var_tmp_bind_mount
2.7_check_var_log_partition
2.8_check_var_log_audit_partition
2.9_check_home_partition
2.10_check_home_nodev
2.11_check_removable_media_nodev
