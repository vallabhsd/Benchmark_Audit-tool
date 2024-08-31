#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# Audit 2: Functions and Checks

# 2.1 Ensure no unconfined daemons exist
function 2.1_no_unconfined_daemons() {
  output=$(ps -eZ | grep "initrc" | grep -v "tr" | awk '{print $NF}' | uniq)
  handle_output "$output" "2.1 Ensure no unconfined daemons exist"
}

# 2.2 Configure SSH Server
function 2.2_configure_ssh_server() {
  output=$(grep "^Protocol 2" /etc/ssh/sshd_config)
  handle_output "$output" "2.2 Configure SSH Server to use Protocol 2"
}

# 2.3 Disable SSH Root Login
function 2.3_disable_ssh_root_login() {
  output=$(grep "^PermitRootLogin no" /etc/ssh/sshd_config)
  handle_output "$output" "2.3 Disable SSH Root Login"
}

# 2.4 Disable SSH X11 Forwarding
function 2.4_disable_ssh_x11_forwarding() {
  output=$(grep "^X11Forwarding no" /etc/ssh/sshd_config)
  handle_output "$output" "2.4 Disable SSH X11 Forwarding"
}

# 2.5 Set SSH Idle Timeout Interval
function 2.5_set_ssh_idle_timeout() {
  output=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config)
  handle_output "$output" "2.5 Set SSH Idle Timeout Interval"
}

# 2.6 Ensure appropriate permissions on SSH configuration file
function 2.6_check_ssh_config_permissions() {
  output=$(stat /etc/ssh/sshd_config | grep "Uid: (    0/    root)   Gid: (    0/    root)")
  handle_output "$output" "2.6 Ensure appropriate permissions on SSH configuration file"
}

# 2.7 Disable Unnecessary Network Protocols
function 2.7_disable_unnecessary_network_protocols() {
  output=$(lsmod | egrep "dccp|sctp|rds|tipc")
  handle_output "$output" "2.7 Disable Unnecessary Network Protocols"
}

# 2.8 Configure IP Forwarding
function 2.8_configure_ip_forwarding() {
  output=$(sysctl net.ipv4.ip_forward | grep "0")
  handle_output "$output" "2.8 Configure IP Forwarding"
}

# 2.9 Ensure Packet Redirect Sending is Disabled
function 2.9_disable_packet_redirect() {
  output=$(sysctl net.ipv4.conf.all.send_redirects | grep "0")
  handle_output "$output" "2.9 Ensure Packet Redirect Sending is Disabled"
}

# 2.10 Disable IPv6 (if not needed)
function 2.10_disable_ipv6() {
  output=$(sysctl net.ipv6.conf.all.disable_ipv6 | grep "1")
  handle_output "$output" "2.10 Disable IPv6"
}

# Call all Audit 2 functions
2.1_no_unconfined_daemons
2.2_configure_ssh_server
2.3_disable_ssh_root_login
2.4_disable_ssh_x11_forwarding
2.5_set_ssh_idle_timeout
2.6_check_ssh_config_permissions
2.7_disable_unnecessary_network_protocols
2.8_configure_ip_forwarding
2.9_disable_packet_redirect
2.10_disable_ipv6
