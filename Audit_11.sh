#!/bin/bash

# Function to handle output based on conditions
function handle_output() {
  if [[ -z "$1" ]]; then
    echo "$2 not satisfied." >> not_satisfied.txt
  else
    echo "$2 satisfied." >> satisfied.txt
  fi
}

# 11.1 Set Warning Banner for Standard Login Services (Scored)
function 11.1_check_warning_banners() {
  motd_output=$(ls -l /etc/motd | grep "-rw-r--r--")
  issue_output=$(ls -l /etc/issue | grep "-rw-r--r--")
  issue_net_output=$(ls -l /etc/issue.net | grep "-rw-r--r--")

  if [[ -n "$motd_output" ]] && [[ -n "$issue_output" ]] && [[ -n "$issue_net_output" ]]; then
    motd_contents=$(cat /etc/motd)
    issue_contents=$(cat /etc/issue)
    issue_net_contents=$(cat /etc/issue.net)

    if [[ "$motd_contents" =~ "Authorized uses only. All activity may be monitored and reported." ]] &&
       [[ "$issue_contents" =~ "Authorized uses only. All activity may be monitored and reported." ]] &&
       [[ "$issue_net_contents" =~ "Authorized uses only. All activity may be monitored and reported." ]]; then
      echo "11.1 Set Warning Banner for Standard Login Services (Scored) satisfied." >> satisfied.txt
    else
      echo "11.1 Set Warning Banner for Standard Login Services (Scored) not satisfied." >> not_satisfied.txt
    fi
  else
    echo "11.1 Set Warning Banner for Standard Login Services (Scored) not satisfied." >> not_satisfied.txt
  fi
}

# 11.2 Remove OS Information from Login Warning Banners (Scored)
function 11.2_check_remove_os_info() {
  issue_check=$(egrep '(\\v|\\r|\\m|\\s)' /etc/issue)
  motd_check=$(egrep '(\\v|\\r|\\m|\\s)' /etc/motd)
  issue_net_check=$(egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net)

  if [[ -z "$issue_check" ]] && [[ -z "$motd_check" ]] && [[ -z "$issue_net_check" ]]; then
    echo "11.2 Remove OS Information from Login Warning Banners (Scored) satisfied." >> satisfied.txt
  else
    echo "11.2 Remove OS Information from Login Warning Banners (Scored) not satisfied." >> not_satisfied.txt
  fi
}

# 11.3 Set Graphical Warning Banner (Not Scored)
function 11.3_check_graphical_warning_banner() {
  if [[ -n $(pgrep -x "lightdm") ]]; then
    echo "11.3 Set Graphical Warning Banner (Not Scored) check needed for lightdm." >> not_satisfied.txt
    # Additional checks or instructions for lightdm would go here
  elif [[ -n $(pgrep -x "gdm") ]] || [[ -n $(pgrep -x "kdm") ]]; then
    echo "11.3 Set Graphical Warning Banner (Not Scored) check needed for GNOME Display Manager or KDM." >> not_satisfied.txt
    # Additional checks or instructions for GNOME Display Manager or KDM would go here
  else
    echo "11.3 Set Graphical Warning Banner (Not Scored) graphical display manager not found." >> not_satisfied.txt
  fi
}

# Main script execution
11.1_check_warning_banners
11.2_check_remove_os_info
11.3_check_graphical_warning_banner


echo "Review complete. Check 'satisfied.txt' and 'not_satisfied.txt' for details."
