#!/bin/bash

# ./portScan.sh <ip-address>

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"

if [ $1 ]; then
    ip_address=$1
    for port in $(seq 1 65535); do
        timeout 1 bash -c "echo ' ' > /dev/tcp/$ip_address/$port" && echo -e "[*] Port ${redColour}$port${endColour} - ${greenColour}OPEN${endColour}" &
    done; wait
else
    echo -e "\n[*] Use: .portScan.sh <ip_address>\n"
    exit 1
fi
