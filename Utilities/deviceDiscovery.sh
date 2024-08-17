#!/bin/bash

# Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
purpleColour="\e[0;35m\033[1m"
redColour="\e[0;31m\033[1m"

for i in $(seq 2 254); do
    timeout 1 bash -c "ping -c 1 10.0.2.$i > /dev/null 2>&1" && echo -e "${redColour}[*]${endColour} ${purpleColour}Host 10.0.2.$i${endColour} - ${greenColour}ACTIVE${endColour}" &
done; wait
