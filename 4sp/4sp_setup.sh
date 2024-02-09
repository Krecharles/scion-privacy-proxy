#!/bin/bash

# Prompt for source IPv4 with options for defaults, accommodating lowercase inputs
echo "Enter the source IP address you want to use (Enter 'A' for the 172.16.11.1 default, 'B' for the 172.16.12.1 default, or enter a custom IP):"
read SRC_IPV4_CHOICE

SRC_IPV4_CHOICE=$(echo "$SRC_IPV4_CHOICE" | tr '[:lower:]' '[:upper:]') # Convert to uppercase for consistency

# Automatically set destination based on source selection and inform the user
case $SRC_IPV4_CHOICE in
    A)
        SRC_IPV4="172.16.11.1"
        DEST_IPV4="172.16.12.0/24" # Default B for dest
        echo "Source IP set to 172.16.11.1. Destination IP automatically set to 172.16.12.0/24."
        ;;
    B)
        SRC_IPV4="172.16.12.1"
        DEST_IPV4="172.16.11.0/24" # Default A for dest
        echo "Source IP set to 172.16.12.1. Destination IP automatically set to 172.16.11.0/24."
        ;;
    *)
        SRC_IPV4=$SRC_IPV4_CHOICE
        echo "Enter the destination IP address:"
        read DEST_IPV4
        ;;
esac

# Prompt for the destination SCION address
echo "Enter the destination SCION address (e.g., 19-ffaa:1:10fb):"
read DEST_SCION_ADDRESS

# Prompt for number_of_paths_n
echo "Enter the number of paths N:"
read NUMBER_OF_PATHS_N

# Prompt for number_of_paths_t
echo "Enter the number of paths T:"
read NUMBER_OF_PATHS_T

# Generate the configuration file 4sp.toml
cat <<EOF >4sp.toml
[gateway]
traffic_policy_file = "./4sp.json"

[metrics]
prometheus = "127.0.0.1:30456"

[log.console]
level = "info"

[tunnel]
src_ipv4 = "$SRC_IPV4" 
number_of_paths_n = $NUMBER_OF_PATHS_N
number_of_paths_t = $NUMBER_OF_PATHS_T
aes_key = "157cf3aa823cfc5ab5bada84fdd3c31ef7b2a7be710f999e48a6037d427c5d6b"
EOF

# Generate the traffic policy file 4sp.json
cat <<EOF >4sp.json
{
    "ASes": {
        "$DEST_SCION_ADDRESS": {
            "Nets": [
                "$DEST_IPV4"
            ]
        }
    },
    "ConfigVersion": 9001
}
EOF

echo "Configuration file (4sp.toml) and traffic policy file (4sp.json) generated successfully."

# Add the source IP address to the loopback interface
echo "Add the source IP address to the loopback interface"
sudo ip address add $SRC_IPV4 dev lo  # script needs sudo for this
