#!/bin/bash
set -e 

INSTALL_DIR="/usr/bin"
CONF_DIR="/etc/key2port"
KEYS_DIR="$CONF_DIR/keys"
LOG_DIR="/var/log/key2port"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Scanning for network interfaces"
INTERFACES=($(ip -o link show | awk -F': ' '{print $2}'))
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

echo "Available interfaces:"
for i in "${!INTERFACES[@]}"; do
    if [[ "${INTERFACES[$i]}" == "$DEFAULT_IFACE" ]]; then
        echo "  $((i+1))) ${INTERFACES[$i]} (default)"
    else
        echo "  $((i+1))) ${INTERFACES[$i]}"
    fi
done

SUGGESTED_IFACE=${DEFAULT_IFACE:-${INTERFACES[0]}}
read -p "Choose an interface [$SUGGESTED_IFACE]: " USER_INPUT

if [[ -z "$USER_INPUT" ]]; then
    FINAL_IFACE=$SUGGESTED_IFACE
elif [[ "$USER_INPUT" =~ ^[0-9]+$ ]] && [ "$USER_INPUT" -le "${#INTERFACES[@]}" ]; then
    FINAL_IFACE=${INTERFACES[$((USER_INPUT-1))]}
else
    FINAL_IFACE=$USER_INPUT
fi

echo "Using interface: $FINAL_IFACE"

echo "Setting up directories"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONF_DIR"
mkdir -p "$KEYS_DIR"

echo "Building binaries"
make clean
make DEBUG=0

echo "Installing binaries"
cp k2p-server "$INSTALL_DIR/k2p-server"
cp k2p-client "$INSTALL_DIR/k2p-client"
chmod +x "$INSTALL_DIR/k2p-server"
chmod +x "$INSTALL_DIR/k2p-client"

echo "Creating defualt config"
if [ -d conf ]; then
    cp -r conf/* "$CONF_DIR"
else 
    cp -r ../conf/* "$CONF_DIR"
fi

mkdir -p "$LOG_DIR"

if [ -f "$CONF_DIR/key2port.conf" ]; then
    sed -i "s/^interface =.*/interface = $FINAL_IFACE/" "$CONF_DIR/key2port.conf"
fi

nft add table inet key2port_filter
nft add chain inet key2port_filter input "{ type filter hook input priority -5; policy accept; }"
nft add rule inet key2port_filter input meta mark 0x99 counter accept

if [ -d /etc/nftables.d ]; then
    nft list table inet key2port_filter > /etc/nftables.d/key2port.nft
    echo "Ok: Saved persistant rules to /etc/nfttables.d/key2port.nft"
else
    echo "Warning: /etc/nftables.d not found. Add key2port_filter table to you startup script manually for persistance"
fi

echo "Installation complete. What next?"
echo "Add users public keys to $KEYS_DIR"
