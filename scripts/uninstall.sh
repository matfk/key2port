#!/bin/bash
echo "Uninstalling key2port"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

pkill k2p-server || true

INSTALL_DIR="/usr/bin"
CONF_DIR="/etc/key2port"
LOG_DIR="/var/log/key2port"

echo "Cleaning up config"
rm -rf "$CONF_DIR"
rm -rf "$LOG_DIR"
rm "$INSTALL_DIR/k2p-server"
rm "$INSTALL_DIR/k2p-client"

echo "Cleaning up nftables"
nft delete table inet key2port_filter 2>/dev/null || true
nft delete table inet key2port 2>/dev/null || true

if [ -f /etc/nftables.d/key2port.nft ]; then
    rm /etc/nftables.d/key2port.nft
    echo "Removed /etc/nftables.d/key2port.nft"
fi

echo "Uninstall complete"
