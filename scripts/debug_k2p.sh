#!/bin/bash

# check the nftables
if nft list table inet k2p_filter > /dev/null 2>&1; then
    echo "[OK] nftables 'k2p_filter' table exists."
    HITS=$(nft list table inet k2p_filter | grep "0x99" | awk '{print $7}')
    echo "     -> Total authorized packets passed: $HITS"
else
    echo "Error: 'k2p_filter' table missing! run scripts/install.sh."
fi

# check for active ones
if nft list table inet key2port > /dev/null 2>&1; then
    echo "Ok: nftables 'key2port' table exists."
    ELEMENTS=$(nft list set inet key2port temp_allowed | grep -c "\.")
    if [ "$ELEMENTS" -gt 0 ]; then
        echo "Ok: There are currently $ELEMENTS authorized IP(s) in the set."
        nft list set inet key2port temp_allowed | grep "\."
    else
        echo "Idle: No active authorizations at the moment"
    fi
else
    echo "info: 'key2port' table has not been created yet"
fi
