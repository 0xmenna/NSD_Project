#!/usr/bin/env bash
set -euo pipefail

SUPPLICANT_CONF="${SUPPLICANT_CONF:-/root/config/b1_supplicant.conf}"

# Link up
ip link set eth0 up

# Addressing & route
ip addr add 192.168.32.101/24 dev eth0
ip route add default via 192.168.32.1 dev eth0

# Install supplicant config
cat "$SUPPLICANT_CONF" > /etc/wpa_supplicant.conf

# Start wpa_supplicant in background
# wpa_supplicant -B -c /etc/wpa_supplicant.conf -D wired -i eth0

echo "client-B1 deploy complete."
