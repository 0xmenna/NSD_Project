#!/usr/bin/env bash
set -euo pipefail

# Ensure links up
ip link set eth0 up
ip link set eth1 up
ip link set eth2 up
ip link set lo   up

# Create a virtual bridge and attach three interfaces:
# one connected to the router and two connected to client devices in their respective VLANs.
ip link add br0 type bridge
ip link set br0 up
ip link set dev eth0 master br0
ip link set dev eth1 master br0
ip link set dev eth2 master br0

# Assign an IP address to the virtual bridge interface.
# This IP is the one associated to the RADIUS client.
ip addr add 192.168.2.100/24 dev br0
ip route add default via 192.168.2.1

# Configure default ACL policies
ebtables -F
ebtables -P FORWARD DROP
ebtables -P INPUT ACCEPT
ebtables -P OUTPUT ACCEPT

# Port towards the router is enabled
ebtables -A FORWARD -i eth0 -j ACCEPT

# Enable EAPoL fwd
echo 8 > /sys/class/net/br0/bridge/group_fwd_mask

# Enable vlan on bridge interface
ip link set dev br0 type bridge vlan_filtering 1

cat /root/config/hostapd.conf > /etc/hostapd/hostapd.conf
