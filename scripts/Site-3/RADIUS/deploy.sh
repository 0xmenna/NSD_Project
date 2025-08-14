#!/usr/bin/env bash
set -euo pipefail

ip addr add 192.168.3.101/24 dev eth0
ip route add default via 192.168.3.1

cat /root/config/clients.conf > /etc/freeradius/3.0/clients.conf
cat /root/config/users.conf   > /etc/freeradius/3.0/users

service freeradius start

echo "RADIUS deploy complete."