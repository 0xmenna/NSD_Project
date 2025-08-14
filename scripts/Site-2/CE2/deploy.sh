#!/usr/bin/env bash
set -euo pipefail

TRUNK_IF="${TRUNK_IF:-eth1}"

# Ensure links up
ip link set eth0 up
ip link set eth1 up
ip link set lo   up

# vtysh configuration
vtysh <<'VTY'
configure terminal
!
! ---- Interfaces
interface eth0
 ip address 10.1.2.2/30
!
interface eth1
 ip address 192.168.2.1/24
exit
!
! ---- BGP (CE2 ↔ PE R103)
router bgp 65002
 network 192.168.2.0/24
 network 192.168.32.0/24
 network 192.168.95.0/24
 neighbor 10.1.2.1 remote-as 100
exit
!
end
write memory
VTY

# VLANs
declare -A VLAN_IPS=(
  [32]="192.168.32.1/24"
  [95]="192.168.95.1/24"
)

for vid in "${!VLAN_IPS[@]}"; do
  ip link add link "${TRUNK_IF}" name "${TRUNK_IF}.${vid}" type vlan id "${vid}"
  ip link set "${TRUNK_IF}.${vid}" up
  ip addr add "${VLAN_IPS[$vid]}" dev "${TRUNK_IF}.${vid}"
done

echo "CE2 deploy complete."
