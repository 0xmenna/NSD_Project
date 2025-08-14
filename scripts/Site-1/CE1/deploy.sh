#!/usr/bin/env bash
set -euo pipefail

# Ensure links are up
ip link set eth0 up
ip link set eth1 up
ip link set lo   up

# vtysh configuration
vtysh <<'VTY'
configure terminal
!
! ---- Interfaces
interface eth0
 ip address 10.1.1.2/30
!
interface eth1
 ip address 192.168.1.1/24
exit
!
! ---- BGP (CE1 ↔ PE R101)
router bgp 65001
 network 192.168.1.0/24
 neighbor 10.1.1.1 remote-as 100
exit
!
end
write memory
VTY

echo "CE1 deploy complete."
