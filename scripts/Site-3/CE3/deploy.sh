#!/usr/bin/env bash
set -euo pipefail


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
 ip address 10.1.3.2/30
!
interface eth1
 ip address 192.168.3.1/24
exit
!
! ---- BGP (CE3 ↔ PE R102)
router bgp 65003
 network 192.168.3.0/24
 neighbor 10.1.3.1 remote-as 100
exit
!
end
write memory
VTY

echo "CE3 deploy complete."
