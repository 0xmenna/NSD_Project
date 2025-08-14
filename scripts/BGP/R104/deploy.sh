#!/usr/bin/env bash
set -euo pipefail

MPLS_CONF="${MPLS_CONF:-/root/config/R104_mpls.conf}"

# MPLS sysctls
sysctl -p "$MPLS_CONF"

# Ensure links up
ip link set eth0 up
ip link set eth1 up
ip link set eth2 up
ip link set lo   up

# vtysh configuration
vtysh <<'VTY'
configure terminal
!
! ---- Interfaces
interface eth0
 ip address 10.0.100.2/30
!
interface eth1
 ip address 10.0.100.6/30
!
interface eth2
 ip address 10.0.100.10/30
!
interface lo
 ip address 1.255.0.4/32
exit
!
! ---- OSPF
router ospf
 ospf router-id 1.255.0.4
 network 1.255.0.4/32 area 0
 network 10.0.100.0/30 area 0
 network 10.0.100.4/30 area 0
 network 10.0.100.8/30 area 0
exit
!
! ---- LDP
mpls ldp
 router-id 1.255.0.4
 ordered-control
 address-family ipv4
  discovery transport-address 1.255.0.4
  interface eth0
  interface eth1
  interface eth2
  interface lo
 exit
exit
!
end
write memory
VTY

echo "R104 deploy complete."
