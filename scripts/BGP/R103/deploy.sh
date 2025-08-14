#!/usr/bin/env bash
set -euo pipefail

MPLS_CONF="${MPLS_CONF:-/root/config/R103_mpls.conf}"

# VRF
ip link add mainVPN type vrf table 10
ip link set mainVPN up
ip link set eth0 master mainVPN

# MPLS sysctls
sysctl -p "$MPLS_CONF"

# Ensure links up
ip link set eth0 up
ip link set eth1 up
ip link set lo up

# vtysh configuration
vtysh <<'VTY'
configure terminal
!
! ---- Interfaces
interface eth0
 ip address 10.1.2.1/30
!
interface eth1
 ip address 10.0.100.9/30
!
interface lo
 ip address 1.255.0.3/32
exit
!
! ---- OSPF
router ospf
 ospf router-id 1.255.0.3
 network 1.255.0.3/32 area 0
 network 10.0.100.8/30 area 0
exit
!
! ---- LDP
mpls ldp
 router-id 1.255.0.3
 ordered-control
 address-family ipv4
  discovery transport-address 1.255.0.3
  interface eth1
  interface lo
 exit
exit
!
! ---- iBGP core (AS 100)
router bgp 100
 bgp router-id 1.255.0.3
 !
 neighbor 1.255.0.1 remote-as 100
 neighbor 1.255.0.1 update-source 1.255.0.3
 neighbor 1.255.0.2 remote-as 100
 neighbor 1.255.0.2 update-source 1.255.0.3
 !
 address-family ipv4 unicast
  neighbor 1.255.0.1 next-hop-self
  neighbor 1.255.0.2 next-hop-self
 address-family ipv4 vpn
  neighbor 1.255.0.1 activate
  neighbor 1.255.0.1 next-hop-self
  neighbor 1.255.0.2 activate
  neighbor 1.255.0.2 next-hop-self
 exit
exit
!
! ---- VRF mainVPN (CE-PE)
router bgp 100 vrf mainVPN
  address-family ipv4
    neighbor 10.1.2.2 remote-as 65002
exit
!
! ---- RD & RT
router bgp 100 vrf mainVPN
 address-family ipv4 unicast
  redistribute static
  label vpn export auto
  rd vpn export 100:0
  rt vpn import 100:1
  rt vpn export 100:2
  export vpn
  import vpn
 exit
exit
!
end
write memory
VTY

echo "R103 deploy complete."
