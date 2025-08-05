# Network and System Defense Project


## Network Topology

### TODO: insert topology image

---


## Network Configuration

### AS100: BGP/MPLS VPN Backbone

AS100 is configured as the provider backbone for the customer VPN.

#### Requirements

* **FRRouting** installed on all routers.
* Access to the **`vtysh` CLI tool** to manage FRR daemons.
* Kernel modules for MPLS:

  * `mpls-router`
  * `mpls-iptunnel`

To load modules on boot, add to `/etc/modules`:

```text
mpls-router
mpls-iptunnel
```

#### 1. R101 Configuration

Most considerations made to R101 also apply to the other border routers (R102 and R103).

##### 1.1 Interfaces

```text
interface eth0
 ip address 10.1.1.1/30
exit
!
interface eth1
 ip address 10.0.100.1/30
exit
!
interface lo
 ip address 1.255.0.1/32
exit
!
```

##### 1.2 OSPF

```text
router ospf
 ospf router-id 1.255.0.1
 network 1.255.0.1/32 area 0
 network 10.0.100.0/30 area 0
exit
!
```

##### 1.3 VRF

Define the VRF to properly manage the traffic related to the sites of the customer VPN.

```text
ip link add mainVPN type vrf table 10
ip link set mainVPN up
ip link set eth0 master mainVPN
```

##### 1.4 MPLS Setup

Set the following parameters to the mpls kernel level modules.

`R101_mpls.conf`:

```text
net.mpls.conf.lo.input = 1
net.mpls.conf.eth1.input = 1
net.mpls.conf.mainVPN.input = 1
net.mpls.platform_labels = 100000
```

```bash
sysctl -p R101_mpls.conf
```

##### 1.5 LDP

This configuration enables label distribution toward the core network via eth1, specifies the loopback interface and the discovery address used at the transport level.
```text
mpls ldp
 router-id 1.255.0.1
 ordered-control
 address-family ipv4
  discovery transport-address 1.255.0.1
  interface eth1
  interface lo
 exit
exit
!
```

##### 1.6 iBGP Core Peering
R101 is a border router, therefore we must configure iBGP to route traffic towards other edge routers to reach the different customer sites.

This configuration forms an overlay newtork between border routers to properly manage routing internally, within AS100. Each border router must know each other.

```text
router bgp 100
 bgp router-id 1.255.0.1

 neighbor 1.255.0.2 remote-as 100
 neighbor 1.255.0.2 update-source 1.255.0.1
 neighbor 1.255.0.3 remote-as 100
 neighbor 1.255.0.3 update-source 1.255.0.1

 address-family ipv4 unicast
  neighbor 1.255.0.2 next-hop-self
  neighbor 1.255.0.3 next-hop-self
 exit

 address-family ipv4 vpn
  neighbor 1.255.0.2 activate
  neighbor 1.255.0.2 next-hop-self
  neighbor 1.255.0.3 activate
  neighbor 1.255.0.3 next-hop-self
 exit
exit
!
```

##### 1.7 CE-PE Dynamic Routing

The following configuration allows to route traffic dynamically between the customer edge and the provider edge, without requiring a less flexible static configuration.
```text
router bgp 100 vrf mainVPN
 address-family ipv4
  neighbor 10.1.1.2 remote-as 65001
 exit
exit
!
```

##### 1.8 RD & RT
This configuration defines:

- A route destinguisher to make potentially overlapping IPv4 addresses from different VPNs unique within the MPLS VPN backbone.

- A route target is configured to enable the Spoke-Hub topology by controlling how VPN routes are imported and exported between sites, ensuring that spokes can communicate only through the hub. Since R101 is the PE for Site 1, it imports routes exported by the hub PE and exports its own routes to the hub. This setup ensures that the hub PE maintains awareness of each spoke’s routing information, while spokes remain isolated from one another and are hub dependent.

```text
router bgp 100 vrf mainVPN
 address-family ipv4 unicast
  label vpn export auto
  rd vpn export 100:0
  rt vpn import 100:1
  rt vpn export 100:2
  export vpn
  import vpn
 exit
exit
!
```


#### 2. R102 Configuration

##### 2.1 Interfaces

```text
interface eth0
 ip address 10.1.3.1/30
exit
!
interface eth1
 ip address 10.0.100.5/30
exit
!
interface lo
 ip address 1.255.0.2/32
exit
!
```

##### 2.2 OSPF

```text
router ospf
 ospf router-id 1.255.0.2
 network 1.255.0.2/32 area 0
 network 10.0.100.4/30 area 0
exit
!
```

##### 2.3 VRF

```text
ip link add mainVPN type vrf table 10
ip link set mainVPN up
ip link set eth0 master mainVPN
```

##### 2.4 MPLS Setup

`R102_mpls.conf`:

```text
net.mpls.conf.lo.input = 1
net.mpls.conf.eth1.input = 1
net.mpls.conf.mainVPN.input = 1
net.mpls.platform_labels = 100000
```

Apply:

```bash
sysctl -p R102_mpls.conf
```

##### 2.5 LDP

```text
mpls ldp
 router-id 1.255.0.2
 ordered-control
 address-family ipv4
  discovery transport-address 1.255.0.2
  interface eth1
  interface lo
 exit
exit
!
```

##### 2.6 iBGP Core Peering

```text
router bgp 100
 bgp router-id 1.255.0.2

 neighbor 1.255.0.1 remote-as 100
 neighbor 1.255.0.1 update-source 1.255.0.2
 neighbor 1.255.0.3 remote-as 100
 neighbor 1.255.0.3 update-source 1.255.0.2

 address-family ipv4 unicast
  neighbor 1.255.0.1 next-hop-self
  neighbor 1.255.0.3 next-hop-self
 exit

 address-family ipv4 vpn
  neighbor 1.255.0.1 activate
  neighbor 1.255.0.1 next-hop-self
  neighbor 1.255.0.3 activate
  neighbor 1.255.0.3 next-hop-self
 exit
exit
!
```

##### 2.7 CE-PE Dynamic Routing

```text
router bgp 100 vrf mainVPN
 address-family ipv4
  neighbor 10.1.3.2 remote-as 65003
 exit
exit
!
```

##### 2.8 Spoke-Spoke Communication
This configuration is required to ensure that spokes are reachable through the hub PE. The hub PE exports a default route to the spokes, so when a spoke tries to communicate with the other, its PE does not have a specific route to the destination PE, but it does have the default route pointing to the hub. The hub PE, in turn, holds the necessary routes to all spokes and can forward traffic accordingly.

```text
! This just ensures that the default route exists in the VRF.
ip route 0.0.0.0/0 Null0 vrf mainVPN
router bgp 100 vrf mainVPN
    address-family ipv4 unicast
        network 0.0.0.0/0
    exit
exit

```

##### 2.9 RD & RT

In this configuration, the hub PE imports all routes received from the spoke PEs and exports its default route to the spokes.

```text
router bgp 100 vrf mainVPN
 address-family ipv4 unicast
  label vpn export auto
  rd vpn export 100:0
  rt vpn import 100:2
  rt vpn export 100:1
  export vpn
  import vpn
 exit
exit
!
```


#### 3. R103 Configuration

##### 3.1 Interfaces

```text
interface eth0
 ip address 10.1.2.1/30
exit
!
interface eth1
 ip address 10.0.100.9/30
exit
!
interface lo
 ip address 1.255.0.3/32
exit
!
```

##### 3.2 OSPF

```text
router ospf
 ospf router-id 1.255.0.3
 network 1.255.0.3/32 area 0
 network 10.0.100.8/30 area 0
exit
!
```

##### 3.3 VRF

```text
ip link add mainVPN type vrf table 10
ip link set mainVPN up
ip link set eth0 master mainVPN
```

##### 3.4 MPLS Setup

`R103_mpls.conf`:

```text
net.mpls.conf.lo.input = 1
net.mpls.conf.eth1.input = 1
net.mpls.conf.mainVPN.input = 1
net.mpls.platform_labels = 100000
```

Apply:

```bash
sysctl -p R103_mpls.conf
```

##### 3.5 LDP

```text
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
```

##### 3.6 iBGP Core Peering

```text
router bgp 100
 bgp router-id 1.255.0.3

 neighbor 1.255.0.1 remote-as 100
 neighbor 1.255.0.1 update-source 1.255.0.3
 neighbor 1.255.0.2 remote-as 100
 neighbor 1.255.0.2 update-source 1.255.0.3

 address-family ipv4 unicast
  neighbor 1.255.0.1 next-hop-self
  neighbor 1.255.0.2 next-hop-self
 exit

 address-family ipv4 vpn
  neighbor 1.255.0.1 activate
  neighbor 1.255.0.1 next-hop-self
  neighbor 1.255.0.2 activate
  neighbor 1.255.0.2 next-hop-self
 exit
exit
!
```

##### 3.7 CE-PE Dynamic Routing

```text
router bgp 100 vrf mainVPN
 address-family ipv4
  neighbor 10.1.2.2 remote-as 65002
 exit
exit
!
```

##### 3.8 RD & RT

```text
router bgp 100 vrf mainVPN
 address-family ipv4 unicast
  label vpn export auto
  rd vpn export 100:0
  rt vpn import 100:1
  rt vpn export 100:2
  export vpn
  import vpn
 exit
exit
!
```


#### 4. R104 Configuration

R104 does not require iBGP peering configuration, as it operates purely as a core (P) router. It only needs to participate in OSPF and LDP; MPLS label switching will handle the transit traffic. Routing between provider edges (PEs) traverses R104 using MPLS labels, with no need for local BGP routing and VPN awareness.

##### 4.1 Interfaces

```text
interface eth0
 ip address 10.0.100.2/30
exit
!
interface eth1
 ip address 10.0.100.6/30
exit
!
interface eth2
 ip address 10.0.100.10/30
exit
!
interface lo
 ip address 1.255.0.4/32
exit
!
```

##### 4.2 OSPF

```text
router ospf
 ospf router-id 1.255.0.4
 network 1.255.0.4/32 area 0
 network 10.0.100.0/30 area 0
 network 10.0.100.4/30 area 0
 network 10.0.100.8/30 area 0
exit
!
```

##### 4.3 MPLS Parameters

`R104_mpls.conf`:

```text
net.mpls.conf.lo.input = 1
net.mpls.conf.eth0.input = 1
net.mpls.conf.eth1.input = 1
net.mpls.conf.eth2.input = 1
net.mpls.platform_labels = 100000
```
Apply:

```bash
sysctl -p R104_mpls.conf
```


##### 4.4 LDP

```text
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
```


#### Testing

* **OSPF adjacencies**: `show ip ospf neighbor`
* **LDP sessions**: `show mpls ldp neighbor`
* **BGP VPNv4 routes**: `show bgp ipv4 vpn`
