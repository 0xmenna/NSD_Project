# Network and System Defense Project


## Network Topology

### TODO: insert topology image

---

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
!
interface eth1
 ip address 10.0.100.1/30
!
interface lo
 ip address 1.255.0.1/32
```

##### 1.2 OSPF

```text
router ospf
 ospf router-id 1.255.0.1
 network 1.255.0.1/32 area 0
 network 10.0.100.0/30 area 0
```

##### 1.3 VRF

Define the VRF to properly manage the traffic related to the sites of the customer VPN.

```bash
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
```

##### 1.6 iBGP Core Peering
R101 is a border router, therefore we must configure iBGP to route traffic towards other edge routers to reach the different customer sites.

This configuration forms an overlay newtork between border routers to properly manage routing internally, within AS100. Each border router must know each other.

```text
router bgp 100
 bgp router-id 1.255.0.1
 !
 neighbor 1.255.0.2 remote-as 100
 neighbor 1.255.0.2 update-source 1.255.0.1
 neighbor 1.255.0.3 remote-as 100
 neighbor 1.255.0.3 update-source 1.255.0.1
 !
 address-family ipv4 unicast
  neighbor 1.255.0.2 next-hop-self
  neighbor 1.255.0.3 next-hop-self
 address-family ipv4 vpn
  neighbor 1.255.0.2 activate
  neighbor 1.255.0.2 next-hop-self
  neighbor 1.255.0.3 activate
  neighbor 1.255.0.3 next-hop-self
```

##### 1.7 CE-PE Dynamic Routing

The following configuration allows to route traffic dynamically between the customer edge and the provider edge, without requiring a less flexible static configuration.
```text
router bgp 100 vrf mainVPN
 address-family ipv4
  neighbor 10.1.1.2 remote-as 65001
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
```


#### 2. R102 Configuration

##### 2.1 Interfaces

```text
interface eth0
 ip address 10.1.3.1/30
!
interface eth1
 ip address 10.0.100.5/30
!
interface lo
 ip address 1.255.0.2/32
```

##### 2.2 OSPF

```text
router ospf
 ospf router-id 1.255.0.2
 network 1.255.0.2/32 area 0
 network 10.0.100.4/30 area 0
```

##### 2.3 VRF

```bash
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
```

##### 2.6 iBGP Core Peering

```text
router bgp 100
 bgp router-id 1.255.0.2
 !
 neighbor 1.255.0.1 remote-as 100
 neighbor 1.255.0.1 update-source 1.255.0.2
 neighbor 1.255.0.3 remote-as 100
 neighbor 1.255.0.3 update-source 1.255.0.2
 !
 address-family ipv4 unicast
  neighbor 1.255.0.1 next-hop-self
  neighbor 1.255.0.3 next-hop-self
 address-family ipv4 vpn
  neighbor 1.255.0.1 activate
  neighbor 1.255.0.1 next-hop-self
  neighbor 1.255.0.3 activate
  neighbor 1.255.0.3 next-hop-self
```

##### 2.7 CE-PE Dynamic Routing

```text
router bgp 100 vrf mainVPN
 address-family ipv4
  neighbor 10.1.3.2 remote-as 65003
```

##### 2.8 Spoke-Spoke Communication
This configuration is required to ensure that spokes are reachable through the hub PE. The hub PE exports a default route to the spokes, so when a spoke tries to communicate with the other, its PE does not have a specific route to the destination PE, but it does have the default route pointing to the hub. The hub PE, in turn, holds the necessary routes to all spokes and can forward traffic accordingly.

```text
! This just ensures that the default route exists in the VRF.
ip route 0.0.0.0/0 Null0 vrf mainVPN
router bgp 100 vrf mainVPN
    address-family ipv4 unicast
        network 0.0.0.0/0
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
```


#### 3. R103 Configuration

##### 3.1 Interfaces

```text
interface eth0
 ip address 10.1.2.1/30
!
interface eth1
 ip address 10.0.100.9/30
!
interface lo
 ip address 1.255.0.3/32
```

##### 3.2 OSPF

```text
router ospf
 ospf router-id 1.255.0.3
 network 1.255.0.3/32 area 0
 network 10.0.100.8/30 area 0
```

##### 3.3 VRF

```bash
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
```

##### 3.6 iBGP Core Peering

```text
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
```

##### 3.7 CE-PE Dynamic Routing

```text
router bgp 100 vrf mainVPN
 address-family ipv4
  neighbor 10.1.2.2 remote-as 65002
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
```


#### 4. R104 Configuration

R104 does not require iBGP peering configuration, as it operates purely as a core (P) router. It only needs to participate in OSPF and LDP; MPLS label switching will handle the transit traffic. Routing between provider edges (PEs) traverses R104 using MPLS labels, with no need for local BGP routing and VPN awareness.

##### 4.1 Interfaces

```text
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
```

##### 4.2 OSPF

```text
router ospf
 ospf router-id 1.255.0.4
 network 1.255.0.4/32 area 0
 network 10.0.100.0/30 area 0
 network 10.0.100.4/30 area 0
 network 10.0.100.8/30 area 0
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
```

---


### VPN Site 1

#### CE1 Configuration

##### 1. Interfaces

```text
interface eth0
 ip address 10.1.1.2/30
!
interface eth1
 ip address 192.168.1.1/24
```

##### 2. Dynamic routing

To complete the CE-PE routing configuration between the Site 1 CE and the border router R101, BGP must also be configured on the CE. Specifically, the CE should advertise the local network (192.168.1.0/24) and specify the address of its BGP neighbor (R101). This ensures that the CE can advertise its routes to the corresponding PE router in AS100.

```text
router bgp 65001
 network 192.168.1.0/24
 neighbor 10.1.1.1 remote-as 100
```


#### client-A1 Configuration

```bash
ip addr add 192.168.1.101/24 dev enp3s0
ip route add default via 192.168.1.1
```


##### AppArmor

This setup implements mandatory access control (MAC) rules using AppArmor for three specific use cases:

1. **Restrict `wget` write access to a safe directory**.
   `wget` is commonly used to download files from the web. To mitigate the risk of it writing to unintended locations, we allow it to write only to a designated safe directory.

2. **Deny all networking for `netcat`**.
   `netcat` can be used in insecure contexts, such as creating reverse shells. To prevent potential abuse, we completely block its networking capabilities.

3. **Restrict a custom read/write program to a safe directory**.
   A custom Python program (`rw_file.py`) is capable of reading from and writing to files. We confine it so that it can only access files within a specified safe directory.

All profiles were generated using the `aa-genprof` tool.

###### `wget` Profile

**Location:** `/etc/apparmor.d/usr.bin.wget`

```text
# Last Modified: Wed Aug  6 14:08:22 2025
abi <abi/3.0>,

include <tunables/global>

/usr/bin/wget {
  include <abstractions/base>
  include <abstractions/nameservice>
  include <abstractions/ssl_certs>

  /etc/gai.conf r,
  /etc/host.conf r,
  /etc/hosts r,
  /etc/nsswitch.conf r,
  /etc/wgetrc r,
  /usr/bin/wget mr,
  /usr/share/publicsuffix/public_suffix_list.dafsa r,
  
  owner /home/client/safe_downloads/** w,
}
```

###### `netcat` Profile

**Location:** `/etc/apparmor.d/usr.bin.nc.openbsd`

```text
# Last Modified: Wed Aug  6 15:05:30 2025
abi <abi/3.0>,

include <tunables/global>

/usr/bin/nc.openbsd {
  include <abstractions/apache2-common>
  include <abstractions/base>

  /etc/nsswitch.conf r,
  /etc/services r,
  /usr/bin/nc.openbsd mr,

  deny network,
}
```

###### `rw_file.py` Script

**Script Functionality:**

* **Read mode:** Displays file contents (like `cat`).
* **Write mode:** Accepts a file path, offset and content.

```python
#!/usr/bin/env python3
import os
import sys

def usage():
    print(f"Usage:")
    print(f"  {sys.argv[0]} read <file>")
    print(f"  {sys.argv[0]} write <file> <offset> <content>")
    sys.exit(1)

def read_file(path):
    try:
        with open(path, "rb") as f:
            sys.stdout.buffer.write(f.read())
    except FileNotFoundError:
        print(f"Error: File '{path}' not found.", file=sys.stderr)
    except PermissionError:
        print(f"Error: Permission denied for '{path}'.", file=sys.stderr)

def write_file(path, offset, content):
    try:
        offset = int(offset)
        if offset < 0:
            print("Error: Offset must be non-negative.", file=sys.stderr)
            return
        with open(path, "r+b") as f:
            f.seek(offset)
            f.write(content.encode())
    except FileNotFoundError:
        print(f"Error: File '{path}' not found.", file=sys.stderr)
    except PermissionError:
        print(f"Error: Permission denied for '{path}'.", file=sys.stderr)
    except ValueError:
        print("Error: Offset must be an integer.", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
    mode = sys.argv[1].lower()
    file_path = sys.argv[2]
    if mode == "read":
        read_file(file_path)
    elif mode == "write" and len(sys.argv) == 5:
        write_file(file_path, sys.argv[3], sys.argv[4])
    else:
        usage()
```

###### `rw_file.py` Profile

**Location:** `/etc/apparmor.d/home.client.rw_file.py`

```text
# Last Modified: Wed Aug  6 17:57:56 2025
abi <abi/3.0>,

include <tunables/global>

/home/client/rw_file.py {
  include <abstractions/base>
  include <abstractions/consoles>
  include <abstractions/python>

  /etc/ld.so.cache r,
  /home/client/rw_file.py r,
  /usr/bin/env ix,
  /usr/bin/python3.12 mrix,
  /usr/lib/ r,

  owner /home/client/safe_dir/** rw,

}
```

###### Enforcing the Profiles

```bash
apparmor_parser -r /etc/apparmor.d/usr.bin.wget
apparmor_parser -r /etc/apparmor.d/usr.bin.nc.openbsd
apparmor_parser -r /etc/apparmor.d/home.client.rw_file.py

aa-enforce /etc/apparmor.d/usr.bin.wget
aa-enforce /etc/apparmor.d/usr.bin.nc.openbsd
aa-enforce /etc/apparmor.d/home.client.rw_file.py
```

###### Disabling the Profiles

```bash
aa-disable /etc/apparmor.d/usr.bin.wget
aa-disable /etc/apparmor.d/usr.bin.nc.openbsd
aa-disable /etc/apparmor.d/home.client.rw_file.py
```

---


### VPN Site 2

#### CE2 Configuration

```text
interface eth0
 ip address 10.1.2.2/30
!
interface eth1
 ip address 192.168.2.1/24
```

```text
router bgp 65002
 network 192.168.2.0/24
 network 192.168.32.0/24
 network 192.168.95.0/24
 neighbor 10.1.2.1 remote-as 100
```

##### VLANs

To configure VLANs within Site 2, we create two separate virtual interfaces bound to the physical eth1 interface. So, the link associated with eth1 will carry traffic for both VLANs. The IP addresses for each VLAN are then assigned to their respective virtual interfaces.

```bash
ip link add link eth1 name eth1.32 type vlan id 32
ip link add link eth1 name eth1.95 type vlan id 95

ip link set eth0.32 up
ip link set eth0.95 up

ip addr add 192.168.32.1/24 dev eth1.32
ip addr add 192.168.95.1/24 dev eth0.95
```


#### Switch Configuration


```bash
# To reach the core network we define the default gateway and associate a new IP address to the interface toward the edge router.
ip addr add 192.168.2.100/24 dev eth0
ip route add default via 192.168.2.1

# We build a virtual bridge and associate to it the two interfaces facing the client devices within the two VLANs.
ip link add bridge type bridge
ip link set bridge up
ip link set dev eth1 master bridge
ip link set dev eth2 master bridge
ip link set dev bridge type bridge vlan_filtering 1

# Configure the default ACL policies so that bridge related traffic is blocked for forwarding. The switch wont forward packets unless a spcific rule permits it.
ebtables -F
ebtables -P FORWARD DROP
ebtables -P INPUT ACCEPT
ebtables -P OUTPUT ACCEPT

# Enable EAPoL forwarding
echo 8 > /sys/class/net/bridge/bridge/group_fwd_mask
```

###### hostapd.conf

```text
# Control interface settings
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0

# Enable logging for all modules
logger_syslog=-1
logger_stdout=-1

# Log level
logger_syslog_level=2
logger_stdout_level=2

# Driver interface type
driver=wired

# Enable IEEE 802.1X authorization
ieee8021x=1

# Use port access entry (PAE) group address
# (01:80:c2:00:00:03) when sending EAPOL frames
use_pae_group_addr=1

# Network interface for authentication requests
interface=bridge

# Local IP address used as NAS-IP-Address
own_ip_addr=192.168.2.100

# Unique NAS-Identifier within scope of RADIUS server
nas_identifier=hostapd.nsd-project.org

# RADIUS authentication server
auth_server_addr=192.168.3.101
auth_server_port=1812
auth_server_shared_secret=rad1u5_5ecret
```

Authentication requests will be handled by the virtual bridge interface to which the two physical interfaces are attached, therefore requests will come from the two client within the two VLANs.

The switch authenticator will send the requests to the server throgh its IP address mapped to the eth0 interface (that faces the edge router toward the provider network). 
The provider network through the BGP/MPLS backbone will handle routing to reach the VPN Site 3 (that contains the Radius server).


##### eBPF Configuration

##### TODO


#### client-B1 Configuration

```bash
ip addr add 192.168.32.101/24 dev eth0
ip route add default via 192.168.32.1

cat b1_supplicant.conf > /etc/wpa_supplicant.conf
```

###### b1_supplicant.conf
```text
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="client-B1"
    password="pa55w0rd_b1"
    eapol_flags=0
}
```


#### client-B2 Configuration

```bash
ip addr add 192.168.95.101/24 dev eth0
ip route add default via 192.168.95.1

cat b2_supplicant.conf > /etc/wpa_supplicant.conf
```

###### b2_supplicant.conf
```text
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="client-B2"
    password="pa55w0rd_b2"
    eapol_flags=0
}
```

---


### VPN Site 3

#### CE3 Configuration

```text
interface eth0
 ip address 10.1.3.2/30
!
interface eth1
 ip address 192.168.3.1/24
```

```text
router bgp 65003
 network 192.168.3.0/24
 neighbor 10.1.3.1 remote-as 100
```


#### Radius Server Configuration

```bash
ip addr add 192.168.3.101/24 dev eth0
ip route add default via 192.168.3.1

cat clients.conf > /etc/freeradius/3.0/clients.conf
cat users.conf > /etc/freeradius/3.0/users

service freeradius start
```

Set the authenticator device IP address from which the server will receive the authentication requests (i.e. the switch ip address) and the shared secret.

###### clients.conf

```text
client switch {
    ipaddr = 192.168.2.100
    secret = "rad1u5_5ecret"
    shortname = nsd_project
}

```

Set authenticating users information and set the VLANs IDs as attributes within the radius message repsonse in case of a successful authentication.

###### users.conf
```text
client-B1   Cleartext-Password := "pa55w0rd_b1"
            Service-Type = Framed-User,
            Tunnel-Type = 13,
            Tunnel-Medium-Type = 6,
            Tunnel-Private-Group-ID = 32

client-B2   Cleartext-Password := "pa55w0rd_b2"
            Service-Type = Framed-User,
            Tunnel-Type = 13,
            Tunnel-Medium-Type = 6,
            Tunnel-Private-Group-ID = 95
```