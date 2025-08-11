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

To configure VLANs within Site 2, two distinct virtual sub-interfaces are created on the physical interface eth1, each corresponding to a specific VLAN. This configuration enables eth1 to serve as a trunk link, carrying tagged traffic for both VLANs. Each virtual sub-interface is then assigned an IP address.

```bash
ip link add link eth0 name eth0.32 type vlan id 32
ip link add link eth0 name eth0.95 type vlan id 95

ip link set eth0.32 up
ip link set eth0.95 up

ip addr add 192.168.32.1/24 dev eth0.32
ip addr add 192.168.95.1/24 dev eth0.95
```


#### Switch Configuration


```bash
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

cat hostapd.conf > /etc/hostapd/hostapd.conf
```

Authentication requests are received on the virtual bridge interface, which aggregates the two interfaces connected to the client devices in the separate VLANs. These requests originate from clients within each VLAN.

The switch, acting as the authenticator, forwards the requests to the RADIUS server (EAPoL forwarding is enabled) using the IP address assigned to the bridge interface (that embeds eth0). Routing to VPN Site 3, where the RADIUS server resides, is handled by the provider network via the BGP/MPLS backbone.

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
interface=br0

# Local IP address used as NAS-IP-Address
own_ip_addr=192.168.2.100

# Unique NAS-Identifier within scope of RADIUS server
nas_identifier=hostapd.nsd-project.org

# RADIUS authentication server
auth_server_addr=192.168.3.101
auth_server_port=1812
auth_server_shared_secret=rad1u5_5ecret
```


##### eBPF Configuration

##### TODO


#### client-B1 Configuration

```bash
ip addr add 192.168.32.101/24 dev eth0
ip route add default via 192.168.32.1

cat b1_supplicant.conf > /etc/wpa_supplicant.conf

# start wpa_supplicant in background
wpa_supplicant -B -c/etc/wpa_supplicant.conf -Dwired -ieth0
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

# start wpa_supplicant in background
wpa_supplicant -B -c/etc/wpa_supplicant.conf -Dwired -ieth0
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

Set the IP address of the authenticator device (i.e., the switch) from which the RADIUS server will receive authentication requests, and configure the shared secret used to secure the communication between the switch and the server.

###### clients.conf

```text
client cumulus1 {
    ipaddr = 192.168.2.100
    secret = "rad1u5_5ecret"
    shortname = nsd_project
}

```

Configure the users' authentication details and define the VLAN IDs as attributes in the RADIUS response message, to be returned upon successful authentication.

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



---



# eBPF 802.1X + RADIUS: Build & Deploy (eth0 uplink, eth1/eth2 clients)

This single README has everything you need: directory layout, all source files, and exact build/attach/run steps.

---

## Overview

* **Goal**: enforce VLAN and access on a Linux bridge based on 802.1X (EAPOL) + RADIUS results.
* **Hooks**:

  * **TC egress** on `eth1`/`eth2`: record the *intended* port for each `EAP-Request(id)`.
  * **XDP ingress** on `eth1`/`eth2`: only allow `EAP-Response(id)` on that intended port; learn `id → {MAC, ifindex}`.
  * **XDP ingress** on `eth0`: parse RADIUS replies; extract `EAP-Message(id)` and VLAN; publish `{MAC → {state, vlan, ifindex}}` for the userspace enforcer.
* **Userspace** (Rust): watches the `auth_map` and applies `bridge vlan` + `ebtables` rules.

Default interfaces: `eth0` (uplink/router/RADIUS), `eth1` & `eth2` (access ports for Client-B1/B2).

---

## Prereqs (Ubuntu/Debian-like)

```bash
sudo apt-get update
sudo apt-get install -y clang llvm make iproute2 bpftool ebtables bridge-utils pkg-config \
                        build-essential git curl
# Rust toolchain (if not installed)
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env

# eBPF FS + JIT (once per boot)
sudo mount -t bpf bpf /sys/fs/bpf || true
sudo sysctl -w net.core.bpf_jit_enable=1
```

---

## Create project directory

```bash
mkdir -p ebpf-auth && cd ebpf-auth
```

---

## Directory layout

```
ebpf-auth/
├── Makefile
├── common_defs.h
├── tc_eap_req.c        # TC egress on eth1/eth2: record EAP-Request(id) -> port
├── xdp_eap_ing.c       # XDP ingress on eth1/eth2: gate EAP-Response(id) to that port + learn MAC
├── xdp_radius.c        # XDP ingress on eth0: parse RADIUS, emit {MAC -> {state,vlan,port}} to auth_map
└── enforcer/           # Rust userspace VLAN/MAC enforcer
    ├── Cargo.toml
    └── src/main.rs
```

> Create the files below exactly as shown.

---

## Files — eBPF programs & headers

### `Makefile`

```make
# ---- Interface names (override on the command line if different) -----------
IF_UPLINK ?= eth0       # RADIUS/uplink
IF_ACCESS1 ?= eth1      # client 1
IF_ACCESS2 ?= eth2      # client 2

# ---- Toolchain --------------------------------------------------------------
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFOBJ := tc_eap_req.o xdp_eap_ing.o xdp_radius.o

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  TARGET_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
  TARGET_ARCH := arm64
else ifeq ($(UNAME_M),armv7l)
  TARGET_ARCH := arm
else
  TARGET_ARCH := x86
endif

CFLAGS_BPF := -O2 -g -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) -Wall -Werror -I.
LDFLAGS_BPF :=

.PHONY: all
all: $(BPFOBJ)

%.o: %.c common_defs.h
    $(CLANG) $(CFLAGS_BPF) -c $< -o $@
    -$(LLVM_STRIP) -g $@ 2>/dev/null || true

.PHONY: bpffs
bpffs:
    sudo mount -t bpf bpf /sys/fs/bpf || true

.PHONY: clean
clean:
    rm -f $(BPFOBJ)

.PHONY: show-maps
show-maps:
    sudo bpftool map show | egrep 'expected_id_map|id2mac_map|auth_map' || true

# ---- Attach / Detach TC (EAP Request on egress) ----------------------------
.PHONY: attach-tc
attach-tc: tc_eap_req.o
    sudo tc qdisc add dev $(IF_ACCESS1) clsact 2>/dev/null || true
    sudo tc filter add dev $(IF_ACCESS1) egress bpf da obj tc_eap_req.o sec tc
    sudo tc qdisc add dev $(IF_ACCESS2) clsact 2>/dev/null || true
    sudo tc filter add dev $(IF_ACCESS2) egress bpf da obj tc_eap_req.o sec tc

.PHONY: detach-tc
detach-tc:
    - sudo tc qdisc del dev $(IF_ACCESS1) clsact
    - sudo tc qdisc del dev $(IF_ACCESS2) clsact

# ---- Attach / Detach XDP (EAP Responses on access ports) -------------------
.PHONY: attach-eap-xdp
attach-eap-xdp: xdp_eap_ing.o
    sudo ./xdp_loader -A --dev $(IF_ACCESS1) --filename xdp_eap_ing.o --progname xdp_eap_ing
    sudo ./xdp_loader -A --dev $(IF_ACCESS2) --filename xdp_eap_ing.o --progname xdp_eap_ing

.PHONY: detach-eap-xdp
detach-eap-xdp:
    - sudo ./xdp_loader -D --dev $(IF_ACCESS1) --progname xdp_eap_ing || sudo ip link set dev $(IF_ACCESS1) xdp off
    - sudo ./xdp_loader -D --dev $(IF_ACCESS2) --progname xdp_eap_ing || sudo ip link set dev $(IF_ACCESS2) xdp off

# ---- Attach / Detach XDP (RADIUS on uplink) --------------------------------
.PHONY: attach-radius
attach-radius: xdp_radius.o
    sudo ./xdp_loader -A --dev $(IF_UPLINK) --filename xdp_radius.o --progname xdp_radius_parse

.PHONY: detach-radius
detach-radius:
    - sudo ./xdp_loader -D --dev $(IF_UPLINK) --progname xdp_radius_parse || sudo ip link set dev $(IF_UPLINK) xdp off

# ---- Orchestration ----------------------------------------------------------
.PHONY: attach-all
attach-all: bpffs all attach-tc attach-eap-xdp attach-radius show-maps

.PHONY: detach-all
detach-all: detach-radius detach-eap-xdp detach-tc
```

### `common_defs.h`

```c
#pragma once
#include <linux/types.h>

struct expected_entry {
    __u32 ifindex;   // access port where the EAP-Request(id) was sent
    __u64 ts_ns;     // when the request was seen
};

struct id_mac_entry {
    __u8  mac[6];    // supplicant MAC that sent a valid Response(id) on that port
    __u32 ifindex;   // access port
    __u64 ts_ns;     // when we learned it
};

struct auth_value {
    __u16 vlan_id;      // from Tunnel-Private-Group-ID
    __u8  state;        // 1=Access-Accept (EAP-Success), 0=Reject
    __u8  applied;      // userspace flips to 1 after enforcing rules
    __u32 ifindex;      // access port
    __u64 last_seen_ns; // for housekeeping/telemetry
};
```

### `tc_eap_req.c` (TC egress: record intended port per EAP-Request id)

```c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include "common_defs.h"

#define ETH_P_EAPOL 0x888E
#define EAPOL_TYPE_EAP_PACKET 0

struct eapol_hdr { __u8 ver, type; __be16 len; } __attribute__((packed));
struct eap_hdr   { __u8 code, id;  __be16 len; } __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);                       // EAP id (low 8 bits)
    __type(value, struct expected_entry);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);      // /sys/fs/bpf/expected_id_map
} expected_id_map SEC(".maps");

static __always_inline bool ok(void *p, void *end, __u64 sz) {
    return (void *)((char*)p + sz) <= end;
}

SEC("tc")
int tc_eap_req(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (!ok(eth, end, sizeof(*eth))) return TC_ACT_OK;
    if (eth->h_proto != __bpf_htons(ETH_P_EAPOL)) return TC_ACT_OK;

    struct eapol_hdr *eol = (void *)(eth + 1);
    if (!ok(eol, end, sizeof(*eol))) return TC_ACT_OK;
    if (eol->type != EAPOL_TYPE_EAP_PACKET) return TC_ACT_OK;

    struct eap_hdr *eap = (void *)(eol + 1);
    if (!ok(eap, end, sizeof(*eap))) return TC_ACT_OK;
    if (eap->code != 1 /* Request */) return TC_ACT_OK;

    __u32 key = eap->id;
    struct expected_entry val = {
        .ifindex = (__u32)skb->ifindex,  // egress port
        .ts_ns   = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&expected_id_map, &key, &val, BPF_ANY);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

### `xdp_eap_ing.c` (XDP ingress on eth1/eth2: gate Responses; learn id→MAC)

```c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include "common_defs.h"

#define ETH_P_EAPOL 0x888E
#define EAPOL_TYPE_EAP_PACKET 0
#define TTL_NS (5ULL * 1000000000ULL)

struct eapol_hdr { __u8 ver, type; __be16 len; } __attribute__((packed));
struct eap_hdr   { __u8 code, id;  __be16 len; } __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);                       // EAP id
    __type(value, struct expected_entry);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);      // /sys/fs/bpf/expected_id_map
} expected_id_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);                       // EAP id
    __type(value, struct id_mac_entry);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);      // /sys/fs/bpf/id2mac_map
} id2mac_map SEC(".maps");

static __always_inline bool ok(void *p, void *end, __u64 sz) {
    return (void *)((char*)p + sz) <= end;
}

SEC("xdp")
int xdp_eap_ing(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (!ok(eth, end, sizeof(*eth))) return XDP_PASS;
    if (eth->h_proto != __bpf_htons(ETH_P_EAPOL)) return XDP_PASS;

    struct eapol_hdr *eol = (void *)(eth + 1);
    if (!ok(eol, end, sizeof(*eol))) return XDP_PASS;
    if (eol->type != EAPOL_TYPE_EAP_PACKET) return XDP_PASS;

    struct eap_hdr *eap = (void *)(eol + 1);
    if (!ok(eap, end, sizeof(*eap))) return XDP_PASS;

    if (eap->code != 2 /* Response */) return XDP_PASS;

    __u32 key = eap->id;
    struct expected_entry *exp = bpf_map_lookup_elem(&expected_id_map, &key);
    if (!exp) return XDP_DROP;

    __u64 now = bpf_ktime_get_ns();
    if (now - exp->ts_ns > TTL_NS) return XDP_DROP;
    if (exp->ifindex != (__u32)ctx->ingress_ifindex) return XDP_DROP;

    // Valid responder on intended port: learn id -> {mac, ifindex}
    struct id_mac_entry im = { .ifindex = (__u32)ctx->ingress_ifindex, .ts_ns = now };
    __builtin_memcpy(im.mac, eth->h_source, ETH_ALEN);
    bpf_map_update_elem(&id2mac_map, &key, &im, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### `xdp_radius.c` (XDP ingress on eth0: parse RADIUS; emit decisions)

```c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "common_defs.h"

#define RAD_CODE_ACCEPT 2
#define RAD_CODE_REJECT 3
#define RAD_HDR_LEN 20
#define RAD_ATTR_EAP_MESSAGE 79
#define RAD_ATTR_TUNNEL_PRIVATE_GROUP_ID 81

static __always_inline bool ok(void *p, void *end, __u64 sz) {
    return (void *)((char*)p + sz) <= end;
}

struct eap_hdr { __u8 code, id; __be16 len; } __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct id_mac_entry);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/id2mac_map
} id2mac_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct expected_entry);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/expected_id_map
} expected_id_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u8[6]);
    __type(value, struct auth_value);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/auth_map
} auth_map SEC(".maps");

static __always_inline int parse_dec_u16(const char *p, const char *end, __u16 *out)
{
    __u32 v=0; int seen=0;
#pragma unroll
    for (int i=0;i<5;i++) {
        if (p+i >= end) break;
        char c = p[i];
        if (c<'0'||c>'9') break;
        v = v*10 + (c-'0'); seen=1;
        if (v>4095) break;
    }
    if (!seen) return -1;*out = v; return 0;
}

SEC("xdp")
int xdp_radius_parse(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    // IPv4/UDP
    struct ethhdr *eth = data;
    if (!ok(eth, end, sizeof(*eth))) return XDP_PASS;

    if (eth->h_proto != __bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if (!ok(ip, end, sizeof(*ip))) return XDP_PASS;
    int ihl = ip->ihl * 4;
    if (ihl < (int)sizeof(*ip)) return XDP_PASS;

    struct udphdr *udp = (void *)((char*)ip + ihl);
    if (!ok(udp, end, sizeof(*udp))) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    // RADIUS replies from server: src port 1812
    if (udp->source != __bpf_htons(1812)) return XDP_PASS;

    unsigned char *r = (void *)(udp + 1);
    if (r + RAD_HDR_LEN > (unsigned char*)end) return XDP_PASS;

    __u8  code = r[0];
    __u16 rlen = (__u16)(r[2] << 8 | r[3]);
    if (rlen < RAD_HDR_LEN) return XDP_PASS;

    unsigned char *ra = r + RAD_HDR_LEN, *rend = r + rlen;
    if (rend > (unsigned char*)end) return XDP_PASS;
    if (!(code == RAD_CODE_ACCEPT || code == RAD_CODE_REJECT)) return XDP_PASS;

    __u8 eap_id=0, eap_code=0; int have_id=0;
    __u16 vlan=0; int have_vlan=0;

#pragma unroll
    for (int i=0;i<64;i++) {
        if (ra + 2 > rend) break;
        __u8 at = ra[0], al = ra[1];
        if (al < 2) break;
        unsigned char *aval = ra + 2, *anext = ra + al;
        if (anext > rend) break;

        if (at == RAD_ATTR_EAP_MESSAGE && al >= 6) {
            struct eap_hdr *eh = (void *)aval;
            if ((void *)(eh + 1) <= (void *)anext) {
                eap_id = eh->id; eap_code = eh->code; have_id = 1;
            }
        } else if (at == RAD_ATTR_TUNNEL_PRIVATE_GROUP_ID && al > 2) {
            __u16 v=0;
            if (!have_vlan && parse_dec_u16((const char*)aval, (const char*)anext, &v)==0)
                if (v>=1 && v<=4094) { vlan=v; have_vlan=1; }
        }
        ra = anext;
    }
    if (!have_id) return XDP_PASS;

    __u32 key = eap_id;
    struct id_mac_entry *im = bpf_map_lookup_elem(&id2mac_map, &key);
    if (!im) return XDP_PASS;

    struct auth_value val = {
        .vlan_id = have_vlan ? vlan : 0,
        .state   = (code == RAD_CODE_ACCEPT && eap_code == 3 /*EAP-Success*/) ? 1 : 0,
        .applied = 0,
        .ifindex = im->ifindex,
        .last_seen_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&auth_map, im->mac, &val, BPF_ANY);

    // Cleanup: free the id for reuse
    bpf_map_delete_elem(&id2mac_map, &key);
    bpf_map_delete_elem(&expected_id_map, &key);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

## Userspace enforcer (Rust)

Create subdirectory and files:

```bash
mkdir -p enforcer/src
```

### `enforcer/Cargo.toml`

```toml
[package]
name = "radius_enforcer"
version = "0.1.0"
edition = "2021"

[dependencies]
aya = "0.12"
clap = { version = "4.5", features = ["derive"] }
anyhow = "1.0"
thiserror = "1.0"
nix = "0.29"
```

### `enforcer/src/main.rs`

```rust
use anyhow::{bail, Context, Result};
use aya::maps::HashMap as BpfHashMap;
use aya::Pod;
use clap::Parser;
use nix::unistd::Uid;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct AuthValue {
    vlan_id: u16,
    state: u8,      // 1=accept, 0=reject
    applied: u8,    // userspace flips to 1 after enforcement
    ifindex: u32,   // access port (from EAP logic)
    last_seen_ns: u64,
}
unsafe impl Pod for AuthValue {}

#[derive(Parser, Debug)]
#[command(name="radius_enforcer")]
struct Args {
    #[arg(long, default_value = "br0")]
    bridge: String,

    /// VLAN→iface mapping, e.g. "32:eth1,95:eth2"
    #[arg(long, value_parser = parse_vlan_map)]
    vlan_map: HashMap<u16, String>,

    #[arg(long, default_value = "/sys/fs/bpf/auth_map")]
    map_path: String,

    #[arg(long, default_value = "1")]
    default_vlan: u16,

    #[arg(long, default_value_t = false)]
    verify_fdb: bool,

    #[arg(long, default_value_t = 200)]
    interval_ms: u64,
}

fn parse_vlan_map(s: &str) -> std::result::Result<HashMap<u16, String>, String> {
    let mut m = HashMap::new();
    if s.trim().is_empty() {
        return Err("vlan_map cannot be empty".into());
    }
    for part in s.split(',') {
        let (k, v) = part
            .split_once(':')
            .ok_or_else(|| format!("invalid vlan_map item: {}", part))?;
        let vid: u16 = k
            .parse()
            .map_err(|_| format!("invalid vlan id in vlan_map item: {}", part))?;
        if v.is_empty() {
            return Err(format!("invalid iface in vlan_map item: {}", part));
        }
        m.insert(vid, v.to_string());
    }
    Ok(m)
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let st = Command::new(cmd).args(args).status()
        .with_context(|| format!("spawn failed: {} {:?}", cmd, args))?;
    if !st.success() {
        bail!("command failed: {} {:?}", cmd, args);
    }
    Ok(())
}

fn ensure_bridge_vlan_filtering(bridge: &str) -> Result<()> {
    run("ip", &["link", "set", "dev", bridge, "type", "bridge", "vlan_filtering", "1"])\
        .or(Ok(()))
}

fn ensure_port_pvid(iface: &str, vid: u16) -> Result<()> {
    let _ = run("bridge", &["vlan", "del", "dev", iface, "vid", &vid.to_string()]);
    run(
        "bridge",
        &[
            "vlan", "add", "dev", iface, "vid", &vid.to_string(), "pvid", "untagged",
        ],
    )
}

fn remove_port_vid(iface: &str, vid: u16) -> Result<()> {
    run("bridge", &["vlan", "del", "dev", iface, "vid", &vid.to_string()]).or(Ok(()))
}

fn ensure_ebtables_base(iface: &str) -> Result<()> {
    let in_chain = format!("AUTH_{}_IN", iface);
    let out_chain = format!("AUTH_{}_OUT", iface);

    let _ = run("ebtables", &["-t", "filter", "-N", &in_chain]);
    let _ = run("ebtables", &["-t", "filter", "-N", &out_chain]);
    let _ = run("ebtables", &["-t", "filter", "-F", &in_chain]);
    let _ = run("ebtables", &["-t", "filter", "-F", &out_chain]);

    let _ = run("ebtables", &["-t", "filter", "-D", "FORWARD", "-i", iface, "-j", &in_chain]);
    run("ebtables", &["-t", "filter", "-I", "FORWARD", "-i", iface, "-j", &in_chain])?;

    let _ = run("ebtables", &["-t", "filter", "-D", "FORWARD", "-o", iface, "-j", &out_chain]);
    run("ebtables", &["-t", "filter", "-I", "FORWARD", "-o", iface, "-j", &out_chain])?;

    let _ = run("ebtables", &["-t", "filter", "-A", &in_chain, "-j", "DROP"]);
    let _ = run("ebtables", &["-t", "filter", "-A", &out_chain, "-j", "DROP"]);
    Ok(())
}

fn mac_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn allow_mac_on_iface(mac: &[u8; 6], iface: &str) -> Result<()> {
    let macs = mac_string(unsafe { &*(mac as *const _ as *const [u8; 6]) });
    let in_chain = format!("AUTH_{}_IN", iface);
    let out_chain = format!("AUTH_{}_OUT", iface);

    let _ = run("ebtables", &["-t", "filter", "-D", &in_chain, "-s", &macs, "-j", "ACCEPT"]);
    run("ebtables", &["-t", "filter", "-I", &in_chain, "-s", &macs, "-j", "ACCEPT"])?;

    let _ = run("ebtables", &["-t", "filter", "-D", &out_chain, "-d", &macs, "-j", "ACCEPT"]);
    run("ebtables", &["-t", "filter", "-I", &out_chain, "-d", &macs, "-j", "ACCEPT"])?;
    Ok(())
}

fn revoke_mac_on_iface(mac: &[u8; 6], iface: &str) -> Result<()> {
    let macs = mac_string(unsafe { &*(mac as *const _ as *const [u8; 6]) });
    let in_chain = format!("AUTH_{}_IN", iface);
    let out_chain = format!("AUTH_{}_OUT", iface);

    let _ = run("ebtables", &["-t", "filter", "-D", &in_chain, "-s", &macs, "-j", "ACCEPT"]);
    let _ = run("ebtables", &["-t", "filter", "-D", &out_chain, "-d", &macs, "-j", "ACCEPT"]);
    Ok(())
}

fn fdb_has_mac_on_iface(bridge: &str, iface: &str, mac: &str) -> bool {
    if let Ok(out) = Command::new("bridge").args(["fdb", "show", "dev", iface]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            return s.lines().any(|l| l.contains(mac));
        }
    }
    if let Ok(out) = Command::new("bridge").args(["fdb", "show", "br", bridge]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            return s.lines().any(|l| l.contains(mac) && l.contains(iface));
        }
    }
    false
}

fn main() -> Result<()> {
    if !Uid::current().is_root() { bail!("run as root"); }
    let args = Args::parse();

    ensure_bridge_vlan_filtering(&args.bridge)?;

    if !Path::new(&args.map_path).exists() {
        bail!("map not found: {}", args.map_path);
    }

    let mut map: BpfHashMap<[u8; 6], AuthValue> =
        BpfHashMap::from_pin(args.map_path.as_str()).context("open auth_map")?;

    for (_vid, ifname) in &args.vlan_map {
        ensure_ebtables_base(ifname)?;
    }

    loop {
        for item in map.iter() {
            let (mac_key, mut val) = match item { Ok(kv) => kv, Err(_) => continue };

            let Some(iface) = args.vlan_map.get(&val.vlan_id) else { continue };
            let macs = mac_string(&mac_key);

            if val.state == 1 && val.applied == 0 {
                if args.verify_fdb && !fdb_has_mac_on_iface(&args.bridge, iface, &macs) {
                    continue;
                }
                ensure_port_pvid(iface, val.vlan_id)
                    .with_context(|| format!("set pvid {} on {}", val.vlan_id, iface))?;
                allow_mac_on_iface(&mac_key, iface)
                    .with_context(|| format!("allow {} on {}", &macs, iface))?;
                val.applied = 1;
                let _ = map.insert(&mac_key, &val, 0);
            } else if val.state == 0 && val.applied == 1 {
                revoke_mac_on_iface(&mac_key, iface)
                    .with_context(|| format!("revoke {} on {}", &macs, iface))?;
                if args.default_vlan != val.vlan_id {
                    let _ = remove_port_vid(iface, val.vlan_id);
                    let _ = ensure_port_pvid(iface, args.default_vlan);
                }
                val.applied = 0;
                let _ = map.insert(&mac_key, &val, 0);
            }
        }
        thread::sleep(Duration::from_millis(args.interval_ms));
    }
}
```

Build the enforcer:

```bash
cd enforcer
cargo build --release
cd ..
```

---

## Build eBPF programs

```bash
make
```

---

## Attach programs

```bash
# bpffs + JIT (if not already done)
sudo mount -t bpf bpf /sys/fs/bpf || true
sudo sysctl -w net.core.bpf_jit_enable=1

# Attach TC egress on access ports (records EAP-Request(id) -> port)
make attach-tc IF_ACCESS1=eth1 IF_ACCESS2=eth2

# Attach XDP ingress on access ports (gates Responses; learns id->MAC)
make attach-eap-xdp IF_ACCESS1=eth1 IF_ACCESS2=eth2

# Attach XDP ingress on uplink (RADIUS parser)
make attach-radius IF_UPLINK=eth0

# Verify pinned maps
make show-maps
```

Expected maps: `expected_id_map`, `id2mac_map`, `auth_map`.

---

## Run the enforcer

Example for your VLAN policy (Client-B1 on eth1 → VLAN 32; Client-B2 on eth2 → VLAN 95):

```bash
sudo ./enforcer/target/release/radius_enforcer \
  --bridge bridge \
  --vlan-map 32:eth1,95:eth2 \
  --map-path /sys/fs/bpf/auth_map \
  --default-vlan 1 \
  --verify-fdb
```

> Ensure your bridge `bridge` has `eth1` and `eth2` as ports, and the switch provides IP reachability to the RADIUS server (hostapd will talk to it via the gateway).

---

## Detach / Cleanup

```bash
# Detach BPF programs
make detach-all IF_UPLINK=eth0 IF_ACCESS1=eth1 IF_ACCESS2=eth2

# Optional: remove pinned maps if left behind (be careful)
sudo rm -f /sys/fs/bpf/expected_id_map /sys/fs/bpf/id2mac_map /sys/fs/bpf/auth_map
```

---

## Troubleshooting

* **No maps shown**: Ensure `bpffs` is mounted and programs loaded succeeded (`dmesg | tail`).
* **EAPOL not flowing**: Verify hostapd is running and 802.1X on the ports. With your EAPOL forwarding, the gate will still only allow the intended port based on the Request(id).
* **Enforcer does nothing**: Check `/sys/fs/bpf/auth_map` with `bpftool map dump pinned /sys/fs/bpf/auth_map`.
* **VLAN not applied**: `bridge vlan show dev eth1`/`eth2`; ensure `vlan_filtering 1` on `bridge`.

---

## Why this design is robust

* The *intended* port is defined by the **EAP-Request(id)** (seen on **egress**, TC).
* Only `EAP-Response(id)` arriving on that exact port (within a short TTL) is permitted (XDP ingress).
* RADIUS Accept/Reject is correlated deterministically via the `id → {MAC,port}` learned from the valid Response.
* The userspace enforcer applies per-port VLAN and MAC rules idempotently.



