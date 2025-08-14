# Network and System Defense Project

## Network Topology

<p align="center">
  <img src="resources/Topology.png" alt="Description">
</p>

---

## Network Deployment

Each node is deployed using a `deploy.sh` script located in the container’s `/root` directory (which has been mounted as a docker volume). All configuration files are stored in `/root/config`.

### AS100: BGP/MPLS VPN Backbone

AS100 is configured as the provider backbone for the customer VPN.

#### 1. R101 Configuration

Most considerations made to R101 also apply to the other border routers (R102 and R103).

###### `deploy.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

MPLS_CONF="${MPLS_CONF:-/root/config/R101_mpls.conf}"

# VRF setup
ip link add mainVPN type vrf table 10
ip link set mainVPN up
ip link set eth0 master mainVPN

# Apply MPLS sysctls from provided file
sysctl -p "$MPLS_CONF"

# Ensure links are up
ip link set eth0 up
ip link set eth1 up
ip link set lo up

# vtysh configuration
vtysh <<'VTY'
configure terminal
!
! ---- Interfaces
interface eth0
 ip address 10.1.1.1/30
!
interface eth1
 ip address 10.0.100.1/30
!
interface lo
 ip address 1.255.0.1/32
exit
!
! ---- OSPF
router ospf
 ospf router-id 1.255.0.1
 network 1.255.0.1/32 area 0
 network 10.0.100.0/30 area 0
exit
!
! ---- LDP
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
! ---- iBGP core peering (AS 100)
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
 exit
exit
!
! ---- CE-PE dynamic routing
router bgp 100 vrf mainVPN
 address-family ipv4
  neighbor 10.1.1.2 remote-as 65001
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

echo "Deploy complete."

```

`R101_mpls.conf`:

```text
net.mpls.conf.lo.input = 1
net.mpls.conf.eth1.input = 1
net.mpls.conf.mainVPN.input = 1
net.mpls.platform_labels = 100000
```

R101 is a border router, therefore it has been configured iBGP to route traffic towards other edge routers to reach the different customer sites.
This configuration forms an overlay newtork between border routers to properly manage routing internally, within AS100. Each border router must know each other. Additionally, the configuration allows to route traffic dynamically between the customer edge and the provider edge, without requiring a less flexible static configuration.

The configuration also defines:

- A route destinguisher to make potentially overlapping IPv4 addresses from different VPNs unique within the MPLS VPN backbone.

- A route target to enable the Spoke-Hub topology by controlling how VPN routes are imported and exported between sites, ensuring that spokes can communicate only through the hub. Since R101 is the PE for Site 1, it imports routes exported by the hub PE and exports its own routes to the hub. This setup ensures that the hub PE maintains awareness of each spoke’s routing information, while spokes remain isolated from one another and are hub dependent.

#### 2. R102 Configuration

###### `deploy.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

MPLS_CONF="${MPLS_CONF:-/root/config/R102_mpls.conf}"

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
 ip address 10.1.3.1/30
!
interface eth1
 ip address 10.0.100.5/30
!
interface lo
 ip address 1.255.0.2/32
exit
!
! ---- OSPF
router ospf
 ospf router-id 1.255.0.2
 network 1.255.0.2/32 area 0
 network 10.0.100.4/30 area 0
exit
!
! ---- LDP
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
! ---- iBGP core (AS 100)
router bgp 100
 bgp router-id 1.255.0.2
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
 exit
exit
!
! ---- CE-PE dynamic routing
router bgp 100 vrf mainVPN
 address-family ipv4
  neighbor 10.1.3.2 remote-as 65003
exit
!
! ---- Spoke-to-Spoke Communication
ip route 0.0.0.0/0 Null0 vrf mainVPN
router bgp 100 vrf mainVPN
 address-family ipv4 unicast
  network 0.0.0.0/0
 exit
exit
!
! ---- RD & RT
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
end
write memory
VTY

echo "R102 deploy complete."

```

`R102_mpls.conf`:

```text
net.mpls.conf.lo.input = 1
net.mpls.conf.eth1.input = 1
net.mpls.conf.mainVPN.input = 1
net.mpls.platform_labels = 100000
```

We ensure that spokes are reachable through the hub PE. The hub PE exports a default route to the spokes, so when a spoke tries to communicate with the other, its PE does not have a specific route to the destination PE, but it does have the default route pointing to the hub. The hub PE, in turn, holds the necessary routes to all spokes and can forward traffic accordingly.

In fact, through route targets, the hub PE imports all routes received from the spoke PEs and exports its default route to the spokes.

#### 3. R103 Configuration

###### `deploy.sh`

```bash
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

```

`R103_mpls.conf`:

```text
net.mpls.conf.lo.input = 1
net.mpls.conf.eth1.input = 1
net.mpls.conf.mainVPN.input = 1
net.mpls.platform_labels = 100000
```

#### 4. R104 Configuration

R104 does not require iBGP peering configuration, as it operates purely as a core (P) router. It only needs to participate in OSPF and LDP; MPLS label switching will handle the transit traffic. Routing between provider edges (PEs) traverses R104 using MPLS labels, with no need for local BGP routing and VPN awareness.

```bash
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

```

`R104_mpls.conf`:

```text
net.mpls.conf.lo.input = 1
net.mpls.conf.eth0.input = 1
net.mpls.conf.eth1.input = 1
net.mpls.conf.eth2.input = 1
net.mpls.platform_labels = 100000
```

---

### VPN Site 1

#### CE1 Configuration

###### `deploy.sh`

```bash
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

```

To complete the CE-PE routing configuration between the Site 1 CE and the border router R101, BGP must also be configured on the CE. Specifically, the CE should advertise the local network (192.168.1.0/24) and specify the address of its BGP neighbor (R101). This ensures that the CE can advertise its routes to the corresponding PE router in AS100.

#### client-A1 Configuration

```bash
ip addr add 192.168.1.101/24 dev enp0s3
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

- **Read mode:** Displays file contents (like `cat`).
- **Write mode:** Accepts a file path, offset and content.

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

###### `deploy.sh`

```bash
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

```

Similarly to the consumer edge of Site 1, we configured dynamic routing via BGP, advertising all the site’s known networks, including the VLAN-associated addresses.

To configure VLANs, two distinct virtual sub-interfaces are created on the physical interface eth1, each corresponding to a specific VLAN. This configuration enables eth1 to serve as a trunk link, carrying tagged traffic for both VLANs. Each virtual sub-interface is then assigned an IP address.

#### Switch Configuration

###### `deploy.sh`

```bash
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
```

Authentication requests are received on the virtual bridge interface, which aggregates the two interfaces connected to the client devices in the separate VLANs. These requests originate from clients within each VLAN.

The switch, acting as the authenticator, forwards the requests to the RADIUS server (EAPoL forwarding is enabled) using the IP address assigned to the bridge interface (that embeds eth0). Routing to VPN Site 3, where the RADIUS server resides, is handled by the provider network via the BGP/MPLS backbone.

Now, to run the hostapd deamon to handle the RADIUS communication:

```bash
# Start hostapd in background
hostapd -B /etc/hostapd/hostapd.conf
```

`hostapd.conf`:

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

#### eBPF Configuration

##### System Design

The system is designed through two core XDP components that work at the kernel level and one in user space. The goal is to record the authentication information of stations and the VLAN assigned by the RADIUS server, and then enforce forwarding and VLAN assignment on the switch.

##### `xdp_eap.c` — EAP identity → MAC

This module captures **EAP‑Response/Identity** from supplicants and records the MAC address associated with the identity contained in the EAP Identity response. We need this because RADIUS replies do not carry the supplicant MAC, and to avoid hard‑coded mappings in user space, we maintain a dynamic `identity → MAC` mapping to then correlate RADIUS decisions with the actual device.

It also captures **EAPOL‑Logoff** when a user leaves and deauthenticates. In that case it changes the station **state** so that the userspace program can immediately undo what was done during enforcement.

Key points:

- Learns and keeps `identity → { mac, ifindex, ts_ns }`.
- Continuously refreshed as EAP responses arrive (even though not in our deployment, users may change the underlying MAC address).
- **TTL policy (10s):** when a new MAC address is found for a given identity, if a previous record exists **within the TTL**, we **keep the old value** to avoid flipping between ports; a new MAC replaces it only **after TTL**.
- Detects **EAPOL‑Logoff** and flips `state = 0` so userspace can roll back prior enforcement.
- Map pinned at: `/sys/fs/bpf/identity_map`.

##### `xdp_radius.c` — RADIUS decisions and VLAN

This is the core module that parses RADIUS packets and records both the authentication outcome and the VLAN assignment.

- Processes **Access‑Accept** packets.
- Extracts:

  - **User‑Name** (identity) → used to look up the MAC in `identity_map`.
  - **Tunnel‑Private‑Group‑ID** → VLAN ID assigned by the server.

- Stores an **auth** entry keyed by **MAC** with:

  - `vlan_id`, `state` (1=auth, 0=deauth), `applied` (flipped by userspace after enforcement), `ifindex`, `last_seen_ns`.

This lets userspace retrieve per‑station decisions and enforce forwarding/VLAN accordingly.

- Map pinned at: `/sys/fs/bpf/auth_map`.

##### `xdp_user` — Userspace enforcer (polling)

A simple polling process reads, at regular intervals, the auth map populated by `xdp_radius`. When it finds an entry not yet applied, it enforces the configuration for that station.

- If `applied == 0` for a MAC:

  - enable L2 forwarding for the station (e.g., via **ebtables**),
  - assign the **VLAN** learned from `Tunnel‑Private‑Group‑ID`,
  - ensure the **trunk** between the switch and the gateway carries that VLAN.

- After enforcement, mark `applied = 1` so it is not reprocessed in the next polling cycles.

- If `state == 0` and `applied == 1` for a MAC (e.g., after **EAPOL‑Logoff**):

  - undo the previous enforcement,
  - remove the **VLAN** membership for that station,
  - then mark `applied = 0`.

- Entries are **not deleted** (so other processes might implement monitoring capabilities; timestamps allow future housekeeping if desired).

##### State model (`state` / `applied`)

- `state` — kernel-driven auth status:

  - `1` = authenticated (from `xdp_radius` on **Access‑Accept**),
  - `0` = deauth (from `xdp_eap` on **EAPOL‑Logoff**).

- `applied` — userspace bookmark:

  - `0` = not yet enforced / already rolled back,
  - `1` = enforcement in place. Only userspace flips this.

**State transitions (per‑MAC):**

| Condition            | Who set it            | Userspace action            | Next state  |
| -------------------- | --------------------- | --------------------------- | ----------- |
| `state=1, applied=0` | kernel (`xdp_radius`) | Enforce forwarding + VLAN   | `applied=1` |
| `state=1, applied=1` | —                     | No change (keep enforced)   | —           |
| `state=0, applied=1` | kernel (`xdp_eap`)    | Rollback (undo enforcement) | `applied=0` |

##### `xdp_eap.c`

```c
// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "xdp_common.h"

#define ETH_P_EAPOL 0x888E
#define EAPOL_TYPE_EAP_PACKET 0
#define EAPOL_TYPE_LOGOFF 2
#define EAP_RES_CODE 2
#define IDENTITY_CODE 1

#define TTL_NS (10ULL * 1000000000ULL) /* identity claim valid for 10s */

struct eapol_hdr {
	__u8 ver, type;
	__be16 len;
} __attribute__((packed));

struct eap_hdr {
	__u8 code, id;
	__be16 len;
} __attribute__((packed));

struct eap_id_t {
	__u8 type; /* 1 = Identity */
} __attribute__((packed));

SEC("xdp")
int xdp_eap_parse(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (!ok(eth, end, sizeof(*eth)))
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_EAPOL))
		return XDP_PASS;

	struct eapol_hdr *eol = (void *)(eth + 1);
	if (!ok(eol, end, sizeof(*eol)))
		return XDP_PASS;

	if (eol->type == EAPOL_TYPE_LOGOFF) {
		// signal access revoke
		struct auth_value *av =
		    bpf_map_lookup_elem(&auth_map, eth->h_source);
		if (av) {
			av->state = 0;
			av->last_seen_ns = bpf_ktime_get_ns();
		}

		return XDP_PASS;
	}

	if (eol->type != EAPOL_TYPE_EAP_PACKET)
		return XDP_PASS;

	struct eap_hdr *eap = (void *)(eol + 1);
	if (!ok(eap, end, sizeof(*eap)))
		return XDP_PASS;

	if (eap->code != EAP_RES_CODE)
		return XDP_PASS;

	struct eap_id_t *eid = (void *)(eap + 1);
	if (!ok(eid, end, sizeof(*eid)))
		return XDP_PASS;

	if (eid->type != IDENTITY_CODE)
		return XDP_PASS;

	__u16 eap_len = bpf_ntohs(eap->len);
	int id_len = (int)eap_len - (int)sizeof(*eap) - 1;
	if (id_len <= 0)
		return XDP_PASS;

	// extract the user identity
	unsigned char *id_ptr = (unsigned char *)(eid + 1);
	// bound the maximum string length
	id_len = id_len >= ID_MAX ? ID_MAX - 1 : id_len;

	struct identity_key key = {};
	// copies `len` bytes; including the null terminating
	// character (+1 is for '\0')
	bpf_core_read_str(key.id, id_len + 1, id_ptr);
	__u64 now = bpf_ktime_get_ns();

	// check whether the identity is already mapped to a mac
	struct identity_val *old_id = bpf_map_lookup_elem(&identity_map, &key);
	if (old_id) {
		// keep first claimant for TTL to avoid flipping between ports
		if (now - old_id->ts_ns < TTL_NS)
			return XDP_PASS;
	}

	struct identity_val val = {};
	val.ifindex = (__u32)ctx->ingress_ifindex;
	val.ts_ns = now;
	maccpy(val.mac, eth->h_source);

	bpf_map_update_elem(&identity_map, &key, &val, BPF_ANY);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

```

##### `xdp_radius.c`

```c
// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "xdp_common.h"

#define CODE_ACCESS_ACCEPT 2
#define HDR_LEN 20
#define ATTR_USER_NAME 1
#define ATTR_TUNNEL_PGID 81
#define UDP_PORT 1812
#define MAX_ATTRIBUTES 64

#define TTL_NS (15ULL * 1000000000ULL)

struct radius_hdr {
	__u8 code;
	__u8 id;
	__u16 len;
	__u8 auth[16];
} __attribute__((packed));

struct radius_attr_t {
	__u8 type;
	__u8 len;
} __attribute__((packed));

static __always_inline struct udphdr *get_udp(void *data, void *end)
{
	struct ethhdr *eth = data;
	if (!ok(eth, end, sizeof(*eth)))
		return NULL;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return NULL;

	struct iphdr *ip = (void *)(eth + 1);
	if (!ok(ip, end, sizeof(*ip)))
		return NULL;

	if (ip->protocol != IPPROTO_UDP)
		return NULL;

	int ihl = ip->ihl * 4;
	if (ihl < sizeof(*ip) || ihl > 60)
		return NULL;

	struct udphdr *udp = (void *)((char *)ip + ihl);
	if (!ok(udp, end, sizeof(*udp)))
		return NULL;

	return udp;
}

/* Parse decimal VLAN (1..4094) */
static __always_inline bool parse_vlan(const char *src, const char *end,
				       __u16 *out)
{
	__u32 v = 0;
	bool seen = false;
	for (int i = 0; i < 5; i++) {
		if (!ok(src + i, end, 1))
			break;

		char c = src[i];
		if (c < '0' || c > '9')
			break;
		// accumulate digit
		v = v * 10 + (c - '0');
		seen = true;
		if (v > 4094)
			break;
	}
	if (!seen || v < 1 || v > 4094)
		return false;

	*out = (__u16)v;

	return true;
}

SEC("xdp")
int xdp_radius_parse(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

	struct udphdr *udp = get_udp(data, end);
	if (!udp)
		return XDP_PASS;

	if (udp->source != bpf_htons(UDP_PORT))
		return XDP_PASS;

	// extract the RADIUS header
	struct radius_hdr *radius = (void *)(udp + 1);
	if (!ok(radius, end, sizeof(*radius)))
		return XDP_PASS;

	__u8 code = radius->code;

	if (!(code == CODE_ACCESS_ACCEPT))
		return XDP_PASS;

	// identity associated to the user-name attribute
	struct identity_key key = {};
	int uname_len = 0;

	// vlan attribute
	__u16 vlan = 0;

	struct radius_attr_t *curr_attr = (void *)(radius + 1);
	for (int i = 0; i < MAX_ATTRIBUTES; i++) {
		if (!ok(curr_attr, end, sizeof(*curr_attr)))
			break;

		__u8 at = curr_attr->type;
		__u8 al = curr_attr->len - (int)sizeof(*curr_attr);

		char *av = (void *)(curr_attr + 1);

		if (at == ATTR_USER_NAME) {
			// bound the user-name length
			uname_len = al >= ID_MAX ? ID_MAX - 1 : al;
			// copies `len` bytes; including the null terminating
			// character (+1 is for '\0')
			bpf_core_read_str(key.id, uname_len + 1, av);
		} else if (at == ATTR_TUNNEL_PGID) {
			if (!parse_vlan(av, end, &vlan))
				break;
		}

		if (uname_len && vlan)
			// both attributes found, we can exit
			break;

		curr_attr =
		    (void *)((char *)curr_attr + al + (int)sizeof(*curr_attr));
	}

	// check if both user-name and vlan are present
	if (!uname_len || !vlan)
		return XDP_PASS;

	// lookup for the mac associated with the user-name
	struct identity_val *iv = bpf_map_lookup_elem(&identity_map, &key);
	if (!iv)
		return XDP_PASS;

	__u64 now = bpf_ktime_get_ns();
	if (now - iv->ts_ns > TTL_NS) {
		// stale mapping; ignore
		return XDP_PASS;
	}

	// set the authentication value for the mac of the user
	struct auth_value val = {};
	val.vlan_id = vlan;
	val.state = 1; // The packet is ACCESS-ACCEPT
	val.applied = 0;
	val.ifindex = iv->ifindex;
	val.last_seen_ns = now;

	bpf_map_update_elem(&auth_map, iv->mac, &val, BPF_ANY);

	// cleanup: free identity after use
	bpf_map_delete_elem(&identity_map, &key);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

```

###### `xdp_common.c`

```c
#pragma once
#include <linux/types.h>
#include <stdbool.h>

/* Decision stored by xdp_radius for the userspace enforcer */
struct auth_value {
	__u16 vlan_id;	    /* VLAN from Tunnel-Private-Group-ID  */
	__u8 state;	    /* 1 = Auth, 0 = Deauth */
	__u8 applied;	    /* userspace flips to 1 after enforcement */
	__u32 ifindex;	    /* access port for this station */
	__u64 last_seen_ns; /* for housekeeping */
};

/* Supplicant Identity key */
#define ID_MAX 64
struct identity_key {
	char id[ID_MAX];
};

/* Value for identity map: who presented this identity recently */
struct identity_val {
	__u8 mac[6];
	__u32 ifindex;
	__u64 ts_ns;
};

/* identity -> {mac, ifindex, ts} */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct identity_key);
	__type(value, struct identity_val);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME); /* /sys/fs/bpf/identity_map */
} identity_map SEC(".maps");

/* mac -> {vlan, state, applied, ifindex, ts} (used here only to flip state on
 * Logoff) */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u8[6]);
	__type(value, struct auth_value);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME); /* /sys/fs/bpf/auth_map */
} auth_map SEC(".maps");

/* Bounds check helper */
static __always_inline bool ok(const void *p, const void *end, __u64 sz)
{
	return (const void *)((const char *)p + sz) <= end;
}

static __always_inline void maccpy(__u8 *dst, const __u8 *src)
{
	for (int i = 0; i < ETH_ALEN; i++) {
		dst[i] = src[i];
	}
}

```

###### `xdp_user/src/main.rs` (Implemented in Rust)

```rust
use anyhow::{bail, Context, Result};
use aya::maps::{HashMap as BpfHashMap, Map, MapData};
use aya::Pod;
use clap::Parser;
use log::{debug, info, warn, LevelFilter};
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
    state: u8,    // 1=auth, 0=deauth
    applied: u8,  // userspace flips this
    ifindex: u32, // access port (from EAP/identity logic)
    last_seen_ns: u64,
}
unsafe impl Pod for AuthValue {}

#[derive(Parser, Debug)]
#[command(name = "xdp_user")]
struct Args {
    /// Linux bridge name
    #[arg(long, default_value = "br0")]
    bridge: String,

    /// VLAN→iface mapping, e.g. "32:eth1,95:eth2"
    #[arg(long, value_parser = parse_vlan_map)]
    vlan_map: HashMap<u16, String>,

    /// Pinned BPF map path from xdp_radius.c
    #[arg(long, default_value = "/sys/fs/bpf/auth_map")]
    map_path: String,

    /// Interface towards the gateway
    #[arg(long, default_value = "eth0")]
    gateway_iface: String,

    /// Polling interval in ms
    #[arg(long, default_value_t = 200)]
    interval_ms: u64,

    /// Log level: off|error|warn|info|debug|trace
    #[arg(long, default_value = "info")]
    log_level: LevelFilter,
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
    debug!("exec: {} {:?}", cmd, args);
    let st = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("spawn failed: {} {:?}", cmd, args))?;

    if !st.success() {
        bail!("command failed: {} {:?}", cmd, args);
    }
    Ok(())
}

fn ensure_bridge_vlan_filtering(bridge: &str) -> Result<()> {
    info!("enabling VLAN filtering on bridge {}", bridge);
    run(
        "ip",
        &[
            "link",
            "set",
            "dev",
            bridge,
            "type",
            "bridge",
            "vlan_filtering",
            "1",
        ],
    )
    .or(Ok(()))
}

fn enable_vlan(iface: &str, gateway_iface: &str, vid: u16) -> Result<()> {
    // Remove existing vid (best-effort), then add as PVID untagged
    debug!("set PVID {} (untagged) on {}", vid, iface);
    run(
        "bridge",
        &[
            "vlan",
            "add",
            "dev",
            iface,
            "vid",
            &vid.to_string(),
            "pvid",
            "untagged",
        ],
    )?;
    run(
        "bridge",
        &["vlan", "add", "dev", gateway_iface, "vid", &vid.to_string()],
    )
}

fn disable_vlan(iface: &str, gateway_iface: &str, vid: u16) -> Result<()> {
    debug!("remove VID {} on {}", vid, iface);
    run(
        "bridge",
        &["vlan", "del", "dev", gateway_iface, "vid", &vid.to_string()],
    )
    .or(Ok(()))
}

fn mac_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn allow_mac_on_iface(mac: &[u8; 6], iface: &str) -> Result<()> {
    let macs = mac_string(unsafe { &*(mac as *const _ as *const [u8; 6]) });
    info!("allow MAC {} on {}", macs, iface);

    // Ingress rule
    run(
        "ebtables",
        &["-A", "FORWARD", "-i", iface, "-s", &macs, "-j", "ACCEPT"],
    )?;

    // Egress rule
    run(
        "ebtables",
        &["-A", "FORWARD", "-o", iface, "-d", &macs, "-j", "ACCEPT"],
    )?;

    Ok(())
}

fn revoke_mac_on_iface(mac: &[u8; 6], iface: &str) -> Result<()> {
    let macs = mac_string(unsafe { &*(mac as *const _ as *const [u8; 6]) });
    info!("revoke MAC {} on {}", macs, iface);

    let _ = run(
        "ebtables",
        &["-D", "FORWARD", "-i", iface, "-s", &macs, "-j", "ACCEPT"],
    );
    let _ = run(
        "ebtables",
        &["-D", "FORWARD", "-o", iface, "-d", &macs, "-j", "ACCEPT"],
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger from flag (env can still override via RUST_LOG)
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(args.log_level.to_string()),
    )
    .format_timestamp_secs()
    .init();

    if !Uid::current().is_root() {
        bail!("run as root");
    }

    info!(
        "xdp_user start: bridge={}, gateway_iface={}, map_path={}, interval={}ms, vlan_map={:?}",
        args.bridge, args.gateway_iface, args.map_path, args.interval_ms, args.vlan_map
    );

    // VLAN filtering on bridge
    ensure_bridge_vlan_filtering(&args.bridge)?;

    if !Path::new(&args.map_path).exists() {
        bail!("map not found: {}", args.map_path);
    }

    // Open pinned map written by xdp_radius.c
    info!("opening pinned map at {}", args.map_path);
    let md = MapData::from_pin(&args.map_path).context("open pinned auth_map")?;
    let mut map: BpfHashMap<_, [u8; 6], AuthValue> =
        BpfHashMap::try_from(Map::HashMap(md)).context("cast to HashMap")?;

    loop {
        debug!("polling auth_map...");
        let mut to_update: Vec<([u8; 6], AuthValue)> = Vec::new();

        for item in map.iter() {
            let (mac_key, mut val) = match item {
                Ok((k, v)) => (k, v),
                Err(e) => {
                    warn!("map.iter entry error: {e}");
                    continue;
                }
            };

            let Some(iface) = args.vlan_map.get(&val.vlan_id) else {
                warn!(
                    "no iface mapping for VLAN {} (mac={})",
                    val.vlan_id,
                    mac_string(&mac_key)
                );
                continue;
            };

            let macs = mac_string(&mac_key);

            if val.state == 1 && val.applied == 0 {
                info!("ACCEPT {} vlan {} -> {}", macs, val.vlan_id, iface);

                enable_vlan(iface, &args.gateway_iface, val.vlan_id)
                    .with_context(|| format!("set pvid {} on {}", val.vlan_id, iface))?;

                allow_mac_on_iface(&mac_key, iface)
                    .with_context(|| format!("allow {} on {}", &macs, iface))?;

                val.applied = 1;
                to_update.push((mac_key, val));
            } else if val.state == 0 && val.applied == 1 {
                info!("REVOKE {} vlan {} -> {}", macs, val.vlan_id, iface);

                revoke_mac_on_iface(&mac_key, iface)
                    .with_context(|| format!("revoke {} on {}", &macs, iface))?;

                let _ = disable_vlan(iface, &args.gateway_iface, val.vlan_id);

                val.applied = 0;
                to_update.push((mac_key, val));
            } else {
                debug!(
                    "noop for {}: state={}, applied={}, vlan={}, ifindex={}",
                    macs, val.state, val.applied, val.vlan_id, val.ifindex
                );
            }
        }

        if !to_update.is_empty() {
            debug!("writing {} updates back to map", to_update.len());
        }
        for (mac_key, val) in to_update {
            let _ = map.insert(&mac_key, &val, 0);
        }

        thread::sleep(Duration::from_millis(args.interval_ms));
    }
}

```

**NOTE**: To avoid enlarging the document we are not including the Makefile, the xdp_loader binary and the Cargo.toml file for building the Rust user space application.

###### Build and Deploy

To compile the user-space program, Rust was required. Therefore, the `nsdcourse/ebpf:latest` container was extended to include Rust, the XDP project pre-installed in `/root/xdp-tutorial`, and the Rust user-space application already compiled. The resulting container is available at `0xmenna01/ebpf-rust:latest`.

`load_xdp_radius.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

cd /root/xdp-tutorial
./configure && make

# Move to project directory
cd xdp_radius_auth

# Copy the loader into our directory
cp ../basic-solutions/xdp_loader.c .

ip link set eth0 xdp off
ip link set eth1 xdp off
ip link set eth2 xdp off

# Build kernel objects from source
make

# Attach EAP capture program to access ports
./xdp_loader -A --dev eth1 --filename xdp_eap.o --progname xdp_eap_parse || true
./xdp_loader -A --dev eth2 --filename xdp_eap.o --progname xdp_eap_parse || true

# Attach RADIUS parser to uplink port
./xdp_loader -A --dev eth0 --filename xdp_radius.o --progname xdp_radius_parse || true

# Launch userspace enforcer (Rust based binary)
cd xdp_user
./target/release/xdp_user \
  --bridge br0 \
  --vlan-map 32:eth1,95:eth2 \
  --map-path /sys/fs/bpf/auth_map \
  --gateway-iface eth0 \
  --interval-ms 1000 \
  --log-level info

```

#### client-B1 Configuration

###### `deploy.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

SUPPLICANT_CONF="${SUPPLICANT_CONF:-/root/config/b1_supplicant.conf}"

# Link up
ip link set eth0 up

# Addressing & route
ip addr add 192.168.32.101/24 dev eth0
ip route add default via 192.168.32.1 dev eth0

# Install supplicant config
cat "$SUPPLICANT_CONF" > /etc/wpa_supplicant.conf

echo "client-B1 deploy complete."

```

`b1_supplicant.conf`:

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

To run the supplicant deamon:

```bash
# Start wpa_supplicant in background
wpa_supplicant -B -c /etc/wpa_supplicant.conf -D wired -i eth0
```

#### client-B2 Configuration

###### `deploy.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

SUPPLICANT_CONF="${SUPPLICANT_CONF:-/root/config/b2_supplicant.conf}"

# Link up
ip link set eth0 up

# Addressing & route (idempotent)
ip addr add 192.168.95.101/24 dev eth0
ip route add default via 192.168.95.1 dev eth0

# Install supplicant config
cat "$SUPPLICANT_CONF" > /etc/wpa_supplicant.conf

echo "client-B2 deploy complete."

```

`b2_supplicant.conf`:

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

To run the supplicant deamon:

```bash
# Start wpa_supplicant in background
wpa_supplicant -B -c /etc/wpa_supplicant.conf -D wired -i eth0
```

---

### VPN Site 3

#### CE3 Configuration

###### `deploy.sh`

```bash
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

```

#### Radius Server Configuration

###### `deploy.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ip addr add 192.168.3.101/24 dev eth0
ip route add default via 192.168.3.1

cat /root/config/clients.conf > /etc/freeradius/3.0/clients.conf
cat /root/config/users.conf   > /etc/freeradius/3.0/users

service freeradius start

echo "RADIUS deploy complete."
```

Set the IP address of the authenticator device (i.e., the switch) from which the RADIUS server will receive authentication requests, and configure the shared secret used to secure the communication between the switch and the server.

`clients.conf`:

```text
client cumulus1 {
    ipaddr = 192.168.2.100
    secret = "rad1u5_5ecret"
    shortname = nsd_project
}
```

Configure the users' authentication details and define the VLAN IDs as attributes in the RADIUS response message, to be returned upon successful authentication.

`users.conf`:

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
