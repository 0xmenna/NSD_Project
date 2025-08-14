#!/usr/bin/env bash
set -euo pipefail

cd /root/xdp-tutorial/xdp_radius_auth

# Build kernel objects from source
make

# Attach EAP capture program to access ports
./xdp_loader -A --dev eth1 --filename xdp_eap.o --progname xdp_eap_parse
./xdp_loader -A --dev eth2 --filename xdp_eap.o --progname xdp_eap_parse

# Attach RADIUS parser to uplink port
./xdp_loader -A --dev eth0 --filename xdp_radius.o --progname xdp_radius_parse

# Launch userspace enforcer (Rust based binary)
cd xdp_user
./target/release/xdp_user \
  --bridge br0 \
  --vlan-map 32:eth1,95:eth2 \
  --map-path /sys/fs/bpf/auth_map \
  --gateway-iface eth0 \
  --interval-ms 1000 \
  --log-level info
