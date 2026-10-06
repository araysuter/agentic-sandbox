#!/usr/bin/env bash
# Deliberately installs no host Docker or default libvirt network configuration.
set -euo pipefail
[[ $EUID = 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
. /etc/os-release
[[ $ID = ubuntu && $VERSION_ID = 24.04 ]] || { echo 'Ubuntu 24.04 required.' >&2; exit 1; }
apt-get update
apt-get install --no-install-recommends -y \
  build-essential pkg-config libssl-dev protobuf-compiler python3 curl \
  ca-certificates git rsync qemu-system-x86 qemu-utils cloud-image-utils \
  libvirt-daemon-system libvirt-clients libvirt-dev nftables iproute2 libguestfs-tools gnupg
# libvirt is required; existing network definitions and firewall policy are retained.
systemctl enable --now libvirtd.service
