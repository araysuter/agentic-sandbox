#!/usr/bin/env bash
# Installs no host Docker; leaves a newly created unused default NAT network off.
set -euo pipefail
[[ $EUID = 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
. /etc/os-release
[[ $ID = ubuntu && $VERSION_ID = 24.04 ]] || { echo 'Ubuntu 24.04 required.' >&2; exit 1; }
had_default=0
[[ -f /etc/libvirt/qemu/networks/default.xml ]] && had_default=1
apt-get update
apt-get install --no-install-recommends -y \
  build-essential pkg-config libssl-dev protobuf-compiler python3 curl \
  ca-certificates git rsync qemu-system-x86 qemu-utils cloud-image-utils \
  libvirt-daemon-system libvirt-clients libvirt-dev nftables iproute2 libguestfs-tools gnupg
# libvirt is required; existing network definitions and firewall policy are retained.
systemctl enable --now libvirtd.service
# Ubuntu pulls default-network configuration as a dependency even without
# recommendations. Disable it only when this install created it and there are
# no existing guests; never change an operator's pre-existing network.
domains=$(virsh -c qemu:///system list --all --name)
if [[ $had_default = 0 && -z ${domains//[[:space:]]/} ]]; then
  if virsh -c qemu:///system net-info default >/dev/null 2>&1; then
    virsh -c qemu:///system net-autostart default --disable
    if virsh -c qemu:///system net-list --name | grep -qx default; then
      virsh -c qemu:///system net-destroy default
    fi
  fi
fi
