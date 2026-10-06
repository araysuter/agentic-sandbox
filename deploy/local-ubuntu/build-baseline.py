#!/usr/bin/env python3
"""Prepare a secret-free immutable baseline; run only after BIOS SVM/KVM is enabled.

The one-time preparation guest has QEMU user-mode internet for package downloads.
Runtime guests use the separate host-enforced default-deny network policy instead.
No libvirt network or global firewall configuration is touched by this builder.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import tempfile
import urllib.request

IMAGE_URL = 'https://cloud-images.ubuntu.com/noble/20260926/noble-server-cloudimg-amd64.img'
IMAGE_SHA = '6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2'
BASELINE = Path('/var/lib/agentic-sandbox/baselines/ubuntu-24.04-opencode.qcow2')

PREPARE = r'''#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --no-install-recommends -y cloud-init qemu-guest-agent docker.io git \
  curl ca-certificates python3 python3-venv python3-pip jq ripgrep build-essential \
  nodejs npm nftables iptables
install -d /opt/disposable /opt/disposable/semgrep-rules /var/lib/disposable/home/.cache/trivy
download() {
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 "$1" -o "$2"
  printf '%s  %s\n' "$3" "$2" | sha256sum --check --status
}
cd /tmp
download https://github.com/anomalyco/opencode/releases/download/v1.18.35/opencode-linux-x64.tar.gz opencode.tar.gz c8f888b451f5494a18f858fffb0e0b68f4e4baa9c241761c5f206884f0fa640d
tar -xzf opencode.tar.gz
install -m 0755 opencode /usr/local/bin/opencode
download https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz gitleaks.tar.gz 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
tar -xzf gitleaks.tar.gz gitleaks
install -m 0755 gitleaks /usr/local/bin/gitleaks
download https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz trivy.tar.gz c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
tar -xzf trivy.tar.gz trivy
install -m 0755 trivy /usr/local/bin/trivy
python3 -m venv /opt/disposable/semgrep-venv
/opt/disposable/semgrep-venv/bin/pip install --disable-pip-version-check semgrep==1.179.0
ln -s /opt/disposable/semgrep-venv/bin/semgrep /usr/local/bin/semgrep
download https://codeload.github.com/semgrep/semgrep-rules/tar.gz/a84ff9cc2453ca91d581380de4b8b3f272f6f4be rules.tar.gz b227c2d234ffd9c84c4dbd6619a5897a7192637c141baeace3bfc37b0715a887
tar -xzf rules.tar.gz --strip-components=1 -C /opt/disposable/semgrep-rules
systemctl enable --now docker qemu-guest-agent
docker pull busybox:1.36
docker run --rm --network none busybox:1.36 true
trivy --cache-dir /var/lib/disposable/home/.cache/trivy image --download-db-only
trivy --cache-dir /var/lib/disposable/home/.cache/trivy image --download-java-db-only
mkdir -p /tmp/trivy-warm
printf 'FROM busybox:1.36\nUSER 1000\n' > /tmp/trivy-warm/Dockerfile
trivy --cache-dir /var/lib/disposable/home/.cache/trivy config /tmp/trivy-warm
rm -rf /tmp/trivy-warm
opencode --version
# No model request or upstream credential: initialize with the guest HOME/XDG layout.
# This version bundles @ai-sdk/openai-compatible in its provider registry.
HOME=/var/lib/disposable/home \
XDG_CONFIG_HOME=/var/lib/disposable/home/.config \
XDG_DATA_HOME=/var/lib/disposable/home/.local/share \
OPENCODE_DISABLE_MODELS_FETCH=true OPENCODE_DISABLE_AUTOUPDATE=true \
OPENCODE_DISABLE_PROJECT_CONFIG=true \
OPENCODE_CONFIG_CONTENT='{"enabled_providers":["tensorfold"],"model":"tensorfold/fixture","small_model":"tensorfold/fixture","share":"disabled","autoupdate":false,"plugin":[],"provider":{"tensorfold":{"npm":"@ai-sdk/openai-compatible","options":{"baseURL":"http://127.0.0.1:9/v1","apiKey":"preparation-placeholder"},"models":{"fixture":{"name":"fixture","tool_call":true}}}}}' \
opencode models tensorfold | grep -F tensorfold/fixture
semgrep --version
gitleaks version
trivy --version
# Package versions and container digest are recorded inside the frozen image.
dpkg-query -W > /opt/disposable/packages.txt
docker image inspect busybox:1.36 --format '{{json .RepoDigests}}' > /opt/disposable/busybox-digest.json
printf 'ready\n' > /opt/disposable/baseline-ready
systemctl disable --now ssh.service ssh.socket || true
rm -f /etc/ssh/ssh_host_* /tmp/opencode* /tmp/gitleaks* /tmp/trivy* /tmp/rules.tar.gz
apt-get clean
rm -rf /var/lib/apt/lists/* /root/.cache/pip
cloud-init clean --logs --machine-id
'''


def command(args):
    subprocess.run(args, check=True)


def main():
    if os.geteuid() != 0 or not Path('/dev/kvm').exists():
        raise RuntimeError('root and working /dev/kvm required; enable BIOS SVM before building')
    if BASELINE.exists() or BASELINE.is_symlink():
        raise RuntimeError('baseline already exists; stop all VMs and archive it before rebuilding')
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    BASELINE.parent.chmod(0o755)
    qemu = pwd.getpwnam('libvirt-qemu')
    with tempfile.TemporaryDirectory(prefix='.baseline-build-', dir=BASELINE.parent) as directory:
        work = Path(directory)
        work.chmod(0o755)
        disk = work / 'build.qcow2'
        with urllib.request.urlopen(IMAGE_URL, timeout=60) as response, disk.open('wb') as output:
            checksum = hashlib.sha256()
            while block := response.read(1024 * 1024):
                checksum.update(block)
                output.write(block)
        if checksum.hexdigest() != IMAGE_SHA:
            raise RuntimeError('Ubuntu image checksum mismatch')
        command(['qemu-img', 'resize', str(disk), '24G'])
        cloud = {
            'ssh_pwauth': False, 'disable_root': True,
            'write_files': [{'path': '/opt/prepare-baseline.sh', 'permissions': '0700',
                             'content': PREPARE}],
            'runcmd': [['bash', '/opt/prepare-baseline.sh']],
            'power_state': {'mode': 'poweroff', 'delay': 'now',
                            'condition': ['test', '-f', '/opt/disposable/baseline-ready']},
        }
        (work / 'user-data').write_text('#cloud-config\n' + json.dumps(cloud) + '\n')
        (work / 'meta-data').write_text('instance-id: agentic-baseline-builder\nlocal-hostname: agentic-baseline\n')
        seed = work / 'seed.iso'
        command(['cloud-localds', str(seed), str(work / 'user-data'), str(work / 'meta-data')])
        os.chown(work, qemu.pw_uid, qemu.pw_gid)
        os.chown(disk, qemu.pw_uid, qemu.pw_gid)
        logfile = work / 'serial.log'
        process = subprocess.Popen([
            'runuser', '-u', 'libvirt-qemu', '--', 'qemu-system-x86_64',
            '-enable-kvm', '-cpu', 'host', '-m', '4096', '-smp', '2',
            '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(logfile),
            '-drive', f'file={disk},format=qcow2,if=virtio',
            '-drive', f'file={seed},format=raw,media=cdrom,readonly=on',
            '-netdev', 'user,id=prep', '-device', 'virtio-net-pci,netdev=prep',
            '-device', 'virtio-serial-pci', '-chardev', 'socket,path=' + str(work / 'qga.sock') + ',server=on,wait=off,id=qga',
            '-device', 'virtserialport,chardev=qga,name=org.qemu.guest_agent.0',
        ], start_new_session=True)
        try:
            if process.wait(timeout=5400) != 0:
                raise RuntimeError('baseline preparation VM failed')
            marker = subprocess.check_output([
                'guestfish', '--ro', '-a', str(disk), '-i',
                'cat', '/opt/disposable/baseline-ready'], text=True)
            if marker.strip() != 'ready':
                raise RuntimeError('baseline preparation incomplete')
            frozen = work / 'frozen.qcow2'
            command(['qemu-img', 'convert', '-O', 'qcow2', '-c', str(disk), str(frozen)])
            os.chown(frozen, 0, 0)
            frozen.chmod(0o444)
            os.replace(frozen, BASELINE)
            print('Prepared root-owned read-only baseline:', BASELINE)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            if logfile.exists():
                # Preserve bounded diagnostics, not a growing preparation disk.
                with logfile.open('rb') as data:
                    data.seek(max(0, logfile.stat().st_size - 2 * 1024 * 1024))
                    log = Path('/var/log/agentic-sandbox-baseline.log')
                    if log.is_symlink():
                        raise RuntimeError('refusing symlink log destination')
                    log.write_bytes(data.read())
                    log.chmod(0o600)


if __name__ == '__main__':
    main()
