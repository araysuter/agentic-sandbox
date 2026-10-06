#!/usr/bin/env python3
"""Disposable KVM lifecycle. All workload commands execute via the guest agent.

Requires a prepared immutable Ubuntu baseline; no package installs on the host.
The controller owns the admission gate and calls this root-owned entry point.
"""
import base64
import datetime
import ipaddress
import json
import os
import select
import selectors
import signal
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

MAX_SOURCE = 512 * 1024 * 1024
MAX_REPORT = 2 * 1024 * 1024
MAX_MESSAGE = 64 * 1024
ROOT = Path(__file__).resolve().parents[1]


def command(args, *, data=None, timeout=30, optional=False):
    # QGA responses are guest-controlled. Bound all subprocess output before
    # parsing, rather than relying on the requested guest read chunk size.
    parent_pid = os.getpid()
    def parent_death_signal():
        if sys.platform == "linux":
            import ctypes
            if ctypes.CDLL(None).prctl(1, signal.SIGKILL) != 0:
                raise RuntimeError("cannot arm subprocess parent-death signal")
            if os.getppid() != parent_pid:
                os.kill(os.getpid(), signal.SIGKILL)
    process = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                               preexec_fn=parent_death_signal if sys.platform == "linux" else None)
    try:
        if data is not None:
            process.stdin.write(data.encode())
            process.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        output = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise RuntimeError("host operation timed out")
            for key, _ in selector.select(timeout=0.1):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if len(output[key.data]) > 4 * 1024 * 1024:
                    raise RuntimeError("host control response exceeds size bound")
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        result = subprocess.CompletedProcess(args, process.returncode,
                    output["stdout"].decode("utf-8", errors="replace"),
                    output["stderr"].decode("utf-8", errors="replace"))
        if result.returncode and not optional:
            raise RuntimeError(f"host operation {args[0]} failed ({result.returncode})")
        return result
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()



def virsh(args, **kwargs):
    return command(["virsh", "--connect", "qemu:///system", *args], **kwargs)


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output)
    os.replace(temporary, path)


def checked_dir(value):
    root = Path(os.environ.get("DISPOSABLE_STATE_ROOT", "/var/lib/agentic-sandbox/disposable")).resolve()
    raw = Path(value)
    if not raw.is_absolute() or raw.is_symlink() or raw.parent.resolve() != root:
        raise ValueError("session directory must be directly under DISPOSABLE_STATE_ROOT")
    uuid.UUID(raw.name)
    if str(uuid.UUID(raw.name)) != raw.name:
        raise ValueError("canonical UUID session directory required")
    if not raw.is_dir():
        raise ValueError("session directory missing")
    for name in ("runtime.json", "request.json", "gateway.json", "source.tar"):
        if (raw / name).is_symlink():
            raise ValueError("symlink in host session state")
    return raw


def names(session):
    suffix = session.name.replace("-", "")[:12]
    return "asd-" + suffix, "asdb" + suffix[:10], "asdt" + suffix[:10], "asd_" + suffix


def network_settings():
    host = ipaddress.IPv4Address(os.environ.get("DISPOSABLE_GATEWAY_IP", "192.0.2.1"))
    network = ipaddress.IPv4Network(f"{host}/30", strict=False)
    if host != network.network_address + 1:
        raise ValueError("gateway must be first usable address in a dedicated /30")
    port = int(os.environ.get("DISPOSABLE_GATEWAY_PORT", "8123"))
    if not 1024 <= port <= 65535 or port in (8120, 8121, 8122):
        raise ValueError("dedicated non-administration gateway port required")
    return str(host), str(host + 1), str(network), port


def firewall_rules(session):
    _, bridge, tap, table = names(session)
    host, guest_ip, _, port = network_settings()
    # bridge prerouting sees every Ethernet packet, before inet policy. ARP is
    # needed only to discover our gateway; no bridge ports lead to another LAN.
    return f'''table bridge {table} {{
 chain ingress {{ type filter hook prerouting priority -300; policy accept;
  iifname "{tap}" ether type arp accept
  iifname "{tap}" ether type ip ip saddr {guest_ip} ip daddr {host} ip protocol tcp tcp dport {port} accept
  iifname "{tap}" drop
 }}
}}
table inet {table} {{
 chain input {{ type filter hook input priority -300; policy accept;
  iifname "{bridge}" ip daddr {host} tcp dport {port} accept
  iifname "{bridge}" drop
 }}
 chain forward {{ type filter hook forward priority -300; policy accept;
  iifname "{bridge}" drop
  oifname "{bridge}" drop
 }}
}}
'''


def preflight(require_baseline=True):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("disposable KVM runtime requires a trusted root Linux service")
    for tool in ("virsh", "qemu-img", "cloud-localds", "nft", "ip", "getent", "chown", "runuser", "systemd-run", "systemctl"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required host tool missing: {tool}")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("Linux pidfd signaling support and Python 3.9+ required")
    if not Path("/dev/kvm").is_char_device() or not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("KVM unavailable; no container fallback")
    virsh(["capabilities"])
    if command(["systemctl", "show", "basic.target", "--property=ActiveState", "--value"]).stdout.strip() != "active":
        raise RuntimeError("active host systemd required for independent deadline enforcement")
    if require_baseline:
        baseline = os.environ.get("DISPOSABLE_BASE_IMAGE", "")
        if not baseline:
            raise RuntimeError("DISPOSABLE_BASE_IMAGE must point to a prepared Ubuntu baseline")
        image = Path(baseline)
        info = image.stat()
        if not image.is_absolute() or image.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise RuntimeError("baseline must be an absolute regular immutable image")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("baseline must be root-owned and not group/world writable")
        details = json.loads(command(["qemu-img", "info", "--output=json", str(image)]).stdout)
        if details.get("format") != "qcow2" or details.get("backing-filename"):
            raise RuntimeError("baseline must be standalone qcow2")
        command(["getent", "passwd", os.environ.get("DISPOSABLE_QEMU_USER", "libvirt-qemu")])


def guest(session, execute, arguments=None):
    domain, _, _, _ = names(session)
    payload = {"execute": execute}
    if arguments is not None:
        payload["arguments"] = arguments
    reply = json.loads(virsh(["qemu-agent-command", domain, json.dumps(payload)], timeout=20).stdout)
    if "error" in reply:
        raise RuntimeError("guest control operation failed")
    return reply.get("return")


def guest_exec(session, args, timeout=120):
    pid = guest(session, "guest-exec", {"path": args[0], "arg": args[1:], "capture-output": True})["pid"]
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        status = guest(session, "guest-exec-status", {"pid": pid})
        if status.get("exited"):
            if status.get("exitcode", 1) != 0:
                raise RuntimeError("guest command failed")
            return base64.b64decode(status.get("out-data", ""))
        time.sleep(0.5)
    raise RuntimeError("guest command deadline exceeded")


def guest_write(session, target, source):
    handle = guest(session, "guest-file-open", {"path": target, "mode": "wb"})
    try:
        with open(source, "rb") as data:
            while True:
                block = data.read(32768)
                if not block:
                    break
                reply = guest(session, "guest-file-write", {"handle": handle,
                          "buf-b64": base64.b64encode(block).decode()})
                if reply.get("count") != len(block):
                    raise RuntimeError("guest transfer truncated")
    finally:
        guest(session, "guest-file-close", {"handle": handle})


def guest_read(session, target, limit):
    # Fixed guest names only. Root guest controls QGA, so this is output hygiene,
    # not independent attestation; no guest path is ever resolved on the host.
    if target not in ("/var/lib/disposable/report.json", "/var/lib/disposable/events.jsonl"):
        raise ValueError("artifact path is not allowlisted")
    check = "import os,stat; p=" + repr(target) + "; s=os.lstat(p); assert stat.S_ISREG(s.st_mode) and not stat.S_ISLNK(s.st_mode)"
    guest_exec(session, ["/usr/bin/python3", "-c", check], timeout=10)
    handle = guest(session, "guest-file-open", {"path": target, "mode": "rb"})
    data = bytearray()
    try:
        while True:
            reply = guest(session, "guest-file-read", {"handle": handle, "count": 32768})
            data.extend(base64.b64decode(reply.get("buf-b64", ""), validate=True))
            if len(data) > limit:
                raise RuntimeError("guest artifact exceeds size bound")
            if reply.get("eof"):
                return bytes(data)
    finally:
        guest(session, "guest-file-close", {"handle": handle})


def domain_xml(session, memory, cpus):
    domain, bridge, tap, _ = names(session)
    runtime = session / "vm"
    tree = ET.Element("domain", type="kvm")
    ET.SubElement(tree, "name").text = domain
    ET.SubElement(tree, "memory", unit="MiB").text = str(memory)
    ET.SubElement(tree, "vcpu").text = str(cpus)
    operating = ET.SubElement(tree, "os")
    ET.SubElement(operating, "type", arch="x86_64").text = "hvm"
    ET.SubElement(operating, "boot", dev="hd")
    features = ET.SubElement(tree, "features")
    ET.SubElement(features, "acpi")
    ET.SubElement(features, "apic")
    ET.SubElement(tree, "cpu", mode="host-passthrough")
    devices = ET.SubElement(tree, "devices")
    for filename, device, target in (("disk.qcow2", "disk", "vda"), ("seed.iso", "cdrom", "sda")):
        disk = ET.SubElement(devices, "disk", type="file", device=device)
        ET.SubElement(disk, "driver", name="qemu", type="qcow2" if device == "disk" else "raw")
        ET.SubElement(disk, "source", file=str(runtime / filename))
        ET.SubElement(disk, "target", dev=target, bus="virtio" if device == "disk" else "sata")
        if device == "cdrom":
            ET.SubElement(disk, "readonly")
    interface = ET.SubElement(devices, "interface", type="bridge")
    ET.SubElement(interface, "source", bridge=bridge)
    ET.SubElement(interface, "mac", address="52:54:00:ad:00:02")
    ET.SubElement(interface, "target", dev=tap)
    ET.SubElement(interface, "model", type="virtio")
    channel = ET.SubElement(devices, "channel", type="unix")
    ET.SubElement(channel, "source", mode="bind", path=str(runtime / "agent.sock"))
    ET.SubElement(channel, "target", type="virtio", name="org.qemu.guest_agent.0")
    ET.SubElement(devices, "console", type="pty")
    # No host filesystem, GPU, SSH key, libvirt socket, or shared Docker daemon.
    return ET.tostring(tree, encoding="unicode")


def arm_watchdog(session, deadline):
    domain = names(session)[0]
    # Fixed argv; neither report data nor repository code becomes host shell.
    calendar = deadline.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    command(["systemd-run", "--unit=" + domain + "-watchdog",
             "--on-calendar=" + calendar, "--timer-property=AccuracySec=1s",
             "--property=Type=oneshot", "--property=User=root",
             "--property=Restart=on-failure", "--property=RestartSec=5s",
             "--property=StartLimitIntervalSec=0", "--property=TimeoutStartSec=240s",
             "--setenv=DISPOSABLE_STATE_ROOT=" + str(session.parent),
             str(Path(sys.executable).resolve()), str(Path(__file__).resolve()), "watchdog", str(session)])
    if command(["systemctl", "show", domain + "-watchdog.timer", "--property=ActiveState", "--value"]).stdout.strip() != "active":
        raise RuntimeError("host deadline timer did not arm; refusing VM boot")


def disarm_watchdog(session):
    timer = names(session)[0] + "-watchdog.timer"
    load = command(["systemctl", "show", timer, "--property=LoadState", "--value"]).stdout.strip()
    if load == "loaded":
        command(["systemctl", "stop", timer])
    # Do not stop our own watchdog.service from inside its cleanup callback.


def process_start_time(pid):
    # /proc stat process name may contain spaces or ')'; fields after the final
    # ')' start at field3. Field22 is index19 in that tail.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def quiesce_provisioner(session):
    path = session / "runtime.json"
    if not path.exists():
        return
    info = json.loads(path.read_text())
    pid = info.get("provision_pid")
    if pid is None or pid == os.getpid():
        return  # start's own exception cleanup must not kill itself
    expected = info.get("provision_start_time")
    if not isinstance(pid, int) or pid <= 0 or not isinstance(expected, str) or not expected.isdigit():
        raise RuntimeError("invalid provisioner identity; cleanup remains pending")
    try:
        pidfd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return
    try:
        try:
            actual = process_start_time(pid)
        except FileNotFoundError:
            return
        if actual != expected:
            return  # original exited; this PID now belongs to another process
        # The pidfd identifies the original process across exit/PID reuse. Its
        # fixed child commands inherit PDEATHSIG; never signal a negative PGID.
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            pass
        ready, _, _ = select.select([pidfd], [], [], 10)
        if not ready:
            raise RuntimeError("provisioner exit not confirmed; policy retained")
    finally:
        os.close(pidfd)


def watchdog(session):
    for attempt in range(12):
        try:
            stop(session)
            return
        except Exception:
            if attempt == 11:
                raise  # host systemd restarts failed cleanup until it succeeds
            time.sleep(5)


def stop(session):
    quiesce_provisioner(session)
    domain, bridge, _, table = names(session)
    errors = []
    # Never remove firewall while the workload may still be alive.
    inventory = virsh(["list", "--all", "--name"])
    if domain in inventory.stdout.splitlines():
        virsh(["destroy", domain], optional=True)
        state = virsh(["domstate", domain])
        if "shut off" not in state.stdout.lower():
            raise RuntimeError("VM containment failed; firewall and disk retained")
        virsh(["undefine", domain])
        if domain in virsh(["list", "--all", "--name"]).stdout.splitlines():
            raise RuntimeError("VM definition removal failed; cleanup remains pending")
    tables = command(["nft", "list", "tables"]).stdout.splitlines()
    for family in ("bridge", "inet"):
        if f"table {family} {table}" in tables:
            if command(["nft", "delete", "table", family, table], optional=True).returncode:
                errors.append("firewall removal failed")
    links = json.loads(command(["ip", "-json", "link", "show"]).stdout)
    if bridge in [x["ifname"] for x in links]:
        if command(["ip", "link", "delete", bridge], optional=True).returncode:
            errors.append("bridge removal failed")
    runtime = session / "vm"
    if runtime.is_symlink():
        raise RuntimeError("unsafe runtime path")
    if runtime.exists():
        shutil.rmtree(runtime)
    for name in ("source.tar", "gateway.json"):
        (session / name).unlink(missing_ok=True)
    if errors:
        raise RuntimeError("; ".join(errors))
    disarm_watchdog(session)
    atomic_json(session / "runtime.json", {"state": "stopped", "contained": True})


def start(session):
    preflight()
    if (session / "runtime.json").exists():
        raise RuntimeError("session already provisioned; reconcile before retry")
    request = json.loads((session / "request.json").read_text())
    memory, cpus = request.get("memory_mb", 16384), request.get("vcpus", 6)
    if not isinstance(memory, int) or not 1024 <= memory <= 32768 or not isinstance(cpus, int) or not 1 <= cpus <= 8:
        raise ValueError("resource settings outside disposable profile bounds")
    deadline = datetime.datetime.fromisoformat(request["deadline"].replace("Z", "+00:00"))
    if deadline <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("session deadline already passed")
    gateway = json.loads((session / "gateway.json").read_text())
    host, guest_ip, network, port = network_settings()
    parsed = urllib.parse.urlsplit(gateway["url"])
    if parsed.scheme != "http" or parsed.hostname != host or parsed.port != port or parsed.username or parsed.password:
        raise ValueError("gateway must use dedicated bridge host and workload port")
    source = session / "source.tar"
    if source.exists() and (not source.is_file() or source.stat().st_size > MAX_SOURCE):
        raise ValueError("source archive exceeds limit")
    domain, bridge, _, _ = names(session)
    runtime = session / "vm"
    runtime.mkdir(mode=0o750)
    os.chmod(session, 0o711)
    qemu_user = os.environ.get("DISPOSABLE_QEMU_USER", "libvirt-qemu")
    atomic_json(session / "runtime.json", {"state": "provisioning", "domain": domain,
                "bridge": bridge, "network_policy": "default-deny", "gateway_port": port,
                "provision_pid": os.getpid(), "provision_start_time": process_start_time(os.getpid())})
    try:
        arm_watchdog(session, deadline)
        command(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                 os.environ["DISPOSABLE_BASE_IMAGE"], str(runtime / "disk.qcow2"), "80G"])
        # No user credentials; guest control is via libvirt's private agent channel.
        (runtime / "user-data").write_text("#cloud-config\nssh_pwauth: false\ndisable_root: true\n"
            "growpart:\n  mode: auto\n  devices: ['/']\nresize_rootfs: true\n"
            "runcmd:\n  - [systemctl, enable, --now, qemu-guest-agent]\n")
        (runtime / "meta-data").write_text(f"instance-id: {domain}\nlocal-hostname: {domain}\n")
        (runtime / "network-config").write_text("version: 2\nethernets:\n  sandbox:\n"
            "    match:\n      macaddress: '52:54:00:ad:00:02'\n    dhcp4: false\n    dhcp6: false\n"
            f"    addresses: [{guest_ip}/30]\n    routes:\n      - to: default\n        via: {host}\n")
        command(["cloud-localds", "--network-config", str(runtime / "network-config"),
                 str(runtime / "seed.iso"), str(runtime / "user-data"), str(runtime / "meta-data")])
        command(["chown", "-R", qemu_user, str(runtime)])
        command(["runuser", "-u", qemu_user, "--", "test", "-r", str(runtime / "disk.qcow2")])
        command(["runuser", "-u", qemu_user, "--", "test", "-r", os.environ["DISPOSABLE_BASE_IMAGE"]])
        command(["ip", "link", "add", bridge, "type", "bridge"])
        command(["ip", "address", "add", host + "/30", "dev", bridge])
        command(["ip", "link", "set", bridge, "up"])
        command(["nft", "-f", "-"], data=firewall_rules(session))
        (runtime / "domain.xml").write_text(domain_xml(session, memory, cpus))
        virsh(["define", str(runtime / "domain.xml")])
        virsh(["start", domain])
        end = time.monotonic() + 180
        while True:
            try:
                guest(session, "guest-ping")
                break
            except RuntimeError:
                if time.monotonic() >= end:
                    raise RuntimeError("prepared baseline guest agent did not become ready")
                time.sleep(1)
        guest_exec(session, ["/usr/bin/mkdir", "-p", "/var/lib/disposable", "/workspace/source"])
        for name in ("request.json", "gateway.json"):
            guest_write(session, "/var/lib/disposable/" + name, session / name)
        guest_write(session, "/var/lib/disposable/run-audit.py", ROOT / "images/qemu/disposable/run-audit.py")
        if source.exists():
            guest_write(session, "/var/lib/disposable/source.tar", source)
        guest_exec(session, ["/usr/bin/systemd-run", "--unit=disposable-workload", "--collect",
            "--property=RuntimeMaxSec=" + str(max(1, int((deadline - datetime.datetime.now(datetime.timezone.utc)).total_seconds()))),
            "/usr/bin/python3", "/var/lib/disposable/run-audit.py"], timeout=30)
        atomic_json(session / "runtime.json", {"state": "running", "domain": domain,
                    "bridge": bridge, "network_policy": "default-deny", "gateway_port": port})
    except Exception:
        try:
            stop(session)
        except Exception:
            pass  # Controller retains ownership and retries explicit cleanup.
        raise


def status(session):
    if not (session / "runtime.json").exists():
        return {"state": "stopped"}
    runtime = json.loads((session / "runtime.json").read_text())
    if runtime["state"] == "stopped":
        return runtime
    domain, _, _, _ = names(session)
    state = virsh(["domstate", domain], optional=True)
    if state.returncode or "running" not in state.stdout.lower():
        return {"state": "failed", "error": "guest is unavailable"}
    try:
        code = "import pathlib; p=pathlib.Path('/var/lib/disposable/completion.json'); print(p.read_text() if p.exists() else '{\"state\":\"running\"}')"
        result = json.loads(guest_exec(session, ["/usr/bin/python3", "-c", code], timeout=10))
        return result if result.get("state") in ("running", "completed", "failed") else {"state": "failed"}
    except Exception:
        return {"state": "failed", "error": "guest control transport lost"}


def collect(session):
    request = json.loads((session / "request.json").read_text())
    if request.get("kind") != "audit":
        # Interactive sessions have no findings report; retain their selected
        # transcript if present. Missing transcript before first prompt is normal.
        try:
            exists = guest_exec(session, ["/usr/bin/python3", "-c",
                "import pathlib; print(int(pathlib.Path('/var/lib/disposable/events.jsonl').is_file()))"], timeout=10)
            if exists.strip() == b"1":
                logs(session)
        except Exception:
            raise RuntimeError("interactive transcript collection failed")
        return
    data = guest_read(session, "/var/lib/disposable/report.json", MAX_REPORT)
    value = json.loads(data)
    # Full destination, schema and redaction validation is the host publisher's job.
    if not isinstance(value, dict):
        raise ValueError("report must be a JSON object")
    atomic_json(session / "report.json", value)


def message(session):
    path = session / "message.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MESSAGE + 1024:
        raise ValueError("bounded regular prompt file required")
    value = json.loads(path.read_text())
    if not isinstance(value.get("prompt"), str) or len(value["prompt"].encode()) > MAX_MESSAGE:
        raise ValueError("invalid prompt")
    # Publish atomically inside the guest so it cannot consume a partial write.
    guest_write(session, "/var/lib/disposable/message-upload.json", path)
    guest_exec(session, ["/usr/bin/mv", "/var/lib/disposable/message-upload.json",
                        "/var/lib/disposable/message.json"], timeout=10)
    path.unlink()


def grants(session):
    source = session / "gateway.json"
    if source.is_symlink() or source.stat().st_size > 65536:
        raise ValueError("invalid gateway configuration")
    guest_write(session, "/var/lib/disposable/gateway-upload.json", source)
    guest_exec(session, ["/usr/bin/mv", "/var/lib/disposable/gateway-upload.json",
                        "/var/lib/disposable/gateway.json"], timeout=10)


def logs(session):
    data = guest_read(session, "/var/lib/disposable/events.jsonl", MAX_REPORT)
    path = session / "events.jsonl"
    if path.is_symlink():
        raise ValueError("unsafe host output path")
    temporary = session / "events.tmp"
    if temporary.is_symlink():
        raise ValueError("unsafe host output path")
    with open(temporary, "wb") as output:
        os.chmod(temporary, 0o600)
        output.write(data)
    os.replace(temporary, path)


def main():
    if len(sys.argv) in (2, 3) and sys.argv[1] == "check":
        preflight()
        print(json.dumps({"runtime": "kvm", "policy": "default-deny", "baseline": "configured"}))
        return
    if len(sys.argv) != 3 or sys.argv[1] not in ("start", "status", "stop", "collect", "message", "logs", "grants", "watchdog"):
        raise ValueError("usage: disposable-vm.sh check | start|status|collect|stop SESSION_DIR")
    session = checked_dir(sys.argv[2])
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("root Linux runtime required")
    action = sys.argv[1]
    if action == "status":
        print(json.dumps(status(session)))
    elif action == "start":
        start(session)
    elif action == "stop":
        stop(session)
    elif action == "watchdog":
        watchdog(session)
    elif action == "message":
        message(session)
    elif action == "logs":
        logs(session)
    elif action == "grants":
        grants(session)
    else:
        collect(session)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
