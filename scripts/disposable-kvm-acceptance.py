#!/usr/bin/env python3
"""Opt-in Ubuntu KVM acceptance. Creates only an asd-* test guest and removes it.

Run on the designated Ubuntu host with its prepared baseline. This intentionally
changes host nft/bridge state for the test VM; never run from portable CI/Mac.
"""
import argparse
import datetime
import fcntl
import http.server
import importlib.util
import json
import os
import shutil
from pathlib import Path
import socketserver
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime', ROOT / 'scripts/disposable-runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
TOKEN = 'fake-acceptance-capability'


class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == '/fixture' and self.headers.get('Authorization') == 'Bearer ' + TOKEN else 403)
        self.end_headers()
        self.wfile.write(b'fixture')

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--acknowledge-test-vm', action='store_true', required=True)
    parser.add_argument('--blocked-target', required=True,
        help='Reachable operator-owned host/LAN HTTP fixture URL (not production)')
    parser.add_argument('--docker-image', default='busybox:1.36', help='Image already cached in baseline')
    args = parser.parse_args()
    runtime.preflight()
    host, _, _, port = runtime.network_settings()
    root = Path(os.environ.get('DISPOSABLE_STATE_ROOT', '/var/lib/agentic-sandbox/disposable'))
    root.mkdir(parents=True, exist_ok=True)
    controller_lock = open(root / "controller.lock", "a+")
    try:
        fcntl.flock(controller_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("stop disposable controller for this maintenance acceptance run")
    os.chmod(root, 0o711)
    session = root / str(uuid.uuid4())
    session.mkdir(mode=0o700)
    deadline = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    fixture = None
    passed = []
    try:
        runtime.atomic_json(session / 'request.json', {
            'kind': 'interactive', 'model_id': 'fixture-model', 'deadline': deadline.isoformat(),
            'memory_mb': 16384, 'vcpus': 6})
        runtime.atomic_json(session / 'gateway.json', {
            'url': f'http://{host}:{port}', 'model_path': '/fixture', 'token': TOKEN, 'mcp': []})
        fixture = socketserver.TCPServer(('0.0.0.0', port), Fixture)
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        # Verify the blocked target is actually reachable on the host first.
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.open(args.blocked_target, timeout=5).close()
        runtime.start(session)
        runtime.guest_exec(session, ['/usr/bin/docker', 'info'])
        runtime.guest_exec(session, ['/usr/bin/docker', 'run', '--rm', '--network', 'none', args.docker_image, 'true'])
        passed.append('guest Docker daemon and cached container')
        runtime.guest_exec(session, ['/usr/bin/python3', '-c',
            'import urllib.request; r=urllib.request.Request(' + repr(f'http://{host}:{port}/fixture') +
            ',headers={"Authorization":"Bearer ' + TOKEN + '"}); '
            'assert urllib.request.build_opener(urllib.request.ProxyHandler({})).open(r,timeout=5).status==200'])
        passed.append('allowed host fixture through dedicated workload port')
        # These are root guest operations, not host firewall edits.
        runtime.guest_exec(session, ['/usr/bin/python3', '-c',
            'import subprocess; subprocess.run(["nft","flush","ruleset"],check=False); '
            'subprocess.run(["iptables","-F"],check=False)'])
        targets = [args.blocked_target, f'http://{host}:8122/', 'http://169.254.169.254/',
                   'http://1.1.1.1/', 'http://[2606:4700:4700::1111]/']
        for url in targets:
            runtime.guest_exec(session, ['/usr/bin/python3', '-c',
                'import urllib.request,urllib.error,sys; '
                'r=urllib.request.Request(' + repr(url) + '); '
                '\ntry:\n urllib.request.build_opener(urllib.request.ProxyHandler({})).open(r,timeout=3); sys.exit(1)\n'
                'except urllib.error.HTTPError:\n sys.exit(1)\n'
                'except (OSError,TimeoutError):\n sys.exit(0)'], timeout=10)
        passed.append('host/LAN, management, metadata, direct IPv4/IPv6 blocked after guest-root firewall flush')
        for executable in ('opencode', 'semgrep', 'gitleaks', 'trivy'):
            runtime.guest_exec(session, ['/usr/bin/python3', '-c',
                'import shutil; assert shutil.which(' + repr(executable) + ')'])
        passed.append('OpenCode and scanner executables available')
    finally:
        try:
            runtime.stop(session)
            runtime.stop(session)
            assert not (session / 'vm').exists()
            shutil.rmtree(runtime.checked_dir(str(session)))
            assert not session.exists()
            passed.append('VM/disk/network/firewall cleanup and acceptance state removal are repeatable')
        finally:
            if fixture is not None:
                fixture.shutdown()
                fixture.server_close()
    print(json.dumps({'accepted': passed, 'not_measured': [
        'Actual OrcaSAQ model compatibility/accuracy/context memory',
        'MCP/model protocol interoperability (run gateway fixture tests separately)',
        'Hypervisor escape resistance']}, indent=2))


if __name__ == '__main__':
    main()
