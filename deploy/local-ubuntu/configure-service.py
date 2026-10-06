#!/usr/bin/env python3
"""Configure loopback-only management; do not publish Tailscale or start VMs."""
import json
import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess


def private_write(path, content):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError('refusing symlink configuration')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--replace-config', action='store_true',
                        help='explicitly replace existing management and endpoint configuration')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('run with sudo')
    release = Path('/opt/agentic-sandbox/current').resolve(strict=True)
    if release.parent != Path('/opt/agentic-sandbox/releases'):
        raise RuntimeError('trusted release required')
    if not args.replace_config and any(Path(p).exists() for p in (
            '/etc/agentic-sandbox/management.env', '/etc/agentic-sandbox/endpoints.json')):
        raise RuntimeError('existing configuration retained; review before using --replace-config')
    for name in ('/etc/agentic-sandbox', '/var/lib/agentic-sandbox',
                 '/var/lib/agentic-sandbox/secrets', '/var/lib/agentic-sandbox/baselines'):
        folder = Path(name)
        if folder.is_symlink():
            raise RuntimeError('refusing symlink state directory')
        folder.mkdir(parents=True, exist_ok=True)
        folder.chmod(0o700 if 'secrets' in name or name == '/etc/agentic-sandbox' else 0o755)
    token_file = Path('/var/lib/agentic-sandbox/secrets/operator-tokens.toml')
    if not token_file.exists():
        token = secrets.token_hex(32)
        private_write(token_file, '[[tokens]]\ntoken = "' + token + '"\nrole = "admin"\n')
        private_write('/etc/agentic-sandbox/operator-token', token + '\n')
    presets = [{
        'id': 'studio', 'kind': 'model', 'model_name': 'swift-1.5',
        'base_url': 'https://ai-api.ashersuter.com/v1',
        'path_prefixes': ['/v1/chat/completions', '/v1/models'],
        'methods': ['GET', 'POST'], 'allow_private': False,
        'credential_env': 'TENSORFOLD_API_KEY',
    }]
    private_write('/etc/agentic-sandbox/endpoints.json', json.dumps(presets, indent=2) + '\n')
    private_write('/etc/agentic-sandbox/management.env', '\n'.join([
        'LISTEN_ADDR=127.0.0.1:8120', 'AGENTIC_HTTP_LISTEN_IP=127.0.0.1',
        'SECRETS_DIR=/var/lib/agentic-sandbox/secrets', 'RUST_LOG=info',
        'DISPOSABLE_ENABLED=1', 'DISPOSABLE_STATE_ROOT=/var/lib/agentic-sandbox/disposable',
        'DISPOSABLE_RUNTIME_SCRIPT=/opt/agentic-sandbox/current/scripts/disposable-vm.sh',
        'DISPOSABLE_BASE_IMAGE=/var/lib/agentic-sandbox/baselines/ubuntu-24.04-opencode.qcow2',
        'DISPOSABLE_GATEWAY_IP=192.0.2.1', 'DISPOSABLE_GATEWAY_PORT=8123',
        'AGENTIC_DISPOSABLE_ENDPOINTS_FILE=/etc/agentic-sandbox/endpoints.json',
        'LOCAL_AUDITS_ENABLED=1', 'LOCAL_AUDITS_STATE_ROOT=/var/lib/agentic-sandbox/local-audits',
        'LOCAL_AUDITS_WORKER=/opt/agentic-sandbox/current/scripts/security-audit/local_audit_worker.py',
        '',
    ]))
    unit = Path('/etc/systemd/system/agentic-local.service')
    if unit.is_symlink():
        raise RuntimeError('refusing symlink unit')
    shutil.copyfile(release / 'deploy/local-ubuntu/agentic-local.service', unit)
    unit.chmod(0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    print('Configured; management remains loopback-only. No token values printed.')
    print('Enter model key separately into root-only /etc/agentic-sandbox/model-secret.env.')
    print('Admin login token is in root-only /etc/agentic-sandbox/operator-token.')
    print('Start explicitly: sudo systemctl enable --now agentic-local.service')


if __name__ == '__main__':
    main()
