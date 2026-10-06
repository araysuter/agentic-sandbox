#!/usr/bin/env python3
"""Remove only this service and its VM resources; retain shared host software."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--delete-data', action='store_true',
                        help='also permanently delete baseline, audits, tokens and VM state')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('run with sudo')
    release = Path('/opt/agentic-sandbox/current').resolve(strict=True)
    if release.parent != Path('/opt/agentic-sandbox/releases'):
        raise RuntimeError('unexpected release location')
    subprocess.run(['systemctl', 'stop', 'agentic-local.service'], check=True)
    state = Path('/var/lib/agentic-sandbox/disposable')
    if state.is_symlink():
        raise RuntimeError('unexpected symlink state; removal refused')
    environment = dict(os.environ, DISPOSABLE_STATE_ROOT=str(state),
                       DISPOSABLE_GATEWAY_IP='192.0.2.1', DISPOSABLE_GATEWAY_PORT='8123')
    for session in sorted(state.iterdir()) if state.exists() else []:
        try:
            if str(uuid.UUID(session.name)) != session.name:
                continue
        except ValueError:
            continue
        if session.is_symlink():
            raise RuntimeError('unexpected session symlink; removal refused')
        if session.is_dir():
            subprocess.run(['bash', str(release / 'scripts/disposable-vm.sh'),
                            'stop', str(session)], env=environment, check=True)
    # Never remove containment policy or disks if runtime cleanup failed.
    subprocess.run(['systemctl', 'disable', 'agentic-local.service'], check=True)
    Path('/etc/systemd/system/agentic-local.service').unlink(missing_ok=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    if args.delete_data:
        for location in ('/var/lib/agentic-sandbox', '/etc/agentic-sandbox'):
            folder = Path(location)
            if folder.is_symlink():
                raise RuntimeError('unexpected data symlink; removal refused')
            if folder.exists():
                shutil.rmtree(folder)
    else:
        print('Retained baseline, history and credentials. Add --delete-data to remove them.')
    install = Path('/opt/agentic-sandbox')
    if install.is_symlink():
        raise RuntimeError('unexpected install symlink; removal refused')
    shutil.rmtree(install)
    print('Removed app service and trusted releases; shared packages and networks retained.')
    print('Home checkout is retained; remove ~/agentic-sandbox yourself if no longer needed.')
    print('Remove only the app HTTPS port from Tailscale Serve separately; do not reset Serve.')


if __name__ == '__main__':
    main()
