#!/usr/bin/env python3
"""Portable regression tests; no libvirt, host firewall or real VM is touched."""
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import signal
import tarfile
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = load('runtime', ROOT / 'scripts/disposable-runtime.py')
guest = load('guest', ROOT / 'images/qemu/disposable/run-audit.py')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.session = self.root / str(uuid.uuid4())
        self.session.mkdir()
        self.env = patch.dict(os.environ, {'DISPOSABLE_STATE_ROOT': str(self.root)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temporary.cleanup()

    def test_directory_requires_uuid_and_no_escaping_symlinks(self):
        self.assertEqual(runtime.checked_dir(str(self.session)), self.session)
        with self.assertRaises(ValueError):
            runtime.checked_dir(str(self.root))
        (self.session / 'request.json').symlink_to(self.root / 'secret')
        with self.assertRaises(ValueError):
            runtime.checked_dir(str(self.session))

    def test_xml_has_no_mount_gpu_or_host_socket(self):
        value = runtime.domain_xml(self.session, 16384, 6)
        self.assertIn('type="kvm"', value)
        self.assertIn('16384', value)
        self.assertNotIn('<filesystem', value)
        self.assertNotIn('<hostdev', value)
        self.assertNotIn('docker.sock', value)
        self.assertNotIn('8122', value)

    def test_default_deny_ipv4_ipv6_and_forwarding(self):
        value = runtime.firewall_rules(self.session)
        self.assertIn('ether type ip ip saddr 192.0.2.2 ip daddr 192.0.2.1', value)
        self.assertIn('tcp dport 8123', value)
        self.assertIn('hook forward', value)
        self.assertNotIn('ip6 accept', value)
        self.assertNotIn('ct state established accept', value)
        self.assertNotIn('masquerade', value)

    def test_daemon_failure_never_removes_policy_or_disk(self):
        vm = self.session / 'vm'
        vm.mkdir()
        (vm / 'disk.qcow2').write_text('fixture')
        with patch.object(runtime, 'virsh', side_effect=RuntimeError('daemon unavailable')), \
             patch.object(runtime, 'command') as command:
            with self.assertRaises(RuntimeError):
                runtime.stop(self.session)
            command.assert_not_called()
        self.assertTrue((vm / 'disk.qcow2').exists())
        self.assertFalse((self.session / 'runtime.json').exists())

    def test_failed_destruction_keeps_policy(self):
        domain = runtime.names(self.session)[0]
        def virsh(args, **kwargs):
            if args[0] == 'list':
                return subprocess.CompletedProcess(args, 0, domain + '\n', '')
            if args[0] == 'domstate':
                return subprocess.CompletedProcess(args, 0, 'running\n', '')
            return subprocess.CompletedProcess(args, 1, '', '')
        with patch.object(runtime, 'virsh', side_effect=virsh), patch.object(runtime, 'command') as command:
            with self.assertRaises(RuntimeError):
                runtime.stop(self.session)
            command.assert_not_called()

    def test_absent_vm_cleanup_is_idempotent(self):
        def command(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, '[]' if '-json' in args else '', '')
        with patch.object(runtime, 'virsh', return_value=subprocess.CompletedProcess([], 0, '', '')), \
             patch.object(runtime, 'command', side_effect=command):
            runtime.stop(self.session)
            runtime.stop(self.session)
        self.assertEqual(json.loads((self.session / 'runtime.json').read_text())['state'], 'stopped')

    def test_guest_artifact_rejects_excessive_output(self):
        responses = iter([1, {'buf-b64': 'YWJjZA==', 'eof': True}, {}])
        with patch.object(runtime, 'guest_exec'), patch.object(runtime, 'guest', side_effect=lambda *a: next(responses)):
            with self.assertRaises(RuntimeError):
                runtime.guest_read(self.session, '/var/lib/disposable/report.json', 3)

    def test_subprocess_output_is_bounded_and_timeout_kills(self):
        with self.assertRaises(RuntimeError):
            runtime.command(['python3', '-c', 'print("x" * 5000000)'])
        with self.assertRaises(RuntimeError):
            runtime.command(['python3', '-c', 'import time;time.sleep(20)'], timeout=0.1)

    def test_host_watchdog_calendar_arms_fixed_trusted_callback(self):
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, 'active\n', '')
        deadline = datetime.datetime(2026, 10, 7, 10, 0, tzinfo=datetime.timezone.utc)
        with patch.object(runtime, 'command', side_effect=command):
            runtime.arm_watchdog(self.session, deadline)
        self.assertIn('--on-calendar=2026-10-07 10:00:00 UTC', calls[0])
        self.assertIn('--property=Restart=on-failure', calls[0])
        self.assertEqual(calls[0][-2:], ['watchdog', str(self.session)])
        self.assertIn('--timer-property=AccuracySec=1s', calls[0])

    def test_unarmed_host_watchdog_refuses_admission(self):
        with patch.object(runtime, 'command', return_value=subprocess.CompletedProcess([], 0, 'inactive', '')):
            with self.assertRaises(RuntimeError):
                runtime.arm_watchdog(self.session, datetime.datetime.now(datetime.timezone.utc))

    def test_common_stop_quiesces_orphan_before_libvirt_inventory(self):
        runtime.atomic_json(self.session / 'runtime.json', {'provision_pid': 99999, 'provision_start_time': '12345'})
        order = []
        def virsh(args, **kwargs):
            order.append('inventory')
            return subprocess.CompletedProcess(args, 0, '', '')
        def command(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, '[]' if '-json' in args else '', '')
        with patch.object(runtime.os, 'pidfd_open', return_value=55, create=True), \
             patch.object(runtime.signal, 'pidfd_send_signal', side_effect=lambda *a: order.append('kill'), create=True), \
             patch.object(runtime, 'process_start_time', return_value='12345'), \
             patch.object(runtime.select, 'select', side_effect=lambda *a: (order.append('exit') or ([55], [], []))), \
             patch.object(runtime.os, 'close'), patch.object(runtime, 'virsh', side_effect=virsh), \
             patch.object(runtime, 'command', side_effect=command):
            runtime.stop(self.session)
        self.assertEqual(order[:3], ['kill', 'exit', 'inventory'])

    def test_reused_pid_is_never_signaled(self):
        runtime.atomic_json(self.session / 'runtime.json', {'provision_pid': 99999, 'provision_start_time': '12345'})
        with patch.object(runtime.os, 'pidfd_open', return_value=55, create=True), \
             patch.object(runtime.signal, 'pidfd_send_signal', create=True) as kill, \
             patch.object(runtime, 'process_start_time', return_value='different'), patch.object(runtime.os, 'close'):
            runtime.quiesce_provisioner(self.session)
            kill.assert_not_called()

    def test_pidfd_exit_timeout_preserves_policy(self):
        runtime.atomic_json(self.session / 'runtime.json', {'provision_pid': 99999, 'provision_start_time': '12345'})
        with patch.object(runtime.os, 'pidfd_open', return_value=55, create=True), \
             patch.object(runtime.signal, 'pidfd_send_signal', create=True), \
             patch.object(runtime, 'process_start_time', return_value='12345'), \
             patch.object(runtime.select, 'select', return_value=([], [], [])), \
             patch.object(runtime.os, 'close'), patch.object(runtime, 'virsh') as virsh:
            with self.assertRaises(RuntimeError):
                runtime.stop(self.session)
            virsh.assert_not_called()

    def test_watchdog_retries_failed_cleanup(self):
        with patch.object(runtime, 'stop', side_effect=RuntimeError('daemon unavailable')) as stop, \
             patch.object(runtime.time, 'sleep'):
            with self.assertRaises(RuntimeError):
                runtime.watchdog(self.session)
            self.assertEqual(stop.call_count, 12)

    def test_atomic_report_write_rejects_host_symlink(self):
        destination = self.session / 'report.json'
        secret = self.root / 'secret'
        secret.write_text('unchanged')
        destination.with_suffix('.tmp').symlink_to(secret)
        with self.assertRaises(OSError):
            runtime.atomic_json(destination, {'untrusted': True})
        self.assertEqual(secret.read_text(), 'unchanged')

    def test_source_archive_rejects_traversal_links_and_git_credentials(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('file', tarfile.SYMTYPE), ('.git/config', tarfile.REGTYPE)]:
            archive = self.root / 'source.tar'
            with tarfile.open(archive, 'w') as output:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.size = 0
                entry.linkname = '/etc/passwd'
                output.addfile(entry, io.BytesIO())
            with self.assertRaises(ValueError):
                guest.extract_source(archive, self.root / 'workspace')

    def test_gitleaks_exclusions_use_go_re2_anchor_and_descendants(self):
        expression = guest.gitleaks_pattern('node_modules')
        self.assertNotIn(r'\Z', expression)
        self.assertTrue(expression.endswith(r'(?:/.*)?\z'))
        with patch.object(guest.fnmatch, 'translate', return_value=r'(?s:vendor)\Z'):
            self.assertEqual(guest.gitleaks_pattern('vendor'), r'(?s:vendor)(?:/.*)?\z')

    def test_opencode_has_no_cloud_fallback_or_subagents(self):
        config = guest.opencode_config({'model_id': 'fixture-model', 'kind': 'audit'}, {
            'url': 'http://192.0.2.1:8123', 'model_path': '/gateway/session/grant/v1',
            'token': 'fake-session-capability',
            'mcp': [{'id': 'fixture-mcp', 'url': 'http://192.0.2.1:8123/gateway/session/mcp'}]})
        self.assertEqual(config['enabled_providers'], ['tensorfold'])
        self.assertEqual(config['share'], 'disabled')
        self.assertEqual(config['permission']['task'], 'deny')
        self.assertFalse(config['autoupdate'])
        self.assertEqual(config['mcp']['fixture-mcp']['headers']['Authorization'], 'Bearer fake-session-capability')
        self.assertEqual(config['provider']['tensorfold']['options']['apiKey'], 'fake-session-capability')


if __name__ == '__main__':
    unittest.main()
