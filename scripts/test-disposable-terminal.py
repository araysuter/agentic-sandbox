#!/usr/bin/env python3
"""Portable real PTY checks; no KVM, OpenCode, Docker, model, or host changes."""
import importlib.util
import http.server
import json
import subprocess
import sys
import threading
import os
from pathlib import Path
import select
import signal
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('guest_terminal', Path(__file__).resolve().parents[1] / 'images/qemu/disposable/terminal.py')
terminal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminal)


class GuestPtyTests(unittest.TestCase):
    def test_real_controlling_terminal_input_and_resize(self):
        with tempfile.TemporaryDirectory() as folder:
            program = "import os,struct,fcntl,termios;print('TTY='+str(os.isatty(0)),flush=True);data=input();print('ANSWER='+data,flush=True);print('SIZE='+repr(struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\\0'*8))[:2]),flush=True)"
            pid, fd = terminal.spawn(folder, dict(os.environ), ['python3', '-c', program])
            try:
                terminal.resize(fd, 111, 33)
                self.assertEqual(terminal.write_input(fd, b'hello\n'), b'')
                output = b''
                end = time.monotonic() + 5
                while time.monotonic() < end:
                    ready, _, _ = select.select([fd], [], [], .1)
                    if ready:
                        data = terminal.read_output(fd)
                        output += data
                        if not data:
                            break
                self.assertIn(b'TTY=True', output)
                self.assertIn(b'ANSWER=hello', output)
                self.assertIn(b'SIZE=(33, 111)', output)
                os.waitpid(pid, 0)
            finally:
                os.close(fd)

    def test_detached_terminal_child_continues(self):
        with tempfile.TemporaryDirectory() as folder:
            mark = Path(folder) / 'continued'
            program = "import pathlib,time;print('started',flush=True);time.sleep(.2);pathlib.Path('continued').write_text('yes')"
            pid, fd = terminal.spawn(folder, dict(os.environ), ['python3', '-c', program])
            try:
                # No browser/reader is attached during this interval.
                end = time.monotonic() + 3
                while not mark.exists() and time.monotonic() < end:
                    time.sleep(.05)
                self.assertEqual(mark.read_text(), 'yes')
                os.waitpid(pid, 0)
            finally:
                os.close(fd)

    def test_http_bridge_runs_real_pty_without_browser_attachment(self):
        captured = bytearray()
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.assert_auth = self.headers['Authorization']
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                captured.extend(bytes.fromhex(request['output_hex']))
                commands = []
                if request['acknowledged_command'] < 1:
                    commands = [{'sequence': 1, 'type': 'resize', 'cols': 112, 'rows': 34}]
                elif request['acknowledged_command'] < 2:
                    commands = [{'sequence': 2, 'type': 'input', 'hex': b'bridge-input\n'.hex()}]
                reply = json.dumps({'epoch': 'fixture-host', 'acknowledged_output': request['sequence'], 'commands': commands}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                executable = base / 'opencode'
                executable.write_text('#!' + sys.executable + "\nimport os,fcntl,struct,termios\nprint('TTY='+str(os.isatty(0)),flush=True)\nline=input()\nprint('ANSWER='+line,flush=True)\nprint('SIZE='+repr(struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\\0'*8))[:2]),flush=True)\n")
                executable.chmod(0o700)
                (base / 'gateway.json').write_text(json.dumps({'url': 'http://127.0.0.1:' + str(server.server_port), 'session_id': 'fixture', 'token': 'guest-scoped-fixture'}))
                program = "import importlib.util,os;from pathlib import Path;s=importlib.util.spec_from_file_location('t'," + repr(str(Path(terminal.__file__))) + ");t=importlib.util.module_from_spec(s);s.loader.exec_module(t);p=Path(" + repr(folder) + ");code=t.run({'lifetime':'timed'},{},p,p,lambda c:dict(os.environ,PATH=str(p)+':'+os.environ['PATH']));assert code==0"
                subprocess.run([sys.executable, '-c', program], check=True, timeout=10, capture_output=True)
                self.assertIn(b'TTY=True', captured)
                self.assertIn(b'ANSWER=bridge-input', captured)
                self.assertIn(b'SIZE=(34, 112)', captured)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_resize_bounds_reject_invalid(self):
        for cols, rows in ((0, 10), (501, 10), (80, 201), (True, 25)):
            with self.assertRaises(ValueError):
                terminal.resize(-1, cols, rows)


if __name__ == '__main__':
    unittest.main()
