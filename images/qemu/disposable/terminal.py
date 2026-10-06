#!/usr/bin/env python3
"""Guest-only persistent OpenCode PTY; Python stdlib and scoped HTTP bridge.

A browser owns only an input lease. The controlling terminal and child continue
inside the VM when every browser disconnects. Host firewall mediates networking.
"""
import errno
import fcntl
import json
import os
import pty
import select
import signal
import struct
import termios
import time
import urllib.error
import urllib.request

CHUNK = 16384


def resize(fd, cols, rows):
    if type(cols) is not int or type(rows) is not int or not 10 <= cols <= 500 or not 2 <= rows <= 200:
        raise ValueError('invalid terminal dimensions')
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))


def spawn(source, env, argv=None):
    # pty.fork establishes a new session with a controlling terminal; no host
    # shell, ssh daemon, executor socket or direct browser-to-guest connection.
    argv = argv or ['opencode', '--agent', 'sandbox', str(source)]
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.chdir(source)
            os.execvpe(argv[0], argv, dict(env, TERM='xterm-256color', COLORTERM='truecolor'))
        except Exception:
            os.write(2, b'Could not start OpenCode from the prepared baseline.\r\n')
            os._exit(127)
    os.set_blocking(fd, False)
    resize(fd, 100, 30)
    return pid, fd


def read_output(fd):
    try:
        return os.read(fd, CHUNK)
    except OSError as error:
        if error.errno in (errno.EIO, errno.EAGAIN):
            return b''
        raise


def write_input(fd, data):
    # Return unaccepted bytes rather than retrying an already-written prefix.
    _, writable, _ = select.select([], [fd], [], .05)
    if not writable:
        return data
    try:
        return data[os.write(fd, data):]
    except BlockingIOError:
        return data


def run(request, config, state, source, environment, config_factory=None):
    pid, fd = spawn(source, environment(config))
    child_alive = True
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    sequence, acknowledged_command = 1, 0
    pending = b''
    input_remainder = None
    input_sequence = None
    remote_epoch = None
    exit_code = None
    next_poll = 0
    try:
        while True:
            if input_remainder is not None:
                # Finish accepted input locally even if the management process
                # restarts; its ACK floor must reflect those kernel writes.
                try:
                    input_remainder = write_input(fd, input_remainder) if child_alive else b''
                except OSError:
                    input_remainder = b''
                if not input_remainder:
                    if input_sequence is not None:
                        acknowledged_command = input_sequence
                    input_remainder = input_sequence = None
            if not pending:
                ready, _, _ = select.select([fd], [], [], max(0, min(.1, next_poll - time.monotonic())))
                if ready:
                    pending = read_output(fd)
                    if pending:
                        sequence += 1
                if child_alive:
                    ended, status = os.waitpid(pid, os.WNOHANG)
                    if ended:
                        child_alive = False
                        exit_code = os.waitstatus_to_exitcode(status)
            if time.monotonic() < next_poll:
                time.sleep(.02)
                continue
            gateway = json.loads((state / 'gateway.json').read_text())
            url = gateway['url'].rstrip('/') + '/console/' + gateway['session_id'] + '/exchange'
            payload = {'sequence': sequence, 'output_hex': pending.hex(),
                       'acknowledged_command': acknowledged_command, 'exit_code': exit_code}
            http_request = urllib.request.Request(url, data=json.dumps(payload).encode(), method='POST',
                headers={'Authorization': 'Bearer ' + gateway['token'], 'Content-Type': 'application/json'})
            try:
                with opener.open(http_request, timeout=5) as response:
                    raw = response.read(65537)
                    if len(raw) > 65536:
                        raise ValueError('console response exceeds limit')
                    reply = json.loads(raw)
                if remote_epoch != reply['epoch']:
                    if remote_epoch is not None and input_remainder is not None:
                        # Finish an old host epoch's partial kernel write, but
                        # never apply its ACK to fresh controls after restart.
                        input_sequence = None
                    remote_epoch = reply['epoch']
                if reply['acknowledged_output'] >= sequence:
                    pending = b''
                for command in reply.get('commands', []):
                    if command['sequence'] <= acknowledged_command:
                        continue
                    kind = command['type']
                    if kind == 'input':
                        if input_remainder is not None and input_sequence is None:
                            break
                        if not child_alive:
                            acknowledged_command = command['sequence']
                            continue
                        data = input_remainder if input_remainder is not None else bytes.fromhex(command['hex'])
                        if len(data) > CHUNK:
                            raise ValueError('terminal input exceeded bounds')
                        input_remainder = write_input(fd, data)
                        if input_remainder:
                            input_sequence = command['sequence']
                            break
                        input_remainder = None
                    elif kind == 'resize':
                        if child_alive:
                            resize(fd, command['cols'], command['rows'])
                    elif kind == 'restart':
                        if not child_alive:
                            os.close(fd)
                            if config_factory:
                                config = config_factory(gateway)
                            pid, fd = spawn(source, environment(config))
                            child_alive, exit_code = True, None
                            pending = b'\x1b[2J\x1b[H'
                            sequence += 1
                    else:
                        raise ValueError('unexpected guest terminal command')
                    acknowledged_command = command['sequence']
                if exit_code is not None and not pending and request.get('lifetime') != 'until_deleted':
                    return exit_code
            except urllib.error.HTTPError as error:
                if error.code in (401, 403, 404, 410):
                    raise RuntimeError('terminal capability revoked') from error
                # Retries and management restarts preserve both process and PTY.
            except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError):
                pass
            next_poll = time.monotonic() + .15
    finally:
        os.close(fd)
        # A reaped child pid must never be signalled: it could have been reused.
        # Entire descendant containment is the host's authoritative VM deletion.
        if child_alive:
            try:
                os.kill(pid, signal.SIGHUP)
                os.waitpid(pid, os.WNOHANG)
            except (ProcessLookupError, ChildProcessError):
                pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'redirect denied', headers, fp)
