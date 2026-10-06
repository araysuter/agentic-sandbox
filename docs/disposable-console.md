# Interactive OpenCode terminal

Interactive VMs run the **actual OpenCode terminal UI** under a controlling PTY
inside the Ubuntu guest. OpenCode, Docker and tools come from the same immutable
prepared baseline used by audit VMs. The host runs neither the shell nor project
commands. Each VM gets its own thin writable disk overlay, fresh home and workspace.

A browser attachment is independent of the task lifetime. Leaving the page,
closing the browser or losing connectivity does not signal OpenCode or its child
processes. An `until_deleted` VM has no runtime deadline and stays running after
OpenCode exits; **Restart terminal** starts OpenCode again in that VM's existing
workspace. **Delete VM** revokes access, stops the VM and removes its writable disk
and saved session data. The immutable baseline remains available for the next VM.
Host reboot, power loss and hardware failure are not persistent VM guarantees.

## Browser API

All requests use explicit administrator authentication on the operator listener.
Bearer tokens remain in Authorization headers, never query strings or browser
storage. The streaming endpoint uses `fetch` and server-sent events, which supports
authenticated headers without introducing an unauthenticated WebSocket endpoint.

- `GET /api/v2/disposable-sessions/{id}/terminal?after=0` streams `terminal` events.
  Each event is a JSON snapshot: `output: [{sequence, hex}]`, `sequence`,
  `truncated`, `connected`, `exit_code`, `revoked`. Hex contains raw PTY bytes,
  including ANSI escapes, decoded into the browser terminal. Reconnect with the
  last received output sequence. No interpolation into HTML is permitted.
- `POST` to the same path accepts `{type: "attach", client_id: "UUID"}`,
  `{type: "input", client_id, hex}`, `{type: "resize", client_id, cols, rows}`,
  `{type: "detach", client_id}`, or `{type: "restart", client_id}`.
- One browser input lease per VM prevents two tabs from mixing commands. Attach
  refreshes a 30-second lease; the UI refreshes it every 15 seconds. A second
  writer receives 409. Any authenticated administrator may watch output.
- Detach releases only the input lease. Delete uses the VM's existing DELETE
  route, not a terminal disconnect.

Resize accepts 10–500 columns and 2–200 rows. Input chunks are limited to 16 KiB,
with a 64 KiB queue and at most 128 pending controls; pressure returns 429. Output
replay is limited to 1 MiB per VM. Older output is dropped with `truncated: true`.
Deletion immediately clears replay and commands. Management restart can preserve
the running guest task, but the in-memory terminal replay resets; resize requests
let the live terminal redraw. No full unbounded terminal history is retained.

## Guest bridge and isolation

`images/qemu/disposable/terminal.py` uses Python's standard `pty` support, launches
OpenCode inside the guest, and polls the dedicated host data listener. The guest
sends PTY output and receives input/resize controls through
`POST /console/{id}/exchange`, authorized by that VM's scoped guest capability.
The guest never receives an operator identity, GitHub host credential, host shell,
SSH key, Docker socket, libvirt socket, or host project mount.

Output and commands carry separate monotonic acknowledgements. Lost HTTP replies
can be retried without duplicating output or already acknowledged input. A bounded
single command per reply keeps the response below the guest's response limit.
The bridge disables proxy environment discovery and redirects. Each VM uses its
own isolated `/30` network; the default-deny firewall allows only that VM's data
listener, while model/MCP relays enforce their endpoint permissions separately.

Portable tests exercise real controlling PTYs, resize, input, detached-process
continuation, the HTTP bridge, writer leases, bounds, capability separation and
revocation. They do not establish Ubuntu KVM or real OpenCode/model compatibility;
those remain part of the opt-in host acceptance run.
