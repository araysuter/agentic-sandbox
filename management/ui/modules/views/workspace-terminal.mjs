import { TERMINAL_THEME } from '../shared/terminal-theme.mjs';
/** Authenticated guest PTY viewer. Browser detach never deletes the VM. */
export class WorkspaceTerminal {
    constructor({ container, status, control, headers, onExit, fetchImpl = (...args) => fetch(...args), terminalFactory = options => new window.Terminal(options) }) {
        this.container = container; this.status = status; this.control = control; this.headers = headers; this.onExit = onExit; this.fetchImpl = fetchImpl; this.terminalFactory = terminalFactory; this.sequence = 0; this.clientId = crypto.randomUUID(); this.generation = 0;
    }
    async open(id) {
        this.close(); const generation = ++this.generation; this.clientId = crypto.randomUUID(); this.inputQueue = Promise.resolve(); this.id = id; this.sequence = 0;
        this.container.replaceChildren();
        this.term = this.terminalFactory({ cursorBlink: true, fontSize: 13, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', theme: { ...TERMINAL_THEME }, scrollback: 5000, allowProposedApi: false });
        this.term.open(this.container);
        this.term.attachCustomKeyEventHandler?.(event => { if (event.type === 'keydown' && event.ctrlKey && event.shiftKey && event.key.toLowerCase() === 'm') { this.container.ownerDocument.querySelector('#disposable-terminal-reconnect')?.focus(); return false; } return true; }); this.container.querySelector('textarea')?.setAttribute('aria-label', 'Workspace terminal input');
        if (window.FitAddon?.FitAddon) { this.fit = new window.FitAddon.FitAddon(); this.term.loadAddon(this.fit); }
        const resize = () => { try { this.fit?.fit(); if (this.writer) this.send({ type: 'resize', cols: Math.max(10, Math.min(500, this.term.cols)), rows: Math.max(2, Math.min(200, this.term.rows)) }).catch(() => {}); this.demo?.resize(this.term.cols, this.term.rows); } catch {} };
        this.observer = new ResizeObserver(resize); this.observer.observe(this.container);
        this.input = this.term.onData(data => { if (this.demo) this.demo.input(data); else if (this.writer) this.inputQueue = this.inputQueue.then(() => generation === this.generation ? this.send({ type: 'input', hex: [...new TextEncoder().encode(data)].map(n => n.toString(16).padStart(2, '0')).join('') }) : undefined).catch(() => this.status('Input was not accepted. Reconnect to regain control.')); });
        if (window.ManagementPreview?.enabled) { this.demo = window.ManagementPreview.terminal.connect(id, 'main', { output: data => this.term?.write(data), status: this.status }); resize(); return; }
        this.status('Connecting to workspace…');
        try { await this.send({ type: 'attach' }); if (generation !== this.generation) return; this.writer = true; this.status('Connected · your work stays in the VM when this tab closes'); resize(); this.heartbeat = setInterval(() => this.send({ type: 'attach' }).catch(() => { this.writer = false; this.status('Terminal control expired. Reconnect to continue.'); }), 15000); }
        catch (error) { if (generation !== this.generation) return; this.writer = false; this.status(error?.status === 409 || error?.outcome?.status === 409 ? 'Read only · another browser controls this terminal' : 'Could not attach terminal input. Reconnect to retry.'); }
        this.read(generation);
    }
    send(body) { return this.control(this.id, { ...body, client_id: this.clientId }); }
    consume(snapshot) {
        if (Number.isSafeInteger(snapshot.sequence) && snapshot.sequence < this.sequence) { this.sequence = 0; this.term?.write('\r\n[Terminal restarted; output stream resumed]\r\n'); }
        if (snapshot.truncated) this.status('Connected · older terminal output is no longer available');
        for (const frame of snapshot.output || []) { if (frame.sequence <= this.sequence || typeof frame.hex !== 'string' || !/^(?:[a-fA-F0-9]{2})*$/.test(frame.hex)) continue; const bytes = Uint8Array.from(frame.hex.match(/../g) || [], h => parseInt(h,16)); this.term?.write(bytes); this.sequence = frame.sequence; }
        if (snapshot.revoked) { this.writer = false; this.status('Terminal access revoked.'); }
        else if (snapshot.exit_code !== null && snapshot.exit_code !== undefined) { this.status(`OpenCode exited (${snapshot.exit_code}). Your VM and files are still available.`); this.onExit?.(snapshot.exit_code); }
    }
    async read(generation) {
        this.abort = new AbortController();
        try {
            const response = await this.fetchImpl(`/api/v2/disposable-sessions/${encodeURIComponent(this.id)}/terminal?after=${this.sequence}`, { headers: this.headers(), signal: this.abort.signal, cache: 'no-store' });
            if (!response.ok) throw new Error('Terminal unavailable');
            if (response.headers.get('content-type')?.includes('application/json')) { this.consume(await response.json()); if (generation === this.generation) this.retry = setTimeout(() => this.read(generation),1000); return; }
            const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = '';
            while (generation === this.generation) { const { done, value } = await reader.read(); if (done) break; buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g,'\n'); let boundary; while ((boundary = buffer.indexOf('\n\n')) !== -1) { const event = buffer.slice(0,boundary); buffer = buffer.slice(boundary+2); const data = event.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).trim()).join('\n'); if (data) this.consume(JSON.parse(data)); } }
            if (generation === this.generation) { this.status('Connection interrupted. Reconnecting…'); this.retry = setTimeout(() => this.read(generation),1500); }
        } catch (error) { if (generation !== this.generation || error.name === 'AbortError') return; this.status('Terminal disconnected. Retrying connection…'); this.retry = setTimeout(() => this.read(generation),2500); }
    }
    close() {
        ++this.generation; clearTimeout(this.retry); clearInterval(this.heartbeat); this.abort?.abort(); this.observer?.disconnect(); this.input?.dispose(); this.demo?.close(); this.demo = null;
        if (this.id && this.writer) this.send({ type: 'detach' }).catch(() => {});
        this.writer = false; this.id = null; this.term?.dispose(); this.term = null;
    }
}
