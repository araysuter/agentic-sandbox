/** Full application wiring, with memory-only fixtures and no host API or GitHub writes. */
import { auditFixtureRequest } from './preview-fixtures.mjs';
const realFetch = window.fetch.bind(window);
const html = new DOMParser().parseFromString(await (await realFetch('../index.html')).text(), 'text/html');
for (const child of [...html.body.children]) if (child.tagName !== 'SCRIPT') document.body.append(document.importNode(child, true));
const base = document.createElement('base'); base.href = new URL('../', location.href).href; document.head.prepend(base);
const label = document.createElement('p'); label.className = 'interactive-demo-label'; label.textContent = 'Demo preview · simulated VMs and terminal · no real host or GitHub writes'; document.querySelector('.header-content').append(label);
let sessions = [], grants = []; let nextId = 1;
const presets = [{ id: 'studio', kind: 'model', model_name: 'Studio model', base_url: 'http://studio.test/v1', methods: ['POST'], path_prefixes: ['/v1/chat/completions'], allow_private: true }];
const terminalDemo = new Map();
window.ManagementPreview = { enabled: true, terminal: {
    connect(id, name, callbacks) {
        const key = `${id}:${name}`; if (!terminalDemo.has(key)) terminalDemo.set(key, { text: '', input: '' }); const session = terminalDemo.get(key);
        const write = value => { session.text += value; callbacks.output(value); };
        callbacks.status('Demo terminal connected · commands are simulated');
        callbacks.output(session.text || `\x1b[1;36mDemo workspace terminal\x1b[0m\r\nOpenCode + Docker baseline · simulated preview\r\nSession: ${name}\r\nType help for demo commands. No commands execute on a real host.\r\n\r\n\x1b[32mworkspace\x1b[0m $ `);
        return { input(data) { for (const char of data) { if (char === '\r') { const command = session.input.trim(); write('\r\n'); const output = command === 'help' ? 'Demo commands: help, pwd, docker --version, opencode, clear' : command === 'pwd' ? '/workspace' : command === 'docker --version' ? 'Docker baseline is installed in the VM image (simulated).' : command === 'opencode' ? 'OpenCode would open here using the host model. This is a simulated preview.' : command === 'clear' ? '\x1b[2J\x1b[H' : command ? `Demo only: ${command}\r\nNo real command was executed.` : ''; if (output) write(output + '\r\n'); session.input = ''; write('\x1b[32mworkspace\x1b[0m $ '); } else if (char === '\x7f') { if (session.input) { session.input = session.input.slice(0, -1); write('\b \b'); } } else if (char >= ' ') { session.input += char; write(char); } } }, resize() {}, close() {} };
    }
} };
function json(body, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }
window.fetch = async (input, options = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url, location.href); if (!url.pathname.startsWith('/api/')) return realFetch(input, options);
    const method = options.method || 'GET', path = url.pathname, body = typeof options.body === 'string' ? JSON.parse(options.body) : null;
    if (path.startsWith('/api/v2/local-audits')) { try { return json((await auditFixtureRequest(path, { ...options, method })).body); } catch (e) { return json({ message: 'Demo model is busy' }, e.status || 500); } }
    if (path.startsWith('/api/v2/disposable-sessions')) {
        const id = path.split('/')[4], session = sessions.find(s => s.id === id);
        if (path.endsWith('/presets')) return json({ enabled: true, endpoints: presets });
        if (path === '/api/v2/disposable-sessions') {
            if (method === 'POST') { const active = sessions.filter(s => s.state === 'running'); if (active.reduce((n,s) => n+s.request.memory_mb,0)+body.memory_mb>32768 || active.reduce((n,s) => n+s.request.vcpus,0)+body.vcpus>8) return json({ message: 'Demo capacity is full' },409); const { github_token, ...safeBody } = body; const created = { github_credential_configured: !!github_token, id: `demo-vm-${nextId++}`, request: safeBody, state: 'running', deadline: body.lifetime === 'until_deleted' ? null : new Date(Date.now() + body.duration_seconds * 1000).toISOString(), created_at: new Date().toISOString(), policy: { isolation: 'demo', enforcement: 'simulated_only' } }; sessions.push(created); return json(created,201); }
            const memoryUsed=sessions.filter(s=>s.state==='running').reduce((n,s)=>n+s.request.memory_mb,0), cpusUsed=sessions.filter(s=>s.state==='running').reduce((n,s)=>n+s.request.vcpus,0); return json({ enabled: true, sessions, resource_usage: { memory_mb_used: memoryUsed, memory_mb_available: 32768-memoryUsed, vcpus_used: cpusUsed, vcpus_available: 8-cpusUsed }, active_session_id: sessions.find(s => s.state === 'running')?.id || null });
        }
        if (!session) return json({ message: 'No demo session found' },404);
        if (path.endsWith('/grants')) { if (method === 'POST') grants.push({ id: `grant-${grants.length}`, ...body, kind: 'model' }); return json({ grants }); }
        if (path.includes('/grants/') && method === 'DELETE') { grants = grants.filter(g => g.id !== path.split('/').at(-1)); return json({}); }
        if (path.endsWith('/output')) return json({ output: 'Demo session: no real OpenCode process or VM.' });
        if (path.endsWith('/messages')) return json({ accepted: true });
        if (method === 'DELETE') { session.state = 'cancelled'; return json(session); }
        return json(session);
    }
    // Legacy screens use the actual production navigation/forms. No live resources are claimed.
    if (path.includes('bootstrap/readiness')) return json({ ready: false, preview: true });
    if (path.includes('runtime')) return json({ runtimes: [] });
    if (path.includes('capabilities')) return json({ capabilities: [] });
    if (path.includes('/agents') || path.includes('/vms')) return json([]);
    if (path.includes('loadout')) return json({ loadouts: [], items: [], presets: [] });
    if (path.includes('/events')) return json({ events: [], items: [] });
    if (path.includes('/logs')) return json({ logs: [], items: [] });
    if (path.includes('aiwg')) return json({ connected: false, preview: true });
    if (method !== 'GET') return json({ message: 'This advanced operation is unavailable in the simulated preview.' }, 503);
    return json({ items: [], workloads: [], credentials: [], leases: [], profiles: [], sessions: [], capabilities: [], preview: true });
};
// No live socket is opened by the preview. Legacy connection status is visibly simulated.
class PreviewSocket {
    constructor() { this.readyState = 0; setTimeout(() => { this.readyState = 1; this.onopen?.({}); this.onmessage?.({ data: JSON.stringify({ type: 'server_hello', protocol_version: '1', supported_client_messages: ['list_agents'], features: [], preview: true }) }); },0); }
    send() {} close() { this.readyState = 3; } addEventListener() {} removeEventListener() {}
}
PreviewSocket.OPEN = 1; PreviewSocket.CLOSED = 3; window.WebSocket = PreviewSocket;
async function script(src) { await new Promise((resolve,reject) => { const element = document.createElement('script'); element.src = src; element.onload = resolve; element.onerror = reject; document.body.append(element); }); }
await script('vendor/xterm/xterm.min.js'); await script('vendor/xterm/addon-fit.min.js'); await script('app.js');
if (document.readyState !== 'loading') document.dispatchEvent(new Event('DOMContentLoaded'));
await window.ManagementUIReady;
// Dashboard bootstrap's promise continuation finishes before this microtask.
window.auditWorkspace = window.dashboard?.localAuditsWorkspace;
const status = document.querySelector('#connection-status'); if (status) { status.className = ''; const text = status.querySelector('.status-text'); if (text) text.textContent = 'Simulated host'; }
