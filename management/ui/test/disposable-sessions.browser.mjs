import { DisposableWorkspace } from '../modules/views/disposable.mjs';
const results = document.querySelector('#results');
let failures = 0;
function assert(name, value) { const row = document.createElement('p'); row.textContent = `${value ? 'PASS' : 'FAIL'} ${name}`; results.append(row); if (!value) failures++; }
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
async function settle() { for (let i = 0; i < 12; i++) await flush(); }
try {
    const html = new DOMParser().parseFromString(await (await fetch('../index.html')).text(), 'text/html');
    const panel = html.querySelector('#disposable-workspace'); panel.classList.remove('hidden'); document.querySelector('#test-panel').append(document.importNode(panel, true));
    const calls = []; let sessions = [], grants = [], denyRevoke = false, denyCreate = false;
    const deadline = new Date(Date.now() + 3600000).toISOString();
    const request = async (path, options) => {
        calls.push({ path, options });
        const body = options.body ? JSON.parse(options.body) : null;
        if (path.endsWith('/presets')) return { body: { enabled: true, endpoints: [{ id: 'studio-fixture', kind: 'model', base_url: 'http://studio.test:8080/v1', methods: ['POST'], path_prefixes: ['/v1/chat/completions'], allow_private: true }, { id: 'mcp-fixture', kind: 'mcp', base_url: 'https://mcp.test/api', methods: ['POST', 'GET', 'DELETE'], path_prefixes: ['/api'], allow_private: false }] } };
        if (path === '/api/v2/disposable-sessions' && options.method === 'POST') {
            if (denyCreate) throw { outcome: { status: 409 } };
            const session = { id: 'fixture-run', state: 'running', request: body, deadline, policy: { isolation: 'kvm', enforcement: 'runtime_confirmed', default_deny_egress: true }, error: null };
            sessions = [session]; grants = [{ id: 'initial', preset_id: 'studio-fixture', kind: 'model', expires_at: deadline }]; return { body: session };
        }
        if (path === '/api/v2/disposable-sessions') return { body: { enabled: true, sessions, active_session_id: sessions.find((s) => s.state === 'running')?.id } };
        if (path.endsWith('/grants') && options.method === 'GET') return { body: { grants } };
        if (path.endsWith('/grants') && options.method === 'POST') { const grant = { ...body, id: 'added', kind: 'mcp' }; grants.push(grant); return { body: grant }; }
        if (path.includes('/grants/') && options.method === 'DELETE') { if (denyRevoke) throw new Error('fixture unavailable'); grants = grants.filter((g) => g.id !== path.split('/').at(-1)); return { body: null }; }
        if (path.endsWith('/output')) return { body: { output: '<script>window.guestInjected=true</script> fixture transcript' } };
        if (path.endsWith('/messages')) return { body: { accepted: true } };
        if (options.method === 'DELETE') { sessions[0].state = 'cleanup_failed'; sessions[0].error = 'Fixture cleanup still requires retry'; return { body: sessions[0] }; }
        return { body: sessions.find((s) => s.id === path.split('/').at(-1)) };
    };
    const workspace = new DisposableWorkspace({ root: document, request });
    await workspace.refresh();
    document.querySelector('#disposable-operator-token').value = 'fixture-operator-token';
    document.querySelector('#disposable-auth-form').dispatchEvent(new Event('submit', { cancelable: true })); await settle();
    assert('operator token is scoped to authenticated API calls and cleared from the input', calls.at(-1).options.headers.get('Authorization') === 'Bearer fixture-operator-token' && document.querySelector('#disposable-operator-token').value === '');
    assert('configured host presets enable creation', !document.querySelector('#disposable-create').disabled);
    document.querySelector('#disposable-create-form').dispatchEvent(new Event('submit', { cancelable: true })); await settle();
    const created = calls.find((c) => c.path === '/api/v2/disposable-sessions' && c.options.method === 'POST');
    const requestBody = JSON.parse(created.options.body);
    assert('creation requests Small 8 GiB, 2 vCPUs and interactive preset', requestBody.memory_mb === 8192 && requestBody.vcpus === 2 && requestBody.kind === 'interactive' && requestBody.model_id === 'studio-fixture');
    assert('running state shows confirmed host policy', document.querySelector('#disposable-detail').textContent.includes('runtime_confirmed'));
    assert('host determines admission for additional workspaces', !document.querySelector('#disposable-create').disabled);
    assert('guest output is rendered as text', document.querySelector('#disposable-output').textContent.includes('<script>') && !window.guestInjected && !document.querySelector('#disposable-output script'));
    document.querySelector('#disposable-grant-preset').value = 'mcp-fixture';
    document.querySelector('#disposable-grant-duration').value = '300';
    document.querySelector('#disposable-grant-form').dispatchEvent(new Event('submit', { cancelable: true })); await settle();
    assert('temporary MCP grant is rendered with exact method/path scope', document.querySelector('#disposable-grants').textContent.includes('mcp-fixture') && document.querySelector('#disposable-grants').textContent.includes('/api'));
    const add = calls.find((c) => c.path.endsWith('/grants') && c.options.method === 'POST');
    assert('grant expiry never exceeds session deadline', JSON.parse(add.options.body).expires_at === deadline);
    denyRevoke = true;
    [...document.querySelectorAll('#disposable-grants button')].find((b) => b.textContent === 'Revoke mcp-fixture').click(); await settle();
    assert('failed revocation keeps the grant visible', document.querySelector('#disposable-grants').textContent.includes('mcp-fixture') && document.querySelector('#disposable-status').textContent.includes('failed'));
    denyRevoke = false;
    [...document.querySelectorAll('#disposable-grants button')].find((b) => b.textContent === 'Revoke mcp-fixture').click(); await settle();
    assert('successful revocation removes the active grant', !document.querySelector('#disposable-grants').textContent.includes('mcp-fixture'));
    document.querySelector('#disposable-prompt').value = 'Inspect fixture'; document.querySelector('#disposable-message-form').dispatchEvent(new Event('submit', { cancelable: true })); await settle();
    assert('prompt uses scoped guest message route', calls.some((c) => c.path.endsWith('/fixture-run/messages') && JSON.parse(c.options.body).prompt === 'Inspect fixture'));
    document.querySelector('#disposable-cancel').click(); await settle();
    assert('cleanup failure stays visible with a retry control', document.querySelector('#disposable-detail').textContent.includes('cleanup_failed') && !document.querySelector('#disposable-delete').disabled);
    denyCreate = true; await workspace.create();
    assert('a busy admission is reported and not queued', document.querySelector('#disposable-status').textContent.includes('not queued'));
    document.querySelector('#disposable-disconnect').click();
    assert('clearing the operator token removes in-memory authority', workspace.operatorToken === '' && document.querySelector('#disposable-create').disabled);
    workspace.setActive(false);
} catch (error) { assert(`browser fixture crashed: ${error.message}`, false); }
document.body.dataset.result = failures ? 'fail' : 'pass'; document.body.dataset.failures = String(failures);
