import './local-audits-fixture.mjs';
const results = document.createElement('pre'); results.id = 'browser-test-results'; results.style.cssText = 'position:fixed;z-index:99;inset:10px;background:white;padding:24px;overflow:auto'; document.body.append(results);
let failures = 0; const assert = (name, value) => { results.textContent += `${value ? 'PASS' : 'FAIL'} ${name}\n`; if (!value) failures++; };
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setTimeout(resolve, 0)); };
const $ = id => document.querySelector(`#audit-${id}`);
const workspace = window.auditWorkspace;
try {
    await settle(); $('add').click(); assert('suggests first unoccupied weekday', $('weekday').value === '3'); assert('publishing is enabled by default', $('publish').checked);
    $('repository').value = 'demo/new'; $('token').value = 'fixture-only'; $('form').dispatchEvent(new Event('submit', { cancelable: true }));
    assert('PAT clears synchronously on submission', $('token').value === ''); await settle();
    assert('created repository appears in calendar', $('calendar').textContent.includes('new'));
    assert('credentials are not stored in browser storage', localStorage.length === 0 && sessionStorage.length === 0);
    const repo = window.auditFixture.repositories[0]; workspace.edit(repo); $('start').value = '02:00'; $('end').value = '05:00'; await workspace.save();
    const edited = window.auditFixture.repositories[0]; assert('editing retains host audit profile', edited.audit_profile.test_commands[0][0] === 'true'); assert('blank PAT edit keeps saved token', edited.credential_configured);
    const pause = [...$('repositories').querySelectorAll('button')].find(b => b.textContent === 'Pause schedule'); pause.click(); await settle();
    const pausedCall = window.auditFixture.calls.findLast(c => c.method === 'PUT'); assert('pause sends complete server contract with profile', pausedCall.body.repository === 'demo/TellTell' && pausedCall.body.schedule.start_time === '02:00' && pausedCall.body.enabled === false && pausedCall.body.audit_profile.scope[0] === 'src');
    window.auditFixture.setBusy(true); const before = window.auditFixture.calls.length; await workspace.mutate(() => workspace.client.run(repo.id), 'started'); assert('busy request reports no queue', $('status').textContent.includes('not queued')); assert('busy run is never retried', window.auditFixture.calls.length === before + 1); window.auditFixture.setBusy(false);
    await workspace.mutate(() => workspace.client.run(repo.id), 'started'); workspace.setActive(true, true); await settle(); assert('history renders completed result', $('history').textContent.includes('0 issues'));
    await workspace.report(workspace.runs[0]); assert('report uses human-readable finding view', $('report-body').textContent.includes('Findings') && !$('report-body').querySelector('pre')); $('report-dialog').close();
    const hostile = { completion: 'partial', coverage: { scanned_paths: ['src'], scanners: [], tests: [], skipped: [] }, findings: [{ title: '<img src=x onerror=alert(1)>', severity: 'high', path: 'src/a', line_start: 1, impact: 'bad', evidence: 'example', suggested_fix: 'fix', sensitive: false }, { title: 'secret title', path: 'secret.env', sensitive: true }] };
    $('report-body').replaceChildren(); workspace.renderReport($('report-body'), hostile, { state: 'completed', repository: repo.repository }); assert('untrusted reports render as text', !$('report-body').querySelector('img') && $('report-body').textContent.includes('<img')); assert('sensitive finding text and paths are withheld', !$('report-body').textContent.includes('secret.env') && !$('report-body').textContent.includes('secret title'));
    workspace.runs = [{ id: 'busy', repository: repo.repository, state: 'busy', created_at: new Date().toISOString() }, { id: 'interrupted', repository: repo.repository, state: 'interrupted', created_at: new Date().toISOString() }]; workspace.renderHistory(); assert('busy and interrupted are terminal states', !$('history').textContent.includes('Cancel run'));
    await workspace.confirmDelete(window.auditFixture.repositories.at(-1)); [...$('report-body').querySelectorAll('button')][0].click(); await settle(); assert('delete removes repository after confirmation', !window.auditFixture.repositories.some(r => r.repository === 'demo/new'));
} catch (error) { assert(`unexpected browser error: ${error.message}`, false); }
workspace.setActive(false); document.body.dataset.result = failures ? 'fail' : 'pass'; document.body.dataset.failures = String(failures); results.dataset.failures = String(failures); document.title = failures ? `${failures} audit browser failures` : 'Audit browser tests passed';
