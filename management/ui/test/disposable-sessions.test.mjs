import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DisposableClient, disposableSegment, interactiveRequest, repositorySource, grantExpiry, disposableErrorMessage } from '../modules/domains/disposable.mjs';

test('disposable create contract defaults are guest-only and bounded', () => {
    assert.deepEqual(interactiveRequest({ memoryGb: 16, vcpus: 6, durationMinutes: 300, modelId: 'studio-fixture' }), { kind: 'interactive', memory_mb: 16384, vcpus: 6, duration_seconds: 18000, model_id: 'studio-fixture' });
    for (const values of [{ memoryGb: 33 }, { vcpus: 7 }, { durationMinutes: 301 }, { durationMinutes: 0 }, { modelId: '' }]) assert.throws(() => interactiveRequest({ memoryGb: 16, vcpus: 6, durationMinutes: 60, modelId: 'studio-fixture', ...values }));
});
test('grant expiry is bounded by the host-owned deadline', () => {
    const now = Date.parse('2026-10-06T05:00:00Z');
    assert.equal(grantExpiry(60, null, now), '2026-10-06T06:00:00.000Z');
    assert.equal(grantExpiry(300, '2026-10-06T06:00:00Z', now), '2026-10-06T06:00:00.000Z');
    assert.throws(() => grantExpiry(60, '2026-10-06T04:59:59Z', now));
    assert.throws(() => grantExpiry(1.5, '2026-10-06T06:00:00Z', now));
});
test('session and grant identifiers stay within one canonical route', async () => {
    const calls = [];
    const client = new DisposableClient(async (path, options) => { calls.push({ path, ...options }); return { body: { id: 'created' } }; });
    await client.create({ kind: 'interactive', model_id: 'fixture' });
    await client.revoke('run/../../admin', 'grant?secret=fixture');
    assert.equal(calls[0].method, 'POST');
    assert.equal(calls[1].path, '/api/v2/disposable-sessions/run%2F..%2F..%2Fadmin/grants/grant%3Fsecret%3Dfixture');
    assert.equal(calls[1].method, 'DELETE');
    assert.throws(() => disposableSegment(''));
});
test('unknown mutations and busy errors require state reconciliation, never automatic replay', () => {
    assert.match(disposableErrorMessage({ code: 'mutation_outcome_unknown' }), /Refresh session state before retrying/);
    assert.match(disposableErrorMessage({ outcome: { status: 409 } }), /not queued/);
    assert.match(disposableErrorMessage({ status: 503 }), /not configured/);
    assert.equal(disposableErrorMessage({ message: 'secret=do-not-show' }).includes('secret'), false);
});
test('shipped disposable panel exposes lifecycle and accessible permission actions without HTML sinks', async () => {
    const root = new URL('../', import.meta.url);
    const [html, view, app, styles] = await Promise.all(['index.html', 'modules/views/disposable.mjs', 'app.js', 'styles.css'].map((path) => readFile(new URL(path, root), 'utf8')));
    assert.match(html, /data-workspace="disposable"/);
    assert.match(html, /id="disposable-status"[^>]+aria-live="polite"/);
    for (const id of ['create-form', 'grant-form', 'message-form', 'cancel', 'delete', 'policy', 'output']) assert.ok(html.includes(`id="disposable-${id}"`));
    assert.equal(view.includes('innerHTML'), false);
    assert.ok(app.includes("this.disposableWorkspace?.setActive(selected === 'disposable')"));
    assert.ok(styles.includes('body.workspace-disposable'));
    assert.match(styles, /@media \(max-width: 760px\)/);
});

test('optional repository staging requires a pinned commit and bounded data snapshot', () => {
    const commit = 'a'.repeat(40);
    assert.deepEqual(repositorySource('', '', null), {});
    assert.deepEqual(repositorySource('fixture/repo', commit, { size: 1024 }), { repository: 'fixture/repo', commit });
    for (const values of [['../repo', commit, { size: 10 }], ['fixture/repo', 'main', { size: 10 }], ['fixture/repo', commit, { size: 101 * 1024 * 1024 }], ['fixture/repo', commit, null]]) assert.throws(() => repositorySource(...values));
});

test('default HTTP transport keeps native browser fetch bound to the global object', async () => {
    const { HttpTransport } = await import('../modules/transport/http.mjs');
    const original = globalThis.fetch;
    globalThis.fetch = function () { assert.equal(this, globalThis); return Promise.resolve(new Response(JSON.stringify({ ready: true }), { headers: { 'Content-Type': 'application/json' } })); };
    try { assert.equal((await new HttpTransport().request('/api/v2/disposable-sessions')).body.ready, true); }
    finally { globalThis.fetch = original; }
});

test('malformed successful creation is unknown and never automatically replayed', async () => {
    let calls = 0;
    const client = new DisposableClient(async () => { calls++; return { body: null }; });
    await assert.rejects(client.create({ kind: 'interactive' }), (error) => error.code === 'mutation_outcome_unknown');
    assert.equal(calls, 1);
});

test('interactive Small, Medium and Security workspaces can live until explicitly deleted', () => {
    const small = interactiveRequest({ memoryGb: 8, vcpus: 2, modelId: 'studio', name: 'Build server', lifetime: 'until_deleted' });
    assert.equal(small.memory_mb, 8192); assert.equal(small.vcpus, 2);
    assert.equal(interactiveRequest({ memoryGb: 12, vcpus: 4, modelId: 'studio', lifetime: 'until_deleted' }).memory_mb, 12288); assert.equal(small.lifetime, 'until_deleted'); assert.equal(small.name, 'Build server'); assert.equal('duration_seconds' in small, false);
    assert.throws(() => interactiveRequest({ memoryGb: 12, vcpus: 6, modelId: 'studio', lifetime: 'until_deleted' }), /Choose Small/);
    assert.throws(() => interactiveRequest({ memoryGb: 16, vcpus: 6, modelId: 'studio', name: '', lifetime: 'until_deleted' }), /workspace name/);
});

import { WorkspaceTerminal } from '../modules/views/workspace-terminal.mjs';
test('terminal replay accepts output after the host resets its sequence', () => {
    const terminal = new WorkspaceTerminal({ container: {}, status: () => {}, control: () => {}, headers: () => ({}) });
    const writes = []; terminal.term = { write: value => writes.push(value) }; terminal.sequence = 150;
    terminal.consume({ sequence: 1, output: [{ sequence: 1, hex: '6869' }], exit_code: null });
    assert.equal(terminal.sequence, 1); assert.equal(new TextDecoder().decode(writes.at(-1)), 'hi');
    terminal.consume({ sequence: 1, output: [{ sequence: 1, hex: '6869' }], exit_code: null });
    assert.equal(writes.length, 2);
});
