import test from 'node:test';
import assert from 'node:assert/strict';
import { auditRequest, suggestedSchedule, LocalAuditsClient, auditErrorMessage } from '../modules/domains/local-audits.mjs';
const input = { repository: 'owner/repo', weekday: 0, start_time: '01:00', end_time: '06:00', timezone: 'America/Detroit', github_token: 'test-only' };
test('next repository defaults to a separate enabled night', () => {
    assert.equal(suggestedSchedule([{ enabled: true, schedule: { weekday: 0 } }, { enabled: false, schedule: { weekday: 1 } }]).weekday, 1);
});
test('write-only key omitted during edit; scoped fields and default branch preserved', () => {
    const result = auditRequest({ ...input, github_token: '', ignored: 'value' }, { editing: true });
    assert.equal('github_token' in result, false); assert.equal(result.ref_name, ''); assert.equal(result.publish_issues, true); assert.equal('ignored' in result, false);
    assert.throws(() => auditRequest({ ...input, github_token: '' }), /token/);
});
test('rejects cross-midnight, over-five-hour, malformed and invalid timezone windows', () => {
    for (const extra of [{ end_time: '01:09' }, { start_time: '23:00' }, { end_time: '07:00' }, { weekday: 7 }, { end_time: '99:00' }, { timezone: 'not/a-zone' }]) assert.throws(() => auditRequest({ ...input, ...extra }), TypeError);
});
test('mutations use one canonical API request and report failures without retries', async () => {
    const calls = []; const client = new LocalAuditsClient(async (...args) => { calls.push(args); throw Object.assign(new Error(), { status: 409 }); });
    await assert.rejects(client.run('abc/def'));
    assert.equal(calls.length, 1); assert.equal(calls[0][0], '/api/v2/local-audits/abc%2Fdef/run'); assert.equal(calls[0][1].method, 'POST');
    assert.match(auditErrorMessage({ status: 409 }), /not queued/);
    assert.match(auditErrorMessage({ outcomeUnknown: true }), /Refresh before retrying/);
});

test('GitHub URL paste normalizes only the canonical GitHub host', () => { assert.equal(auditRequest({ ...input, repository: 'https://github.com/owner/repo.git' }).repository, 'owner/repo'); assert.throws(() => auditRequest({ ...input, repository: 'https://github.com.attacker.test/owner/repo' }), TypeError); });
