/** Host-only recurring audit contract. Secrets are write-only and never cached. */
const ROOT = '/api/v2/local-audits';
export const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
export function suggestedSchedule(repositories = []) {
    const used = new Set(repositories.filter(r => r.enabled).map(r => r.schedule?.weekday));
    return { weekday: WEEKDAYS.findIndex((_, i) => !used.has(i)) < 0 ? 0 : WEEKDAYS.findIndex((_, i) => !used.has(i)), start_time: '01:00', end_time: '06:00', timezone: 'America/Detroit' };
}
export function auditRequest(values, { editing = false } = {}) {
    let repository = String(values.repository || '').trim();
    if (repository.startsWith('https://github.com/')) repository = repository.slice('https://github.com/'.length).replace(/\/$/, '').replace(/\.git$/, '');
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || repository.split('/').some(p => p === '.' || p === '..' || p.length > 100)) throw new TypeError('Enter a GitHub repository as owner/name.');
    const schedule = { weekday: Number(values.weekday), start_time: values.start_time, end_time: values.end_time, timezone: String(values.timezone || '').trim() };
    const minutes = t => /^([01]\d|2[0-3]):[0-5]\d$/.test(t || '') ? Number(t.slice(0, 2)) * 60 + Number(t.slice(3)) : NaN;
    const duration = minutes(schedule.end_time) - minutes(schedule.start_time);
    if (!Number.isInteger(schedule.weekday) || schedule.weekday < 0 || schedule.weekday > 6 || !Number.isFinite(duration) || duration < 10 || duration > 300) throw new TypeError('Choose a same-day window of 10 minutes to five hours.');
    try { new Intl.DateTimeFormat('en', { timeZone: schedule.timezone }); } catch { throw new TypeError('Enter a valid time zone, such as America/Detroit.'); }
    const github_token = String(values.github_token || '').trim();
    if (!editing && !github_token) throw new TypeError('Add a fine-grained GitHub token for this repository.');
    const body = { repository, schedule, model_id: String(values.model_id || 'studio').trim(), ref_name: String(values.ref_name || '').trim(), enabled: values.enabled !== false, publish_issues: values.publish_issues !== false };
    if (github_token) body.github_token = github_token;
    return body;
}
export function auditErrorMessage(error) {
    if (error?.outcomeUnknown || error?.code === 'mutation_outcome_unknown') return 'The request may have reached the host. Refresh before retrying.';
    const status = error?.status || error?.outcome?.status;
    if (status === 409) return 'The model or repository is busy. This request was not queued. Refresh to check the current run.';
    if ([401, 403].includes(status)) return 'Connect an operator token in Connection settings to manage audits.';
    if ([404, 503].includes(status)) return 'Local audits are unavailable on this host. Check the host setup in Connection settings.';
    if (error instanceof TypeError) return error.message;
    return 'The host could not complete this request. Refresh to check its state before retrying.';
}
const segment = id => { if (typeof id !== 'string' || !id || id.length > 255) throw new TypeError('Invalid audit identifier'); return encodeURIComponent(id); };
export class LocalAuditsClient {
    constructor(request) { this.request = request; }
    async call(path = '', method = 'GET', body) {
        const options = { method, owner: `audits:${method}:${path}` };
        if (body !== undefined) { options.headers = { 'Content-Type': 'application/json' }; options.body = JSON.stringify(body); }
        return (await this.request(ROOT + path, options)).body;
    }
    list() { return this.call(); }
    create(body) { return this.call('', 'POST', body); }
    update(id, body) { return this.call(`/${segment(id)}`, 'PUT', body); }
    remove(id) { return this.call(`/${segment(id)}`, 'DELETE'); }
    run(id) { return this.call(`/${segment(id)}/run`, 'POST'); }
    cancel(id) { return this.call(`/runs/${segment(id)}/cancel`, 'POST'); }
    report(id) { return this.call(`/runs/${segment(id)}/report`); }
}
