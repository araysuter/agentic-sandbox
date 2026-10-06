/** Disposable-session API contract. No credential values or arbitrary upstream URLs. */
const ROOT = '/api/v2/disposable-sessions';
export const TERMINAL_DISPOSABLE_STATES = new Set(['completed', 'failed', 'cancelled', 'deleted']);
export function disposableSegment(value) {
    if (typeof value !== 'string' || !value || value.length > 255) throw new TypeError('Invalid session identifier');
    return encodeURIComponent(value);
}
export function interactiveRequest({ memoryGb, vcpus, durationMinutes, modelId, name, lifetime }) {
    const memory = Number(memoryGb), cpus = Number(vcpus), minutes = Number(durationMinutes);
    if (!((memory === 8 && cpus === 2) || (memory === 12 && cpus === 4) || (memory === 16 && cpus === 6))) throw new TypeError('Choose Small (8 GiB, 2 vCPUs), Medium (12 GiB, 4 vCPUs), or Security (16 GiB, 6 vCPUs).');
    if (name !== undefined && (!String(name).trim() || String(name).trim().length > 80)) throw new TypeError('Enter a workspace name of up to 80 characters.');
    if (lifetime !== 'until_deleted' && (!Number.isInteger(minutes) || minutes < 1 || minutes > 300)) throw new TypeError('Duration must be 1–300 minutes');
    if (typeof modelId !== 'string' || !modelId || modelId.length > 255) throw new TypeError('Choose a host model preset');
    return { kind: 'interactive', memory_mb: memory * 1024, vcpus: cpus, ...(lifetime === 'until_deleted' ? { lifetime: 'until_deleted' } : { duration_seconds: minutes * 60 }), model_id: modelId, ...(name === undefined ? {} : { name: String(name).trim() }) };
}
export function repositorySource(repository, commit, file) {
    if (!repository && !commit && !file) return {};
    if (typeof repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || repository.split('/').some((part) => part.length > 100 || part === '.' || part === '..')) throw new TypeError('Repository must be owner/name');
    if (typeof commit !== 'string' || !/^[a-fA-F0-9]{40}$/.test(commit)) throw new TypeError('Provide the full 40-character commit SHA');
    if (!file || file.size <= 0 || file.size > 100 * 1024 * 1024) throw new TypeError('Select an uncompressed tar snapshot of at most 100 MiB');
    return { repository, commit };
}
export function grantExpiry(minutes, deadline, now = Date.now()) {
    const duration = Number(minutes), limit = deadline == null ? Infinity : Date.parse(deadline);
    if (!Number.isInteger(duration) || duration < 1 || duration > 300 || Number.isNaN(limit) || limit <= now) throw new TypeError('Choose an expiry within the active session deadline');
    return new Date(Math.min(now + duration * 60000, limit)).toISOString();
}
export function disposableErrorMessage(error) {
    if (error?.outcomeUnknown || error?.code === 'mutation_outcome_unknown') return 'Request outcome unknown. Refresh session state before retrying; the VM or permission may already exist.';
    const status = error?.status || error?.outcome?.status;
    if (status === 409) return 'VM capacity is unavailable or cleanup needs confirmation. Refresh to inspect running sessions; this request was not queued.';
    if ([401, 403].includes(status)) return 'Operator authentication is required for disposable session controls.';
    if ([404, 503].includes(status)) return 'Disposable KVM sessions are unavailable or not configured on this host.';
    if (error instanceof TypeError) return error.message;
    return 'The operation failed. Refresh to check the host state before retrying.';
}
export class DisposableClient {
    constructor(request) { this.request = request; }
    async call(path = '', method = 'GET', body) {
        const options = { method, owner: `disposable:${method}:${path}` };
        if (body !== undefined) { options.headers = { 'Content-Type': 'application/json' }; options.body = JSON.stringify(body); }
        return (await this.request(ROOT + path, options)).body;
    }
    presets() { return this.call('/presets'); }
    list() { return this.call(); }
    async create(body) {
        const result = await this.call('', 'POST', body);
        if (!result || typeof result.id !== 'string' || !result.id || result.id.length > 255) {
            const error = new Error('Session creation requires authoritative reconciliation'); error.code = 'mutation_outcome_unknown'; error.outcomeUnknown = true; throw error;
        }
        return result;
    }
    detail(id) { return this.call(`/${disposableSegment(id)}`); }
    remove(id) { return this.call(`/${disposableSegment(id)}`, 'DELETE'); }
    grants(id) { return this.call(`/${disposableSegment(id)}/grants`); }
    grant(id, body) { return this.call(`/${disposableSegment(id)}/grants`, 'POST', body); }
    revoke(id, grantId) { return this.call(`/${disposableSegment(id)}/grants/${disposableSegment(grantId)}`, 'DELETE'); }
    async upload(id, file) {
        if (!file || file.size <= 0 || file.size > 100 * 1024 * 1024) throw new TypeError('Select an uncompressed tar snapshot of at most 100 MiB');
        return (await this.request(`${ROOT}/${disposableSegment(id)}/source`, { method: 'PUT', headers: { 'Content-Type': 'application/x-tar' }, body: file, owner: `disposable:source:${id}` })).body;
    }
    message(id, prompt) { return this.call(`/${disposableSegment(id)}/messages`, 'POST', { prompt }); }
    report(id) { return this.call(`/${disposableSegment(id)}/report`); }
    terminal(id, body) { return this.call(`/${disposableSegment(id)}/terminal`, 'POST', body); }
    output(id) { return this.call(`/${disposableSegment(id)}/output`); }
}
