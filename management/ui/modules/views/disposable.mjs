import { DisposableClient, TERMINAL_DISPOSABLE_STATES, interactiveRequest, repositorySource, grantExpiry, disposableErrorMessage } from '../domains/disposable.mjs';

import { WorkspaceTerminal } from './workspace-terminal.mjs';

const element = (doc, tag, value) => { const node = doc.createElement(tag); if (value !== undefined) node.textContent = String(value); return node; };
/** A build-free panel with refresh-based recovery; mutations are never auto-replayed. */
export class DisposableWorkspace {
    constructor({ root = document, request, now = () => Date.now() }) {
        this.root = root; this.doc = root.ownerDocument || root; this.operatorToken = ''; this.now = now;
        this.client = new DisposableClient((path, options) => {
            const headers = new Headers(options.headers || {});
            if (this.operatorToken) headers.set('Authorization', `Bearer ${this.operatorToken}`);
            return request(path, { ...options, headers });
        });
        this.terminal = this.get('terminal') ? new WorkspaceTerminal({ container: this.get('terminal'), status: message => { this.get('terminal-status').textContent = message; }, control: (id, body) => this.client.terminal(id, body), onExit: () => { if (this.get('terminal-restart')) this.get('terminal-restart').hidden = false; }, headers: () => this.operatorToken ? { Authorization: `Bearer ${this.operatorToken}` } : {} }) : null;
        this.get('size')?.addEventListener('change', () => { const [memory, cpus] = { small: [8, 2], medium: [12, 4], security: [16, 6] }[this.get('size').value]; this.get('memory').value = String(memory); this.get('cpus').value = String(cpus); this.capacityAvailable = !this.resourceUsage || (!this.resourceUsage.blocked && this.resourceUsage.memory_mb_available >= Number(this.get('memory').value) * 1024 && this.resourceUsage.vcpus_available >= Number(this.get('cpus').value)); this.updateControls(); });
        this.get('terminal-restart')?.addEventListener('click', async () => { try { await this.terminal.send({ type: 'restart' }); this.openTerminal(); } catch (error) { this.status(disposableErrorMessage(error)); } });
        this.get('terminal-reconnect')?.addEventListener('click', () => this.openTerminal());
        this.get('delete-workspace')?.addEventListener('click', () => this.confirmRemove());
        this.get('delete-back')?.addEventListener('click', () => this.get('delete-dialog').close());
        this.get('delete-confirm')?.addEventListener('click', () => { this.get('delete-dialog').close(); this.remove(); });
        this.active = false; this.selectedId = null; this.sessions = []; this.permissions = []; this.presets = []; this.enabled = false; this.pending = false; this.revision = 0;
        this.get('auth-form')?.addEventListener('submit', (event) => {
            event.preventDefault(); this.operatorToken = this.get('operator-token').value.trim(); this.get('operator-token').value = ''; this.refresh();
        });
        this.get('disconnect')?.addEventListener('click', () => { this.operatorToken = ''; this.terminal?.close(); this.get('operator-token').value = ''; this.enabled = false; this.updateControls(); this.status('Operator token cleared. Refresh with an authenticated connection to continue.'); });
        this.get('refresh')?.addEventListener('click', () => this.refresh());
        this.get('create-form')?.addEventListener('submit', (event) => { event.preventDefault(); this.create(); });
        this.get('grant-form')?.addEventListener('submit', (event) => { event.preventDefault(); this.addGrant(); });
        this.get('upload-source')?.addEventListener('click', () => this.uploadSource(this.selectedId));
        this.get('message-form')?.addEventListener('submit', (event) => { event.preventDefault(); this.sendMessage(); });
        for (const action of ['cancel', 'delete']) this.get(action)?.addEventListener('click', () => this.get('delete-dialog') ? this.confirmRemove() : this.remove());
    }
    get(name) { return this.root.getElementById ? this.root.getElementById(`disposable-${name}`) : this.root.querySelector(`#disposable-${name}`); }
    status(message, state = 'degraded') { const node = this.get('status'); if (node) { node.textContent = message; node.className = `workspace-status ${state}`; } }
    setActive(active) { this.active = active; clearTimeout(this.timer); if (active) { this.refresh(); if (this.detail?.state === 'running') this.openTerminal(); } else this.terminal?.close(); }
    async refresh() {
        if (this.refreshing) return;
        this.refreshing = true;
        try {
            const [catalog, inventory] = await Promise.all([this.client.presets(), this.client.list()]);
            this.enabled = catalog.enabled === true && inventory.enabled === true;
            this.presets = Array.isArray(catalog.endpoints) ? catalog.endpoints : [];
            this.sessions = Array.isArray(inventory.sessions) ? inventory.sessions : [];
            this.activeSessionId = inventory.active_session_id; this.resourceUsage = inventory.resource_usage; this.capacityAvailable = inventory.resource_usage ? !inventory.resource_usage.blocked && inventory.resource_usage.memory_mb_available >= Number(this.get('memory')?.value || 8) * 1024 && inventory.resource_usage.vcpus_available >= Number(this.get('cpus')?.value || 2) : true;
            this.fillPresets(); this.renderList();
            this.status(!this.enabled ? 'Unavailable: disposable KVM runtime or policy prerequisites are not configured.'
                : this.resourceUsage ? `${this.resourceUsage.memory_mb_used / 1024} of 32 GiB memory · ${this.resourceUsage.vcpus_used} of 8 vCPUs in use` : 'Ready to start a workspace.', this.enabled ? 'ready' : 'degraded');
            if (this.selectedId) await this.loadDetail(this.selectedId);
            this.updateControls();
        } catch (error) { this.enabled = false; this.status(disposableErrorMessage(error)); this.updateControls(); }
        finally { this.refreshing = false; clearTimeout(this.timer); if (this.active) this.timer = setTimeout(() => this.refresh(), 5000); }
    }
    fillPresets() {
        for (const [name, filter] of [['model', (p) => p.kind === 'model'], ['grant-preset', () => true]]) {
            const node = this.get(name); if (!node) continue;
            const previous = node.value; node.replaceChildren();
            const candidates = this.presets.filter(filter);
            for (const preset of candidates) { const option = element(this.doc, 'option', `${preset.id} (${preset.kind})${preset.model_name ? ` · ${preset.model_name}` : ''}`); option.value = preset.id; node.append(option); }
            if (!candidates.length) { const option = element(this.doc, 'option', 'No host presets configured'); option.value = ''; node.append(option); }
            if (candidates.some((p) => p.id === previous)) node.value = previous;
            node.disabled = !this.enabled || !candidates.length || this.pending;
        }
    }
    renderList() {
        const node = this.get('list'); if (!node) return;
        const focused = node.contains(this.doc.activeElement) ? this.doc.activeElement?.dataset?.sessionId : null;
        node.replaceChildren();
        if (!this.sessions.length) node.append(element(this.doc, 'p', 'No disposable sessions.'));
        for (const session of this.sessions) {
            const button = element(this.doc, 'button', `${session.request?.name || session.request?.repository || 'Interactive workspace'} · ${session.state}`);
            button.type = 'button'; button.dataset.sessionId = session.id; button.setAttribute('aria-current', String(session.id === this.selectedId));
            button.addEventListener('click', () => this.select(session.id)); node.append(button);
            if (focused === session.id) button.focus();
        }
    }
    async select(id) { this.terminal?.close(); this.selectedId = id; this.revision += 1; this.detail = null; this.permissions = []; this.renderGrants(); this.renderList(); this.updateControls(); await this.loadDetail(id); }
    async loadDetail(id) {
        const revision = this.revision;
        try {
            const [detail, permissions] = await Promise.all([this.client.detail(id), this.client.grants(id)]);
            if (id !== this.selectedId || revision !== this.revision) return;
            const wasRunning = this.detail?.state === 'running'; this.detail = detail; if (!wasRunning && detail.state === 'running' && this.active) this.openTerminal(); if (detail.state !== 'running') this.terminal?.close(); this.permissions = permissions.grants || []; this.renderDetail(); this.renderGrants(); this.updateControls();
            if (detail.request?.kind === 'audit') await this.loadReport(id, revision);
            else this.get('report').textContent = 'Interactive session: no scheduled audit report.';
            if (detail.state === 'running' || TERMINAL_DISPOSABLE_STATES.has(detail.state)) await this.loadOutput(id, revision);
        } catch (error) { if (id === this.selectedId && revision === this.revision) this.status(disposableErrorMessage(error)); }
    }
    renderDetail() {
        const detail = this.detail, node = this.get('detail'); if (!node || !detail) return;
        node.replaceChildren();
        const dl = element(this.doc, 'dl');
        const values = [ ['Session', detail.id], ['State', detail.state], ['Repository / commit', detail.request?.repository ? `${detail.request.repository} @ ${detail.request.commit}` : 'Empty /workspace in guest'], ['Model preset', detail.request?.model_id], ['Resources', `${detail.request?.memory_mb / 1024} GB · ${detail.request?.vcpus} shared vCPUs`], ['Lifetime', detail.deadline || 'Until deleted'], ['Policy', detail.policy?.enforcement || 'No confirmed enforcement evidence'], ['Cleanup', detail.state === 'cleanup_failed' ? 'Failed: admission remains blocked; retry cleanup.' : detail.state === 'cleaning' ? 'In progress; model ownership retained.' : 'See current lifecycle state'], ['Error', detail.error || 'None'] ];
        for (const [key, value] of values) { dl.append(element(this.doc, 'dt', key), element(this.doc, 'dd', value ?? 'Not reported')); }
        node.append(dl);
        if (this.get('selected-summary')) this.get('selected-summary').textContent = `${detail.request?.name || 'Workspace'} · ${detail.state} · ${detail.request?.memory_mb / 1024} GiB · ${detail.request?.vcpus} vCPUs${detail.request?.lifetime === 'until_deleted' ? ' · Until deleted' : ''}`;
        this.get('policy').textContent = JSON.stringify(detail.policy || { enforcement: 'unknown' }, null, 2);
    }
    renderGrants() {
        const node = this.get('grants'); if (!node) return; node.replaceChildren(); node.append(element(this.doc, 'h4', 'Temporary endpoint grants'));
        if (!this.permissions.length) node.append(element(this.doc, 'p', 'No active endpoint grants.'));
        for (const grant of this.permissions) {
            const section = element(this.doc, 'section'); section.className = 'disposable-grant';
            const preset = this.presets.find((p) => p.id === grant.preset_id);
            section.append(element(this.doc, 'p', `${grant.preset_id} · ${grant.kind} · expires ${grant.expires_at}`));
            if (preset) section.append(element(this.doc, 'p', `${preset.base_url} · paths ${(preset.path_prefixes || []).join(', ')} · methods ${(preset.methods || []).join(', ')} · private destination ${preset.allow_private ? 'explicitly allowed' : 'denied'}`));
            const button = element(this.doc, 'button', `Revoke ${grant.preset_id}`); button.className = 'btn'; button.type = 'button'; button.disabled = this.pending;
            button.addEventListener('click', () => this.mutate(() => this.client.revoke(this.selectedId, grant.id), 'Permission revoked by the host.'));
            section.append(button); node.append(section);
        }
    }
    updateControls() {
        const running = this.detail?.state === 'running';
        const alive = this.detail && !TERMINAL_DISPOSABLE_STATES.has(this.detail.state) && this.detail.state !== 'cleanup_failed';
        for (const [name, disabled] of [['create', !this.enabled || !this.get('model')?.value || this.pending || this.capacityAvailable === false], ['terminal-reconnect', !running || this.pending], ['delete-workspace', !this.detail || this.pending], ['cancel', !alive || this.pending], ['delete', !this.detail || this.pending], ['add-grant', !this.enabled || !running || !this.get('grant-preset')?.value || this.pending], ['send-message', !this.enabled || !running || this.pending], ['upload-source', !this.enabled || this.detail?.state !== 'awaiting_source' || this.pending]]) { const button = this.get(name); if (button) button.disabled = disabled; }
    }
    async mutate(action, message) {
        if (this.pending) return;
        this.pending = true; this.updateControls();
        try { const result = await action(); this.status(message, 'ready'); await this.refresh(); return result; }
        catch (error) { this.status(disposableErrorMessage(error)); }
        finally { this.pending = false; this.fillPresets(); this.updateControls(); this.renderGrants(); }
    }
    async create() {
        let githubToken = this.get('github-token')?.value.trim() || '';
        if (this.get('github-token')) this.get('github-token').value = '';
        let request;
        try {
            request = interactiveRequest({ memoryGb: this.get('memory').value, vcpus: this.get('cpus').value, durationMinutes: this.get('duration').value, modelId: this.get('model').value, name: this.get('name')?.value, lifetime: this.get('name') ? 'until_deleted' : undefined });
            if (githubToken) request.github_token = githubToken;
            Object.assign(request, repositorySource(this.get('repository').value.trim(), this.get('commit').value.trim(), this.get('source-file').files?.[0]));
            const created = await this.mutate(() => this.client.create(request), 'Session admitted. Provisioning and policy verification are in progress.');
            if (created?.id) { await this.select(created.id); if (request.repository) await this.uploadSource(created.id); }
        } catch (error) { this.status(disposableErrorMessage(error)); }
        finally { githubToken = ''; if (request) delete request.github_token; }
    }
    async uploadSource(id) {
        if (!id) return;
        const file = this.get('source-file').files?.[0];
        await this.mutate(() => this.client.upload(id, file), 'Snapshot accepted. Host provisioning and policy verification are in progress.');
    }
    async addGrant() {
        if (!this.detail) return;
        try {
            const expires_at = grantExpiry(this.get('grant-duration').value, this.detail.deadline, this.now());
            await this.mutate(() => this.client.grant(this.selectedId, { preset_id: this.get('grant-preset').value, expires_at }), 'Endpoint access granted by the host.');
        } catch (error) { this.status(disposableErrorMessage(error)); }
    }
    openTerminal() { if (this.get('terminal-restart')) this.get('terminal-restart').hidden = false; if (!window.Terminal) { if (this.get('terminal-status')) this.get('terminal-status').textContent = 'Terminal renderer is unavailable.'; return; } if (this.selectedId && this.detail?.state === 'running') this.terminal?.open(this.selectedId); }
    confirmRemove() { if (this.selectedId) this.get('delete-dialog')?.showModal(); }
    remove() { if (this.selectedId) return this.mutate(() => this.client.remove(this.selectedId), 'Cleanup requested. Refresh to verify that the host destroyed the VM and removed writable storage.'); }
    async sendMessage() {
        const prompt = this.get('prompt').value;
        if (!prompt.trim() || new TextEncoder().encode(prompt).length > 65536) { this.status('Enter a prompt of at most 64 KiB.'); return; }
        await this.mutate(() => this.client.message(this.selectedId, prompt), 'OpenCode request accepted. Output will update while the session runs.');
    }
    async loadReport(id, revision) {
        try {
            const report = await this.client.report(id);
            if (id === this.selectedId && revision === this.revision) this.get('report').textContent = JSON.stringify(report, null, 2).slice(-2097152);
        } catch (_) { if (id === this.selectedId && revision === this.revision) this.get('report').textContent = 'Audit report has not been collected yet. Partial coverage is reported when available.'; }
    }
    async loadOutput(id, revision) {
        try {
            const output = await this.client.output(id);
            if (id === this.selectedId && revision === this.revision) this.get('output').textContent = typeof output === 'string' ? output.slice(-2097152) : JSON.stringify(output, null, 2).slice(-2097152);
        } catch (_) { if (id === this.selectedId && revision === this.revision) this.get('output').textContent = 'Output is not available yet. Refresh or inspect host diagnostics.'; }
    }
}
