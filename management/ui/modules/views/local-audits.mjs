import { LocalAuditsClient, WEEKDAYS, suggestedSchedule, auditRequest, auditErrorMessage } from '../domains/local-audits.mjs';
const node = (doc, tag, text, cls) => { const e = doc.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
const clock = time => { const [h, m] = time.split(':').map(Number); return `${h % 12 || 12}${m ? ':' + String(m).padStart(2, '0') : ''} ${h < 12 ? 'AM' : 'PM'}`; };
const activeRun = run => !['completed', 'failed', 'cancelled', 'skipped_busy', 'interrupted', 'busy'].includes(run.state);
export class LocalAuditsWorkspace {
    constructor({ root = document, request }) {
        this.root = root; this.doc = root.ownerDocument || root; this.operatorToken = ''; this.repositories = []; this.runs = []; this.active = false; this.pending = false; this.enabled = false;
        this.client = new LocalAuditsClient((path, options) => { const headers = new Headers(options.headers || {}); if (this.operatorToken) headers.set('Authorization', `Bearer ${this.operatorToken}`); return request(path, { ...options, headers }); });
        this.render();
        this.get('add').addEventListener('click', () => this.edit());
        this.get('refresh').addEventListener('click', () => this.refresh());
        this.get('form').addEventListener('submit', event => { event.preventDefault(); this.save(); });
        this.get('dialog').addEventListener('close', () => { this.get('token').value = ''; });
        this.get('close').addEventListener('click', () => this.get('dialog').close());
        this.get('cancel').addEventListener('click', () => this.get('dialog').close());
        this.get('report-close').addEventListener('click', () => this.get('report-dialog').close());
        this.get('auth-form').addEventListener('submit', event => { event.preventDefault(); this.operatorToken = this.get('operator-token').value.trim(); this.get('operator-token').value = ''; this.refresh(); });
        this.get('disconnect').addEventListener('click', () => { this.operatorToken = ''; this.enabled = false; this.get('add').disabled = true; this.repositories = []; this.runs = []; this.render(); this.status('Operator token cleared. Connect again or refresh with authenticated host access.'); });
    }
    get(id) { return this.root.querySelector(`#audit-${id}`); }
    status(text, error = false) { const el = this.get('status'); el.textContent = text; el.classList.toggle('audit-error', error); el.hidden = !text; }
    setActive(active, history = false) { this.active = active; this.history = history; this.get('calendar-view').hidden = history; this.get('history-view').hidden = !history; this.get('title').textContent = history ? 'Run history' : 'Weekly audits'; this.get('subtitle').textContent = history ? 'Reports and findings from your local audits.' : 'A quiet night for each repository.'; this.get('add').hidden = history; clearTimeout(this.timer); if (active) this.refresh(); }
    async refresh() {
        if (this.refreshing) return; this.refreshing = true;
        try { const data = await this.client.list(); this.enabled = data.enabled === true; this.repositories = data.repositories || []; this.runs = data.runs || []; this.render(); this.status(this.enabled ? '' : 'Local audits are not enabled on this host. Open Connection settings for setup details.', !this.enabled); }
        catch (error) { this.enabled = false; this.status(auditErrorMessage(error), true); }
        finally { this.get('add').disabled = !this.enabled || this.pending; this.refreshing = false; clearTimeout(this.timer); if (this.active) this.timer = setTimeout(() => this.refresh(), 15000); }
    }
    render() { this.renderCalendar(); this.renderRepositories(); this.renderHistory(); }
    renderCalendar() {
        const grid = this.get('calendar'); grid.replaceChildren();
        const scheduled = this.repositories.filter(r => r.enabled && r.schedule);
        const zones = [...new Set(scheduled.map(r => r.schedule.timezone))];
        this.get('zone').textContent = `${zones.length === 1 ? zones[0] : zones.length ? 'Local time for each event' : 'America/Detroit'} · Repeats every week`;
        let start = 1, end = 6;
        for (const r of scheduled) { start = Math.min(start, Number(r.schedule.start_time.slice(0, 2))); end = Math.max(end, Math.ceil(Number(r.schedule.end_time.slice(0, 2)) + Number(r.schedule.end_time.slice(3)) / 60)); }
        const duration = end - start; grid.style.setProperty('--hours', duration);
        grid.append(node(this.doc, 'div', '', 'audit-calendar-corner'));
        WEEKDAYS.forEach(day => grid.append(node(this.doc, 'div', day, 'audit-day')));
        const axis = node(this.doc, 'div', undefined, 'audit-axis');
        for (let hour = start; hour <= end; hour++) { const label = node(this.doc, 'span', clock(`${String(hour % 24).padStart(2, '0')}:00`)); label.style.top = `${(hour - start) / duration * 100}%`; axis.append(label); }
        grid.append(axis);
        WEEKDAYS.forEach((day, weekday) => {
            const column = node(this.doc, 'div', undefined, 'audit-day-column');
            const entries = scheduled.filter(r => r.schedule.weekday === weekday);
            entries.forEach((repo, index) => {
                const button = node(this.doc, 'button', undefined, `audit-event audit-color-${weekday % 3}`); button.type = 'button'; button.setAttribute('aria-label', `Edit ${repo.repository}, ${day}, ${clock(repo.schedule.start_time)} to ${clock(repo.schedule.end_time)}, ${repo.schedule.timezone}`);
                const minute = t => Number(t.slice(0, 2)) * 60 + Number(t.slice(3));
                button.style.top = `${(minute(repo.schedule.start_time) / 60 - start) / duration * 100}%`; button.style.height = `${(minute(repo.schedule.end_time) - minute(repo.schedule.start_time)) / 60 / duration * 100}%`;
                button.style.left = `${index / entries.length * 100}%`; button.style.width = `${100 / entries.length}%`;
                button.append(node(this.doc, 'strong', repo.repository.split('/')[1]), node(this.doc, 'span', `${clock(repo.schedule.start_time)}–${clock(repo.schedule.end_time)}`), node(this.doc, 'span', zones.length > 1 ? repo.schedule.timezone : 'Weekly audit'));
                button.addEventListener('click', () => this.edit(repo)); column.append(button);
            });
            if (!entries.length) { const add = node(this.doc, 'button', `Schedule ${day}`, 'audit-day-add'); add.type = 'button'; add.disabled = !this.enabled; add.addEventListener('click', () => this.edit(null, weekday)); column.append(add); }
            grid.append(column);
        });
        this.get('empty').hidden = this.repositories.length > 0;
    }
    button(text, action, cls = '') { const button = node(this.doc, 'button', text, `audit-btn ${cls}`); button.type = 'button'; button.disabled = this.pending; button.addEventListener('click', action); return button; }
    renderRepositories() {
        const list = this.get('repositories'); const focused = this.doc.activeElement?.dataset?.focus; const openMenus = new Set([...list.querySelectorAll('details[open]')].map(e => e.dataset.repositoryId)); list.replaceChildren();
        for (const repo of this.repositories) {
            const row = node(this.doc, 'div', undefined, 'audit-repo-row');
            const title = node(this.doc, 'div'); title.append(node(this.doc, 'strong', repo.repository), node(this.doc, 'small', repo.credential_configured ? 'GitHub token configured' : 'GitHub token needed')); row.append(title);
            const next = repo.next_run_at ? new Intl.DateTimeFormat('en-US', { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZone: repo.schedule.timezone }).format(new Date(repo.next_run_at)) : repo.enabled ? `Every ${WEEKDAYS[repo.schedule.weekday]}, ${clock(repo.schedule.start_time)}` : '—';
            const when = node(this.doc, 'div', next, 'audit-next'); when.append(node(this.doc, 'small', repo.schedule.timezone)); row.append(when);
            row.append(node(this.doc, 'span', repo.enabled ? 'Scheduled' : 'Paused', repo.enabled ? 'audit-scheduled' : 'audit-muted'));
            const actions = node(this.doc, 'details', undefined, 'audit-row-menu'); actions.dataset.repositoryId = repo.id; actions.open = openMenus.has(repo.id); const summary = node(this.doc, 'summary', '•••'); summary.setAttribute('aria-label', `Actions for ${repo.repository}`); summary.dataset.focus = repo.id; actions.append(summary);
            const menu = node(this.doc, 'div', undefined, 'audit-menu');
            menu.append(this.button('Edit schedule', () => this.edit(repo)), this.button('Run now', () => this.mutate(() => this.client.run(repo.id), 'Audit started. Follow its progress in Run history.')), this.button(repo.enabled ? 'Pause schedule' : 'Resume schedule', () => this.mutate(() => this.client.update(repo.id, { repository: repo.repository, ref_name: repo.ref_name, model_id: repo.model_id, schedule: repo.schedule, publish_issues: repo.publish_issues, audit_profile: repo.audit_profile, enabled: !repo.enabled }), repo.enabled ? 'Schedule paused.' : 'Schedule resumed.')), this.button('Delete repository', () => this.confirmDelete(repo), 'audit-danger'));
            actions.append(menu); row.append(actions); list.append(row);
        }
        if (focused) [...list.querySelectorAll('summary')].find(e => e.dataset.focus === focused)?.focus();
    }
    async confirmDelete(repo) {
        const dialog = this.get('report-dialog'); this.get('report-title').textContent = 'Delete repository?'; const body = this.get('report-body'); body.replaceChildren(node(this.doc, 'p', `Remove ${repo.repository} and its saved GitHub token? Previous run history is retained.`));
        body.append(this.button('Delete repository', async () => { dialog.close(); await this.mutate(() => this.client.remove(repo.id), 'Repository and saved token removed.'); }, 'audit-danger')); dialog.showModal();
    }
    renderHistory() {
        const list = this.get('history'); list.replaceChildren();
        if (!this.runs.length) { list.append(node(this.doc, 'div', 'No runs yet. Completed audits and their findings will appear here.', 'audit-empty')); return; }
        for (const run of [...this.runs].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))) {
            const row = node(this.doc, 'div', undefined, 'audit-run-row'); const title = node(this.doc, 'div'); title.append(node(this.doc, 'strong', run.repository), node(this.doc, 'small', new Date(run.created_at).toLocaleString())); row.append(title);
            const state = node(this.doc, 'div', run.state.replaceAll('_', ' '), 'audit-run-state'); if (run.error) state.append(node(this.doc, 'small', run.error)); row.append(state);
            const result = run.result; const outcome = node(this.doc, 'div'); outcome.append(node(this.doc, 'span', result ? `${(result.created || 0) + (result.updated || 0)} issues · ${result.withheld || 0} withheld · ${result.deferred || 0} deferred` : 'Report pending', 'audit-muted')); if (result?.publication_enabled === false) outcome.append(node(this.doc, 'small', 'Report only · issues not published')); else if (result?.visibility_verified === false) outcome.append(node(this.doc, 'small', 'Repository visibility not verified')); row.append(outcome);
            row.append(activeRun(run) ? this.button('Cancel run', () => this.mutate(() => this.client.cancel(run.id), 'Cancellation requested. Cleanup may take a moment.')) : this.button('View report', () => this.report(run))); list.append(row);
        }
    }
    async report(run) {
        const dialog = this.get('report-dialog'); this.get('report-title').textContent = `Audit report · ${run.repository}`; const body = this.get('report-body'); body.replaceChildren(node(this.doc, 'p', 'Loading report…')); dialog.showModal();
        try { const report = await this.client.report(run.id); if (!dialog.open) return; body.replaceChildren(); this.renderReport(body, report, run); }
        catch (error) { body.replaceChildren(node(this.doc, 'p', auditErrorMessage(error))); }
    }
    renderReport(body, report, run) {
        if (!report || typeof report !== 'object') { body.append(node(this.doc, 'p', String(report || 'No report is available for this run.'))); return; }
        body.append(node(this.doc, 'p', `Audit ${report.completion || run.state}.`, 'audit-report-completion'));
        const coverage = report.coverage;
        if (coverage) {
            const summary = node(this.doc, 'p', `${coverage.scanned_paths?.length || 0} paths scanned · ${coverage.scanners?.length || 0} scanners · ${coverage.tests?.length || 0} tests · ${coverage.skipped?.length || 0} skipped`, 'audit-muted'); body.append(summary);
            const details = node(this.doc, 'details', undefined, 'audit-report-section'); details.append(node(this.doc, 'summary', 'Coverage details'));
            for (const key of ['scanned_paths', 'scanners', 'tests', 'skipped']) { const entries = coverage[key] || []; if (!entries.length) continue; details.append(node(this.doc, 'h3', key.replaceAll('_', ' '))); const list = node(this.doc, 'ul'); for (const item of entries) list.append(node(this.doc, 'li', typeof item === 'string' ? item : `${item.name}: ${item.status}${item.detail ? ' — ' + item.detail : ''}`)); details.append(list); } body.append(details);
        }
        body.append(node(this.doc, 'h3', 'Findings'));
        if (!report.findings?.length) body.append(node(this.doc, 'p', 'No findings were included in this report.', 'audit-muted'));
        for (const finding of report.findings || []) {
            const details = node(this.doc, 'details', undefined, 'audit-report-section');
            const sensitive = finding.sensitive === true;
            details.append(node(this.doc, 'summary', sensitive ? 'Sensitive finding withheld' : `${finding.severity || 'Finding'} · ${finding.title || 'Untitled finding'}`));
            if (sensitive) details.append(node(this.doc, 'p', 'Sensitive content and source location are withheld from this view.'));
            else { details.append(node(this.doc, 'p', finding.path ? `${finding.path}${finding.line_start ? ':' + finding.line_start : ''}` : 'Source location not provided', 'audit-report-location')); for (const [key, label] of [['impact', 'Impact'], ['evidence', 'Evidence'], ['suggested_fix', 'Suggested fix']]) { if (finding[key]) details.append(node(this.doc, 'h4', label), node(this.doc, 'p', finding[key])); } }
            body.append(details);
        }
        if (run.result) { const result = run.result; body.append(node(this.doc, 'h3', 'GitHub issues'), node(this.doc, 'p', `${result.created || 0} created · ${result.updated || 0} updated · ${result.withheld || 0} withheld · ${result.deferred || 0} deferred`)); if (result.publication_enabled === false) body.append(node(this.doc, 'p', 'This was a report-only run. No issues were published.')); for (const issue of result.issues || []) { try { const url = new URL(issue.url); if (url.protocol !== 'https:' || url.hostname !== 'github.com' || !url.pathname.startsWith('/' + run.repository + '/issues/')) continue; const link = node(this.doc, 'a', `Issue #${issue.number}${issue.action ? ' · ' + issue.action : ''}`); link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.className = 'audit-issue-link'; body.append(link); } catch {} } }
    }
    edit(repo = null, weekday) {
        this.editing = repo; const schedule = repo?.schedule || suggestedSchedule(this.repositories); const form = this.get('form'); form.reset();
        this.get('dialog-title').textContent = repo ? 'Edit repository' : 'Add repository'; this.get('repository').value = repo?.repository || ''; this.get('token').required = !repo; this.get('token').value = ''; this.get('token').placeholder = repo?.credential_configured ? 'Leave blank to keep saved token' : '';
        this.get('weekday').value = weekday ?? schedule.weekday; this.get('start').value = schedule.start_time; this.get('end').value = schedule.end_time; this.get('timezone').value = schedule.timezone; this.get('model').value = repo?.model_id || 'studio'; this.get('ref').value = repo?.ref_name || ''; this.get('publish').checked = repo ? repo.publish_issues === true : true; this.get('form-error').textContent = ''; this.get('dialog').showModal();
    }
    async save() {
        if (this.pending) return; let body;
        try { body = auditRequest({ repository: this.get('repository').value, github_token: this.get('token').value, weekday: this.get('weekday').value, start_time: this.get('start').value, end_time: this.get('end').value, timezone: this.get('timezone').value, model_id: this.get('model').value, ref_name: this.get('ref').value, publish_issues: this.get('publish').checked, enabled: this.editing?.enabled ?? true }, { editing: !!this.editing }); }
        catch (error) { this.get('form-error').textContent = auditErrorMessage(error); this.get('token').value = ''; return; }
        if (this.editing?.audit_profile) body.audit_profile = this.editing.audit_profile;
        this.get('token').value = ''; this.pending = true; this.get('save').disabled = true;
        try { if (this.editing) await this.client.update(this.editing.id, body); else await this.client.create(body); delete body.github_token; this.get('dialog').close(); await this.refresh(); this.status('Weekly schedule saved.'); }
        catch (error) { this.get('form-error').textContent = auditErrorMessage(error); }
        finally { delete body.github_token; this.pending = false; this.render(); this.get('save').disabled = false; this.get('add').disabled = !this.enabled; }
    }
    async mutate(action, success) { if (this.pending) return; this.pending = true; this.render(); try { await action(); await this.refresh(); this.status(success); } catch (error) { this.status(auditErrorMessage(error), true); } finally { this.pending = false; this.render(); this.get('add').disabled = !this.enabled; } }
}
