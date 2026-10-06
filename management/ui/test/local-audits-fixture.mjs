/** Clearly labelled, memory-only fixture. Never makes API requests or GitHub writes. */
import { LocalAuditsWorkspace } from '../modules/views/local-audits.mjs';
const html = new DOMParser().parseFromString(await (await fetch('../index.html')).text(), 'text/html');
for (const selector of ['body > header', '#main-layout', '#audit-dialog', '#audit-report-dialog']) document.body.append(document.importNode(html.querySelector(selector), true));
document.body.classList.add('workspace-audits');
document.querySelector('#audits-workspace').classList.remove('hidden');
const label = document.createElement('p'); label.textContent = 'Demo fixture · no real runs or GitHub writes'; label.style.cssText='font-size:11px;color:#66707c;margin-top:auto;padding:8px'; document.querySelector('.header-content').append(label);
document.querySelector('.header-right').remove();
import { auditFixtureRequest as request } from './preview-fixtures.mjs';
const workspace = new LocalAuditsWorkspace({ root: document, request }); window.auditWorkspace = workspace; workspace.setActive(true);
for (const button of document.querySelectorAll('[data-workspace]')) button.addEventListener('click', () => { const history = button.dataset.workspace === 'audit-history'; if (!['audits','audit-history'].includes(button.dataset.workspace)) { workspace.status('Legacy workspace controls remain available in the full application. This fixture previews local audits only.'); return; } workspace.setActive(true, history); document.querySelectorAll('[data-workspace]').forEach(b => b.classList.toggle('active', b === button)); });
