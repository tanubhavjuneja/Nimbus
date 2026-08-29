// Nimbus — Dashboard Logic

const API = {
    _b: null,
    init() { if (window.pybridge) this._b = window.pybridge; },
    async call(m, ...a) {
        if (!this._b || !this._b[m]) return { success: false, error: 'Bridge not ready' };
        try { const r = await this._b[m](...a); return typeof r === 'string' ? JSON.parse(r) : r; }
        catch (e) { return { success: false, error: String(e) }; }
    }
};

const S = {
    view: 'dashboard', loggedIn: false, account: '',
    workers: [], pages: [], kv: [], r2: [], d1: [], secrets: [],
    warnings: [], hist: { shown: [], ignored: [], fixed: [], stats: {} },
    glossary: {}, audience: 'beginner',
    ollama: { available: false, model: 'none', models: [] },
    alwaysIgnored: [], detailData: null
};

const $ = id => document.getElementById(id);

function toast(msg, type = 'info') {
    const c = $('toasts'); if (!c) return;
    const t = document.createElement('div');
    t.className = `toast ${type === 'success' ? 'ok' : type === 'error' ? 'err' : 'info'}`;
    const ic = { success: '\u2713', error: '\u2717', info: '\u2139' };
    t.innerHTML = `<span>${ic[type] || '\u2139'}</span> ${msg}`;
    c.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateY(8px)'; setTimeout(() => t.remove(), 300); }, 3200);
}

function modal(title, body, actions = []) {
    $('modal').innerHTML = `<h3>${title}</h3><p>${body}</p><div class="modal-acts">${actions.map(a =>
        `<button class="btn ${a.cls || 'btn-ghost'}" onclick="${a.fn}">${a.label}</button>`
    ).join('')}</div>`;
    $('modalBg').style.display = 'flex';
}

function hideModal() { $('modalBg').style.display = 'none'; }

function nav(view) {
    S.view = view;
    S.detailData = null;
    document.querySelectorAll('.nav-link').forEach(el => el.classList.toggle('active', el.dataset.view === view));
    document.querySelectorAll('.page').forEach(el => el.classList.toggle('active', el.id === `p-${view}`));
    const m = {
        dashboard: ['Dashboard', 'Your Cloudflare account overview'],
        warnings: ['Security Warnings', 'Issues that need your attention'],
        services: ['My Services', 'All your Cloudflare resources'],
        history: ['History', 'Past warnings and your decisions'],
        glossary: ['Learn', 'Understand security terms in plain language'],
        settings: ['Settings', 'Customize Nimbus']
    };
    $('title').textContent = m[view]?.[0] || 'Nimbus';
    $('subtitle').textContent = m[view]?.[1] || '';
    render();
}

function badge() {
    const b = $('badge'); if (!b) return;
    const c = S.warnings.length;
    b.style.display = c > 0 ? 'inline' : 'none';
    b.textContent = c > 99 ? '99+' : c;
}

function ago(ts) {
    if (!ts) return '';
    const s = Math.floor(Date.now() / 1000 - ts);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
}

// ═══ Loading Screen ═══════════════════════════

function showLoading() {
    const el = $('loadingOverlay');
    if (el) { el.style.display = 'flex'; el.classList.remove('hidden'); }
}

function hideLoading() {
    const el = $('loadingOverlay');
    if (el) el.classList.add('hidden');
}

function setLoadingStep(steps, activeIdx) {
    const el = $('loadingSteps');
    const txt = $('loadingText');
    if (el) {
        el.innerHTML = steps.map((s, i) => {
            const cls = i < activeIdx ? 'done' : i === activeIdx ? 'active' : '';
            return `<div class="loading-step ${cls}"><div class="loading-step-dot"></div><span>${s}</span></div>`;
        }).join('');
    }
    if (txt) txt.textContent = steps[activeIdx] || 'Loading...';
}

function showLoginScreen() {
    const lo = $('loadingOverlay');
    if (lo) lo.style.display = 'none';
    const ls = $('loginScreen');
    if (ls) ls.style.display = 'flex';
    const app = document.querySelector('.app');
    if (app) app.style.display = 'none';
}

function hideLoginScreen() {
    const ls = $('loginScreen');
    if (ls) ls.style.display = 'none';
    const app = document.querySelector('.app');
    if (app) app.style.display = 'flex';
}

// ═══ Ollama Model Classification ═════════════

function classifyModels(models) {
    const free = [];
    const paid = [];
    for (const m of models) {
        const lower = m.toLowerCase();
        if (lower.includes(':cloud') || lower.includes(':paid') || lower.includes('-cloud')) {
            paid.push(m);
        } else {
            free.push(m);
        }
    }
    free.sort((a, b) => a.localeCompare(b));
    paid.sort((a, b) => a.localeCompare(b));
    return { free, paid };
}

function modelTag(name) {
    const lower = name.toLowerCase();
    if (lower.includes(':cloud') || lower.includes('-cloud') || lower.includes(':paid')) {
        return '<span style="font-size:9px;padding:1px 5px;border-radius:8px;background:var(--orange-dim);color:var(--orange);margin-left:6px">Paid</span>';
    }
    return '<span style="font-size:9px;padding:1px 5px;border-radius:8px;background:var(--green-dim);color:var(--green);margin-left:6px">Free</span>';
}

// ═══ Dashboard ═══════════════════════════════

function pDashboard() {
    const el = $('p-dashboard');
    const cr = S.warnings.filter(w => w.severity === 'Critical').length;

    // Collect recent deployments from pages
    const recentDeps = [];
    (S.pages || []).forEach(p => {
        if (p.modified) recentDeps.push({ name: p.name, type: 'pages', time: p.modified, url: `https://${p.name}.pages.dev` });
    });
    (S.workers || []).forEach(w => {
        if (w.modified) recentDeps.push({ name: w.name, type: 'worker', time: w.modified, url: null });
    });
    recentDeps.sort((a, b) => (b.time || '').localeCompare(a.time || ''));

    el.innerHTML = `
        ${cr > 0 ? `
        <div class="banner">
            <div class="banner-icon">!</div>
            <div class="banner-text">
                <div class="banner-title">${cr} critical ${cr === 1 ? 'issue' : 'issues'} found</div>
                <div class="banner-desc">These could expose your data. We recommend fixing them now.</div>
            </div>
            <button class="btn btn-red btn-sm" onclick="nav('warnings')">View</button>
        </div>` : ''}

        <div class="grid g4" style="margin-bottom:16px">
            <div class="card s-green svc-card" onclick="nav('services')" style="cursor:pointer">
                <div class="card-head"><span class="card-label">Pages</span><div class="card-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#7ee8c0" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg></div></div>
                <div class="card-num">${S.pages.length}</div>
                <div class="card-sub">Projects</div>
            </div>
            <div class="card s-blue svc-card" onclick="nav('services')" style="cursor:pointer">
                <div class="card-head"><span class="card-label">Workers</span><div class="card-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#72b8fa" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div></div>
                <div class="card-num">${S.workers.length}</div>
                <div class="card-sub">Deployed</div>
            </div>
            <div class="card s-cyan svc-card" onclick="nav('services')" style="cursor:pointer">
                <div class="card-head"><span class="card-label">Databases</span><div class="card-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#7aeef8" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg></div></div>
                <div class="card-num">${S.d1.length + S.kv.length + S.r2.length}</div>
                <div class="card-sub">D1 + KV + R2</div>
            </div>
            <div class="card s-purple svc-card" onclick="nav('services')" style="cursor:pointer">
                <div class="card-head"><span class="card-label">Secrets</span><div class="card-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c4b5fd" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></div></div>
                <div class="card-num">${S.secrets.length}</div>
                <div class="card-sub">Worker secrets</div>
            </div>
        </div>

        <div class="grid g2" style="margin-bottom:16px">
            <div class="card">
                <div class="card-head"><span class="card-label">Recent Deployments</span></div>
                ${recentDeps.length === 0 ? '<p style="font-size:12px;color:var(--text3)">No recent deployments.</p>' :
                recentDeps.slice(0, 5).map(d => `
                <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--glass-border)">
                    <div style="width:8px;height:8px;border-radius:50%;background:${d.type === 'pages' ? 'var(--green)' : 'var(--blue)'};flex-shrink:0"></div>
                    <div style="flex:1;min-width:0">
                        <div style="font-size:12px;font-weight:600">${d.name}</div>
                        <div style="font-size:10px;color:var(--text3)">${d.type}</div>
                    </div>
                    ${d.url ? `<a href="${d.url}" target="_blank" style="font-size:10px;color:var(--blue);text-decoration:none" onclick="event.stopPropagation()">Open</a>` : ''}
                    <button class="btn btn-ghost btn-sm" onclick="nav('services')" style="font-size:10px">View</button>
                </div>`).join('')}
            </div>

            <div class="card">
                <div class="card-head"><span class="card-label">Security Issues</span></div>
                ${S.warnings.length === 0 ? '<p style="font-size:12px;color:var(--text3)">No active warnings. All clear!</p>' :
                S.warnings.slice(0, 5).map((w, i) => {
                    const cls = w.severity === 'Critical' ? 'crit' : w.severity === 'High' ? 'high' : 'med';
                    return `
                    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--glass-border);cursor:pointer" onclick="nav('warnings')">
                        <div class="warn-badge ${cls}" style="width:24px;height:24px;font-size:10px;border-radius:6px">${w.severity === 'Critical' ? '!!' : w.severity === 'High' ? '!' : 'i'}</div>
                        <div style="flex:1;min-width:0">
                            <div style="font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${w.message}</div>
                            <div style="font-size:10px;color:var(--text3)">${w.file ? w.file.split(/[\\/]/).pop() : ''}</div>
                        </div>
                        <span class="st st-${cls === 'crit' ? 'crit' : cls === 'high' ? 'warn' : 'info'}" style="font-size:9px">${w.severity}</span>
                    </div>`;
                }).join('')}
                ${S.warnings.length > 5 ? `<div style="text-align:center;padding-top:8px"><button class="btn btn-ghost btn-sm" onclick="nav('warnings')">View all ${S.warnings.length} issues</button></div>` : ''}
            </div>
        </div>

        ${S.secrets.length > 0 ? `
        <div class="sec-head"><span class="sec-title">Your Secrets</span></div>
        <div class="tbl"><table>
            <thead><tr><th>Name</th><th>Type</th><th>Status</th></tr></thead>
            <tbody>${S.secrets.map(s => `<tr><td><strong>${s.name || s}</strong></td><td>${s.type || 'secret'}</td><td><span class="st st-on">Secure</span></td></tr>`).join('')}</tbody>
        </table></div>` : ''}
    `;
}

// ═══ Warnings ════════════════════════════════

function pWarnings() {
    const el = $('p-warnings');
    if (S.warnings.length === 0) {
        el.innerHTML = `<div class="empty"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><h3>All Clear!</h3><p>No security warnings. Your project looks good.</p></div>`;
        return;
    }
    el.innerHTML = S.warnings.map((w, i) => {
        const cls = w.severity === 'Critical' ? 'crit' : w.severity === 'High' ? 'high' : 'med';
        return `
        <div class="warn ${cls}" id="w${i}">
            <div class="warn-head">
                <div class="warn-badge ${cls}">${w.severity === 'Critical' ? '!!' : w.severity === 'High' ? '!' : 'i'}</div>
                <div style="flex:1;min-width:0">
                    <div class="warn-title">${w.message}</div>
                    <div class="warn-file">${w.file || ''}</div>
                </div>
                <span class="st st-${cls === 'crit' ? 'crit' : cls === 'high' ? 'warn' : 'info'}">${w.severity}</span>
            </div>
            <div class="warn-body">
                <div class="warn-explain" id="we${i}">${w.simple_explanation || w.message}</div>
                ${w.terms?.length ? `<div class="warn-terms">${w.terms.map(t => `<span class="term-tag" onclick="showTerm('${t}')">${t}</span>`).join('')}</div>` : ''}
                <div id="wa${i}"></div>
            </div>
            <div class="warn-acts">
                <button class="btn btn-green btn-sm" onclick="fixW(${i})" id="wf${i}">Fix This</button>
                <button class="btn btn-ghost btn-sm" onclick="askAI(${i})" ${S.ollama.available ? '' : 'disabled title="Connect Ollama first"'}>
                    ${S.ollama.available ? 'Ask AI' : 'AI Offline'}
                </button>
                <span class="spacer"></span>
                <button class="btn btn-ghost btn-sm" onclick="dismissW(${i})">Dismiss</button>
                <button class="btn btn-ghost btn-sm" onclick="alwaysIgnore(${i})">Always Ignore</button>
            </div>
        </div>`;
    }).join('');
}

async function fixW(i) {
    const w = S.warnings[i]; if (!w) return;
    const btn = $(`wf${i}`);
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin" style="width:13px;height:13px;border-width:1.5px"></span>'; }
    const r = await API.call('fix_finding', JSON.stringify(w), '.');
    if (r.success) {
        toast(r.message || 'Fixed!', 'success');
        if (r.note) toast(r.note, 'info');
        S.warnings.splice(i, 1);
        pWarnings(); badge(); refresh();
    } else {
        toast(`Could not fix: ${r.error}`, 'error');
        if (btn) { btn.disabled = false; btn.textContent = 'Fix This'; }
    }
}

async function dismissW(i) {
    const w = S.warnings[i]; if (!w) return;
    await API.call('ignore_warning', w.id || '');
    S.warnings.splice(i, 1);
    pWarnings(); badge();
    toast('Dismissed', 'info');
}

async function alwaysIgnore(i) {
    const w = S.warnings[i]; if (!w) return;
    await API.call('ignore_check_always', w.check || '');
    S.warnings.splice(i, 1);
    S.alwaysIgnored.push(w.check);
    pWarnings(); badge();
    toast(`All "${w.check}" warnings hidden permanently`, 'info');
}

async function askAI(i) {
    const w = S.warnings[i]; if (!w) return;
    const c = $(`wa${i}`); if (!c) return;
    c.innerHTML = '<div class="ai-box"><div class="ai-box-head"><span class="spin" style="width:13px;height:13px;border-width:1.5px"></span> Analyzing with AI...</div></div>';
    const r = await API.call('analyze_finding', JSON.stringify(w));
    if (r.success && r.data) {
        const d = r.data;
        c.innerHTML = `<div class="ai-box">
            <div class="ai-box-head"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v6m0 6v6m11-7h-6m-6 0H1"/></svg>
            AI Analysis ${d.is_real_issue === false ? ' \u2014 Not a real issue' : ''}</div>
            <div>${d.explanation || 'No explanation.'}</div>
            ${d.recommendation ? `<div style="margin-top:8px"><strong>What to do:</strong> ${d.recommendation}</div>` : ''}
            ${d.data_at_risk ? `<div style="margin-top:4px;color:var(--orange)"><strong>Data at risk:</strong> ${d.data_at_risk}</div>` : ''}
        </div>`;
    } else {
        c.innerHTML = `<div class="ai-box" style="border-color:rgba(252,165,165,0.2);background:rgba(252,165,165,0.05)">AI unavailable: ${r.error || 'Could not connect'}</div>`;
    }
}

// ═══ Project Detail ═══════════════════════════

async function showProjectDetail(type, name) {
    S.detailData = { type, name, loading: true, data: null };
    render();
    let r;
    if (type === 'pages') r = await API.call('get_project_details', name);
    else if (type === 'd1') r = await API.call('get_d1_details', name);
    else if (type === 'r2') r = await API.call('get_r2_details', name);
    else if (type === 'kv') r = await API.call('get_kv_details', name);
    if (r?.success) {
        S.detailData.data = r.data;
        S.detailData.loading = false;
    } else {
        S.detailData.loading = false;
        S.detailData.error = r?.error || 'Failed to load details';
    }
    render();
}

function closeDetail() { S.detailData = null; render(); }

function renderDetail() {
    if (!S.detailData) return '';
    const d = S.detailData;
    if (d.loading) return `<div class="detail-panel"><div class="loading-text">Loading ${d.name}...</div><div class="loading-spinner" style="width:24px;height:24px;margin:12px auto"></div></div>`;
    if (d.error) return `<div class="detail-panel"><div class="detail-header"><div class="detail-title">${d.name}</div><button class="detail-close" onclick="closeDetail()">&times;</button></div><p style="color:var(--red)">${d.error}</p></div>`;

    const info = d.data || {};
    let html = `<div class="detail-panel"><div class="detail-header"><div class="detail-title">${d.name}</div><button class="detail-close" onclick="closeDetail()">&times;</button></div>`;

    if (d.type === 'pages') {
        html += `<div class="detail-grid">
            <div class="detail-stat"><div class="detail-stat-label">URL</div><div class="detail-stat-value"><a href="${info.url || '#'}" target="_blank">${info.url || '-'}</a></div></div>
            <div class="detail-stat"><div class="detail-stat-label">Project</div><div class="detail-stat-value">${info.name || d.name}</div></div>
        </div>`;
        const deps = info.deployments || [];
        if (deps.length > 0) {
            html += `<div class="detail-section"><div class="detail-section-title">Recent Deployments</div>
            <div class="tbl"><table><thead><tr><th>URL</th><th>Created</th><th>Branch</th></tr></thead><tbody>`;
            deps.slice(0, 5).forEach(dep => {
                const url = dep.url || dep.deploy_url || '-';
                const created = dep.created_on || dep.created || '-';
                const branch = dep.deployment_trigger?.metadata?.branch || dep.branch || '-';
                html += `<tr><td><a href="${url}" target="_blank" style="color:var(--blue);text-decoration:none;font-size:11px">${url.length > 40 ? url.substring(0, 40) + '...' : url}</a></td><td style="font-size:11px">${created}</td><td><span class="detail-tag blue">${branch}</span></td></tr>`;
            });
            html += `</tbody></table></div></div>`;
        }
    } else if (d.type === 'd1') {
        html += `<div class="detail-grid">
            <div class="detail-stat"><div class="detail-stat-label">UUID</div><div class="detail-stat-value" style="font-size:11px">${info.uuid || '-'}</div></div>
            <div class="detail-stat"><div class="detail-stat-label">Tables</div><div class="detail-stat-value">${info.num_tables || '0'}</div></div>
            <div class="detail-stat"><div class="detail-stat-label">Size</div><div class="detail-stat-value">${info.file_size ? (parseInt(info.file_size) / (1024 * 1024)).toFixed(2) + ' MB' : '-'}</div></div>
        </div>`;
        const tables = info.tables || [];
        if (tables.length > 0) {
            html += `<div class="detail-section"><div class="detail-section-title">Tables</div><div style="display:flex;flex-wrap:wrap;gap:6px">`;
            tables.forEach(t => html += `<span class="detail-tag blue">${t.name || t}</span>`);
            html += `</div></div>`;
        }
    } else if (d.type === 'r2') {
        const objs = info.objects || [];
        html += `<div class="detail-grid"><div class="detail-stat"><div class="detail-stat-label">Objects</div><div class="detail-stat-value">${objs.length}</div></div></div>`;
        if (objs.length > 0) {
            html += `<div class="detail-section"><div class="detail-section-title">Objects</div>
            <div class="tbl"><table><thead><tr><th>Key</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>`;
            objs.slice(0, 20).forEach(o => {
                const sz = o.size ? (parseInt(o.size) / 1024).toFixed(1) + ' KB' : '-';
                const mod = o.last_modified || o.modified || '-';
                html += `<tr><td style="font-size:11px;font-family:monospace">${o.key || '-'}</td><td>${sz}</td><td style="font-size:11px">${mod}</td><td><button class="btn btn-red btn-sm" onclick="deleteR2Obj('${d.name}','${o.key || ''}')">Delete</button></td></tr>`;
            });
            html += `</tbody></table></div></div>`;
        }
    } else if (d.type === 'kv') {
        const keys = info.keys || [];
        html += `<div class="detail-grid"><div class="detail-stat"><div class="detail-stat-label">Namespace ID</div><div class="detail-stat-value" style="font-size:11px">${info.id || '-'}</div></div>
        <div class="detail-stat"><div class="detail-stat-label">Keys</div><div class="detail-stat-value">${keys.length}</div></div></div>`;
        if (keys.length > 0) {
            html += `<div class="detail-section"><div class="detail-section-title">Keys</div><div style="display:flex;flex-wrap:wrap;gap:6px">`;
            keys.forEach(k => html += `<span class="detail-tag green">${k.name || k}</span>`);
            html += `</div></div>`;
        }
    } else if (d.type === 'worker') {
        html += `<div class="detail-grid">
            <div class="detail-stat"><div class="detail-stat-label">Worker</div><div class="detail-stat-value">${info.name || d.name}</div></div>
        </div>`;
        const routes = info.routes || [];
        if (routes.length > 0) {
            html += `<div class="detail-section"><div class="detail-section-title">Routes</div>
            <div class="tbl"><table><thead><tr><th>Pattern</th><th>Script</th></tr></thead><tbody>`;
            routes.forEach(r => {
                html += `<tr><td style="font-size:12px">${r.pattern || '-'}</td><td style="font-size:11px;color:var(--text3)">${r.script || '-'}</td></tr>`;
            });
            html += `</tbody></table></div></div>`;
        } else {
            html += `<p style="font-size:12px;color:var(--text3);margin-top:10px">No routes configured.</p>`;
        }
    }

    html += `</div>`;
    return html;
}

async function deleteR2Obj(bucket, key) {
    if (!confirm(`Delete ${key} from ${bucket}?`)) return;
    const r = await API.call('delete_r2_object', bucket, key);
    if (r.success) { toast(r.message, 'success'); showProjectDetail('r2', bucket); }
    else toast(r.error || 'Delete failed', 'error');
}

// ═══ Services ════════════════════════════════

function pServices() {
    const el = $('p-services');
    el.innerHTML = `
        ${renderDetail()}

        <div class="sec-head">
            <span class="sec-title">Pages Projects</span>
            <div style="display:flex;gap:6px">
                <button class="btn btn-ghost btn-sm" onclick="browseProjectDir()" title="Set project directory for scans">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>
                    ${S.scanPath ? S.scanPath.split(/[\\/]/).pop() : 'Set Path'}
                </button>
                <button class="btn btn-green btn-sm" onclick="showCreatePages()">+ New Pages Project</button>
            </div>
        </div>
        ${S.pages.length === 0 ? '<p style="color:var(--text3);margin-bottom:14px">No Pages projects.</p>' : `
        <div class="tbl"><table>
            <thead><tr><th>Project</th><th>URL</th><th>Modified</th><th></th></tr></thead>
            <tbody>${S.pages.map(p => `<tr class="svc-card" onclick="showProjectDetail('pages','${p.name || ''}')">
                <td><strong>${p.name || '-'}</strong></td>
                <td><a href="https://${p.name}.pages.dev" target="_blank" style="color:var(--blue);text-decoration:none" onclick="event.stopPropagation()">${p.name}.pages.dev</a></td>
                <td>${p.modified || '-'}</td>
                <td style="display:flex;gap:6px">
                    <button class="btn btn-glow btn-sm" onclick="event.stopPropagation();redeployPages('${p.name || ''}')">Redeploy</button>
                    <button class="btn btn-red btn-sm" onclick="event.stopPropagation();deletePagesProject('${p.name || ''}')">Delete</button>
                </td>
            </tr>`).join('')}</tbody>
        </table></div>`}

        <div class="sec-head" style="margin-top:20px">
            <span class="sec-title">Workers</span>
            <button class="btn btn-green btn-sm" onclick="showCreateWorker()">+ New Worker</button>
        </div>
        ${S.workers.length === 0 ? '<p style="color:var(--text3)">No Workers deployed.</p>' : `
        <div class="tbl"><table>
            <thead><tr><th>Name</th><th>Routes</th><th>Modified</th><th></th></tr></thead>
            <tbody>${S.workers.map(w => `<tr class="svc-card" onclick="showWorkerDetail('${w.name || ''}')">
                <td><strong>${w.name || '-'}</strong></td>
                <td style="font-size:11px;color:var(--text3)">${w.routes || '-'}</td>
                <td>${w.modified || '-'}</td>
                <td><button class="btn btn-red btn-sm" onclick="event.stopPropagation();deleteWorker('${w.name || ''}')">Delete</button></td>
            </tr>`).join('')}</tbody>
        </table></div>`}

        <div class="sec-head" style="margin-top:20px">
            <span class="sec-title">D1 Databases</span>
            <button class="btn btn-blue btn-sm" onclick="showCreateD1()">+ New Database</button>
        </div>
        ${S.d1.length === 0 ? '<p style="color:var(--text3)">No D1 databases.</p>' : `
        <div class="tbl"><table>
            <thead><tr><th>Database</th><th>Tables</th><th>Size</th><th></th></tr></thead>
            <tbody>${S.d1.map(d => `<tr class="svc-card" onclick="showProjectDetail('d1','${d.name || ''}')">
                <td><strong>${d.name || '-'}</strong></td>
                <td>${d.num_tables || '0'}</td>
                <td>${d.file_size ? (parseInt(d.file_size)/(1024*1024)).toFixed(2)+' MB' : '-'}</td>
                <td><button class="btn btn-red btn-sm" onclick="event.stopPropagation();deleteD1('${d.name || ''}')">Delete</button></td>
            </tr>`).join('')}</tbody>
        </table></div>`}

        <div class="sec-head" style="margin-top:20px">
            <span class="sec-title">KV Namespaces</span>
        </div>
        ${S.kv.length === 0 ? '<p style="color:var(--text3)">No KV namespaces.</p>' : `
        <div class="tbl"><table>
            <thead><tr><th>Name</th><th>ID</th></tr></thead>
            <tbody>${S.kv.map(k => `<tr class="svc-card" onclick="showProjectDetail('kv','${k.id || ''}')">
                <td><strong>${k.title || '-'}</strong></td>
                <td><code style="font-size:11px;color:var(--text3)">${k.id || '-'}</code></td>
            </tr>`).join('')}</tbody>
        </table></div>`}

        <div class="sec-head" style="margin-top:20px">
            <span class="sec-title">R2 Buckets</span>
            <button class="btn btn-cyan btn-sm" onclick="showCreateR2()">+ New Bucket</button>
        </div>
        ${S.r2.length === 0 ? '<p style="color:var(--text3)">No R2 buckets.</p>' : `
        <div class="tbl"><table>
            <thead><tr><th>Bucket</th><th>Created</th><th></th></tr></thead>
            <tbody>${S.r2.map(r => `<tr class="svc-card" onclick="showProjectDetail('r2','${r.name || ''}')">
                <td><strong>${r.name || '-'}</strong></td>
                <td>${r.created_on ? new Date(r.created_on).toLocaleDateString() : '-'}</td>
                <td style="display:flex;gap:6px">
                    <button class="btn btn-blue btn-sm" onclick="event.stopPropagation();showUploadR2('${r.name || ''}')">Upload</button>
                    <button class="btn btn-red btn-sm" onclick="event.stopPropagation();deleteR2('${r.name || ''}')">Delete</button>
                </td>
            </tr>`).join('')}</tbody>
        </table></div>`}

        <div class="sec-head" style="margin-top:20px">
            <span class="sec-title">Deploy Local Project</span>
        </div>
        <div class="card svc-card" onclick="showDeployLocal()" style="cursor:pointer;text-align:center;padding:28px">
            <div style="font-size:14px;font-weight:600;margin-bottom:6px">Deploy from Directory</div>
            <div style="font-size:12px;color:var(--text3)">Select a local directory with wrangler.toml or package.json to deploy</div>
        </div>
    `;
}

// ═══ Create/Deploy Modals ═════════════════════

function showCreateD1() {
    $('modal').innerHTML = `
        <h3>Create D1 Database</h3>
        <p>A D1 database stores structured data for your Cloudflare Workers, like user accounts or product listings.</p>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Database Name</label>
            <input class="inp" id="d1Name" placeholder="e.g. my-database" autofocus />
        </div>
        <div class="modal-acts">
            <button class="btn btn-ghost" onclick="hideModal()">Cancel</button>
            <button class="btn btn-glow" onclick="createD1()">Create Database</button>
        </div>`;
    $('modalBg').style.display = 'flex';
}

async function createD1() {
    const name = $('d1Name')?.value?.trim();
    if (!name) { toast('Enter a database name', 'error'); return; }
    toast('Creating database...', 'info');
    const r = await API.call('create_d1_database', name);
    if (r.success) { toast(r.message || 'Database created!', 'success'); hideModal(); refresh(); }
    else toast(r.error || 'Failed', 'error');
}

async function deleteD1(name) {
    if (!confirm(`Delete database "${name}"? This cannot be undone.`)) return;
    const r = await API.call('delete_d1_database', name);
    if (r.success) { toast(r.message, 'success'); refresh(); }
    else toast(r.error || 'Failed', 'error');
}

function showCreateR2() {
    $('modal').innerHTML = `
        <h3>Create R2 Bucket</h3>
        <p>R2 is Cloudflare's object storage. Store files like images, videos, backups, and logs without egress fees.</p>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Bucket Name</label>
            <input class="inp" id="r2Name" placeholder="e.g. my-images" autofocus />
        </div>
        <div class="modal-acts">
            <button class="btn btn-ghost" onclick="hideModal()">Cancel</button>
            <button class="btn btn-glow" onclick="createR2()">Create Bucket</button>
        </div>`;
    $('modalBg').style.display = 'flex';
}

async function createR2() {
    const name = $('r2Name')?.value?.trim();
    if (!name) { toast('Enter a bucket name', 'error'); return; }
    toast('Creating bucket...', 'info');
    const r = await API.call('create_r2_bucket', name);
    if (r.success) { toast(r.message || 'Bucket created!', 'success'); hideModal(); refresh(); }
    else toast(r.error || 'Failed', 'error');
}

async function deleteR2(name) {
    if (!confirm(`Delete bucket "${name}" and all its contents? This cannot be undone.`)) return;
    const r = await API.call('delete_r2_bucket', name);
    if (r.success) { toast(r.message, 'success'); refresh(); }
    else toast(r.error || 'Failed', 'error');
}

function showUploadR2(bucket) {
    $('modal').innerHTML = `
        <h3>Upload to ${bucket}</h3>
        <p>Select a file from your computer to upload to this R2 bucket.</p>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">File</label>
            <div style="display:flex;gap:8px">
                <input class="inp" id="r2FilePath" placeholder="No file selected" readonly style="flex:1" />
                <button class="btn btn-glow btn-sm" onclick="browseR2File()">Browse</button>
            </div>
        </div>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Object Key (name in the bucket)</label>
            <input class="inp" id="r2ObjectKey" placeholder="e.g. images/photo.png" />
        </div>
        <div class="modal-acts">
            <button class="btn btn-ghost" onclick="hideModal()">Cancel</button>
            <button class="btn btn-glow" onclick="uploadR2File('${bucket}')">Upload</button>
        </div>`;
    $('modalBg').style.display = 'flex';
}

async function browseR2File() {
    const r = await API.call('browse_file');
    if (r.success && r.path) {
        $('r2FilePath').value = r.path;
        const filename = r.path.split(/[\\/]/).pop();
        if ($('r2ObjectKey') && !$('r2ObjectKey').value) {
            $('r2ObjectKey').value = filename;
        }
    }
}

async function browseProjectDir() {
    const r = await API.call('browse_directory');
    if (r.success && r.path) {
        S.scanPath = r.path;
        toast(`Project path set to: ${r.path.split(/[\\/]/).pop()}`, 'success');
        pServices();
        refresh();
    }
}

async function uploadR2File(bucket) {
    const filePath = $('r2FilePath')?.value?.trim();
    const key = $('r2ObjectKey')?.value?.trim();
    if (!filePath || !key) { toast('Select a file and enter an object key', 'error'); return; }
    toast('Uploading...', 'info');
    const r = await API.call('upload_r2_file', bucket, key, filePath);
    if (r.success) { toast(r.message || 'Uploaded!', 'success'); hideModal(); showProjectDetail('r2', bucket); }
    else toast(r.error || 'Upload failed', 'error');
}

function showDeployPages(name) {
    $('modal').innerHTML = `
        <h3>Deploy Pages Project</h3>
        <p>Deploy a new version of <strong>${name}</strong>.</p>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Project Directory</label>
            <div style="display:flex;gap:8px">
                <input class="inp" id="deployDir" placeholder="No directory selected" readonly style="flex:1" />
                <button class="btn btn-glow btn-sm" onclick="browseDeployPagesDir()">Browse</button>
            </div>
        </div>
        <div class="modal-acts">
            <button class="btn btn-ghost" onclick="hideModal()">Cancel</button>
            <button class="btn btn-glow" onclick="doDeployPages('${name}')">Deploy Now</button>
        </div>`;
    $('modalBg').style.display = 'flex';
}

async function browseDeployPagesDir() {
    const r = await API.call('browse_directory');
    if (r.success && r.path) $('deployDir').value = r.path;
}

async function doDeployPages(name) {
    const dir = $('deployDir')?.value?.trim();
    if (!dir) { toast('Select a directory', 'error'); return; }
    toast('Deploying Pages...', 'info');
    hideModal();
    const r = await API.call('deploy', 'pages', name);
    if (r.success) toast('Pages deployed!', 'success');
    else toast(r.error || 'Deploy failed', 'error');
    refresh();
}

function showCreatePages() {
    $('modal').innerHTML = `
        <h3>New Pages Project</h3>
        <p>Create a new Cloudflare Pages project. Pages hosts static sites and Jamstack apps with automatic HTTPS and CI/CD.</p>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Project Name</label>
            <input class="inp" id="pagesName" placeholder="e.g. my-website" autofocus />
        </div>
        <div class="modal-acts">
            <button class="btn btn-ghost" onclick="hideModal()">Cancel</button>
            <button class="btn btn-glow" onclick="createPages()">Create Project</button>
        </div>`;
    $('modalBg').style.display = 'flex';
}

async function createPages() {
    const name = $('pagesName')?.value?.trim();
    if (!name) { toast('Enter a project name', 'error'); return; }
    toast('Creating Pages project...', 'info');
    const r = await API.call('create_pages_project', name);
    if (r.success) { toast(r.message || 'Project created!', 'success'); hideModal(); refresh(); }
    else toast(r.error || 'Failed', 'error');
}

function showDeployLocal() {
    $('modal').innerHTML = `
        <h3>Deploy Local Project</h3>
        <p>Select a local directory containing your Cloudflare project. Nimbus will detect the project type and deploy it.</p>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Project Directory</label>
            <div style="display:flex;gap:8px">
                <input class="inp" id="localDir" placeholder="No directory selected" readonly style="flex:1" />
                <button class="btn btn-glow btn-sm" onclick="browseDeployDir()">Browse</button>
            </div>
        </div>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Project Name (optional)</label>
            <input class="inp" id="localName" placeholder="Auto-detect from directory" />
        </div>
        <div class="modal-acts">
            <button class="btn btn-ghost" onclick="hideModal()">Cancel</button>
            <button class="btn btn-glow" onclick="doDeployLocal()">Deploy</button>
        </div>`;
    $('modalBg').style.display = 'flex';
}

async function browseDeployDir() {
    const r = await API.call('browse_directory');
    if (r.success && r.path) $('localDir').value = r.path;
}

async function doDeployLocal() {
    const dir = $('localDir')?.value?.trim();
    const name = $('localName')?.value?.trim();
    if (!dir) { toast('Select a directory', 'error'); return; }
    toast('Deploying...', 'info');
    hideModal();
    const r = await API.call('smart_deploy', dir, name || '', '');
    if (r.success) toast(r.message || r.output || 'Deployed!', 'success');
    else toast(r.error || 'Deploy failed', 'error');
    refresh();
}

async function redeployPages(name) {
    toast(`Redeploying ${name}...`, 'info');
    const r = await API.call('redeploy_pages', name);
    if (r.success) toast(r.message || 'Redeploy triggered!', 'success');
    else toast(r.error || 'Redeploy failed', 'error');
}

async function deletePagesProject(name) {
    if (!confirm(`Delete Pages project "${name}"? This cannot be undone.`)) return;
    const r = await API.call('delete_pages_project', name);
    if (r.success) { toast(r.message, 'success'); refresh(); }
    else toast(r.error || 'Delete failed', 'error');
}

async function deleteWorker(name) {
    if (!confirm(`Delete worker "${name}"? This cannot be undone.`)) return;
    const r = await API.call('delete_worker', name);
    if (r.success) { toast(r.message, 'success'); refresh(); }
    else toast(r.error || 'Delete failed', 'error');
}

function showCreateWorker() {
    $('modal').innerHTML = `
        <h3>Create Worker</h3>
        <p>Create a new Cloudflare Worker. Workers run your code on Cloudflare's edge network with zero cold starts.</p>
        <div style="margin:16px 0">
            <label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Worker Name</label>
            <input class="inp" id="workerName" placeholder="e.g. my-api-worker" autofocus />
        </div>
        <div class="modal-acts">
            <button class="btn btn-ghost" onclick="hideModal()">Cancel</button>
            <button class="btn btn-glow" onclick="createWorker()">Create Worker</button>
        </div>`;
    $('modalBg').style.display = 'flex';
}

async function createWorker() {
    const name = $('workerName')?.value?.trim();
    if (!name) { toast('Enter a worker name', 'error'); return; }
    toast('Creating worker...', 'info');
    const r = await API.call('create_worker_project', name);
    if (r.success) { toast(r.message || 'Worker created!', 'success'); hideModal(); }
    else toast(r.error || 'Failed', 'error');
}

async function showWorkerDetail(name) {
    S.detailData = { type: 'worker', name, loading: true, data: null };
    render();
    const [routesR] = await Promise.all([API.call('get_worker_routes', name)]);
    const data = { name };
    if (routesR.success) data.routes = routesR.data;
    S.detailData.data = data;
    S.detailData.loading = false;
    render();
}

// ═══ History ═════════════════════════════════

function pHist() {
    const el = $('p-history');
    const h = S.hist;
    const all = [
        ...h.fixed.map(w => ({ ...w, _act: 'Fixed', _cls: 'on', _ic: '\u2713' })),
        ...h.ignored.map(w => ({ ...w, _act: 'Ignored', _cls: 'off', _ic: '\u2717' })),
    ].sort((a, b) => (b.fixed_at || b.ignored_at || 0) - (a.fixed_at || a.ignored_at || 0));

    el.innerHTML = `
        <div class="grid g3" style="margin-bottom:18px">
            <div class="card" style="text-align:center"><div class="card-num" style="color:var(--green)">${h.stats.total_fixed || 0}</div><div class="card-sub">Fixed</div></div>
            <div class="card" style="text-align:center"><div class="card-num" style="color:var(--text3)">${h.stats.total_ignored || 0}</div><div class="card-sub">Ignored</div></div>
            <div class="card" style="text-align:center"><div class="card-num" style="color:var(--blue)">${h.stats.total_shown || 0}</div><div class="card-sub">Active</div></div>
        </div>
        ${all.length === 0 ? '<div class="empty"><h3>No History Yet</h3><p>Fix or dismiss warnings to see them here.</p></div>' :
        all.map(w => `
        <div class="hist-item">
            <div class="hist-icon" style="background:var(--${w._cls === 'on' ? 'green' : 'blue'}-dim);color:var(--${w._cls === 'on' ? 'green' : 'text3'})">${w._ic}</div>
            <div class="hist-body">
                <div class="hist-title">${w.message || w.check}</div>
                <div class="hist-detail">${w._act}${w.file ? ' \u2014 ' + w.file.split(/[\\/]/).pop() : ''}</div>
            </div>
            <span class="st st-${w._cls}">${w._act}</span>
            <span class="hist-time">${ago(w.fixed_at || w.ignored_at)}</span>
        </div>`).join('')}
    `;
}

// ═══ Glossary ════════════════════════════════

function pGlossary() {
    const el = $('p-glossary');
    const terms = Object.entries(S.glossary);
    el.innerHTML = `
        <div style="margin-bottom:16px"><input class="inp" placeholder="Search terms... (SSL, WAF, DNS)" oninput="filterGlos(this.value)" /></div>
        <div id="glosList">${terms.map(([k, g]) => `
        <div class="glos-card" data-t="${k.toLowerCase()}" onclick="this.querySelector('.glos-detail').classList.toggle('open')">
            <div class="glos-term">${g.term || k}</div>
            <div class="glos-simple">${g.simple}</div>
            <div class="glos-detail">
                <div class="glos-tech"><strong>Technical:</strong> ${g.technical}</div>
                <div class="glos-why"><strong>Why it matters:</strong> ${g.why_it_matters}</div>
            </div>
        </div>`).join('')}</div>
    `;
}

function filterGlos(q) {
    document.querySelectorAll('.glos-card').forEach(el => el.style.display = el.dataset.t.includes(q.toLowerCase()) ? '' : 'none');
}

async function showTerm(t) {
    const r = await API.call('explain_term', t);
    if (r.success) modal(r.data.term || t, r.data.explanation, [{ label: 'Got it', cls: 'btn-glow', fn: 'hideModal()' }]);
}

// ═══ Settings ═════════════════════════════════

async function pSettings() {
    const el = $('p-settings');
    let models = S.ollama.models || [];

    el.innerHTML = `
        <div class="set-group">
            <div class="set-label">Who is using Nimbus?</div>
            <div class="set-desc">Changes how explanations are written. Beginners get simple language. Technical users get detailed specs.</div>
            <div class="set-opts">
                <button class="set-opt ${S.audience === 'beginner' ? 'on' : ''}" onclick="setAud('beginner')">Beginner</button>
                <button class="set-opt ${S.audience === 'intermediate' ? 'on' : ''}" onclick="setAud('intermediate')">Intermediate</button>
                <button class="set-opt ${S.audience === 'technical' ? 'on' : ''}" onclick="setAud('technical')">Technical</button>
            </div>
        </div>

        <div class="set-group">
            <div class="set-label">Ollama AI Integration</div>
            <div class="set-desc">Connect to a local Ollama instance for AI-powered code analysis.</div>
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
                <div class="ai-dot ${S.ollama.available ? 'on' : ''}"></div>
                <span style="font-size:13px">${S.ollama.available ? `Connected \u2014 ${S.ollama.model}` : 'Not connected'}</span>
            </div>
            ${models.length > 0 ? `
            <div style="margin-top:10px">
                ${(() => { const { free, paid } = classifyModels(models); return `
                ${free.length > 0 ? `
                <div class="set-label" style="font-size:11px;color:var(--green);margin-bottom:6px">FREE MODELS</div>
                <div class="set-opts" style="margin-bottom:12px">
                    ${free.map(m => `<button class="set-opt ${S.ollama.model === m ? 'on' : ''}" onclick="pickModel('${m}')">${m.replace(/:latest$/, '')}${modelTag(m)}</button>`).join('')}
                </div>` : ''}
                ${paid.length > 0 ? `
                <div class="set-label" style="font-size:11px;color:var(--orange);margin-bottom:6px">PAID MODELS (Cloud)</div>
                <div class="set-opts">
                    ${paid.map(m => `<button class="set-opt ${S.ollama.model === m ? 'on' : ''}" onclick="pickModel('${m}')">${m.replace(/:latest$/, '')}${modelTag(m)}</button>`).join('')}
                </div>` : ''}
                `; })()}
            </div>` : `
            <p style="font-size:12px;color:var(--text3)">Install Ollama from <a href="https://ollama.ai" target="_blank" style="color:var(--blue)">ollama.ai</a> and run <code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px">ollama serve</code> to enable AI features.</p>`}
        </div>

        <div class="set-group">
            <div class="set-label">Always Ignored Checks</div>
            <div class="set-desc">These warning types are permanently hidden. Re-enable anytime.</div>
            ${S.alwaysIgnored.length === 0 ? '<p style="font-size:12px;color:var(--text3)">None ignored.</p>' : `
            <div style="display:flex;flex-wrap:wrap;gap:6px">
                ${S.alwaysIgnored.map(c => `<span style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;background:rgba(90,122,150,0.12);font-size:12px;color:var(--text3)">${c}<button style="background:none;border:none;color:var(--red);cursor:pointer;font-size:14px" onclick="unignore('${c}')">&times;</button></span>`).join('')}
            </div>`}
        </div>
    `;
}

async function setAud(a) { S.audience = a; await API.call('set_audience', a); pSettings(); toast(`Explanations set to ${a}`, 'info'); }
async function unignore(c) { await API.call('unignore_check', c); const r = await API.call('get_always_ignored'); if (r.success) S.alwaysIgnored = r.data; pSettings(); toast(`"${c}" warnings will show again`, 'info'); }
async function pickModel(m) { await API.call('ollama_set_model', m); S.ollama.model = m; S.ollama.available = true; $('ai-dot').className = 'ai-dot on'; $('ai-label').textContent = `AI: ${m}`; pSettings(); toast(`Using model: ${m}`, 'success'); }

// ═══ Data Loading (Parallel) ══════════════════

const LOAD_STEPS = [
    'Checking Cloudflare login',
    'Fetching Pages projects',
    'Fetching D1 databases',
    'Fetching KV namespaces',
    'Fetching R2 buckets',
    'Fetching secrets',
    'Running security scan',
    'Loading warning history',
    'Checking Ollama AI'
];

async function refresh() {
    if (!S.loggedIn) return;

    showLoading();
    setLoadingStep(LOAD_STEPS, 0);

    // Fire ALL API calls in parallel
    const promises = [
        API.call('list_pages'),
        API.call('list_d1'),
        API.call('list_kv'),
        API.call('list_r2'),
        API.call('list_secrets'),
        API.call('security_scan', S.scanPath || '.'),
        API.call('get_warning_history'),
        API.call('ollama_status'),
        API.call('get_always_ignored'),
        API.call('list_workers')
    ];

    setLoadingStep(LOAD_STEPS, 1);

    const results = await Promise.allSettled(promises);

    setLoadingStep(LOAD_STEPS, LOAD_STEPS.length);

    $('loadingText').textContent = 'All loaded!';
    setTimeout(() => hideLoading(), 200);

    const get = (r, fallback) => r.status === 'fulfilled' && r.value?.success ? (Array.isArray(r.value.data) ? r.value.data : r.value.data || fallback) : fallback;

    S.pages = get(results[0], []);
    S.d1 = get(results[1], []);
    S.kv = get(results[2], []);
    S.r2 = get(results[3], []);
    S.secrets = get(results[4], []);
    S.warnings = get(results[5], []);
    S.hist = get(results[6], { shown: [], ignored: [], fixed: [], stats: {} });

    if (results[7].status === 'fulfilled' && results[7].value?.success) {
        S.ollama.available = results[7].value.data.available;
        S.ollama.model = results[7].value.data.model;
        S.ollama.models = results[7].value.data.models || [];
        const aiDot = $('ai-dot');
        const aiLabel = $('ai-label');
        if (aiDot) aiDot.className = `ai-dot ${S.ollama.available ? 'on' : ''}`;
        if (aiLabel) aiLabel.textContent = S.ollama.available ? `AI: ${S.ollama.model}` : 'AI: offline';
    }

    S.alwaysIgnored = get(results[8], []);
    S.workers = get(results[9], []);

    badge();
    render();
}

function render() {
    ({ dashboard: pDashboard, warnings: pWarnings, services: pServices, history: pHist, glossary: pGlossary, settings: pSettings }[S.view] || pDashboard)();
}

// ═══ Login ════════════════════════════════════

function updateUI() {
    if (S.loggedIn) {
        const un = $('username'); if (un) un.textContent = S.account;
        const us = $('userstatus'); if (us) { us.textContent = 'Connected'; us.style.color = 'var(--green)'; }
        const av = $('avatar'); if (av) av.textContent = S.account.charAt(0).toUpperCase();
        const bl = $('btnLogin'); if (bl) bl.style.display = 'none';
        const blo = $('btnLogout'); if (blo) { blo.style.display = ''; blo.onclick = doLogout; }
        hideLoginScreen();
    } else {
        const un = $('username'); if (un) un.textContent = 'Not connected';
        const us = $('userstatus'); if (us) { us.textContent = 'Offline'; us.style.color = ''; }
        const av = $('avatar'); if (av) av.textContent = '?';
        const bl = $('btnLogin'); if (bl) { bl.style.display = ''; bl.onclick = doLogin; }
        const blo = $('btnLogout'); if (blo) blo.style.display = 'none';
    }
}

function doLogout() {
    S.loggedIn = false;
    S.account = '';
    S.workers = []; S.pages = []; S.kv = []; S.r2 = []; S.d1 = []; S.secrets = [];
    S.warnings = []; S.hist = { shown: [], ignored: [], fixed: [], stats: {} };
    updateUI();
    badge();
    showLoginScreen();
    toast('Logged out', 'info');
}

async function doLogin() {
    const btn = $('btnLoginMain') || $('btnLogin');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin" style="width:13px;height:13px;border-width:1.5px"></span> Opening browser...'; }

    const r = await API.call('login');

    if (btn) { btn.disabled = false; btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Connect Cloudflare'; }

    if (r.success) {
        if (r.data?.waiting) {
            toast('Complete login in your browser. Checking status...', 'info');
            pollLoginStatus();
        } else if (r.data?.account) {
            S.loggedIn = true;
            S.account = r.data.account;
            updateUI();
            toast(`Connected as ${S.account}!`, 'success');
            refresh();
        } else {
            toast('Login failed \u2014 try again', 'error');
        }
    } else {
        toast('Login failed: ' + (r.error || 'Unknown error'), 'error');
    }
}

let _loginPolls = 0;
function pollLoginStatus() {
    if (_loginPolls > 40) { _loginPolls = 0; toast('Login timed out. Try again.', 'error'); return; }
    _loginPolls++;
    setTimeout(async () => {
        const r = await API.call('check_login');
        if (r.success && r.data?.logged_in) {
            _loginPolls = 0;
            S.loggedIn = true;
            S.account = r.data.account || 'Unknown';
            updateUI();
            toast(`Connected as ${S.account}!`, 'success');
            refresh();
        } else {
            pollLoginStatus();
        }
    }, 3000);
}

// ═══ Init ═════════════════════════════════════

async function init() {
    API.init();

    document.querySelectorAll('.nav-link').forEach(el => {
        el.addEventListener('click', e => { e.preventDefault(); nav(el.dataset.view); });
    });

    const br = $('btnRefresh'); if (br) br.onclick = () => { if (S.loggedIn) { toast('Refreshing...', 'info'); refresh(); } };
    const bl = $('btnLogin'); if (bl) bl.onclick = doLogin;
    const blo = $('btnLogout'); if (blo) blo.onclick = doLogout;
    const mb = $('modalBg'); if (mb) mb.onclick = e => { if (e.target === e.currentTarget) hideModal(); };

    // Show loading immediately
    showLoading();
    setLoadingStep(['Checking Cloudflare login'], 0);

    // Check login
    const lr = await API.call('check_login');

    if (lr.success && lr.data?.logged_in) {
        S.loggedIn = true;
        S.account = lr.data.account || 'Unknown';
        updateUI();
        toast(`Connected as ${S.account}`, 'success');
        refresh();
    } else {
        // Not logged in — show login screen, no dashboard
        showLoginScreen();
    }

    // Load glossary in background
    API.call('get_glossary').then(gr => {
        if (gr.success) S.glossary = gr.data || {};
    }).catch(() => {});
}

if (window.pybridge) init(); else window._onBridgeReady = init;
