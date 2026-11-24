/* Classic Web Vulns Studio — client. No dependencies. */
'use strict';

const $ = (sel) => document.querySelector(sel);
const state = { modules: [], journal: [], writeups: [], selected: null, armed: {} };
let xssConfirmSent = false;

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 3500);
}

function showError(el, msg) {
  el.textContent = msg;
  el.hidden = false;
}
function hideError(el) { el.hidden = true; el.textContent = ''; }

async function api(path, method, body) {
  const opts = { method: method || 'GET', headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || ('Request failed (' + res.status + ')'));
    err.status = res.status;
    throw err;
  }
  return data;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ------------------------------------------------------------------ tabs --
function switchTab(name) {
  for (const n of ['modules', 'journal', 'portfolio']) {
    $('#tab-' + n).setAttribute('aria-selected', String(n === name));
    $('#panel-' + n).hidden = n !== name;
  }
  if (name === 'journal') renderJournal();
  if (name === 'portfolio') renderWriteups();
}
$('#tab-modules').addEventListener('click', () => switchTab('modules'));
$('#tab-journal').addEventListener('click', () => switchTab('journal'));
$('#tab-portfolio').addEventListener('click', () => switchTab('portfolio'));

// --------------------------------------------------------------- modules --
function statusBadge(p) {
  if (p.status === 'solved') return '<span class="badge solved">Solved</span>';
  if (p.status === 'in_progress') return '<span class="badge progress">In progress · stage ' + p.stage + '/5</span>';
  return '<span class="badge fresh">Not started</span>';
}

function renderModuleList() {
  $('#moduleList').innerHTML = state.modules.map((mod) => {
    const p = mod.progress;
    return '<button type="button" class="scenario-item' + (state.selected === mod.key ? ' active' : '') + '" data-key="' + esc(mod.key) + '">' +
      '<span class="sc-num">' + mod.num + '</span>' +
      '<span class="sc-main"><strong>' + esc(mod.title) + '</strong><small>' + esc(mod.level) + ' · ' + esc(mod.owasp) + '</small></span>' +
      statusBadge(p) + '</button>';
  }).join('');
  document.querySelectorAll('.scenario-item').forEach((el) => {
    el.addEventListener('click', () => selectModule(el.getAttribute('data-key')));
  });
}

function stageBar(mod) {
  const p = mod.progress;
  return '<ol class="stages">' + mod.stage_names.map((name, i) =>
    '<li class="' + (i < p.stage ? 'done' : i === p.stage ? 'current' : '') + '">' + esc(name) + '</li>'
  ).join('') + '</ol>';
}

function lessonCard(mod) {
  return '<div class="card lesson-card">' +
    '<h3>Lesson — root cause &amp; fix</h3>' +
    '<p><strong>Root cause:</strong> ' + esc(mod.root_cause) + '</p>' +
    '<p><strong>Fix:</strong> ' + esc(mod.fix) + '</p>' +
    '</div>';
}

function workbenchHtml(mod) {
  if (mod.workbench === 'search') {
    return '<div class="card workbench"><h3>Shop search — <code>' + esc(mod.endpoint) + '</code></h3>' +
      '<form id="searchForm" class="chat-form"><input id="searchInput" maxlength="500" required autocomplete="off" placeholder="Search the catalog…" aria-label="Product search"><button type="submit">Search</button></form>' +
      '<div id="searchOut" class="workbench-out"><p class="empty-note">No search yet.</p></div></div>';
  }
  if (mod.workbench === 'reviews') {
    return '<div class="card workbench"><h3>Product page — Trail Boots reviews</h3>' +
      '<p class="hint-text">Reviews render below exactly as stored. Marker flag: <span id="flagState">not set</span></p>' +
      '<div id="reviewList"></div>' +
      '<form id="reviewForm"><div class="field"><label for="reviewAuthor">Name</label><input id="reviewAuthor" maxlength="60" required value="tester"></div>' +
      '<div class="field"><label for="reviewText">Review</label><textarea id="reviewText" rows="2" maxlength="2000" required placeholder="Write a review…"></textarea></div>' +
      '<button type="submit">Post review</button></form>' +
      '<p class="form-error" id="reviewError" role="alert" hidden></p></div>';
  }
  if (mod.workbench === 'ssrf') {
    return '<div class="card workbench"><h3>Image fetch — <code>' + esc(mod.endpoint) + '</code></h3>' +
      '<form id="fetchForm" class="chat-form"><input id="fetchInput" maxlength="500" required autocomplete="off" placeholder="/internal/status or a full URL…" aria-label="URL to fetch"><button type="submit">Fetch</button></form>' +
      '<div id="fetchOut" class="workbench-out"><p class="empty-note">Nothing fetched yet.</p></div></div>';
  }
  if (mod.workbench === 'csrf') {
    return '<div class="card workbench"><h3>Account — ambient session</h3>' +
      '<p>Current account email: <strong id="accountEmail">…</strong></p>' +
      '<form id="emailForm" class="chat-form"><input id="emailInput" maxlength="120" required autocomplete="off" placeholder="new email address" aria-label="New email"><button type="submit">Change email via GET link</button></form>' +
      '<p class="hint-text">This issues the same GET request a link would — no form, no anti-forgery check.</p>' +
      '<div class="field"><label for="victimEmail">Victim-simulation target email</label><input id="victimEmail" maxlength="120" value="victim-target@example.com"></div>' +
      '<button type="button" id="victimBtn2">Run victim simulation</button>' +
      '<p class="form-error" id="csrfError" role="alert" hidden></p></div>';
  }
  return '';
}

function renderDetail() {
  const mod = state.modules.find((m) => m.key === state.selected);
  if (!mod) {
    $('#moduleDetail').innerHTML = '<p class="empty-note">Select a module to begin.</p>';
    return;
  }
  const p = mod.progress;
  const solved = p.status === 'solved';
  $('#moduleDetail').innerHTML =
    '<article class="card detail-card">' +
    '<h2>' + mod.num + '. ' + esc(mod.title) + '</h2>' +
    '<p class="meta">' + esc(mod.level) + ' · ' + esc(mod.owasp) + ' · ' + esc(mod.source) + '</p>' +
    '<p><strong>Objective:</strong> ' + esc(mod.objective) + '</p>' +
    '<p>' + esc(mod.briefing) + '</p>' +
    stageBar(mod) +
    '<p class="meta">Attempts: ' + p.attempts + ' · Hints used: ' + p.hints_used + (solved && p.solved_at ? ' · Solved: ' + esc(p.solved_at.slice(0, 10)) : '') + '</p>' +
    (p.evidence ? '<p class="meta">Evidence: ' + esc(p.evidence) + '</p>' : '') +
    '<div class="detail-actions">' +
      '<button type="button" id="hintBtn">Hint</button>' +
      (solved ? '<button type="button" id="genWriteupBtn">Generate writeup</button>' : '') +
      '<button type="button" class="danger" id="resetBtn">Reset module</button>' +
    '</div>' +
    '<p class="form-error" id="detailError" role="alert" hidden></p>' +
    '</article>' +
    workbenchHtml(mod) +
    lessonCard(mod);

  bindWorkbench(mod);
  $('#hintBtn').addEventListener('click', onHint);
  const gw = $('#genWriteupBtn');
  if (gw) gw.addEventListener('click', onGenerateWriteup);
  $('#resetBtn').addEventListener('click', onReset);
}

function updateProgress(p) {
  const mod = state.modules.find((m) => m.key === p.module_key);
  if (mod) mod.progress = p;
}

async function selectModule(key) {
  state.selected = key;
  renderModuleList();
  renderDetail();
  const mod = state.modules.find((m) => m.key === key);
  if (mod && mod.workbench === 'reviews') loadReviews();
  if (mod && mod.workbench === 'csrf') loadAccount();
}

async function onHint() {
  hideError($('#detailError'));
  try {
    const data = await api('/api/hint', 'POST', { module_key: state.selected });
    toast('Hint (' + data.hints_used + ' used): ' + data.hint);
    updateProgress(data.progress);
    renderModuleList();
    renderDetail();
  } catch (e) {
    showError($('#detailError'), e.message);
  }
}

async function onGenerateWriteup() {
  hideError($('#detailError'));
  try {
    const data = await api('/api/writeups/generate', 'POST', { module_key: state.selected });
    state.writeups.unshift(data.writeup);
    renderWriteupCounts();
    toast('Writeup generated: ' + data.writeup.title);
    switchTab('portfolio');
  } catch (e) {
    showError($('#detailError'), e.message);
  }
}

// Two-step confirm: first click arms the button for 4 seconds, second confirms.
function armConfirm(btn, actionLabel, fn) {
  const key = btn.id;
  if (state.armed[key]) {
    clearTimeout(state.armed[key].timer);
    delete state.armed[key];
    btn.textContent = btn.dataset.label;
    fn();
    return;
  }
  btn.dataset.label = btn.textContent;
  btn.textContent = 'Click again to confirm: ' + actionLabel;
  btn.classList.add('armed');
  state.armed[key] = { timer: setTimeout(() => {
    delete state.armed[key];
    btn.textContent = btn.dataset.label;
    btn.classList.remove('armed');
  }, 4000) };
}

async function onReset(ev) {
  const btn = ev.currentTarget;
  armConfirm(btn, 'reset this module', async () => {
    hideError($('#detailError'));
    try {
      const data = await api('/api/reset', 'POST', { module_key: state.selected });
      updateProgress(data.progress);
      renderModuleList();
      renderDetail();
      const mod = state.modules.find((m) => m.key === state.selected);
      if (mod && mod.workbench === 'reviews') loadReviews();
      if (mod && mod.workbench === 'csrf') loadAccount();
      toast('Module reset — fresh run.');
    } catch (e) {
      showError($('#detailError'), e.message);
    }
  });
}

// ------------------------------------------------------------- workbench --
function bindWorkbench(mod) {
  if (mod.workbench === 'search') {
    $('#searchForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const q = $('#searchInput').value;
      try {
        const data = await api('/api/shop/search?q=' + encodeURIComponent(q));
        updateProgress(data.progress);
        renderModuleList();
        $('#searchOut').innerHTML = '<table class="results"><thead><tr><th>#</th><th>Name</th><th>Detail</th></tr></thead><tbody>' +
          data.rows.map((r) => '<tr><td>' + esc(r.id) + '</td><td>' + esc(r.name) + '</td><td>' + esc(r.detail) + '</td></tr>').join('') +
          '</tbody></table>' + (data.leaked_users ? '<p class="ok">Users table returned — objective complete.</p>' : '');
        renderDetailHeadline();
      } catch (e) {
        $('#searchOut').innerHTML = '<p class="form-error">' + esc(e.message) + '</p>';
      }
    });
  }
  if (mod.workbench === 'reviews') {
    $('#reviewForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      hideError($('#reviewError'));
      try {
        const data = await api('/api/shop/reviews', 'POST', {
          product: 'trail-boots',
          author: $('#reviewAuthor').value.trim(),
          text: $('#reviewText').value,
        });
        updateProgress(data.progress);
        renderModuleList();
        $('#reviewText').value = '';
        loadReviews();
      } catch (e) {
        showError($('#reviewError'), e.message);
      }
    });
  }
  if (mod.workbench === 'ssrf') {
    $('#fetchForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const u = $('#fetchInput').value;
      try {
        const data = await api('/api/shop/fetch-image?url=' + encodeURIComponent(u));
        updateProgress(data.progress);
        renderModuleList();
        $('#fetchOut').innerHTML = '<pre class="workbench-pre">' + esc(JSON.stringify(data.body || data, null, 2)) + '</pre>';
        renderDetailHeadline();
      } catch (e) {
        $('#fetchOut').innerHTML = '<p class="form-error">' + esc(e.message) + '</p>';
        refreshState();
      }
    });
  }
  if (mod.workbench === 'csrf') {
    $('#emailForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      hideError($('#csrfError'));
      try {
        const data = await api('/api/shop/account/change-email?email=' + encodeURIComponent($('#emailInput').value.trim()));
        updateProgress(data.progress);
        renderModuleList();
        $('#accountEmail').textContent = data.account.email;
        toast('Email changed via GET — objective complete.');
        renderDetailHeadline();
      } catch (e) {
        showError($('#csrfError'), e.message);
      }
    });
    $('#victimBtn2').addEventListener('click', async () => {
      hideError($('#csrfError'));
      try {
        const data = await api('/api/victim', 'POST', { module_key: 'csrf', email: $('#victimEmail').value.trim() });
        updateProgress(data.progress);
        renderModuleList();
        $('#accountEmail').textContent = data.account.email;
        toast(data.replies[data.replies.length - 1].text);
        renderDetailHeadline();
      } catch (e) {
        showError($('#csrfError'), e.message);
      }
    });
  }
}

// Re-render the detail header (stage bar / solved state) without losing
// workbench output: simplest correct approach is a full state refresh.
async function refreshState() {
  try {
    const data = await api('/api/state');
    state.modules = data.modules;
    state.journal = data.journal;
    state.writeups = data.writeups;
    renderModuleList();
  } catch (e) { /* keep current view on failure */ }
}

function renderDetailHeadline() {
  refreshState().then(() => {
    const mod = state.modules.find((m) => m.key === state.selected);
    if (!mod) return;
    const detail = $('#moduleDetail');
    if (!detail) return;
    // Re-render only if the module just solved (stage bar / buttons change).
    if (mod.progress.status === 'solved') renderDetail();
  });
}

async function loadReviews() {
  const list = $('#reviewList');
  if (!list) return;
  try {
    const data = await api('/api/shop/reviews?product=trail-boots');
    xssConfirmSent = false;
    // DELIBERATE FLAW (training): review text is inserted as live markup,
    // exactly as the vulnerable page would. This is the stored-XSS module.
    list.innerHTML = data.reviews.map((r) =>
      '<article class="review"><header><strong>' + esc(r.author) + '</strong> <span class="meta">' + esc(r.created_at.slice(0, 10)) + '</span></header>' +
      '<div class="review-text">' + r.text + '</div></article>'
    ).join('');
    if (window.__xssFlag === 'PRACTICE-MARKER') {
      const flagEl = $('#flagState');
      if (flagEl) flagEl.textContent = 'SET — practice flag executed';
      const mod = state.modules.find((m) => m.key === 'stored-xss');
      if (mod && mod.progress.status !== 'solved' && !xssConfirmSent) {
        xssConfirmSent = true;
        try {
          const data2 = await api('/api/xss/confirm', 'POST', { marker: 'PRACTICE-MARKER' });
          updateProgress(data2.progress);
          renderModuleList();
          toast('Marker executed — objective complete.');
          window.__xssFlag = undefined;
          renderDetail();
        } catch (e) { /* flag set but no stored marker: leave for manual review */ }
      }
    }
  } catch (e) {
    list.innerHTML = '<p class="form-error">' + esc(e.message) + '</p>';
  }
}

async function loadAccount() {
  const el = $('#accountEmail');
  if (!el) return;
  try {
    const data = await api('/api/shop/account');
    el.textContent = data.account.email;
  } catch (e) {
    el.textContent = 'could not load';
  }
}

// --------------------------------------------------------------- journal --
function renderJournal() {
  const list = $('#journalList');
  if (state.journal.length === 0) {
    list.innerHTML = '<p class="empty-note">No journal entries yet. Log your first request above.</p>';
    return;
  }
  list.innerHTML = state.journal.map((e) =>
    '<article class="card entry">' +
    '<header><strong>Entry ' + e.id + '</strong>' + (e.module_key ? ' · <span>' + esc(e.module_key) + '</span>' : '') +
    ' · <span class="result-' + esc(e.result) + '">' + esc(e.result) + '</span>' +
    '<span class="entry-date">' + esc(e.created_at.slice(0, 10)) + '</span></header>' +
    '<p class="prompt-text">“' + esc(e.prompt) + '”</p>' +
    '<p class="meta">Intent: ' + esc(e.intent) + ' · Technique: ' + esc(e.technique) + ' · Evasion: ' + esc(e.evasion) + ' · Channel: ' + esc(e.input_channel) + '</p>' +
    (e.notes ? '<p>' + esc(e.notes) + '</p>' : '') +
    '<div class="entry-actions"><button type="button" class="danger small" data-del-journal="' + e.id + '">Delete entry</button></div>' +
    '</article>'
  ).join('');
  list.querySelectorAll('[data-del-journal]').forEach((btn) => {
    btn.addEventListener('click', (ev) => {
      const id = Number(btn.getAttribute('data-del-journal'));
      armConfirm(ev.currentTarget, 'delete this entry', async () => {
        try {
          await api('/api/journal/' + id, 'DELETE');
          state.journal = state.journal.filter((x) => x.id !== id);
          renderJournal();
          renderWriteupCounts();
          toast('Journal entry deleted.');
        } catch (e) { toast('Delete failed: ' + e.message); }
      });
    });
  });
}

$('#journalForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  hideError($('#journalError'));
  const entry = {
    prompt: $('#jPrompt').value.trim(),
    intent: $('#jIntent').value.trim(),
    technique: $('#jTechnique').value.trim(),
    evasion: $('#jEvasion').value.trim() || undefined,
    input_channel: $('#jChannel').value.trim() || undefined,
    module_key: $('#jModule').value || null,
    result: $('#jResult').value,
    notes: $('#jNotes').value.trim() || undefined,
  };
  try {
    const data = await api('/api/journal', 'POST', entry);
    state.journal.unshift(data.entry);
    ev.target.reset();
    renderJournal();
    renderWriteupCounts();
    toast('Journal entry added.');
  } catch (e) {
    showError($('#journalError'), e.message);
  }
});

// ------------------------------------------------------------- portfolio --
function renderWriteups() {
  const list = $('#writeupList');
  if (state.writeups.length === 0) {
    list.innerHTML = '<p class="empty-note">No writeups yet. Solve a module and generate one, or write one by hand above.</p>';
    return;
  }
  list.innerHTML = state.writeups.map((w) =>
    '<article class="card entry">' +
    '<header><strong>' + esc(w.title) + '</strong> · <span>' + esc(w.status) + '</span>' +
    '<span class="entry-date">' + esc(w.created_at.slice(0, 10)) + '</span></header>' +
    (w.owasp ? '<p class="meta">' + esc(w.owasp) + '</p>' : '') +
    '<pre class="writeup-body">' + esc(w.body) + '</pre>' +
    '<div class="entry-actions"><button type="button" class="danger small" data-del-writeup="' + w.id + '">Delete writeup</button></div>' +
    '</article>'
  ).join('');
  list.querySelectorAll('[data-del-writeup]').forEach((btn) => {
    btn.addEventListener('click', (ev) => {
      const id = Number(btn.getAttribute('data-del-writeup'));
      armConfirm(ev.currentTarget, 'delete this writeup', async () => {
        try {
          await api('/api/writeups/' + id, 'DELETE');
          state.writeups = state.writeups.filter((x) => x.id !== id);
          renderWriteups();
          renderWriteupCounts();
          toast('Writeup deleted.');
        } catch (e) { toast('Delete failed: ' + e.message); }
      });
    });
  });
}

$('#writeupForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  hideError($('#writeupError'));
  try {
    const data = await api('/api/writeups', 'POST', {
      title: $('#wTitle').value.trim(),
      owasp: $('#wOwasp').value.trim(),
      body: $('#wBody').value,
    });
    state.writeups.unshift(data.writeup);
    ev.target.reset();
    renderWriteups();
    renderWriteupCounts();
    toast('Writeup created.');
  } catch (e) {
    showError($('#writeupError'), e.message);
  }
});

// --------------------------------------------------------------- export --
$('#exportBtn').addEventListener('click', async () => {
  try {
    const data = await api('/api/export');
    const stamp = data.generated_at.slice(0, 10);
    const blob = new Blob([data.markdown], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'web-vuln-studio-training-record-' + stamp + '.md';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast('Training record exported as Markdown.');
  } catch (e) {
    toast('Export failed: ' + e.message);
  }
});

function renderWriteupCounts() {
  $('#journalCount').textContent = state.journal.length ? '(' + state.journal.length + ')' : '';
  $('#writeupCount').textContent = state.writeups.length ? '(' + state.writeups.length + ')' : '';
}

// ------------------------------------------------------------------ init --
(async function init() {
  try {
    const data = await api('/api/state');
    state.modules = data.modules;
    state.journal = data.journal;
    state.writeups = data.writeups;
    const sel = $('#jModule');
    for (const mod of state.modules) {
      const opt = document.createElement('option');
      opt.value = mod.key;
      opt.textContent = mod.num + '. ' + mod.title;
      sel.appendChild(opt);
    }
    renderModuleList();
    renderWriteupCounts();
    $('#saveState').textContent = 'Progress saved on this server';
  } catch (e) {
    document.querySelector('main').innerHTML = '<p class="empty-note">Could not load the studio: ' + esc(e.message) + '</p>';
  }
})();
