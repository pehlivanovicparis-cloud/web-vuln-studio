// Classic Web Vulns Studio — standalone server (Node.js standard library only).
// Serves public/ and a JSON API. State lives in data/data.json, seeded from
// data/seed.json on first run. All mutations are serialized through one queue
// and committed with an atomic write (tmp file + rename).
//
// TRAINING SAFETY: every flaw here is modeled against fictional in-memory
// data. The SQL evaluator is a naive string matcher over fake tables (no real
// database). The image fetcher dispatches in-process to mock internal
// handlers and never opens a network socket. Reviews render unescaped on
// purpose, and the only marker the app honors is a local flag-setter with no
// network behavior. No real secrets, credentials, or outbound calls exist in
// this app (the only network client is the KV store in lib/store.js).
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const SEED_PATH = path.join(DATA_DIR, 'seed.json');
const DATA_PATH = path.join(DATA_DIR, 'data.json');
const PUBLIC_DIR = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT || 3000);

const MODULE_KEYS = ['sqli', 'stored-xss', 'ssrf', 'csrf'];
const JOURNAL_RESULTS = ['worked', 'blocked', 'partial', 'untested'];
const WRITEUP_EXISTS_MESSAGE =
  'A writeup for this module already exists — open it in the list below instead of generating a duplicate.';

// ---------------------------------------------------------------- state ----

// Store: file-backed locally (data/data.json, created from seed on first
// run — identical to the original behaviour), Vercel KV-backed when
// KV_REST_API_URL + KV_REST_API_TOKEN are set. See lib/store.js.
const { createStore } = require('./lib/store');
const store = createStore({
  key: 'web-vuln-studio:state',
  seedPath: SEED_PATH,
  dataPath: DATA_PATH,
});

// In-memory state. File mode: loaded once, like the original server.
// KV mode: reloaded fresh from KV on every request (a serverless
// invocation must never trust a warm in-memory copy).
let state = null;

async function ensureState() {
  if (state === null || store.useKv) state = await store.load();
  return state;
}

// Same save semantics as before: every mutation commits.
async function saveState(s) {
  await store.save(s);
}

// Serialize every mutation so concurrent requests cannot interleave writes.
// Each mutator runs against the single in-memory state, then commits atomically.
let writeQueue = Promise.resolve();
function mutate(fn) {
  const run = writeQueue.then(async () => {
    const result = fn(state);
    await saveState(state);
    return result;
  });
  // Keep the queue alive even if one mutation throws.
  writeQueue = run.catch(() => {});
  return run;
}

function moduleDef(key) {
  return state.modules.find((m) => m.key === key) || null;
}

function progress(key) {
  return state.progress[key];
}

// Monotonic stage advance + sticky solved state. Never decreases, never un-solves.
function advance(key, targetStage) {
  const p = progress(key);
  if (targetStage > p.stage) p.stage = targetStage;
  if (p.status === 'not_started') p.status = 'in_progress';
}

function solve(key, evidence) {
  const p = progress(key);
  p.stage = 5;
  if (!p.solved_at) p.solved_at = new Date().toISOString();
  if (evidence) p.evidence = evidence;
  p.status = 'solved';
}

function publicProgress(key) {
  const p = progress(key);
  return {
    module_key: p.module_key,
    status: p.status,
    stage: p.stage,
    attempts: p.attempts,
    hints_used: p.hints_used,
    solved_at: p.solved_at,
    evidence: p.evidence || null,
  };
}

// ------------------------------------------------------- fictional data ----
// Fake in-memory tables. Invented accounts, invented products, no real data.

const PRODUCTS = [
  { id: 1, name: 'Trail Boots', price: 89, blurb: 'Waterproof hiking boots, great grip.' },
  { id: 2, name: 'River Jacket', price: 129, blurb: 'Light rain shell, packs small.' },
  { id: 3, name: 'Summit Pack', price: 149, blurb: '45L pack with rain cover.' },
  { id: 4, name: 'Camp Mug', price: 19, blurb: 'Enamel mug, 350ml.' },
  { id: 5, name: 'Trail Socks', price: 12, blurb: 'Merino blend, 3-pack.' },
];

const USERS = [
  { id: 1, username: 'carlos', email: 'carlos@example.com', role: 'customer' },
  { id: 2, username: 'maria', email: 'maria@example.com', role: 'staff' },
  { id: 3, username: 'jun', email: 'jun@example.com', role: 'customer' },
];

// Deliberately naive query evaluator: the modeled flaw. It treats the raw
// input as query syntax — a tautology returns everything, and a UNION-shaped
// input returns rows from the fake users table. There is no real database.
function runMockQuery(input) {
  const raw = String(input || '');
  const lower = raw.toLowerCase();
  if (lower.includes('union') && lower.includes('select')) {
    if (lower.includes('users')) {
      return {
        kind: 'union-users',
        leaked_users: true,
        rows: USERS.map((u) => ({ kind: 'user', id: u.id, name: u.username, detail: u.email + ' · ' + u.role })),
      };
    }
    return { kind: 'union-other', leaked_users: false, rows: [] };
  }
  if (/or\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i.test(raw)) {
    return {
      kind: 'tautology',
      leaked_users: false,
      rows: PRODUCTS.map((p) => ({ kind: 'product', id: p.id, name: p.name, detail: '$' + p.price + ' · ' + p.blurb })),
    };
  }
  const needle = raw.replace(/[%_]/g, '').trim().toLowerCase();
  const matched = needle
    ? PRODUCTS.filter((p) => p.name.toLowerCase().includes(needle))
    : PRODUCTS.slice();
  return {
    kind: 'lookup',
    leaked_users: false,
    rows: matched.map((p) => ({ kind: 'product', id: p.id, name: p.name, detail: '$' + p.price + ' · ' + p.blurb })),
  };
}

// ------------------------------------------------- mock internal routes ----
// Fake instance metadata. These handlers run in-process only; the fetcher
// below dispatches to them by pathname and never opens a socket.

function internalStatus() {
  return {
    instance: 'mock-internal-01',
    region: 'fictional-east-1',
    service: 'mock-shop',
    uptime_seconds: 4242,
    practice_only: true,
  };
}

function internalConfig() {
  return {
    service: 'mock-shop',
    feature_flags: { reviews: true, image_fetch: true },
    practice_only: true,
  };
}

const INTERNAL_ROUTES = {
  '/internal/status': internalStatus,
  '/internal/config': internalConfig,
};

// The XSS marker: the only flag the app honors. A review carrying this exact
// flag-setter, rendered by the page, proves stored execution with no network
// behavior of any kind.
const XSS_FLAG_SNIPPET = "window.__xssFlag='PRACTICE-MARKER'";
const XSS_MARKER = 'PRACTICE-MARKER';

// ------------------------------------------------------------ writeups ----

function buildWriteupBody(mod, prog) {
  const lines = [];
  lines.push('Source: ' + mod.source + ' (Classic Web Vulns Studio — contained mock)');
  lines.push('Classification: ' + mod.owasp);
  lines.push('Result: objective completed in ' + prog.attempts + ' attempt(s), ' + prog.hints_used + ' hint(s) used.');
  lines.push('');
  lines.push('OBJECTIVE');
  lines.push(mod.objective);
  lines.push('');
  lines.push('ENDPOINT');
  lines.push(mod.endpoint);
  lines.push('');
  lines.push('EVIDENCE');
  lines.push(prog.evidence || 'Objective completed in the trainer.');
  lines.push('');
  lines.push('ROOT CAUSE');
  lines.push(mod.root_cause);
  lines.push('');
  lines.push('FIX');
  lines.push(mod.fix);
  lines.push('');
  lines.push('ETHICS NOTE');
  lines.push('Performed in an authorized, intentionally vulnerable training simulation with fictional data. Do not use these techniques against production systems or any system without explicit written authorization.');
  return lines.join('\n');
}

function buildExportMarkdown() {
  const now = new Date().toISOString();
  const lines = [];
  lines.push('# Classic Web Vulns Studio — Training Record');
  lines.push('Generated: ' + now);
  lines.push('');
  lines.push('Authorized practice only — fictional shop, fictional data.');
  lines.push('');
  lines.push('## Modules');
  lines.push('');
  lines.push('| # | Module | Level | Status | Stage | Attempts | Hints used | Solved |');
  lines.push('|---|---|---|---|---|---|---|---|');
  for (const mod of state.modules) {
    const p = state.progress[mod.key];
    lines.push('| ' + mod.num + ' | ' + mod.title + ' | ' + mod.level + ' | ' + p.status + ' | ' + p.stage + ' / 5 | ' + p.attempts + ' | ' + p.hints_used + ' | ' + (p.solved_at || '—') + ' |');
  }
  lines.push('');
  lines.push('## Prompt Journal');
  lines.push('');
  if (state.journal.length === 0) {
    lines.push('No journal entries yet.');
  } else {
    for (const e of state.journal) {
      lines.push('### Entry ' + e.id + (e.module_key ? ' — ' + e.module_key : ''));
      lines.push('Prompt: ' + e.prompt);
      lines.push('Intent: ' + e.intent + ' · Technique: ' + e.technique + ' · Evasion: ' + e.evasion + ' · Channel: ' + e.input_channel + ' · Result: ' + e.result);
      if (e.notes) lines.push('Notes: ' + e.notes);
      lines.push('Logged: ' + e.created_at);
      lines.push('');
    }
  }
  lines.push('');
  lines.push('## Portfolio Writeups');
  lines.push('');
  if (state.writeups.length === 0) {
    lines.push('No writeups yet.');
  } else {
    for (const w of state.writeups) {
      lines.push('### ' + w.title);
      lines.push('');
      lines.push(w.body);
      lines.push('');
    }
  }
  return { generated_at: now, markdown: lines.join('\n') };
}

// -------------------------------------------------------------- http ----

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function sendError(res, status, message) {
  sendJson(res, status, { ok: false, error: message });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function validateModuleKey(key) {
  return typeof key === 'string' && MODULE_KEYS.includes(key);
}

function requireString(v, max) {
  return typeof v === 'string' && v.trim().length > 0 && v.length <= max;
}

function publicModule(mod) {
  return {
    key: mod.key, num: mod.num, title: mod.title, level: mod.level,
    source: mod.source, owasp: mod.owasp, objective: mod.objective,
    briefing: mod.briefing, endpoint: mod.endpoint, workbench: mod.workbench,
    has_victim_sim: mod.has_victim_sim, hints: mod.hints,
    stage_names: mod.stage_names, root_cause: mod.root_cause, fix: mod.fix,
    progress: publicProgress(mod.key),
  };
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// The request handler is exported so Vercel can run it serverless
// (api/index.js). `node server.js` still starts the standalone server.
async function handler(req, res) {
  try {
    await ensureState();
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;

    // ---- Mock internal route (direct) ------------------------------------
    // Fake metadata only. The same handler is reachable through the
    // image-fetch feature below — that reachability is the modeled flaw.
    if (req.method === 'GET' && pathname === '/internal/status') {
      return sendJson(res, 200, { ok: true, ...internalStatus() });
    }

    // ---- API ------------------------------------------------------------
    if (pathname.startsWith('/api/')) {
      // Read-only endpoints.
      if (req.method === 'GET' && pathname === '/api/state') {
        return sendJson(res, 200, {
          ok: true,
          modules: state.modules.map(publicModule),
          journal: state.journal,
          writeups: state.writeups,
        });
      }
      if (req.method === 'GET' && pathname === '/api/modules') {
        return sendJson(res, 200, { ok: true, modules: state.modules.map(publicModule) });
      }
      if (req.method === 'GET' && pathname === '/api/journal') {
        return sendJson(res, 200, { ok: true, entries: state.journal });
      }
      if (req.method === 'GET' && pathname === '/api/writeups') {
        return sendJson(res, 200, { ok: true, writeups: state.writeups });
      }
      if (req.method === 'GET' && pathname === '/api/export') {
        const report = buildExportMarkdown();
        return sendJson(res, 200, { ok: true, ...report });
      }

      // ---- Shop: product search (modeled SQLi) ---------------------------
      if (req.method === 'GET' && pathname === '/api/shop/search') {
        const q = url.searchParams.get('q') || '';
        const result = runMockQuery(q);
        await mutate(() => {
          const p = progress('sqli');
          p.attempts += 1;
          if (p.status !== 'solved') {
            if (result.kind === 'union-users') {
              solve('sqli', 'UNION query returned the fake users table (3 rows).');
            } else if (result.kind === 'union-other') {
              advance('sqli', 4);
            } else if (result.kind === 'tautology') {
              advance('sqli', 3);
            } else {
              advance('sqli', 1);
            }
          }
          return null;
        });
        return sendJson(res, 200, {
          ok: true,
          query_echo: q,
          kind: result.kind,
          rows: result.rows,
          leaked_users: result.leaked_users,
          progress: publicProgress('sqli'),
        });
      }

      // ---- Shop: reviews (modeled stored XSS) ---------------------------
      if (pathname === '/api/shop/reviews') {
        if (req.method === 'GET') {
          const product = url.searchParams.get('product') || 'trail-boots';
          const reviews = state.reviews.filter((r) => r.product === product);
          return sendJson(res, 200, { ok: true, product, reviews });
        }
        if (req.method === 'POST') {
          let body;
          try {
            body = await readBody(req);
          } catch (e) {
            return sendError(res, 400, e.message);
          }
          if (!requireString(body.product, 60)) return sendError(res, 400, 'product is required (1–60 characters).');
          if (!requireString(body.author, 60)) return sendError(res, 400, 'author is required (1–60 characters).');
          if (!requireString(body.text, 2000)) return sendError(res, 400, 'text is required (1–2000 characters).');
          const review = await mutate(() => {
            const p = progress('stored-xss');
            p.attempts += 1;
            if (p.status !== 'solved') {
              if (body.text.includes('<script') || body.text.includes('onerror')) advance('stored-xss', 3);
              else advance('stored-xss', 1);
            }
            const now = new Date().toISOString();
            const r = {
              id: state.next_review_id++,
              product: body.product,
              author: body.author,
              text: body.text,
              created_at: now,
            };
            state.reviews.push(r);
            return r;
          });
          return sendJson(res, 201, { ok: true, review, progress: publicProgress('stored-xss') });
        }
      }

      // ---- XSS flag confirmation ------------------------------------------
      if (req.method === 'POST' && pathname === '/api/xss/confirm') {
        let body;
        try {
          body = await readBody(req);
        } catch (e) {
          return sendError(res, 400, e.message);
        }
        if (body.marker !== XSS_MARKER) return sendError(res, 400, 'Unknown marker.');
        const confirmed = await mutate(() => {
          const stored = state.reviews.some((r) => r.text.includes(XSS_FLAG_SNIPPET));
          if (!stored) return false;
          const p = progress('stored-xss');
          if (p.status !== 'solved') {
            solve('stored-xss', 'Stored review carried the practice flag; the page rendered it and the flag was detected.');
          }
          return true;
        });
        if (!confirmed) return sendError(res, 400, 'No stored review carries the practice flag yet.');
        return sendJson(res, 200, { ok: true, solved: true, progress: publicProgress('stored-xss') });
      }

      // ---- Shop: image-fetch feature (modeled SSRF, contained in-process) --------
      // CONTAINMENT: this handler never opens a network socket. It parses
      // the supplied value as a URL, takes only its pathname, and dispatches
      // in-process to a hardcoded map of mock internal handlers. Arbitrary
      // external addresses can never be fetched — there is no fetch call,
      // no http client, and no socket anywhere in this path.
      if (req.method === 'GET' && pathname === '/api/shop/fetch-image') {
        const rawUrl = url.searchParams.get('url') || '';
        let pathnameOfUrl = null;
        try {
          pathnameOfUrl = new URL(rawUrl, 'http://mock-internal/').pathname;
        } catch (e) {
          return sendError(res, 400, 'Unparseable URL.');
        }
        const handled = await mutate(() => {
          const p = progress('ssrf');
          p.attempts += 1;
          if (p.status !== 'solved') {
            if (pathnameOfUrl === '/internal/status') {
              solve('ssrf', 'Image-fetch parameter resolved to the mock internal status route.');
            } else if (INTERNAL_ROUTES[pathnameOfUrl]) {
              advance('ssrf', 3);
            } else {
              advance('ssrf', 1);
            }
          }
          return null;
        });
        void handled;
        const fn = INTERNAL_ROUTES[pathnameOfUrl];
        if (!fn) {
          return sendJson(res, 404, { ok: false, error: 'Mock upstream: 404 — no such internal route.', progress: publicProgress('ssrf') });
        }
        return sendJson(res, 200, { ok: true, resolved_path: pathnameOfUrl, body: fn(), progress: publicProgress('ssrf') });
      }

      // ---- Shop: account (modeled CSRF) -----------------------------------
      if (req.method === 'GET' && pathname === '/api/shop/account') {
        return sendJson(res, 200, { ok: true, account: state.account });
      }

      // State-changing GET with no anti-forgery check — the modeled flaw.
      if (req.method === 'GET' && pathname === '/api/shop/account/change-email') {
        const email = url.searchParams.get('email') || '';
        if (!requireString(email, 120) || !email.includes('@')) {
          return sendError(res, 400, 'email is required and must contain @ (max 120 characters).');
        }
        const account = await mutate(() => {
          const p = progress('csrf');
          p.attempts += 1;
          state.account.email = email;
          if (p.status !== 'solved') {
            solve('csrf', 'Account email changed via a single GET request with no anti-forgery check.');
          }
          return state.account;
        });
        return sendJson(res, 200, { ok: true, account, progress: publicProgress('csrf') });
      }

      // Mutating endpoints below — JSON body required.
      let body;
      try {
        body = await readBody(req);
      } catch (e) {
        return sendError(res, 400, e.message);
      }

      if (req.method === 'POST' && pathname === '/api/hint') {
        const key = body.module_key;
        if (!validateModuleKey(key)) return sendError(res, 400, 'Unknown module_key.');
        const result = await mutate(() => {
          const mod = moduleDef(key);
          const p = progress(key);
          const idx = Math.min(p.stage, mod.hints.length - 1);
          p.hints_used += 1;
          return { hint: mod.hints[idx], hints_used: p.hints_used, progress: publicProgress(key) };
        });
        return sendJson(res, 200, { ok: true, ...result });
      }

      if (req.method === 'POST' && pathname === '/api/reset') {
        const key = body.module_key;
        if (!validateModuleKey(key)) return sendError(res, 400, 'Unknown module_key.');
        const result = await mutate(() => {
          // One atomic batch: progress + module runtime state reset together.
          state.progress[key] = {
            module_key: key, status: 'not_started', stage: 0,
            attempts: 0, hints_used: 0, solved_at: null, evidence: null,
          };
          if (key === 'stored-xss') {
            const seed = JSON.parse(fs.readFileSync(SEED_PATH, 'utf8'));
            state.reviews = seed.reviews;
            state.next_review_id = seed.next_review_id;
          }
          if (key === 'csrf') {
            state.account = { username: 'carlos', email: 'carlos@example.com', role: 'customer' };
          }
          return { progress: publicProgress(key) };
        });
        return sendJson(res, 200, { ok: true, ...result });
      }

      if (req.method === 'POST' && pathname === '/api/victim') {
        const mod = moduleDef(body.module_key);
        if (!mod || !validateModuleKey(body.module_key)) return sendError(res, 400, 'Unknown module_key.');
        if (!mod.has_victim_sim) return sendError(res, 400, 'This module has no victim simulation.');
        if (!requireString(body.email, 120) || !body.email.includes('@')) {
          return sendError(res, 400, 'email is required and must contain @ (max 120 characters).');
        }
        const result = await mutate(() => {
          const p = progress('csrf');
          p.attempts += 1;
          const target = body.email;
          state.account.email = target;
          const replies = [
            { role: 'victim', text: 'carlos: visits a mock malicious page while signed in to the shop. The page contains a hidden request to the email-change link — he clicks nothing.' },
            { role: 'system', text: 'The hidden request fired with carlos\u2019s session and changed the account email to ' + target + '. OBJECTIVE COMPLETE — a state change behind a GET link needs no victim action at all.' },
          ];
          solve('csrf', 'Victim simulation changed the account email via the mock malicious page.');
          return { replies, progress: publicProgress('csrf'), account: state.account };
        });
        return sendJson(res, 200, { ok: true, ...result });
      }

      if (req.method === 'POST' && pathname === '/api/journal') {
        if (!requireString(body.prompt, 2000)) return sendError(res, 400, 'prompt is required (1–2000 characters).');
        if (!requireString(body.intent, 60)) return sendError(res, 400, 'intent is required (1–60 characters).');
        if (!requireString(body.technique, 60)) return sendError(res, 400, 'technique is required (1–60 characters).');
        if (body.module_key !== undefined && body.module_key !== null && !validateModuleKey(body.module_key)) {
          return sendError(res, 400, 'module_key must be one of the 4 module keys or null.');
        }
        if (body.result !== undefined && !JOURNAL_RESULTS.includes(body.result)) {
          return sendError(res, 400, 'result must be one of: worked, blocked, partial, untested.');
        }
        if (body.evasion !== undefined && (typeof body.evasion !== 'string' || body.evasion.length > 60)) {
          return sendError(res, 400, 'evasion must be at most 60 characters.');
        }
        if (body.input_channel !== undefined && (typeof body.input_channel !== 'string' || body.input_channel.length > 60)) {
          return sendError(res, 400, 'input_channel must be at most 60 characters.');
        }
        if (body.notes !== undefined && (typeof body.notes !== 'string' || body.notes.length > 2000)) {
          return sendError(res, 400, 'notes must be at most 2000 characters.');
        }
        const entry = await mutate(() => {
          const now = new Date().toISOString();
          const e = {
            id: state.next_journal_id++,
            prompt: body.prompt,
            intent: body.intent,
            technique: body.technique,
            evasion: body.evasion || 'None',
            input_channel: body.input_channel || 'Web request',
            result: body.result || 'untested',
            notes: body.notes || '',
            module_key: body.module_key || null,
            created_at: now,
            updated_at: now,
          };
          state.journal.unshift(e);
          return e;
        });
        return sendJson(res, 201, { ok: true, entry });
      }

      const journalIdMatch = pathname.match(/^\/api\/journal\/(\d+)$/);
      if (journalIdMatch) {
        const id = Number(journalIdMatch[1]);
        if (req.method === 'PUT') {
          if (body.module_key !== undefined && body.module_key !== null && !validateModuleKey(body.module_key)) {
            return sendError(res, 400, 'module_key must be one of the 4 module keys or null.');
          }
          if (body.result !== undefined && !JOURNAL_RESULTS.includes(body.result)) {
            return sendError(res, 400, 'result must be one of: worked, blocked, partial, untested.');
          }
          const updated = await mutate(() => {
            const e = state.journal.find((x) => x.id === id);
            if (!e) return null;
            for (const f of ['prompt', 'intent', 'technique', 'evasion', 'input_channel', 'result', 'notes', 'module_key']) {
              if (body[f] !== undefined) e[f] = body[f];
            }
            e.updated_at = new Date().toISOString();
            return e;
          });
          if (!updated) return sendError(res, 404, 'Journal entry not found.');
          return sendJson(res, 200, { ok: true, entry: updated });
        }
        if (req.method === 'DELETE') {
          const deleted = await mutate(() => {
            const idx = state.journal.findIndex((x) => x.id === id);
            if (idx === -1) return false;
            state.journal.splice(idx, 1);
            return true;
          });
          if (!deleted) return sendError(res, 404, 'Journal entry not found.');
          return sendJson(res, 200, { ok: true, deleted: id });
        }
      }

      if (req.method === 'POST' && pathname === '/api/writeups/generate') {
        const key = body.module_key;
        if (!validateModuleKey(key)) return sendError(res, 400, 'Unknown module_key.');
        const mod = moduleDef(key);
        const p = progress(key);
        if (p.status !== 'solved') return sendError(res, 400, 'Module is not solved yet — generate a writeup only after the objective is complete.');
        if (state.writeups.some((w) => w.module_key === key)) {
          return sendError(res, 409, WRITEUP_EXISTS_MESSAGE);
        }
        const writeup = await mutate(() => {
          // Re-check inside the serialized mutation: race-safe dedupe.
          if (state.writeups.some((w) => w.module_key === key)) return null;
          const now = new Date().toISOString();
          const w = {
            id: state.next_writeup_id++,
            module_key: key,
            title: mod.title + ' — ' + mod.writeup_source_label + ' writeup',
            owasp: mod.owasp,
            status: 'draft',
            body: buildWriteupBody(mod, progress(key)),
            created_at: now,
            updated_at: now,
          };
          state.writeups.unshift(w);
          return w;
        });
        if (!writeup) return sendError(res, 409, WRITEUP_EXISTS_MESSAGE);
        return sendJson(res, 201, { ok: true, writeup });
      }

      if (req.method === 'POST' && pathname === '/api/writeups') {
        if (!requireString(body.title, 200)) return sendError(res, 400, 'title is required (1–200 characters).');
        const writeup = await mutate(() => {
          const now = new Date().toISOString();
          const w = {
            id: state.next_writeup_id++,
            module_key: body.module_key && validateModuleKey(body.module_key) ? body.module_key : null,
            title: body.title,
            owasp: typeof body.owasp === 'string' ? body.owasp.slice(0, 120) : '',
            status: 'draft',
            body: typeof body.body === 'string' ? body.body.slice(0, 20000) : '',
            created_at: now,
            updated_at: now,
          };
          state.writeups.unshift(w);
          return w;
        });
        return sendJson(res, 201, { ok: true, writeup });
      }

      const writeupIdMatch = pathname.match(/^\/api\/writeups\/(\d+)$/);
      if (writeupIdMatch) {
        const id = Number(writeupIdMatch[1]);
        if (req.method === 'PUT') {
          const updated = await mutate(() => {
            const w = state.writeups.find((x) => x.id === id);
            if (!w) return null;
            for (const f of ['title', 'owasp', 'body', 'status']) {
              if (body[f] !== undefined) w[f] = body[f];
            }
            w.updated_at = new Date().toISOString();
            return w;
          });
          if (!updated) return sendError(res, 404, 'Writeup not found.');
          return sendJson(res, 200, { ok: true, writeup: updated });
        }
        if (req.method === 'DELETE') {
          const deleted = await mutate(() => {
            const idx = state.writeups.findIndex((x) => x.id === id);
            if (idx === -1) return false;
            state.writeups.splice(idx, 1);
            return true;
          });
          if (!deleted) return sendError(res, 404, 'Writeup not found.');
          return sendJson(res, 200, { ok: true, deleted: id });
        }
      }

      return sendError(res, 404, 'Unknown API route.');
    }

    // ---- Static files -----------------------------------------------------
    let filePath = pathname === '/' ? '/index.html' : pathname;
    filePath = decodeURIComponent(filePath);
    const safe = path.normalize(filePath).replace(/^(\.\.[\/\\])+/, '');
    const full = path.join(PUBLIC_DIR, safe);
    if (!full.startsWith(PUBLIC_DIR)) return sendError(res, 403, 'Forbidden.');
    if (!fs.existsSync(full) || fs.statSync(full).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not found');
    }
    const ext = path.extname(full).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(full).pipe(res);
  } catch (err) {
    console.error(err);
    if (!res.headersSent) sendError(res, 500, 'Internal server error.');
  }
}

module.exports = handler;

if (require.main === module) {
  const server = http.createServer(handler);
  server.listen(PORT, () => {
    console.log('Classic Web Vulns Studio listening on http://localhost:' + PORT);
  });
}
