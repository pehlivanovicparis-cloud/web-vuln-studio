'use strict';
// Classic Web Vulns Studio — test suite (Node.js standard library only).
// Boots the real server on port 3000, proves each of the four flaws is
// genuinely exploitable over HTTP, proves SSRF containment, proves state
// persistence, and sweeps the repo for secret-like strings. No network
// beyond localhost. Run: node tests/run-tests.js
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT = path.join(__dirname, '..');
const BASE = 'http://127.0.0.1:3000';
const DATA_JSON = path.join(ROOT, 'data', 'data.json');

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log('ok - ' + name);
  } catch (e) {
    failed += 1;
    failures.push(name + ' :: ' + e.message);
    console.log('FAIL - ' + name + ' :: ' + e.message);
  }
}

async function req(method, p, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + p, opts);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* non-JSON body */ }
  return { status: res.status, text, json };
}

async function resetModule(key) {
  const r = await req('POST', '/api/reset', { module_key: key });
  assert.strictEqual(r.status, 200, 'reset ' + key + ' should be 200, got ' + r.status);
}

async function getProgress(key) {
  const r = await req('GET', '/api/state');
  assert.strictEqual(r.status, 200);
  const mod = r.json.modules.find((m) => m.key === key);
  assert.ok(mod, 'module ' + key + ' present in state');
  return mod.progress;
}

let server = null;

async function startServer() {
  server = spawn('node', ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: '3000' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', () => {});
  server.stderr.on('data', (d) => { process.stderr.write('[server] ' + d); });
  const deadline = Date.now() + 15000;
  for (;;) {
    try {
      const r = await fetch(BASE + '/api/state');
      if (r.ok) return;
    } catch (e) { /* not up yet */ }
    if (Date.now() > deadline) throw new Error('server did not become ready on port 3000');
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function stopServer() {
  if (!server) return;
  const s = server;
  server = null;
  await new Promise((resolve) => {
    s.once('exit', resolve);
    s.kill('SIGTERM');
    setTimeout(resolve, 3000).unref();
  });
}

async function main() {
  if (fs.existsSync(DATA_JSON)) fs.unlinkSync(DATA_JSON);

  await startServer();
  try {
    await test('serves homepage with practice-only banner and title', async () => {
      const r = await req('GET', '/');
      assert.strictEqual(r.status, 200);
      assert.ok(r.text.includes('Classic Web Vulns Studio'), 'title present');
      assert.ok(r.text.includes('Authorized practice only'), 'banner present');
      assert.ok(r.text.includes('fictional data'), 'fictional-data notice present');
      assert.ok(r.text.includes('Paris Pehlivanovic'), 'copyright footer present');
    });

    await test('state lists 4 modules with hints, root cause, fix, objective', async () => {
      const r = await req('GET', '/api/state');
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.json.modules.length, 4);
      for (const m of r.json.modules) {
        for (const f of ['key', 'num', 'title', 'level', 'objective', 'briefing', 'hints', 'stage_names', 'root_cause', 'fix', 'progress']) {
          assert.ok(m[f] !== undefined && m[f] !== null, m.key + ' has ' + f);
        }
        assert.ok(Array.isArray(m.hints) && m.hints.length >= 3, m.key + ' has >=3 hints');
        assert.strictEqual(m.stage_names.length, 5, m.key + ' has 5 stages');
        assert.ok(m.briefing.length > 40, m.key + ' briefing non-trivial');
        assert.ok(m.root_cause.length > 40, m.key + ' root cause non-trivial');
        assert.ok(m.fix.length > 40, m.key + ' fix lesson non-trivial');
      }
      assert.deepStrictEqual(r.json.modules.map((m) => m.key), ['sqli', 'stored-xss', 'ssrf', 'csrf']);
    });

    // ---- SQLi -----------------------------------------------------------
    await test('sqli: normal search returns matching products only, no users', async () => {
      await resetModule('sqli');
      const r = await req('GET', '/api/shop/search?q=' + encodeURIComponent('Trail'));
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.json.leaked_users, false);
      assert.ok(r.json.rows.length >= 1, 'at least one product row');
      assert.ok(r.json.rows.every((row) => row.kind === 'product'), 'all rows are products');
      assert.ok(r.json.rows.some((row) => row.name.includes('Trail')), 'Trail product returned');
    });

    await test('sqli: tautology returns the whole catalog', async () => {
      const r = await req('GET', '/api/shop/search?q=' + encodeURIComponent("' OR '1'='1"));
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.json.leaked_users, false);
      assert.ok(r.json.rows.length >= 4, 'tautology returns all products, got ' + r.json.rows.length);
    });

    await test('sqli: UNION-style input dumps the fake users table and solves', async () => {
      const payload = "' UNION SELECT username, email FROM users--";
      const r = await req('GET', '/api/shop/search?q=' + encodeURIComponent(payload));
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.json.leaked_users, true);
      const names = r.json.rows.map((row) => row.name);
      assert.ok(names.includes('carlos'), 'users dump includes carlos: ' + names.join(','));
      assert.ok(r.json.rows.some((row) => row.kind === 'user'), 'user rows present');
      const p = await getProgress('sqli');
      assert.strictEqual(p.status, 'solved', 'sqli solved after users dump');
      assert.strictEqual(p.stage, 5);
    });

    // ---- Stored XSS -----------------------------------------------------
    await test('xss: confirm with no stored marker fails and does not solve', async () => {
      await resetModule('stored-xss');
      const r = await req('POST', '/api/xss/confirm', { marker: 'PRACTICE-MARKER' });
      assert.strictEqual(r.status, 400, 'confirm without stored marker must fail');
      const p = await getProgress('stored-xss');
      assert.notStrictEqual(p.status, 'solved');
    });

    await test('xss: review is stored and served raw (unescaped)', async () => {
      const marker = '<img src="x" onerror="window.__xssFlag=\'PRACTICE-MARKER\'">';
      const post = await req('POST', '/api/shop/reviews', {
        product: 'trail-boots', author: 'tester', text: 'Great boots! ' + marker,
      });
      assert.strictEqual(post.status, 201, 'review created, got ' + post.status);
      const get = await req('GET', '/api/shop/reviews?product=trail-boots');
      assert.strictEqual(get.status, 200);
      const stored = get.json.reviews.find((rv) => rv.text.includes('__xssFlag'));
      assert.ok(stored, 'marker review present in served reviews');
      assert.ok(stored.text.includes('<img src="x" onerror='), 'payload served raw, not escaped: ' + stored.text);
      assert.ok(!stored.text.includes('&lt;img'), 'payload must not be HTML-escaped');
    });

    await test('xss: frontend renders reviews via innerHTML and detects the flag', async () => {
      const r = await req('GET', '/app.js');
      assert.strictEqual(r.status, 200);
      assert.ok(r.text.includes('innerHTML'), 'app.js renders reviews with innerHTML');
      assert.ok(r.text.includes('__xssFlag'), 'app.js detects the marker flag');
      assert.ok(r.text.includes('/api/xss/confirm'), 'app.js confirms the flag with the server');
    });

    await test('xss: confirm after stored marker solves the module', async () => {
      const r = await req('POST', '/api/xss/confirm', { marker: 'PRACTICE-MARKER' });
      assert.strictEqual(r.status, 200, 'confirm should succeed, got ' + r.status);
      assert.strictEqual(r.json.solved, true);
      const p = await getProgress('stored-xss');
      assert.strictEqual(p.status, 'solved');
    });

    // ---- SSRF -----------------------------------------------------------
    await test('ssrf: unvalidated param reaches the mock internal route and solves', async () => {
      await resetModule('ssrf');
      const r = await req('GET', '/api/shop/fetch-image?url=' + encodeURIComponent('/internal/status'));
      assert.strictEqual(r.status, 200, 'fetch-image should be 200, got ' + r.status);
      assert.ok(r.json.body && r.json.body.instance, 'internal metadata returned');
      assert.ok(String(r.json.body.instance).includes('mock'), 'metadata is clearly fake: ' + r.json.body.instance);
      const p = await getProgress('ssrf');
      assert.strictEqual(p.status, 'solved', 'ssrf solved after reaching internal route');
    });

    await test('ssrf: arbitrary external URLs are never fetched', async () => {
      const bad = [
        'https://example.com/image.png',
        'http://169.254.169.254/latest/meta-data/',
        'http://127.0.0.1:9/admin',
        'https://localhost:3000/api/state',
      ];
      for (const u of bad) {
        const r = await req('GET', '/api/shop/fetch-image?url=' + encodeURIComponent(u));
        assert.ok(r.status === 400 || r.status === 404, u + ' must not succeed, got ' + r.status);
        const body = JSON.stringify(r.json || r.text);
        assert.ok(!body.includes('ami-id') && !body.includes('instance-id'), 'no cloud metadata in ' + u);
        assert.ok(!body.includes('Classic Web Vulns Studio') || u.includes('localhost'), 'no real app content fetched from ' + u);
      }
    });

    await test('ssrf: server code performs no outbound fetch (containment by construction)', async () => {
      const src = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
      assert.ok(!/\bfetch\s*\(/.test(src), 'server.js must not call fetch()');
      assert.ok(!/https?\.get\s*\(/.test(src), 'server.js must not call http(s).get()');
      assert.ok(!/https?\.request\s*\(/.test(src), 'server.js must not call http(s).request()');
      assert.ok(!/child_process/.test(src), 'server.js must not spawn processes');
      assert.ok(!/net\.connect/.test(src), 'server.js must not open sockets');
      const store = fs.readFileSync(path.join(ROOT, 'lib', 'store.js'), 'utf8');
      assert.ok(store.includes('/get/') && store.includes('/set/'), 'store fetch is KV-only');
    });

    await test('ssrf: direct mock internal route returns fake metadata', async () => {
      const r = await req('GET', '/internal/status');
      assert.strictEqual(r.status, 200);
      assert.ok(String(r.json.instance).includes('mock'));
      assert.ok(r.json.practice_only === true, 'internal route self-labels as practice-only');
    });

    // ---- CSRF -----------------------------------------------------------
    await test('csrf: state-changing GET with no anti-forgery check changes the email', async () => {
      await resetModule('csrf');
      const before = await req('GET', '/api/shop/account');
      assert.strictEqual(before.json.account.email, 'carlos@example.com');
      const r = await req('GET', '/api/shop/account/change-email?email=' + encodeURIComponent('attacker@example.com'));
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.json.account.email, 'attacker@example.com');
      const p = await getProgress('csrf');
      assert.strictEqual(p.status, 'solved', 'csrf solved after GET email change');
    });

    await test('csrf: victim simulation applies the change as the victim session', async () => {
      await resetModule('csrf');
      const r = await req('POST', '/api/victim', { module_key: 'csrf', email: 'victim-target@example.com' });
      assert.strictEqual(r.status, 200, 'victim sim should be 200, got ' + r.status);
      assert.ok(Array.isArray(r.json.replies) && r.json.replies.length >= 2, 'victim sim returns a transcript');
      const after = await req('GET', '/api/shop/account');
      assert.strictEqual(after.json.account.email, 'victim-target@example.com');
      const p = await getProgress('csrf');
      assert.strictEqual(p.status, 'solved');
    });

    // ---- Hints / journal / writeups / export ----------------------------
    await test('hint endpoint returns a stage-appropriate hint and counts use', async () => {
      await resetModule('sqli');
      const r = await req('POST', '/api/hint', { module_key: 'sqli' });
      assert.strictEqual(r.status, 200);
      assert.ok(typeof r.json.hint === 'string' && r.json.hint.length > 20, 'hint text present');
      assert.strictEqual(r.json.hints_used, 1);
    });

    await test('journal: add works, unknown module key rejected', async () => {
      const ok = await req('POST', '/api/journal', {
        prompt: 'test prompt', intent: 'Discovery', technique: 'Direct request', module_key: 'sqli', result: 'worked',
      });
      assert.strictEqual(ok.status, 201);
      const bad = await req('POST', '/api/journal', {
        prompt: 'x', intent: 'x', technique: 'x', module_key: 'nope',
      });
      assert.strictEqual(bad.status, 400);
    });

    await test('writeups: generate requires solved, dedupes on second generate', async () => {
      await resetModule('csrf');
      const early = await req('POST', '/api/writeups/generate', { module_key: 'csrf' });
      assert.strictEqual(early.status, 400, 'unsolved module must not generate');
      await req('GET', '/api/shop/account/change-email?email=' + encodeURIComponent('attacker@example.com'));
      const gen = await req('POST', '/api/writeups/generate', { module_key: 'csrf' });
      assert.strictEqual(gen.status, 201, 'solved module generates, got ' + gen.status);
      assert.ok(gen.json.writeup.body.includes('ROOT CAUSE'), 'writeup has root cause');
      assert.ok(gen.json.writeup.body.includes('FIX'), 'writeup has fix');
      const dup = await req('POST', '/api/writeups/generate', { module_key: 'csrf' });
      assert.strictEqual(dup.status, 409, 'duplicate generate must be rejected');
    });

    await test('export returns a Markdown training record', async () => {
      const r = await req('GET', '/api/export');
      assert.strictEqual(r.status, 200);
      assert.ok(r.json.markdown.includes('Classic Web Vulns Studio'), 'export names the studio');
      assert.ok(r.json.markdown.includes('The Loose Query') && r.json.markdown.includes('The Raw Review'), 'export lists modules');
      assert.ok(r.json.markdown.includes('|'), 'export has a Markdown table');
    });

    await test('reset restores module state (email + reviews + progress)', async () => {
      await resetModule('csrf');
      const acct = await req('GET', '/api/shop/account');
      assert.strictEqual(acct.json.account.email, 'carlos@example.com', 'email restored by reset');
      await resetModule('stored-xss');
      const revs = await req('GET', '/api/shop/reviews?product=trail-boots');
      assert.ok(!revs.json.reviews.some((rv) => rv.text.includes('__xssFlag')), 'marker review cleared by reset');
      const p = await getProgress('stored-xss');
      assert.strictEqual(p.status, 'not_started');
    });

    // ---- Persistence across restart -------------------------------------
    await test('state persists across a server restart', async () => {
      await resetModule('sqli');
      await req('GET', '/api/shop/search?q=' + encodeURIComponent("' UNION SELECT username, email FROM users--"));
      const before = await getProgress('sqli');
      assert.strictEqual(before.status, 'solved');
      await stopServer();
      await startServer();
      const after = await getProgress('sqli');
      assert.strictEqual(after.status, 'solved', 'solved state survived restart');
      const st = await req('GET', '/api/state');
      assert.ok(st.json.journal.length >= 1, 'journal survived restart');
    });

    // ---- Secret sweep + banner ------------------------------------------
    await test('no secret-like strings anywhere in the repo', async () => {
      const patterns = [
        /AKIA[0-9A-Z]{16}/,
        /ghp_[A-Za-z0-9]{20,}/,
        /gho_[A-Za-z0-9]{20,}/,
        /sk-[A-Za-z0-9]{8,}/,
        /-----BEGIN[A-Z ]*PRIVATE KEY-----/,
        /["'](password|passwd|secret|api[_-]?key)["']\s*:\s*["'][^"']{4,}["']/i,
        /Bearer [A-Za-z0-9_\-]{10,}/,
        /(password|passwd)\s*=\s*["'][^"']+["']/i,
      ];
      const skipDirs = new Set(['tests', 'node_modules', '.git']);
      const hits = [];
      const walk = (dir) => {
        for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
          if (skipDirs.has(ent.name)) continue;
          const full = path.join(dir, ent.name);
          if (ent.isDirectory()) { walk(full); continue; }
          if (ent.name === 'data.json') continue;
          const content = fs.readFileSync(full, 'utf8');
          for (const pat of patterns) {
            if (pat.test(content)) hits.push(full + ' matches ' + pat);
          }
        }
      };
      walk(ROOT);
      assert.strictEqual(hits.length, 0, 'secret-like strings found: ' + hits.join('; '));
    });

    await test('banner is present in the single-page shell covering all tabs', async () => {
      const r = await req('GET', '/');
      assert.ok(r.text.includes('id="tab-modules"') || r.text.includes('tab-modules'), 'modules tab present');
      assert.ok(r.text.includes('tab-journal'), 'journal tab present');
      assert.ok(r.text.includes('tab-portfolio'), 'portfolio tab present');
      const bannerIdx = r.text.indexOf('Authorized practice only');
      const mainIdx = r.text.indexOf('<main>');
      assert.ok(bannerIdx !== -1 && bannerIdx < mainIdx, 'banner sits above all tab panels');
    });
  } finally {
    await stopServer();
  }

  console.log('\nRan: ' + (passed + failed) + ', Passed: ' + passed + ', Failed: ' + failed);
  if (failures.length) {
    console.log('Failures:');
    for (const f of failures) console.log(' - ' + f);
  }
  if (fs.existsSync(DATA_JSON)) fs.unlinkSync(DATA_JSON);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Harness error:', e);
  if (fs.existsSync(DATA_JSON)) { try { fs.unlinkSync(DATA_JSON); } catch (_) { /* ignore */ } }
  process.exit(2);
});
