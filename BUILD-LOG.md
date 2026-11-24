# Classic Web Vulns Studio — Build Log

Built 2026-11-24, local only. No deployment, no git push, no browser work.
Structure mirrors the AI Hacker Practice Simulator exactly: server.js entry,
api/index.js Vercel entry, lib/store.js (copied verbatim — generic store),
public/index.html + app.js + styles.css, data/seed.json, package.json,
vercel.json (includeFiles is a STRING brace glob, never an array), README.md,
LICENSE (sibling text verbatim), .gitignore. Node stdlib only,
`node server.js`, port 3000. State lives under its own KV key
`web-vuln-studio:state` — the sibling's key is not reused.

## Tests first, then build

Tests were written before the app (tests/run-tests.js, stdlib only, boots
the real server on port 3000). Final run:

- Ran: 23, Passed: 23, Failed: 0
- First run: 20/23. Three failures, all fixed without weakening a test:
  1. A code comment header ("image fetch (modeled…") tripped the
     containment grep for `fetch(` — comment reworded; the guard stays
     strict (any `fetch(` token in server.js fails).
  2. The victim-sim test omitted `module_key` — test fixed to the sibling's
     `/api/victim` shape (the app and frontend already required it).
  3. The export test asserted the wrong strings — fixed to assert module
     titles, which is what the export table contains.

## Curl evidence (local server, port 3000, 2026-11-24)

1. SQLi normal — `GET /api/shop/search?q=Trail` → 2 product rows
   (Trail Boots, Trail Socks), `leaked_users:false`.
2. SQLi tautology — `q=' OR '1'='1'` → all 5 products, kind `tautology`.
3. SQLi UNION — `q=' UNION SELECT username, email FROM users--` → 3 user
   rows (carlos, maria, jun), `leaked_users:true`, progress solved/stage 5.
4. Stored XSS — POST review carrying
   `<img src="x" onerror="window.__xssFlag='PRACTICE-MARKER'">` → 201;
   GET reviews serves the payload raw (no `&lt;` escaping); POST
   `/api/xss/confirm` with marker `PRACTICE-MARKER` → solved. Browser
   execution itself is via the innerHTML render path in public/app.js
   (asserted by test); the confirm endpoint validates the stored marker.
5. SSRF — `GET /api/shop/fetch-image?url=/internal/status` → 200 with fake
   metadata (`mock-internal-01`, `practice_only:true`), solved.
   `url=https://example.com/image.png` → 404 mock error, nothing fetched.
   `url=http://169.254.169.254/latest/meta-data/` → 404 mock error, no
   metadata. Code check: no `fetch(`, `http.get`, `http.request`,
   `child_process`, or socket use in server.js; the only network client is
   the KV store in lib/store.js.
6. CSRF — account `carlos@example.com` → GET
   `/api/shop/account/change-email?email=attacker@example.com` → email
   changed, solved. After reset, POST `/api/victim` → victim transcript +
   email changed to `victim-target@example.com`, solved.
7. Persistence — solved state + journal survived a kill + restart.
8. Export — GET /api/export returns the Markdown training record.
9. Secret sweep — no secret-like strings in the repo (test scans every file
   except tests/ and data.json).
10. Banner — "Authorized practice only — fictional shop, fictional data…"
    sits above all tab panels; footer carries
    "© 2026 Paris Pehlivanovic. All rights reserved."

## State shipped

`data/data.json` was removed after testing, so the shipped tree starts from
`data/seed.json`: no module solved, journal empty, no writeups, seed reviews,
fictional account carlos@example.com.

## Unfinished / left for the parent

- Deployment (GitHub repo + Vercel import + KV binding) — parent's step.
  Repo creation is blocked at API level per the sibling's history; create on
  github.com first, then push.
- No browser verification of the rendered pages was done (subagent has no
  browser). The XSS flag execution path is proven at the HTTP + code level
  only; a live-browser check of the review render is still worthwhile
  before Paris relies on the auto-confirm flow.
- The SSRF `@`-trick form (`http://example.com@/internal/status`) resolves
  by pathname to the mock internal handler, like any other URL with that
  path. That is the intended modeled flaw (unvalidated param reaches
  internal routes) and no socket ever opens, but it is recorded here
  deliberately rather than hidden.

Self-score:
1) Goal hit? Yes — all four flaws exploitable over HTTP exactly as briefed,
   containment proven behaviorally and by code inspection, 23/23 tests.
2) Tools right? Yes — tests-first caught three real issues (one in the app
   comment, two in the tests); curl probes verified the live behavior.
3) Waste — what I'd skip next time? The first test run's port-3000 boot
   raced the readiness poll once during drafting; the poll loop handled it,
   no time lost.
