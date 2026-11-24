# Classic Web Vulns Studio

A contained practice range for classic web vulnerabilities: four deliberately
vulnerable features in a fictional shop, with progress tracking, an attack
journal with classification, and a portfolio of training writeups with a
one-click Markdown training-record export.

Copyright © 2026 Paris Pehlivanovic. All rights reserved.

## What it is

The studio reproduces the structure of the AI Hacker Practice Simulator as a
standalone Node.js app (standard library only, zero dependencies). Each module
is a mock-shop feature with a real, working flaw — modeled against fictional
in-memory data only. There is no real database, no real outbound fetching,
and no real user data anywhere in the app.

The four modules:

1. **The Loose Query** (Practitioner) — product search concatenates input
   into a query over a fake in-memory catalog. A UNION-shaped input returns
   rows from the fake users table. A03:2021 Injection.
2. **The Raw Review** (Expert) — product reviews render unescaped. A stored
   review carrying the harmless practice flag executes when the page renders
   it, and the app detects the flag to mark the objective complete. No
   network behavior of any kind. A03:2021 Injection (Stored XSS).
3. **The Helpful Fetcher** (Practitioner) — an image-by-URL feature with no
   validation. The flaw is real in logic but physically contained: the
   fetcher dispatches in-process to mock internal handlers and never opens
   a network socket, so no external address can ever be fetched. A10:2021
   SSRF.
4. **The One-Click Email Change** (Apprentice) — account email changes via a
   GET request with no anti-forgery check, plus a simulated victim flow: a
   mock malicious page fires the request with the victim's session, fully
   simulated inside the app. A01:2021 Broken Access Control (CSRF).

All training happens against fictional data in an intentionally vulnerable
practice environment. Do not use these techniques against production systems
or any system without explicit written authorization.

## How to run

Requires Node.js 18 or newer. No install step — there are no dependencies.

```sh
node server.js
```

Then open http://localhost:3000 in a browser. To use a different port:

```sh
PORT=8080 node server.js
```

## How it works

- **Modules** — pick one from the list, read the briefing and objective,
  then use the workbench: the shop search, the reviews page, the image
  fetcher, or the account page. The kill-chain bar shows your stage.
  Hints reveal the next step for your current stage and count against the
  run. Resetting a module clears its progress and restores its runtime
  state (reviews, account email) in one atomic step.
- **Attack journal** — log requests with classification (intent, technique,
  evasion, input channel) and the result (worked / blocked / partial /
  untested). Entries can be tied to one of the four module keys; the server
  rejects any other module key.
- **Portfolio** — generate a writeup from a solved module (objective,
  endpoint, evidence, root cause, fix), or write one by hand. Generating a
  second writeup for the same module is rejected instead of duplicating.
- **Export report** — downloads the full training record (module progress,
  every journal entry, every writeup) as a dated Markdown file.

## Data

Progress is stored in `data/data.json`, created from `data/seed.json` on
first run. `data/data.json` is gitignored (it is your personal training
record); `data/seed.json` ships the empty starting state: no module solved,
journal empty, no writeups, seed reviews, and the fictional account.
Delete `data/data.json` to start over.

## Containment notes

- The SQL evaluator is a naive string matcher over fake in-memory tables.
  There is no database driver, no shell, and no query ever leaves the
  process.
- The image fetcher never calls `fetch()`, `http.get()`, or any socket API.
  It parses the supplied value, takes only its pathname, and dispatches to
  a hardcoded map of mock internal handlers. External URLs return a mock
  404 and no content is ever retrieved.
- The stored-XSS marker is a local flag-setter only. The app honors exactly
  one marker value, and the flag detection code performs no network calls.
- The CSRF victim flow is fully simulated server-side. No cookies, no
  cross-site requests, and no real session exists.
- State mutations commit as one atomic batch: each request mutates the
  single in-memory state and persists it with a temp-file + rename, and all
  mutations run through one serialized queue.
- Stages advance monotonically and solved state is sticky — a solved
  module cannot be unsolved by later requests.
- Writeup generation re-checks for an existing writeup inside the serialized
  mutation, so two simultaneous generates cannot both succeed.
- Journal entries are validated server-side against the four real module
  keys; unknown keys are rejected.
- Destructive actions (reset module, delete journal entry, delete writeup)
  require a two-step confirm in the UI.

## Tests

```sh
npm test
```

The suite boots the real server on port 3000 and proves each flaw is
exploitable over HTTP, proves SSRF containment (behavioral + code-level),
proves persistence across a restart, and sweeps the repo for secret-like
strings. It removes `data/data.json` before and after the run so the shipped
tree starts from the seed state.
