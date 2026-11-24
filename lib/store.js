'use strict';
// Store abstraction: file-backed locally, Vercel KV-backed when KV env is set.
// Node.js standard library only (global fetch, Node >= 18). No dependencies.
//
// File mode (KV_REST_API_URL / KV_REST_API_TOKEN absent):
//   identical to the original behaviour — state lives in data/data.json,
//   created from data/seed.json on first load, written via tmp file + rename.
// KV mode (both env vars set):
//   state lives under one key in Vercel KV via the KV REST API:
//     GET  {KV_REST_API_URL}/get/<key>  -> {"result": "<json>" | null}
//     POST {KV_REST_API_URL}/set/<key>  -> raw JSON body -> {"result": "OK"}
//   A missing key is seeded from data/seed.json, saved to KV, and returned.
//   Every load() reads fresh from KV — callers must load per request in
//   serverless mode, never trust a warm in-memory copy across invocations.

const fs = require('fs');
const path = require('path');

function createStore({ key, seedPath, dataPath, normalize, onCorrupt }) {
  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  const useKv = Boolean(kvUrl && kvToken);
  const base = kvUrl ? kvUrl.replace(/\/+$/, '') : '';

  const norm = typeof normalize === 'function' ? normalize : (d) => d;

  function readSeed() {
    return JSON.parse(fs.readFileSync(seedPath, 'utf8'));
  }

  function writeFile(data) {
    fs.mkdirSync(path.dirname(dataPath), { recursive: true });
    const tmp = dataPath + '.tmp-' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', 'utf8');
    fs.renameSync(tmp, dataPath);
  }

  // File mode load. Mirrors the original per-app loadData/loadState:
  // missing file -> seed (and persist it); corrupt file -> seed fallback
  // only when onCorrupt === 'seed' (Lab HQ), otherwise throw (Studio,
  // Simulator, AHS all crashed on a corrupt file before, and still do).
  function fileLoad() {
    if (!fs.existsSync(dataPath)) {
      const seeded = norm(readSeed());
      writeFile(seeded);
      return seeded;
    }
    try {
      return norm(JSON.parse(fs.readFileSync(dataPath, 'utf8')));
    } catch (err) {
      if (onCorrupt === 'seed') {
        console.error('data.json unreadable, falling back to seed:', err.message);
        const seeded = norm(readSeed());
        writeFile(seeded);
        return seeded;
      }
      throw err;
    }
  }

  async function kvGet() {
    const res = await fetch(base + '/get/' + encodeURIComponent(key), {
      headers: { Authorization: 'Bearer ' + kvToken },
    });
    if (!res.ok) throw new Error('KV GET failed: HTTP ' + res.status);
    const body = await res.json();
    return body.result; // stored JSON string, or null when the key is absent
  }

  async function kvSet(value) {
    const res = await fetch(base + '/set/' + encodeURIComponent(key), {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + kvToken,
        'Content-Type': 'text/plain; charset=utf-8',
      },
      body: value,
    });
    if (!res.ok) throw new Error('KV SET failed: HTTP ' + res.status);
    await res.json().catch(() => {});
  }

  async function kvLoad() {
    const raw = await kvGet();
    if (raw === null || raw === undefined) {
      const seeded = norm(readSeed());
      await kvSet(JSON.stringify(seeded));
      return seeded;
    }
    return norm(JSON.parse(raw));
  }

  async function load() {
    return useKv ? kvLoad() : fileLoad();
  }

  async function save(data) {
    if (useKv) {
      await kvSet(JSON.stringify(data));
      return;
    }
    writeFile(data);
  }

  return { load, save, useKv };
}

module.exports = { createStore };
