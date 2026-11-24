'use strict';
// Vercel serverless entry point. Requires the app's HTTP handler from
// server.js (which only listens when run directly) and re-exports it.
// The handler serves both the static frontend (public/) and the JSON API,
// so vercel.json rewrites every path here.
const handler = require('../server.js');

module.exports = handler;
