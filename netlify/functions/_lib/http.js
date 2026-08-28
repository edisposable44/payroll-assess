// netlify/functions/_lib/http.js
// Tiny shared helpers so every function returns consistent JSON + CORS headers,
// and so auth-checking boilerplate isn't copy-pasted with subtle differences.

const { verifyToken } = require('./crypto');

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(statusCode, body) {
  return { statusCode, headers: { ...CORS, 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

function preflight(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  return null;
}

function parseBody(event) {
  try {
    return event.body ? JSON.parse(event.body) : {};
  } catch {
    return {};
  }
}

/**
 * Verifies the Bearer session token from the Authorization header.
 * Returns the decoded { email, role, exp, ... } payload, or null if missing/invalid/expired.
 */
function requireSession(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return null;
  const secret = process.env.ADMIN_TOKEN_SECRET;
  if (!secret) return null;
  const payload = verifyToken(m[1], secret);
  if (!payload || payload.typ !== 'session') return null;
  return payload;
}

module.exports = { CORS, json, preflight, parseBody, requireSession };
