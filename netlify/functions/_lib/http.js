// netlify/functions/_lib/http.js
// Tiny shared helpers so every function returns consistent JSON + CORS headers,
// and so auth-checking boilerplate isn't copy-pasted with subtle differences.

const { verifyToken } = require('./crypto');
const { airtableListAll } = require('./airtable');

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
 * Verifies the Bearer session token from the Authorization header, AND
 * re-checks the account's Actif status live in Airtable on every call.
 *
 * Why the extra Airtable round-trip: session tokens are stateless (signed,
 * not stored) so they can't be individually revoked before they expire (up
 * to 4h). Without this check, suspending or deleting an admin would only
 * take effect once their current token expires. Re-reading Actif here makes
 * suspension/deletion effective immediately, at the cost of one Airtable
 * read per authenticated request — an acceptable trade for this app's low
 * traffic. Async on purpose: every caller must `await requireSession(...)`.
 *
 * Returns the decoded { email, role, exp, ... } payload, or null if the
 * token is missing/invalid/expired, OR the account no longer exists/is inactive.
 */
async function requireSession(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return null;
  const secret = process.env.ADMIN_TOKEN_SECRET;
  if (!secret) return null;
  const payload = verifyToken(m[1], secret);
  if (!payload || payload.typ !== 'session') return null;

  try {
    const matches = await airtableListAll('Admins', `LOWER({Email})='${payload.email.replace(/'/g, "\\'")}'`);
    const rec = matches[0];
    if (!rec || rec.fields.Actif !== 'Oui') return null;
  } catch {
    return null; // fail closed: if we can't verify, treat as unauthenticated
  }

  return payload;
}

module.exports = { CORS, json, preflight, parseBody, requireSession };

