// netlify/functions/admin-data.js
// Authenticated Airtable proxy for the ADMIN DASHBOARD only (Sessions,
// Resultats, Questions). Requires a valid session token (Authorization:
// Bearer <token>) — this is what makes the admin dashboard actually
// inaccessible to candidates, even if they guess a URL or read the JS: every
// request here is rejected server-side without a token signed by
// ADMIN_TOKEN_SECRET, which never leaves the server.
//
// Role-scoped allowlist (defense in depth beyond "just hide the button"):
//   master : Sessions (GET/POST/PATCH), Resultats (GET), Questions (GET/POST/PATCH/DELETE)
//   admin  : Sessions (GET/POST/PATCH), Resultats (GET), Questions (GET only)
// The dedicated Admins management (create/reset/list) endpoints are NOT
// reachable here on purpose — they have their own master-only functions.

const { json, preflight, requireSession } = require('./_lib/http');
const { airtableRequest } = require('./_lib/airtable');

const ALLOWLIST = {
  Sessions: { master: ['GET', 'POST', 'PATCH'], admin: ['GET', 'POST', 'PATCH'] },
  Resultats: { master: ['GET'], admin: ['GET'] },
  Questions: { master: ['GET', 'POST', 'PATCH', 'DELETE'], admin: ['GET'] },
};

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;

  const session = await requireSession(event);
  if (!session) return json(401, { error: 'Session invalide ou expirée. Reconnectez-vous.' });

  const params = event.queryStringParameters || {};
  const table = params.table;
  const id = params.id || '';
  const qs = params.qs || '';
  const method = event.httpMethod;

  if (!table) return json(400, { error: 'Missing "table" query parameter' });

  const rule = ALLOWLIST[table];
  if (!rule) return json(403, { error: `Table "${table}" non accessible via ce endpoint.` });
  const allowedMethods = rule[session.role] || [];
  if (!allowedMethods.includes(method)) {
    return json(403, { error: `Action non autorisée pour votre rôle (${session.role}) sur ${table}.` });
  }

  let body = null;
  if (event.body) {
    try {
      body = JSON.parse(event.body);
    } catch {
      return json(400, { error: 'Invalid JSON body' });
    }
  }

  try {
    const data = await airtableRequest(table, method, body, id, qs);
    return json(200, data);
  } catch (e) {
    return json(e.status || 500, { error: e.message, airtableError: e.airtableError });
  }
};
