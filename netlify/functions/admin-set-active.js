// netlify/functions/admin-set-active.js
// MASTER ADMIN ONLY: suspend a delegated admin ("jusqu'à nouvel ordre") or
// reactivate one. Reversible — unlike admin-delete.js. Takes effect
// IMMEDIATELY: requireSession() re-checks Actif live in Airtable on every
// authenticated request, so a suspended admin loses dashboard access right
// away rather than only once their current session token expires.
//
// Cannot target the Master account (suspending yourself makes no sense and
// would be a self-inflicted lockout with no recovery path except the
// break-glass procedure).

const { json, preflight, parseBody, requireSession } = require('./_lib/http');
const { airtableListAll, airtableRequest } = require('./_lib/airtable');

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const session = await requireSession(event);
  if (!session) return json(401, { error: 'Session invalide ou expirée.' });
  if (session.role !== 'master') return json(403, { error: 'Réservé au master admin.' });

  const { email, active } = parseBody(event);
  if (!email || typeof active !== 'boolean') {
    return json(400, { error: 'email et active (booléen) sont requis.' });
  }
  const emailNorm = String(email).trim().toLowerCase();

  try {
    const matches = await airtableListAll('Admins', `LOWER({Email})='${emailNorm.replace(/'/g, "\\'")}'`);
    const rec = matches[0];
    if (!rec) return json(404, { error: 'Administrateur introuvable.' });
    if (rec.fields.Role === 'Master') {
      return json(400, { error: 'Le compte du master admin ne peut pas être suspendu.' });
    }

    await airtableRequest('Admins', 'PATCH', { fields: { Actif: active ? 'Oui' : 'Non' } }, rec.id);

    return json(200, { ok: true, email: emailNorm, active });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
