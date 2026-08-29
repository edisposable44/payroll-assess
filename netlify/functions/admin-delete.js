// netlify/functions/admin-delete.js
// MASTER ADMIN ONLY: permanently deletes a delegated admin account.
// Irreversible — unlike admin-set-active.js (suspend). Takes effect
// immediately for the same reason as suspension: requireSession() re-checks
// the account exists+is active on every authenticated request, so a deleted
// admin's existing session token stops working right away.
//
// Cannot target the Master account (there is deliberately no self-service
// way to delete the sole master — that would brick the whole admin system
// with no recovery path).

const { json, preflight, parseBody, requireSession } = require('./_lib/http');
const { airtableListAll, airtableRequest } = require('./_lib/airtable');

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const session = await requireSession(event);
  if (!session) return json(401, { error: 'Session invalide ou expirée.' });
  if (session.role !== 'master') return json(403, { error: 'Réservé au master admin.' });

  const { email } = parseBody(event);
  if (!email) return json(400, { error: 'Email requis.' });
  const emailNorm = String(email).trim().toLowerCase();

  try {
    const matches = await airtableListAll('Admins', `LOWER({Email})='${emailNorm.replace(/'/g, "\\'")}'`);
    const rec = matches[0];
    if (!rec) return json(404, { error: 'Administrateur introuvable.' });
    if (rec.fields.Role === 'Master') {
      return json(400, { error: 'Le compte du master admin ne peut pas être supprimé.' });
    }

    await airtableRequest('Admins', 'DELETE', null, rec.id);

    return json(200, { ok: true, email: emailNorm });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
