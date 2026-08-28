// netlify/functions/admin-reset-password.js
// MASTER ADMIN ONLY: forces a new temporary password for a delegated admin
// (e.g. they're locked out). Sets MustChangePassword so they must pick their
// own password on next login. Cannot target the Master account itself via
// this endpoint (master password recovery is a deliberate out-of-band process,
// not a self-service button — prevents a compromised master session from
// silently rotating its own recovery path).

const { json, preflight, parseBody, requireSession } = require('./_lib/http');
const { hashPassword, generateTempPassword } = require('./_lib/crypto');
const { airtableListAll, airtableRequest } = require('./_lib/airtable');

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const session = requireSession(event);
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
      return json(400, { error: "Le mot de passe du master admin ne peut pas être réinitialisé depuis cet écran." });
    }

    const tempPassword = generateTempPassword();
    const hash = hashPassword(tempPassword);
    await airtableRequest('Admins', 'PATCH', { fields: { PasswordHash: hash, MustChangePassword: 'Oui' } }, rec.id);

    return json(200, { ok: true, email: emailNorm, tempPassword });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
