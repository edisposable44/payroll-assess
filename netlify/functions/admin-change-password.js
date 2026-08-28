// netlify/functions/admin-change-password.js
// Lets a logged-in admin (master or delegated) change their OWN password.
// Used both for the mandatory first-login change (after a temp password from
// admin-create/admin-reset-password) and for voluntary password changes.
// Requires a valid session token AND the current password (defense against a
// stolen/left-open browser session being used to silently take over the account).

const { json, preflight, parseBody, requireSession } = require('./_lib/http');
const { verifyPassword, hashPassword, signToken } = require('./_lib/crypto');
const { airtableListAll, airtableRequest } = require('./_lib/airtable');

function validatePasswordStrength(p) {
  if (typeof p !== 'string' || p.length < 10) return 'Au moins 10 caractères requis.';
  if (!/[a-z]/.test(p)) return 'Au moins une minuscule requise.';
  if (!/[A-Z]/.test(p)) return 'Au moins une majuscule requise.';
  if (!/[0-9]/.test(p)) return 'Au moins un chiffre requis.';
  if (!/[^a-zA-Z0-9]/.test(p)) return 'Au moins un caractère spécial requis.';
  return null;
}

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const session = requireSession(event);
  if (!session) return json(401, { error: 'Session invalide ou expirée. Reconnectez-vous.' });

  const { currentPassword, newPassword } = parseBody(event);
  if (!currentPassword || !newPassword) return json(400, { error: 'Mot de passe actuel et nouveau requis.' });

  const strengthErr = validatePasswordStrength(newPassword);
  if (strengthErr) return json(400, { error: strengthErr });

  try {
    const matches = await airtableListAll('Admins', `LOWER({Email})='${session.email.replace(/'/g, "\\'")}'`);
    const rec = matches[0];
    if (!rec) return json(404, { error: 'Compte introuvable.' });

    if (!verifyPassword(currentPassword, rec.fields.PasswordHash)) {
      return json(401, { error: 'Mot de passe actuel incorrect.' });
    }

    const newHash = hashPassword(newPassword);
    await airtableRequest('Admins', 'PATCH', { fields: { PasswordHash: newHash, MustChangePassword: 'Non' } }, rec.id);

    const secret = process.env.ADMIN_TOKEN_SECRET;
    const token = signToken({ typ: 'session', email: session.email, role: session.role, mustChange: false }, secret, 4 * 3600);

    return json(200, { ok: true, token });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
