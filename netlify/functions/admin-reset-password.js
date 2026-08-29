// netlify/functions/admin-reset-password.js
// MASTER ADMIN ONLY — genuine last resort: use this when a delegated admin
// is truly locked out (lost their device, uninstalled ntfy, unsubscribed
// from their topic) so neither normal login NOR the self-service
// "Mot de passe oublié" flow can reach them (both require receiving a code
// on their ntfy topic). A forgotten password ALONE does not need this —
// admin-forgot-password.js / admin-reset-own-password.js handle that with
// zero master involvement, as long as the admin can still receive
// notifications on their existing topic.
//
// Regenerates BOTH the password AND the ntfy topic together, in one action:
// if a device was lost, the OLD topic should be considered burned too (it's
// a shared secret — don't keep sending future codes to a channel the admin
// may no longer control). MustChangePassword is set so the admin is forced
// to choose their own password again on next login.
//
// Cannot target the Master account itself (master recovery is a deliberate,
// separately-gated "break glass" procedure — see admin-master-recover.js —
// not a self-service button reachable from a possibly-compromised session).

const { json, preflight, parseBody, requireSession } = require('./_lib/http');
const { hashPassword, generateTempPassword, generateNtfyTopic } = require('./_lib/crypto');
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
      return json(400, { error: "Le compte du master admin ne peut pas être réinitialisé depuis cet écran. Voir la procédure de récupération master." });
    }

    const tempPassword = generateTempPassword();
    const hash = hashPassword(tempPassword);
    const ntfyTopic = generateNtfyTopic();

    await airtableRequest('Admins', 'PATCH', {
      fields: { PasswordHash: hash, MustChangePassword: 'Oui', NtfyTopic: ntfyTopic },
    }, rec.id);

    return json(200, { ok: true, email: emailNorm, tempPassword, ntfyTopic });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
