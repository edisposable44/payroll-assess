// netlify/functions/admin-create.js
// MASTER ADMIN ONLY: creates a delegated admin account.
// Generates a temporary password server-side (never chosen by the master, so
// it's never transmitted in plaintext by the master over an insecure channel
// by habit) and returns it ONCE in the response for the master to relay to
// the new admin. MustChangePassword is set so the new admin is forced to pick
// their own password on first login.
//
// Enforces: max 10 delegated admins (master excluded), unique email.

const { json, preflight, parseBody, requireSession } = require('./_lib/http');
const { hashPassword, generateTempPassword, generateNtfyTopic } = require('./_lib/crypto');
const { airtableListAll, airtableRequest } = require('./_lib/airtable');

const MAX_DELEGATED_ADMINS = 10;

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const session = requireSession(event);
  if (!session) return json(401, { error: 'Session invalide ou expirée.' });
  if (session.role !== 'master') return json(403, { error: 'Réservé au master admin.' });

  const { email } = parseBody(event);
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json(400, { error: 'Adresse email invalide.' });
  }

  const emailNorm = String(email).trim().toLowerCase();

  try {
    const existing = await airtableListAll('Admins', `LOWER({Email})='${emailNorm.replace(/'/g, "\\'")}'`);
    if (existing.length > 0) return json(409, { error: 'Un compte existe déjà avec cet email.' });

    const currentAdmins = await airtableListAll('Admins', "AND({Role}='Admin',{Actif}='Oui')");
    if (currentAdmins.length >= MAX_DELEGATED_ADMINS) {
      return json(400, { error: `Limite de ${MAX_DELEGATED_ADMINS} administrateurs délégués atteinte.` });
    }

    const tempPassword = generateTempPassword();
    const hash = hashPassword(tempPassword);
    const ntfyTopic = generateNtfyTopic();

    await airtableRequest('Admins', 'POST', {
      fields: {
        Email: emailNorm,
        PasswordHash: hash,
        Role: 'Admin',
        NtfyTopic: ntfyTopic,
        MustChangePassword: 'Oui',
        Actif: 'Oui',
        CreatedBy: session.email,
        CreatedAt: new Date().toISOString(),
      },
    });

    return json(200, { ok: true, email: emailNorm, tempPassword, ntfyTopic });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
