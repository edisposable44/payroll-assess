// netlify/functions/admin-list.js
// MASTER ADMIN ONLY: lists all admin accounts (master + delegated) for the
// "Administrateurs" management tab. Never returns PasswordHash or
// PushoverUserKey — those stay server-side only.

const { json, preflight, requireSession } = require('./_lib/http');
const { airtableListAll } = require('./_lib/airtable');

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'GET') return json(405, { error: 'Method not allowed' });

  const session = requireSession(event);
  if (!session) return json(401, { error: 'Session invalide ou expirée.' });
  if (session.role !== 'master') return json(403, { error: 'Réservé au master admin.' });

  try {
    const records = await airtableListAll('Admins');
    const admins = records
      .map((r) => ({
        email: r.fields.Email,
        role: r.fields.Role,
        actif: r.fields.Actif === 'Oui',
        mustChangePassword: r.fields.MustChangePassword === 'Oui',
        createdBy: r.fields.CreatedBy || '',
        createdAt: r.fields.CreatedAt || '',
        hasPushoverKey: !!r.fields.PushoverUserKey,
      }))
      .sort((a, b) => (a.role === b.role ? a.email.localeCompare(b.email) : a.role === 'Master' ? -1 : 1));
    return json(200, { admins });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
