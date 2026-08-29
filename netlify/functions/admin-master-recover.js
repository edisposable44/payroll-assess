// netlify/functions/admin-master-recover.js
// BREAK-GLASS recovery for the Master admin — the one account with no one
// "above" it to reset its password via the normal delegated-admin flow.
//
// Deliberately gated by a SEPARATE secret, MASTER_RECOVERY_SECRET, distinct
// from BOOTSTRAP_SECRET:
//   - BOOTSTRAP_SECRET is meant to be deleted/rotated right after the very
//     first setup (see DEPLOIEMENT.md) — it should not exist long-term.
//   - MASTER_RECOVERY_SECRET is meant to be kept, indefinitely, in a safe
//     place (a password manager, not in Netlify's UI history, ideally known
//     to only one or two trusted people) specifically so this recovery path
//     stays available whenever it's genuinely needed.
// Splitting them means rotating one never accidentally disables the other's
// use case.
//
// This endpoint requires that a Master record ALREADY exists (if none does,
// use admin-bootstrap.js instead). Regenerates the ntfy topic together with
// the password, same reasoning as admin-reset-password.js: a recovery event
// usually means the old device/channel should be considered burned.
//
// Call it (from a trusted machine only, e.g. not over a public wifi):
//   POST /.netlify/functions/admin-master-recover
//   { "secret": "<MASTER_RECOVERY_SECRET>", "newPassword": "NewSolidPassword123!" }

const crypto = require('crypto');
const { json, preflight, parseBody } = require('./_lib/http');
const { hashPassword, generateNtfyTopic } = require('./_lib/crypto');
const { airtableListAll, airtableRequest } = require('./_lib/airtable');

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const { secret, newPassword } = parseBody(event);

  const expected = process.env.MASTER_RECOVERY_SECRET;
  if (!expected) return json(500, { error: 'Server not configured: MASTER_RECOVERY_SECRET missing.' });
  if (!secret || !timingSafeStrEqual(secret, expected)) {
    return json(403, { error: 'Invalid recovery secret.' });
  }
  if (!newPassword || String(newPassword).length < 10) {
    return json(400, { error: 'newPassword is required and must be at least 10 characters.' });
  }

  try {
    const masters = await airtableListAll('Admins', "{Role}='Master'");
    const rec = masters[0];
    if (!rec) {
      return json(404, { error: 'No master admin exists yet — use admin-bootstrap instead.' });
    }

    const hash = hashPassword(newPassword);
    const ntfyTopic = generateNtfyTopic();
    await airtableRequest('Admins', 'PATCH', {
      fields: { PasswordHash: hash, NtfyTopic: ntfyTopic, MustChangePassword: 'Non', Actif: 'Oui' },
    }, rec.id);

    return json(200, { ok: true, email: rec.fields.Email, ntfyTopic });
  } catch (e) {
    return json(500, { error: e.message });
  }
};

function timingSafeStrEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
