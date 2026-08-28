// netlify/functions/admin-bootstrap.js
// ONE-TIME setup endpoint: creates the single Master admin record in Airtable.
// Gated by BOOTSTRAP_SECRET (a Netlify env var you set, use once, then should
// rotate/remove) — this is the only way a master password ever gets set, and
// it is hashed here, server-side, before it ever reaches Airtable.
//
// Call it once (e.g. with curl or Postman):
//   POST /.netlify/functions/admin-bootstrap
//   { "secret": "<BOOTSTRAP_SECRET>", "email": "you@company.com",
//     "password": "YourChosenPassword123!", "pushoverUserKey": "u1a2b3..." }
//
// Refuses to run again once a Master record already exists.

const crypto = require('crypto');
const { json, preflight, parseBody } = require('./_lib/http');
const { hashPassword } = require('./_lib/crypto');
const { airtableRequest, airtableListAll } = require('./_lib/airtable');

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const { secret, email, password, pushoverUserKey } = parseBody(event);

  const expected = process.env.BOOTSTRAP_SECRET;
  if (!expected) return json(500, { error: 'Server not configured: BOOTSTRAP_SECRET missing.' });
  if (!secret || !timingSafeStrEqual(secret, expected)) {
    return json(403, { error: 'Invalid bootstrap secret.' });
  }

  if (!email || !password) {
    return json(400, { error: 'email and password are required.' });
  }
  if (!pushoverUserKey) {
    return json(400, { error: 'pushoverUserKey is required so the master admin can receive 2FA codes.' });
  }
  if (String(password).length < 10) {
    return json(400, { error: 'Password must be at least 10 characters.' });
  }

  try {
    const existingMasters = await airtableListAll('Admins', "{Role}='Master'");
    if (existingMasters.length > 0) {
      return json(409, { error: 'A master admin already exists. Bootstrap can only run once.' });
    }

    const hash = hashPassword(password);
    await airtableRequest('Admins', 'POST', {
      fields: {
        Email: String(email).trim().toLowerCase(),
        PasswordHash: hash,
        Role: 'Master',
        PushoverUserKey: pushoverUserKey,
        MustChangePassword: 'Non',
        Actif: 'Oui',
        CreatedBy: 'bootstrap',
        CreatedAt: new Date().toISOString(),
      },
    });

    return json(200, { ok: true, email: String(email).trim().toLowerCase() });
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
