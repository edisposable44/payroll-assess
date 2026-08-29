// netlify/functions/admin-forgot-password.js
// SELF-SERVICE password recovery, step 1 of 2. Requires ZERO master
// involvement — the only proof of identity needed is "can receive a code on
// the ntfy topic already on file for this account", which is exactly the
// same trust level the account already relies on for normal login 2FA.
//
// Master intervention (admin-reset-password.js) is only needed for the
// genuinely last-resort case: the admin can no longer receive anything on
// their ntfy topic at all (lost device, uninstalled the app). A merely
// forgotten password is NOT that case — this endpoint handles it entirely.
//
// Response is intentionally identical whether the email exists, is inactive,
// or has no ntfy topic configured — this prevents using "forgot password" as
// an account-enumeration oracle. A code is only actually sent when the
// account genuinely exists, is active, and has a topic on file.

const { json, preflight, parseBody } = require('./_lib/http');
const { signToken, generateOtp, hashOtp } = require('./_lib/crypto');
const { airtableListAll } = require('./_lib/airtable');
const { sendOtpNtfy } = require('./_lib/ntfy');

const RESET_TTL_SECONDS = 10 * 60; // 10 minutes — a little longer than login OTP, since the admin also has to type a new password in the same step

const GENERIC_RESPONSE = { ok: true, message: 'Si ce compte existe et est actif, un code de vérification a été envoyé.' };

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const secret = process.env.ADMIN_TOKEN_SECRET;
  if (!secret) return json(500, { error: 'Server not configured: ADMIN_TOKEN_SECRET missing.' });

  const { email } = parseBody(event);
  if (!email) return json(400, { error: 'Email requis.' });

  try {
    const emailNorm = String(email).trim().toLowerCase();
    const matches = await airtableListAll('Admins', `LOWER({Email})='${emailNorm.replace(/'/g, "\\'")}'`);
    const rec = matches[0];

    // Silently do nothing if the account can't actually receive a code —
    // but always return the SAME response shape either way.
    if (!rec || rec.fields.Actif !== 'Oui' || !rec.fields.NtfyTopic) {
      return json(200, GENERIC_RESPONSE);
    }

    const code = generateOtp();
    await sendOtpNtfy(rec.fields.NtfyTopic, code);

    const resetToken = signToken(
      { typ: 'reset_pending', email: emailNorm, codeHash: hashOtp(code), attempts: 0 },
      secret,
      RESET_TTL_SECONDS
    );

    return json(200, { ...GENERIC_RESPONSE, resetToken, expiresInSeconds: RESET_TTL_SECONDS });
  } catch (e) {
    // Even on unexpected errors, don't leak details — but do surface a 200
    // with the generic message so the UI doesn't dead-end the user.
    return json(200, GENERIC_RESPONSE);
  }
};
