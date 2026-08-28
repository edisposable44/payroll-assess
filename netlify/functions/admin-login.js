// netlify/functions/admin-login.js
// Step 1 of admin authentication: verify email + password.
// On success, generates a 6-digit OTP, sends it via Telegram Bot, and returns a
// short-lived, stateless "otp_pending" token that embeds the OTP's hash (not
// the OTP itself) — admin-verify-otp.js checks the code against this token.
//
// Deliberately generic error messages (never reveal whether the email exists
// or the password was wrong) to avoid account enumeration.

const { json, preflight, parseBody } = require('./_lib/http');
const { verifyPassword, signToken, generateOtp, hashOtp } = require('./_lib/crypto');
const { airtableListAll } = require('./_lib/airtable');
const { sendOtpTelegram } = require('./_lib/telegram');

const OTP_TTL_SECONDS = 5 * 60; // 5 minutes

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const secret = process.env.ADMIN_TOKEN_SECRET;
  if (!secret) return json(500, { error: 'Server not configured: ADMIN_TOKEN_SECRET missing.' });

  const { email, password } = parseBody(event);
  if (!email || !password) return json(400, { error: 'Email et mot de passe requis.' });

  const GENERIC_FAIL = { error: 'Identifiants incorrects.' };

  try {
    const emailNorm = String(email).trim().toLowerCase();
    const matches = await airtableListAll('Admins', `LOWER({Email})='${emailNorm.replace(/'/g, "\\'")}'`);
    const rec = matches[0];
    if (!rec || rec.fields.Actif !== 'Oui') return json(401, GENERIC_FAIL);

    const ok = verifyPassword(password, rec.fields.PasswordHash);
    if (!ok) return json(401, GENERIC_FAIL);

    const role = rec.fields.Role === 'Master' ? 'master' : 'admin';
    const mustChange = rec.fields.MustChangePassword === 'Oui';
    const requireOtp = process.env.REQUIRE_OTP !== 'false'; // default ON

    if (!requireOtp) {
      const token = signToken({ typ: 'session', email: emailNorm, role, mustChange }, secret, 4 * 3600);
      return json(200, { stage: 'ok', token, role, mustChangePassword: mustChange });
    }

    if (!rec.fields.TelegramChatId) {
      return json(400, {
        error: "Aucun compte Telegram configuré. Contactez le master admin pour l'ajouter avant de pouvoir vous connecter.",
      });
    }

    const otp = generateOtp();
    await sendOtpTelegram(rec.fields.TelegramChatId, otp);

    const tempToken = signToken(
      { typ: 'otp_pending', email: emailNorm, role, mustChange, otpHash: hashOtp(otp), attempts: 0 },
      secret,
      OTP_TTL_SECONDS
    );

    return json(200, { stage: 'otp', tempToken, expiresInSeconds: OTP_TTL_SECONDS });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
