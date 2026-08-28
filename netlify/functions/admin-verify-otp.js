// netlify/functions/admin-verify-otp.js
// Step 2 of admin authentication: verify the 6-digit Pushover code against the
// hash embedded in the "otp_pending" token from admin-login.js.
//
// Rate limiting without a database: each failed attempt returns a NEW
// otp_pending token with attempts+1, signed with the SAME remaining expiry
// (not reset) — so the attacker gets at most 5 tries within the original
// 5-minute window, enforced purely by signature verification.

const { json, preflight, parseBody } = require('./_lib/http');
const { verifyToken, signToken, verifyOtp } = require('./_lib/crypto');

const SESSION_TTL_SECONDS = 4 * 3600; // 4 hours
const MAX_ATTEMPTS = 5;

exports.handler = async function (event) {
  const pf = preflight(event);
  if (pf) return pf;
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const secret = process.env.ADMIN_TOKEN_SECRET;
  if (!secret) return json(500, { error: 'Server not configured: ADMIN_TOKEN_SECRET missing.' });

  const { tempToken, code } = parseBody(event);
  if (!tempToken || !code) return json(400, { error: 'tempToken et code requis.' });

  const payload = verifyToken(tempToken, secret);
  if (!payload || payload.typ !== 'otp_pending') {
    return json(401, { error: 'Session de vérification invalide ou expirée. Reconnectez-vous.' });
  }
  if (payload.attempts >= MAX_ATTEMPTS) {
    return json(429, { error: 'Trop de tentatives. Reconnectez-vous pour recevoir un nouveau code.' });
  }

  const ok = verifyOtp(code, payload.otpHash);
  if (!ok) {
    const remainingTtl = Math.max(1, Math.floor((payload.exp - Date.now()) / 1000));
    const newTempToken = signToken(
      { typ: 'otp_pending', email: payload.email, role: payload.role, mustChange: payload.mustChange, otpHash: payload.otpHash, attempts: payload.attempts + 1 },
      secret,
      remainingTtl
    );
    const attemptsRemaining = MAX_ATTEMPTS - (payload.attempts + 1);
    return json(401, {
      error: attemptsRemaining > 0 ? `Code incorrect. ${attemptsRemaining} tentative(s) restante(s).` : 'Code incorrect. Reconnectez-vous.',
      tempToken: attemptsRemaining > 0 ? newTempToken : undefined,
    });
  }

  const token = signToken(
    { typ: 'session', email: payload.email, role: payload.role, mustChange: payload.mustChange },
    secret,
    SESSION_TTL_SECONDS
  );
  return json(200, { token, role: payload.role, mustChangePassword: payload.mustChange });
};
