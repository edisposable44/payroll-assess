// netlify/functions/admin-reset-own-password.js
// SELF-SERVICE password recovery, step 2 of 2. Verifies the code sent by
// admin-forgot-password.js and sets a NEW password in the same step — no
// separate "verify then change" round trip, less friction for the admin.
//
// Same stateless rate-limiting pattern as admin-verify-otp.js: each wrong
// code returns a NEW resetToken with attempts+1, signed with the SAME
// remaining expiry (not reset) — max 5 tries within the original 10-minute
// window, enforced purely by signature verification, no database needed.
//
// On success: sets MustChangePassword to 'Non' (the admin just deliberately
// chose it) and, since they've already proven both "knows the code from
// their ntfy device" is unnecessary to repeat, logs them straight into a
// session — no need to make them log in again right after.

const { json, preflight, parseBody } = require('./_lib/http');
const { verifyToken, signToken, verifyOtp, hashPassword } = require('./_lib/crypto');
const { airtableListAll, airtableRequest } = require('./_lib/airtable');

const MAX_ATTEMPTS = 5;
const SESSION_TTL_SECONDS = 4 * 3600;

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

  const secret = process.env.ADMIN_TOKEN_SECRET;
  if (!secret) return json(500, { error: 'Server not configured: ADMIN_TOKEN_SECRET missing.' });

  const { resetToken, code, newPassword } = parseBody(event);
  if (!resetToken || !code || !newPassword) {
    return json(400, { error: 'resetToken, code et newPassword sont requis.' });
  }

  const payload = verifyToken(resetToken, secret);
  if (!payload || payload.typ !== 'reset_pending') {
    return json(401, { error: 'Session de réinitialisation invalide ou expirée. Recommencez.' });
  }
  if (payload.attempts >= MAX_ATTEMPTS) {
    return json(429, { error: 'Trop de tentatives. Recommencez depuis "Mot de passe oublié".' });
  }

  const codeOk = verifyOtp(code, payload.codeHash);
  if (!codeOk) {
    const remainingTtl = Math.max(1, Math.floor((payload.exp - Date.now()) / 1000));
    const newResetToken = signToken(
      { typ: 'reset_pending', email: payload.email, codeHash: payload.codeHash, attempts: payload.attempts + 1 },
      secret,
      remainingTtl
    );
    const attemptsRemaining = MAX_ATTEMPTS - (payload.attempts + 1);
    return json(401, {
      error: attemptsRemaining > 0 ? `Code incorrect. ${attemptsRemaining} tentative(s) restante(s).` : 'Code incorrect. Recommencez depuis "Mot de passe oublié".',
      resetToken: attemptsRemaining > 0 ? newResetToken : undefined,
    });
  }

  const strengthErr = validatePasswordStrength(newPassword);
  if (strengthErr) return json(400, { error: strengthErr, resetToken }); // let them retry the password without burning an attempt

  try {
    const matches = await airtableListAll('Admins', `LOWER({Email})='${payload.email.replace(/'/g, "\\'")}'`);
    const rec = matches[0];
    if (!rec || rec.fields.Actif !== 'Oui') {
      return json(401, { error: 'Compte introuvable ou suspendu.' });
    }

    const hash = hashPassword(newPassword);
    await airtableRequest('Admins', 'PATCH', { fields: { PasswordHash: hash, MustChangePassword: 'Non' } }, rec.id);

    const role = rec.fields.Role === 'Master' ? 'master' : 'admin';
    const canManageQuestions = role === 'master' || rec.fields.CanManageQuestions === 'Oui';
    const token = signToken({ typ: 'session', email: payload.email, role, mustChange: false, canManageQuestions }, secret, SESSION_TTL_SECONDS);

    return json(200, { ok: true, token, role, canManageQuestions });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
