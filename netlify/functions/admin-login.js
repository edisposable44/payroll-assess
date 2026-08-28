// netlify/functions/admin-login.js
// Step 1 of admin authentication: verify email + password.
// On success, generates a 6-digit OTP, sends it via ntfy.sh, and returns a
// short-lived, stateless "otp_pending" token that embeds the OTP's hash (not
// the OTP itself) — admin-verify-otp.js checks the code against this token.
//
// Error messages stay generic ("Identifiants incorrects") for any wrong
// email/password combination, to avoid account enumeration. The ONE
// exception: once the PASSWORD has been verified correct, a suspended
// account gets a clear, specific message — at that point the person has
// already proven they own the credentials, so telling them "your account is
// suspended, contact the master admin" leaks nothing an attacker could use,
// and saves a suspended (but legitimate) admin from assuming they simply
// forgot their password and retrying self-service reset for no reason.

const { json, preflight, parseBody } = require('./_lib/http');
const { verifyPassword, signToken, generateOtp, hashOtp } = require('./_lib/crypto');
const { airtableListAll } = require('./_lib/airtable');
const { sendOtpNtfy } = require('./_lib/ntfy');

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

    // Always run verifyPassword even if rec is missing (dummy hash) so the
    // response time doesn't itself reveal whether the email exists.
    const ok = verifyPassword(password, rec ? rec.fields.PasswordHash : 'dummysalt:dummyhash');
    if (!rec || !ok) return json(401, GENERIC_FAIL);

    // Password is correct beyond this point — safe to be specific.
    if (rec.fields.Actif !== 'Oui') {
      return json(403, { error: 'Ce compte a été suspendu. Contactez le master admin.' });
    }

    const role = rec.fields.Role === 'Master' ? 'master' : 'admin';
    const mustChange = rec.fields.MustChangePassword === 'Oui';
    const canManageQuestions = role === 'master' || rec.fields.CanManageQuestions === 'Oui';
    const requireOtp = process.env.REQUIRE_OTP !== 'false'; // default ON

    if (!requireOtp) {
      const token = signToken({ typ: 'session', email: emailNorm, role, mustChange, canManageQuestions }, secret, 4 * 3600);
      return json(200, { stage: 'ok', token, role, mustChangePassword: mustChange, canManageQuestions });
    }

    if (!rec.fields.NtfyTopic) {
      return json(400, {
        error: "Aucun canal de notification configuré. Contactez le master admin pour l'ajouter avant de pouvoir vous connecter.",
      });
    }

    const otp = generateOtp();
    await sendOtpNtfy(rec.fields.NtfyTopic, otp);

    const tempToken = signToken(
      { typ: 'otp_pending', email: emailNorm, role, mustChange, canManageQuestions, otpHash: hashOtp(otp), attempts: 0 },
      secret,
      OTP_TTL_SECONDS
    );

    return json(200, { stage: 'otp', tempToken, expiresInSeconds: OTP_TTL_SECONDS });
  } catch (e) {
    return json(500, { error: 'Erreur serveur : ' + e.message });
  }
};
