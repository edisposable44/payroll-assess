// netlify/functions/_lib/crypto.js
// Zero-dependency security primitives for the admin auth system.
// Uses only Node's built-in `crypto` module — no npm packages to install/bundle.
//
// Design choices (documented for future maintainers):
//   - Password hashing: scrypt (Node built-in), NOT bcrypt. scrypt is a modern,
//     memory-hard KDF with equivalent security properties to bcrypt, and ships
//     in Node core — avoids adding bcryptjs as a dependency that has to survive
//     esbuild bundling in Netlify Functions.
//   - Tokens (session + OTP-challenge): stateless, HMAC-SHA256 signed, base64url
//     encoded "header.payload.signature", similar shape to a JWT but hand-rolled
//     and minimal on purpose ("keep it simple" — no jsonwebtoken dependency).
//     Verification is a constant-time HMAC compare; expiry is enforced via an
//     `exp` (unix ms) claim baked into the payload.
//   - No database-backed session table is needed: because the token itself
//     carries all state (including OTP attempt counters), there is nothing to
//     look up server-side to verify a session or an OTP submission.

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Password hashing (scrypt)
// ---------------------------------------------------------------------------

const SCRYPT_KEYLEN = 64;

/** Hash a plaintext password. Returns "salt:hash" (both hex). Never store the plaintext. */
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(plain), salt, SCRYPT_KEYLEN).toString('hex');
  return `${salt}:${hash}`;
}

/** Verify a plaintext password against a stored "salt:hash" string. Constant-time compare. */
function verifyPassword(plain, stored) {
  if (!stored || typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  try {
    const candidate = crypto.scryptSync(String(plain), salt, SCRYPT_KEYLEN);
    const expected = Buffer.from(hash, 'hex');
    if (candidate.length !== expected.length) return false;
    return crypto.timingSafeEqual(candidate, expected);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Stateless signed tokens
// ---------------------------------------------------------------------------

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

/**
 * Sign a JSON-serializable payload. `ttlSeconds` sets the `exp` claim.
 * Returns a compact "payload.signature" string (base64url of each part).
 */
function signToken(payload, secret, ttlSeconds) {
  if (!secret) throw new Error('signToken: missing secret');
  const body = { ...payload, iat: Date.now(), exp: Date.now() + ttlSeconds * 1000 };
  const payloadB64 = b64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest();
  return `${payloadB64}.${b64url(sig)}`;
}

/**
 * Verify a token produced by signToken(). Returns the decoded payload object,
 * or null if the signature is invalid, malformed, or the token has expired.
 */
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || !secret) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadB64).digest();
  let providedSig;
  try {
    providedSig = b64urlDecode(sigB64);
  } catch {
    return null;
  }
  if (providedSig.length !== expectedSig.length) return null;
  if (!crypto.timingSafeEqual(providedSig, expectedSig)) return null;
  let payload;
  try {
    payload = JSON.parse(b64urlDecode(payloadB64).toString('utf8'));
  } catch {
    return null;
  }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

// ---------------------------------------------------------------------------
// Random generators
// ---------------------------------------------------------------------------

/** 6-digit numeric OTP, zero-padded. */
function generateOtp() {
  return crypto.randomInt(0, 1000000).toString().padStart(6, '0');
}

/** Hash an OTP the same way as a password (short-lived, but never stored in plaintext even inside a signed token). */
function hashOtp(code) {
  return crypto.createHash('sha256').update(String(code)).digest('hex');
}
function verifyOtp(code, hash) {
  const candidate = crypto.createHash('sha256').update(String(code)).digest();
  let expected;
  try {
    expected = Buffer.from(hash, 'hex');
  } catch {
    return false;
  }
  if (candidate.length !== expected.length) return false;
  return crypto.timingSafeEqual(candidate, expected);
}

/** Readable temporary password: 14 chars, mixed alphabet, no ambiguous glyphs (0/O, 1/l/I). */
function generateTempPassword() {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnpqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%*?';
  const all = upper + lower + digits + symbols;
  const pick = (set) => set[crypto.randomInt(0, set.length)];
  let pw = pick(upper) + pick(lower) + pick(digits) + pick(symbols);
  for (let i = pw.length; i < 14; i++) pw += pick(all);
  // shuffle
  const arr = pw.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

/**
 * Random, unguessable ntfy.sh topic name for OTP delivery. Long and random
 * on purpose: a public ntfy.sh topic is effectively "public if guessed", so
 * this doubles as the shared secret between the server and that admin's
 * device (nobody chooses their own topic — see _lib/ntfy.js for why).
 */
function generateNtfyTopic() {
  return 'pa-' + crypto.randomBytes(16).toString('hex'); // pa-<32 hex chars>
}

module.exports = {
  hashPassword, verifyPassword,
  signToken, verifyToken,
  generateOtp, hashOtp, verifyOtp,
  generateTempPassword, generateNtfyTopic,
};
