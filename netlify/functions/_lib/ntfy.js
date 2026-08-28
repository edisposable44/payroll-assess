// netlify/functions/_lib/ntfy.js
// Sends the 2FA one-time code via ntfy.sh (https://ntfy.sh) — free, open
// source, no account, no phone number, no SMS fee. Replaces Telegram (which
// now charges a one-time SMS verification fee to create an account) and
// Pushover (paid after a 30-day trial).
//
// How it works: ntfy is a simple pub/sub HTTP service. Each admin subscribes
// (via the ntfy app or a browser) to a "topic" — effectively a channel name.
// Anyone who knows a topic name can publish to it or read it on the public
// ntfy.sh server, so the topic itself acts as a shared secret. That's why
// this app NEVER lets a human pick their own topic: generateNtfyTopic() in
// crypto.js creates a long random one server-side, and it's shown ONCE to
// the master admin to relay to the new admin (same pattern as the temporary
// password).
//
// Optional environment variable:
//   NTFY_SERVER  → base URL of the ntfy server (default: https://ntfy.sh).
//                  Set this if you later self-host ntfy for extra privacy.

async function sendOtpNtfy(topic, code) {
  if (!topic) {
    throw new Error('This admin has no NtfyTopic configured — cannot send OTP.');
  }
  const base = (process.env.NTFY_SERVER || 'https://ntfy.sh').replace(/\/+$/, '');
  const url = `${base}/${encodeURIComponent(topic)}`;

  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Title': 'PayrollAssess - Code de connexion',
      'Priority': 'high',
      'Tags': 'closed_lock_with_key',
    },
    body: `Votre code : ${code}\nValide 5 minutes. Ne le partagez avec personne.`,
  });

  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`ntfy send failed (${r.status}): ${text || r.statusText}`);
  }
  return true;
}

module.exports = { sendOtpNtfy };
