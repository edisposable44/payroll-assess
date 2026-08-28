// netlify/functions/_lib/pushover.js
// Sends the 2FA one-time code via Pushover (https://pushover.net).
//
// Pushover routes messages by "User Key" (tied to the recipient's Pushover
// account/devices) — NOT by phone number. Each admin who needs OTP delivery
// installs the free Pushover app and gives you their personal User Key,
// stored in Airtable on their Admins record (field PushoverUserKey).
//
// Required environment variable:
//   PUSHOVER_API_TOKEN  → your Pushover "Application" token (create one app
//                          in your Pushover dashboard, e.g. "PayrollAssess Admin")

async function sendOtpPush(userKey, code) {
  const APP_TOKEN = process.env.PUSHOVER_API_TOKEN;
  if (!APP_TOKEN) {
    throw new Error('Server not configured: PUSHOVER_API_TOKEN missing.');
  }
  if (!userKey) {
    throw new Error('This admin has no PushoverUserKey configured — cannot send OTP.');
  }

  const params = new URLSearchParams({
    token: APP_TOKEN,
    user: userKey,
    title: 'PayrollAssess — Code de connexion',
    message: `Votre code : ${code}\nValide 5 minutes. Ne le partagez avec personne.`,
    priority: '0',
  });

  const r = await fetch('https://api.pushover.net/1/messages.json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || data.status !== 1) {
    const msg = (data.errors && data.errors.join(', ')) || r.statusText;
    throw new Error('Pushover send failed: ' + msg);
  }
  return true;
}

module.exports = { sendOtpPush };
