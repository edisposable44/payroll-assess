// netlify/functions/_lib/telegram.js
// Sends the 2FA one-time code via a Telegram Bot — completely free, no trial
// period and no paid tier, unlike Pushover.
//
// One-time setup (see DEPLOIEMENT.md for full walkthrough):
//   1. In Telegram, message @BotFather → /newbot → follow the prompts.
//      BotFather gives you a Bot Token → set it as TELEGRAM_BOT_TOKEN.
//   2. Each admin who needs OTP delivery must open a chat with YOUR bot and
//      send it any message (e.g. "/start") — a Telegram bot can only message
//      a user who has messaged it first; this is a platform-wide anti-spam rule.
//   3. Get that admin's numeric Chat ID (message @userinfobot to see your own
//      ID instantly) and store it in Airtable on their Admins record
//      (field TelegramChatId).

async function sendOtpTelegram(chatId, code) {
  const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
  if (!BOT_TOKEN) {
    throw new Error('Server not configured: TELEGRAM_BOT_TOKEN missing.');
  }
  if (!chatId) {
    throw new Error('This admin has no TelegramChatId configured — cannot send OTP.');
  }

  const text = `🔐 *PayrollAssess — Code de connexion*\n\nVotre code : \`${code}\`\nValide 5 minutes. Ne le partagez avec personne.`;

  const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || !data.ok) {
    const msg = data.description || r.statusText;
    // Most common failure: the admin never messaged the bot first (Telegram
    // returns "Forbidden: bot can't initiate conversation with a user").
    throw new Error('Telegram send failed: ' + msg);
  }
  return true;
}

module.exports = { sendOtpTelegram };
