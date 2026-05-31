// /api/telegram-login
//
// Starts the Telegram OAuth flow by 302-redirecting the user's browser
// straight to oauth.telegram.org. Telegram authenticates the user and
// then redirects back to `return_to` (our /api/auth GET handler), which
// verifies the payload, mints a JWT, and redirects to /?token=…
//
// Using a server-side redirect instead of the JS widget avoids the
// popup→postMessage flow, which fails when users sign in by phone number.
//
// Required env vars:
//   TELEGRAM_BOT_TOKEN — bot token from BotFather (the `<bot_id>:<secret>` form)

module.exports = (req, res) => {
  const botId = process.env.TELEGRAM_BOT_TOKEN.split(':')[0];
  const origin = 'https://tasktracker-ten-umber.vercel.app';
  const returnTo = encodeURIComponent(origin + '/api/auth');
  const url = `https://oauth.telegram.org/auth?bot_id=${botId}&origin=${origin}&embed=0&request_access=write&return_to=${returnTo}`;
  res.writeHead(302, { Location: url });
  res.end();
};
