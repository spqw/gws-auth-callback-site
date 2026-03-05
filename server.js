const express = require('express');
const crypto = require('crypto');

const app = express();
const port = Number(process.env.PORT || 3000);

const cfg = {
  clientId: process.env.GOOGLE_CLIENT_ID || '',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  redirectUri: process.env.GOOGLE_REDIRECT_URI || 'https://gws.spqw.net/oauth/callback',
  quotaProjectId: process.env.GOOGLE_QUOTA_PROJECT_ID || 'citric-abbey-489317-a6',
  loginHint: process.env.GOOGLE_LOGIN_HINT || 'jihoon00023@gmail.com',
  scopes:
    process.env.GOOGLE_SCOPES ||
    [
      'https://www.googleapis.com/auth/drive',
      'https://www.googleapis.com/auth/spreadsheets',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/calendar',
      'https://www.googleapis.com/auth/documents',
      'https://www.googleapis.com/auth/presentations',
      'https://www.googleapis.com/auth/tasks',
      'https://www.googleapis.com/auth/pubsub',
      'https://www.googleapis.com/auth/cloud-platform',
    ].join(' '),
};

function page(title, body) {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>${title}</title>
<style>
:root { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
body { margin:0; background:linear-gradient(160deg,#eff6ff,#f8fafc); color:#0f172a; }
main { max-width: 680px; margin: 0 auto; padding: 20px 16px 44px; }
.card { background:#fff; border:1px solid #dbe3ee; border-radius:16px; padding:16px; box-shadow: 0 10px 24px rgba(15,23,42,.08);} 
h1 { font-size: 1.2rem; margin:0 0 10px; }
p { margin: 10px 0; line-height:1.45; }
.btn { display:inline-block; background:#0f766e; color:#fff; text-decoration:none; border-radius:10px; padding:12px 14px; font-weight:600; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break:break-all; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:10px; }
pre { background:#0f172a; color:#e2e8f0; border-radius:10px; padding:12px; overflow:auto; font-size:.8rem; }
.note { color:#475569; font-size:.93rem; }
.warn { color:#7c2d12; background:#ffedd5; border:1px solid #fed7aa; padding:10px; border-radius:8px; }
</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'gws-auth-callback-site' });
});

app.get('/', (_req, res) => {
  const ready = cfg.clientId && cfg.clientSecret;
  res.send(
    page(
      'GWS OAuth Helper',
      `<section class="card">
        <h1>GWS OAuth Callback Helper</h1>
        <p class="note">This page handles Google OAuth callback and generates a ready-to-use <span class="mono">credentials.json</span> for <span class="mono">gws</span>.</p>
        ${
          ready
            ? `<p><a class="btn" href="/auth/start">Start Google Login</a></p>`
            : `<p class="warn">Server is missing OAuth env vars. Set <span class="mono">GOOGLE_CLIENT_ID</span> and <span class="mono">GOOGLE_CLIENT_SECRET</span>.</p>`
        }
        <p class="note">Redirect URI configured: <span class="mono">${cfg.redirectUri}</span></p>
      </section>`
    )
  );
});

app.get('/auth/start', (_req, res) => {
  if (!cfg.clientId || !cfg.clientSecret) {
    res.status(500).send('Missing OAuth config on server.');
    return;
  }
  const params = new URLSearchParams({
    scope: cfg.scopes,
    access_type: 'offline',
    include_granted_scopes: 'true',
    response_type: 'code',
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
    prompt: 'consent',
    login_hint: cfg.loginHint,
  });
  res.redirect(`https://accounts.google.com/o/oauth2/auth?${params.toString()}`);
});

app.get('/oauth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) {
    res.status(400).send(page('OAuth Error', `<section class="card"><h1>OAuth error</h1><p class="warn">${String(error)}</p></section>`));
    return;
  }
  if (!code) {
    res.status(400).send(page('Missing Code', `<section class="card"><h1>Missing code</h1><p>No authorization code in callback.</p></section>`));
    return;
  }

  try {
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        code: String(code),
        grant_type: 'authorization_code',
        redirect_uri: cfg.redirectUri,
      }),
    });

    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok || !tokenJson.refresh_token) {
      res.status(400).send(
        page(
          'Token Exchange Failed',
          `<section class="card"><h1>Token exchange failed</h1><p class="warn">Google did not return a refresh token.</p><pre>${JSON.stringify(tokenJson, null, 2)}</pre></section>`
        )
      );
      return;
    }

    const credentials = {
      type: 'authorized_user',
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      refresh_token: tokenJson.refresh_token,
      quota_project_id: cfg.quotaProjectId,
    };

    const payload = Buffer.from(JSON.stringify(credentials, null, 2)).toString('base64url');
    const sig = crypto.createHmac('sha256', cfg.clientSecret).update(payload).digest('base64url');

    res.send(
      page(
        'OAuth Success',
        `<section class="card">
          <h1>Success</h1>
          <p>Download your <span class="mono">credentials.json</span> and place it at <span class="mono">~/.config/gws/credentials.json</span>.</p>
          <p><a class="btn" href="/download?payload=${encodeURIComponent(payload)}&sig=${encodeURIComponent(sig)}">Download credentials.json</a></p>
          <p class="note">Then run:</p>
          <pre>gws auth status\ngws drive files list --params '{"pageSize":1}'</pre>
        </section>`
      )
    );
  } catch (err) {
    res.status(500).send(page('Server Error', `<section class="card"><h1>Server error</h1><pre>${String(err)}</pre></section>`));
  }
});

app.get('/download', (req, res) => {
  const { payload, sig } = req.query;
  if (!payload || !sig) {
    res.status(400).send('Invalid download request');
    return;
  }
  const expected = crypto.createHmac('sha256', cfg.clientSecret).update(String(payload)).digest('base64url');
  if (expected !== sig) {
    res.status(403).send('Invalid signature');
    return;
  }

  const raw = Buffer.from(String(payload), 'base64url').toString('utf8');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="credentials.json"');
  res.send(raw);
});

app.listen(port, () => {
  console.log(`gws auth callback helper listening on ${port}`);
});
