require('dotenv').config();

const express  = require('express');
const session  = require('express-session');
const path     = require('path');
const fs       = require('fs');
const https    = require('https');
const bcrypt   = require('bcrypt');
const crypto   = require('crypto');
const db       = require('./db/db');

// Fingerprint Node SDK — exact implementation from docs
// https://docs.fingerprint.com/docs/sealed-client-results
// Package: @fingerprint/node-sdk (v7.0+)
// Install: npm install @fingerprint/node-sdk
let unsealEventsResponse, DecryptionAlgorithm;
try {
  const fpSdk = require('@fingerprint/node-sdk');
  unsealEventsResponse = fpSdk.unsealEventsResponse;
  DecryptionAlgorithm  = fpSdk.DecryptionAlgorithm;
  if (!unsealEventsResponse) throw new Error('unsealEventsResponse not found in exports');
  console.log('✅  @fingerprint/node-sdk loaded — sealed results enabled');
} catch(e) {
  console.warn('⚠️  @fingerprint/node-sdk not loaded:', e.message);
  console.warn('    Run: npm install @fingerprint/node-sdk\n');
}

const app  = express();
const PORT = process.env.PORT || 3000;

if (!process.env.FP_PUBLIC_KEY)  console.warn('\n⚠️  FP_PUBLIC_KEY not set in .env\n');
if (!process.env.FP_API_KEY)     console.warn('⚠️  FP_API_KEY not set — Server API fallback will not work\n');
if (!process.env.FP_SEALED_KEY)  console.warn('⚠️  FP_SEALED_KEY not set — sealed results will fall back to Server API\n');
if (!process.env.DATABASE_URL)   console.warn('⚠️  DATABASE_URL not set — database features will not work\n');

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = {
  SIGNAL_TTL_MINUTES:   10,   // Server API cache window
  SUSPECT_THRESHOLD:    12,   // Suspect score step-up trigger
  VIDEO_LIMIT:          3,    // Free videos per device
  HEARTBEAT_TTL_MINS:   5,    // Session considered dead after 5 min no heartbeat
};

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret:            process.env.SESSION_SECRET || 'fp-university-dev-secret',
  resave:            false,
  saveUninitialized: false,
  cookie:            { maxAge: 24 * 60 * 60 * 1000 },
}));

function requireAuth(req, res, next) {
  if (req.session.email && req.session.visitorId) return next();
  res.status(401).json({ ok: false, error: 'Not authenticated' });
}

// ── Single-session + heartbeat middleware ─────────────────────────────────────
async function requireValidSession(req, res, next) {
  const clientToken = req.headers['x-session-token'];
  const visitorId   = req.session.visitorId;

  if (!clientToken || !visitorId) return next();

  try {
    const dev = await getDevice(visitorId);

    // 1. Token mismatch — displaced by a newer login on the same device
    if (dev?.active_session_token && dev.active_session_token !== clientToken) {
      return res.status(401).json({
        ok: false, reason: 'session_displaced',
        error: 'You have been signed in on another window or device. This session has ended.',
      });
    }

    // 2. Heartbeat TTL — session went stale (tab was closed without logout)
    if (dev?.session_last_seen_at) {
      const staleMins = (Date.now() - new Date(dev.session_last_seen_at).getTime()) / 60000;
      if (staleMins > CONFIG.HEARTBEAT_TTL_MINS) {
        return res.status(401).json({
          ok: false, reason: 'session_expired',
          error: 'Your session has expired due to inactivity. Please sign in again.',
        });
      }
    }

    // 3. Cross-device check — has the user logged in from a different device since?
    if (req.session.email) {
      const { rows } = await db.query(
        'SELECT active_visitor_id FROM users WHERE email = $1', [req.session.email]);
      const activeVid = rows[0]?.active_visitor_id;
      if (activeVid && activeVid !== visitorId) {
        return res.status(401).json({
          ok: false, reason: 'session_displaced',
          error: 'You have signed in from a different device. This session has ended.',
        });
      }
    }
  } catch(e) {
    console.error('[session check]', e.message);
    // Non-fatal — don't block on DB failure
  }
  next();
}

// Combined auth + session check used by all protected routes
function requireAuthAndSession(req, res, next) {
  if (!req.session.email || !req.session.visitorId) {
    return res.status(401).json({ ok: false, error: 'Not authenticated' });
  }
  requireValidSession(req, res, next);
}

function serveWithKey(res, filename) {
  const html = fs.readFileSync(path.join(__dirname, 'public', filename), 'utf8')
    .replace(/__FP_PUBLIC_KEY__/g, process.env.FP_PUBLIC_KEY || '');
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
}

// ── Pages ─────────────────────────────────────────────────────────────────────
app.get('/',          (req, res) => { if (req.session.email) return res.redirect('/videos'); serveWithKey(res, 'login.html'); });
app.get('/videos', (req, res) => {
  if (!req.session.email) return res.redirect('/');
  // Prevent back/forward cache restoring a stale authenticated page.
  // The pageshow listener in videos.html re-validates on persisted restore.
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  serveWithKey(res, 'videos.html');
});
app.get('/contact',   (req, res) => serveWithKey(res, 'contact.html'));
app.get('/admin',     (req, res) => { if (!req.session.email) return res.redirect('/'); serveWithKey(res, 'admin.html'); });
app.get('/reset-password', (req, res) => serveWithKey(res, 'reset-password.html'));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────────────────────────
// DATABASE HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function upsertDevice(visitorId, fields = {}) {
  const { activeEmail, suspectScore, vpn, highActivity, fpSignals, lastApiCallAt,
          activeSessionToken, sessionStartedAt, sessionLastSeenAt } = fields;
  await db.query(`
    INSERT INTO devices
      (visitor_id, active_email, suspect_score, vpn, high_activity, fp_signals,
       last_api_call_at, active_session_token, session_started_at, session_last_seen_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
    ON CONFLICT (visitor_id) DO UPDATE SET
      active_email          = COALESCE($2,  devices.active_email),
      suspect_score         = COALESCE($3,  devices.suspect_score),
      vpn                   = COALESCE($4,  devices.vpn),
      high_activity         = COALESCE($5,  devices.high_activity),
      fp_signals            = COALESCE($6,  devices.fp_signals),
      last_api_call_at      = COALESCE($7,  devices.last_api_call_at),
      active_session_token  = COALESCE($8,  devices.active_session_token),
      session_started_at    = COALESCE($9,  devices.session_started_at),
      session_last_seen_at  = COALESCE($10, devices.session_last_seen_at),
      updated_at            = NOW()
  `, [visitorId,
      activeEmail          ?? null,
      suspectScore         ?? null,
      vpn                  ?? null,
      highActivity         ?? null,
      fpSignals            ? JSON.stringify(fpSignals) : null,
      lastApiCallAt        ?? null,
      activeSessionToken   ?? null,
      sessionStartedAt     ?? null,
      sessionLastSeenAt    ?? null]);
}

async function getDevice(visitorId) {
  const { rows } = await db.query('SELECT * FROM devices WHERE visitor_id = $1', [visitorId]);
  return rows[0] || null;
}

// Returns true if the last Server API call for this device is within the TTL window.
// When true, routes should use DB-cached signals instead of making a fresh API call.
function signalsAreFresh(dev) {
  if (!dev?.last_api_call_at) return false;
  const ageMinutes = (Date.now() - new Date(dev.last_api_call_at).getTime()) / 60000;
  return ageMinutes < CONFIG.SIGNAL_TTL_MINUTES;
}

async function getVideoViews(visitorId, email) {
  // Return watched video IDs for this device OR this email account.
  // Using UNION to combine both lookups so either match counts.
  const { rows } = await db.query(`
    SELECT DISTINCT video_id FROM video_views
    WHERE visitor_id = $1
       OR LOWER(email) = LOWER($2)
  `, [visitorId, email || '']);
  return rows.map(r => r.video_id);
}

async function getCert(visitorId, email) {
  // Return certification record for this device OR this email account.
  const { rows } = await db.query(`
    SELECT * FROM certifications
    WHERE visitor_id = $1
       OR LOWER(email) = LOWER($2)
    ORDER BY submitted_at DESC NULLS LAST
    LIMIT 1
  `, [visitorId, email || '']);
  return rows[0] || null;
}

async function getReview(visitorId, email) {
  // Return review for this device OR this email account.
  const { rows } = await db.query(`
    SELECT * FROM reviews
    WHERE visitor_id = $1
       OR LOWER(email) = LOWER($2)
    ORDER BY submitted_at DESC NULLS LAST
    LIMIT 1
  `, [visitorId, email || '']);
  return rows[0] || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// FINGERPRINT HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function logFpApiCall(event, visitorId, uiTrigger, signals = {}) {
  try {
    await db.query(
      `INSERT INTO fp_api_log (visitor_id, event, ui_trigger, signals) VALUES ($1,$2,$3,$4)`,
      [visitorId || null, event, uiTrigger || null, JSON.stringify(signals)]
    );
  } catch (e) { console.error('[FP log]', e.message); }
}

async function saveSmartSignals(visitorId, requestId, uiTrigger, products) {
  const p     = products || {};
  const id    = p.identification?.data || {};
  const bot   = p.botd?.data?.bot || {};
  const vpnD  = p.vpn?.data || {};
  const ip4   = p.ipInfo?.data?.v4 || {};
  const geo   = ip4.geolocation || {};
  try {
    await db.query(`
      INSERT INTO smart_signals (
        visitor_id,request_id,ui_trigger,
        confidence,first_seen_at,last_seen_at,
        incognito,vpn,proxy,tor,tampering,high_activity,location_spoofing,
        bot_result,bot_type,suspect_score,
        ip_v4_address,ip_country,ip_city,ip_timezone,vpn_origin_country,raw
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
      [ visitorId, requestId, uiTrigger || null,
        id.confidence?.score??null, id.firstSeenAt?.global??null, id.lastSeenAt?.global??null,
        p.incognito?.data?.result??null, vpnD.result??null, p.proxy?.data?.result??null,
        p.tor?.data?.result??null, p.tampering?.data?.result??null, p.highActivity?.data?.result??null,
        p.locationSpoofing?.data?.result??null, bot.result??null, bot.type??null,
        p.suspectScore?.data?.result??null, ip4.address??null, geo.country?.name??null,
        geo.city?.name??null, geo.timezone??null, vpnD.originCountry??null,
        JSON.stringify(products) ]
    );
  } catch (e) { console.error('[saveSmartSignals]', e.message); }
}

function fpServerApiGet(apiPath) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'ap.api.fpjs.io', path: apiPath, method: 'GET',
      headers: { 'Auth-API-Key': process.env.FP_API_KEY, 'Accept': 'application/json' },
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(data) }); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.end();
  });
}

// Core Server API fetch — always calls the API, updates DB, returns flat signals.
// All routes that need FRESH signals call this directly.
async function fetchAndCacheSignals(visitorId, requestId, uiTrigger) {
  if (!process.env.FP_API_KEY) return null;
  const { status, body } = await fpServerApiGet(`/events/${requestId}`);
  if (status !== 200) {
    await logFpApiCall('smart-signals — ERROR', visitorId, uiTrigger, { status, error: body?.error?.message });
    return null;
  }
  const p               = body.products || {};
  const freshScore      = p.suspectScore?.data?.result ?? null;
  const freshVpn        = p.vpn?.data?.result === true;
  const now             = new Date();

  await upsertDevice(visitorId, {
    suspectScore: freshScore, vpn: freshVpn, lastApiCallAt: now,
    fpSignals: { suspectScore: freshScore, vpn: freshVpn, lastApiCallAt: now.toISOString() },
  });
  await logFpApiCall('smart-signals (Server API)', visitorId, uiTrigger, {
    incognito: p.incognito?.data?.result, vpn: p.vpn?.data?.result,
    bot: p.botd?.data?.bot?.result, suspectScore: freshScore,
  });
  await saveSmartSignals(visitorId, requestId, uiTrigger, body.products);

  return { products: p, freshScore, freshVpn, raw: body };
}

// ── Unseal sealed client results ─────────────────────────────────────────────
// Called when the JS agent (v4) returns a sealed_result blob instead of plain data.
// Eliminates the separate Server API call at login time — one round trip instead of two.
// Falls back to the regular Server API if:
//   - FP_SEALED_KEY is not set
//   - The SDK is not installed
//   - Unsealing fails (e.g. wrong key, corrupted blob)
// ── Unseal sealed client results ─────────────────────────────────────────────
// Exact implementation from: https://docs.fingerprint.com/docs/sealed-client-results
// Requires @fingerprint/node-sdk v7.0+
async function unsealResult(sealedResultBase64) {
  if (!unsealEventsResponse || !DecryptionAlgorithm) {
    throw new Error('@fingerprint/node-sdk not available — run: npm install @fingerprint/node-sdk');
  }
  if (!process.env.FP_SEALED_KEY) {
    throw new Error('FP_SEALED_KEY not set in .env');
  }

  const unsealedData = await unsealEventsResponse(
    Buffer.from(sealedResultBase64, 'base64'),
    [
      {
        key:       Buffer.from(process.env.FP_SEALED_KEY.trim(), 'base64'),
        algorithm: DecryptionAlgorithm.Aes256Gcm,
      },
    ]
  );

  console.log('[FP] ✅ Sealed result unsealed successfully');
  return unsealedData;
}

// ── Extract flat signals from unsealed v4 payload ─────────────────────────────
// Structure confirmed from live payload dump — all values are PRIMITIVE (no .result wrapper):
// bot: "not_detected" | "bad"        (string)
// vpn: false | true                  (boolean)
// incognito: false | true            (boolean)
// suspect_score: 12                  (number)
// proxy: true | false                (boolean)
// ip_address: "1.2.3.4"             (string, top-level)
// ip_info.v4.geolocation.city_name  (note: city_name not city.name)
// ip_info.v4.geolocation.country_name (note: country_name not country.name)
// ip_info.v4.geolocation.timezone   (string)
// identification.visitor_id          (string)
// identification.confidence.score    (number)
// identification.first_seen_at       (unix ms)
// identification.last_seen_at        (unix ms)
function extractSignalsFromProducts(p) {
  if (!p) return {};

  // ── v4 sealed format (flat, primitives, snake_case) ──────────────────────────
  if (p.identification && p.identification.visitor_id !== undefined) {
    const id  = p.identification;
    const geo = p.ip_info?.v4?.geolocation || {};
    const toISO = ms => ms ? new Date(ms).toISOString() : null;
    return {
      visitorId:        id.visitor_id          || null,
      requestId:        p.event_id             || null,
      confidence:       id.confidence?.score   ?? null,
      firstSeenAt:      toISO(id.first_seen_at),
      lastSeenAt:       toISO(id.last_seen_at),
      // Primitives — NO .result wrapper in v4
      incognito:        p.incognito            ?? null,   // boolean
      bot:              p.bot                  ?? null,   // "not_detected" | "bad"
      botType:          null,                             // not in v4 payload
      vpn:              p.vpn                  ?? null,   // boolean
      proxy:            p.proxy                ?? null,   // boolean
      tor:              p.ip_blocklist?.tor_node ?? null, // boolean (in ip_blocklist)
      tampering:        p.tampering            ?? null,   // boolean
      highActivity:     p.high_activity_device ?? null,  // boolean
      locationSpoofing: null,                             // not in v4 payload
      suspectScore:     p.suspect_score        ?? null,   // number
      vpnMethods:       p.vpn_methods          ?? null,
      originCountry:    null,                             // use vpn_origin_timezone instead
      // ip_info — note field names: city_name, country_name (not city.name, country.name)
      ipInfo:           { v4: p.ip_info?.v4, v6: p.ip_info?.v6 },
      ipTimezone:       geo.timezone           || null,
      ipCountry:        geo.country_name       || null,   // country_name not country.name
      ipCity:           geo.city_name          || null,   // city_name not city.name
      ipAddress:        p.ip_address           || null,   // top-level, not nested
    };
  }

  // ── v3 Server API format (nested .data, camelCase) ───────────────────────────
  // Used when falling back to Server API (Smart Signals tab, cert/review submit)
  if (p.identification?.data) {
    const id   = p.identification.data;
    const bot  = p.botd?.data?.bot || {};
    const vpnD = p.vpn?.data || {};
    const ip4  = p.ipInfo?.data?.v4 || {};
    const geo  = ip4.geolocation || {};
    return {
      visitorId:        id.visitorId                    || null,
      requestId:        id.requestId                    || null,
      confidence:       id.confidence?.score            ?? null,
      firstSeenAt:      id.firstSeenAt?.global          ?? null,
      lastSeenAt:       id.lastSeenAt?.global           ?? null,
      incognito:        p.incognito?.data?.result       ?? null,
      bot:              bot.result                      ?? null,
      botType:          bot.type                        ?? null,
      vpn:              vpnD.result                     ?? null,
      vpnMethods:       vpnD.methods                    ?? null,
      originCountry:    vpnD.originCountry              ?? null,
      proxy:            p.proxy?.data?.result           ?? null,
      tor:              p.tor?.data?.result             ?? null,
      tampering:        p.tampering?.data?.result       ?? null,
      highActivity:     p.highActivity?.data?.result    ?? null,
      locationSpoofing: p.locationSpoofing?.data?.result ?? null,
      suspectScore:     p.suspectScore?.data?.result    ?? null,
      ipInfo:           { v4: ip4, v6: p.ipInfo?.data?.v6 },
      ipTimezone:       geo.timezone                    ?? null,
      ipCountry:        geo.country?.name               ?? null,
      ipCity:           geo.city?.name                  ?? null,
      ipAddress:        ip4.address                     ?? null,
    };
  }

  console.warn('[FP] extractSignals: unrecognised payload format, keys:', Object.keys(p));
  return {};
}

app.post('/api/signup', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ ok: false, error: 'Email, password and name are required.' });
  if (password.length < 6)
    return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters.' });
  try {
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (existing.rows.length)
      return res.status(409).json({ ok: false, error: 'An account with that email already exists.' });
    const hash = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (email, password_hash, name) VALUES ($1,$2,$3)',
      [email.toLowerCase().trim(), hash, name.trim()]);
    // Never echo password or hash back in the response
    res.json({ ok: true });
  } catch (e) {
    console.error('[signup]', e.message);
    res.status(500).json({ ok: false, error: 'Sign up failed. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ ok: false, error: 'Email and password are required.' });
  try {
    const { rows } = await db.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (!rows.length) return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
    req.session.email  = rows[0].email;
    req.session.userId = rows[0].id;
    // Never echo password_hash or any credential back in the response
    res.json({ ok: true, name: rows[0].name });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ ok: false, error: 'Login failed. Please try again.' });
  }
});

app.post('/api/logout', async (req, res) => {
  const vid   = req.session.visitorId;
  const email = req.session.email;
  try {
    if (vid) await db.query(
      `UPDATE devices SET active_session_token = NULL, active_email = NULL,
       session_last_seen_at = NULL WHERE visitor_id = $1`, [vid]);
    if (email) await db.query(
      'UPDATE users SET active_visitor_id = NULL WHERE email = $1', [email]);
  } catch(e) { console.error('[logout]', e.message); }
  req.session.destroy();
  res.json({ ok: true });
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ ok: false, error: 'Email is required.' });
  res.json({ ok: true, message: 'If that email exists, a reset link has been sent.' });
  try {
    const { rows } = await db.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (!rows.length) return;
    await db.query('UPDATE password_resets SET used = TRUE WHERE email = $1', [email]);
    const token = crypto.randomBytes(32).toString('hex');
    await db.query('INSERT INTO password_resets (email, token, expires_at) VALUES ($1,$2,$3)',
      [email.toLowerCase().trim(), token, new Date(Date.now() + 3600000)]);
    const resetUrl = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${token}`;
    console.log(`\n🔑 Password reset link for ${email}:\n   ${resetUrl}\n`);
  } catch (e) { console.error('[forgot-password]', e.message); }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ ok: false, error: 'Token and password required.' });
  if (password.length < 6) return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters.' });
  try {
    const { rows } = await db.query(
      `SELECT * FROM password_resets WHERE token = $1 AND used = FALSE AND expires_at > NOW()`, [token]);
    if (!rows.length) return res.status(400).json({ ok: false, error: 'Reset link is invalid or has expired.' });
    const hash = await bcrypt.hash(password, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE email = $2', [hash, rows[0].email]);
    await db.query('UPDATE password_resets SET used = TRUE WHERE token = $1', [token]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: 'Reset failed.' }); }
});

// ─────────────────────────────────────────────────────────────────────────────
// FINGERPRINT ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// ── Register visitor ID + unseal sealed result ────────────────────────────────
// Accepts either:
//   (a) sealedResult (base64 blob from JS agent v4) — decrypted here, no Server API needed
//   (b) visitorId + requestId (JS agent v3 fallback) — used when sealed key not active yet
//
// In both cases, generates a session token, sets active_visitor_id on the user,
// and returns signals to the client.
app.post('/api/fp/identify', async (req, res) => {
  if (!req.session.email) return res.status(401).json({ ok: false, error: 'Login first.' });

  // Diagnostic — log everything that arrives so we can see what the client is sending
  // Accept exact field names from docs (event_id, sealed_result_base64)
  // plus fallback camelCase names used before sealed key was active
  const {
    sealed_result_base64,          // doc field name (Step 3)
    sealedResult,                  // our previous field name (fallback)
    event_id,                      // doc field name
    eventId,                       // our previous field name
    visitorId:   rawVisitorId,
    requestId:   rawRequestId,
    confidence, incognito, bot, suspectScore, vpn, highActivity,
  } = req.body;

  const sealedPayload  = sealed_result_base64 || sealedResult || null;
  const rawRequestId2  = event_id || eventId || rawRequestId;

  try {
    let signals    = null;
    let products   = null;
    let visitorId  = rawVisitorId;
    let requestId  = rawRequestId2;
    let usedSealed = false;

    // ── Path A: Sealed result — decrypt server-side ──────────────────────────
    // IMPORTANT: when sealed key is ACTIVE in Dashboard, the v4 agent strips
    // visitor_id from the client payload. visitorId must come from the unsealed
    // result here. If sealedResult is present but FP_SEALED_KEY is not set,
    // the unseal will fail and we fall through to Path B.
    if (sealedPayload) {
      try {
        const unsealed = await unsealResult(sealedPayload);
        products  = unsealed;
        signals   = extractSignalsFromProducts(unsealed);
        visitorId = signals.visitorId;
        requestId = signals.requestId || rawRequestId2;
        usedSealed = true;
        console.log(`[FP] ✅ Sealed result unsealed — visitorId: ${visitorId}, suspect: ${signals.suspectScore}, vpn: ${signals.vpn}, incognito: ${signals.incognito}`);
      } catch(sealErr) {
        console.warn('[FP] Sealed unseal failed:', sealErr.message);
        // Fallback: call Server API using the eventId to get visitorId + signals.
        // This happens when: sealed key is active (so client strips visitorId) but
        // our FP_SEALED_KEY doesn't match yet. The Server API is the safety net.
        if (rawRequestId2 && process.env.FP_API_KEY) {
          console.log('[FP] Falling back to Server API using eventId:', rawRequestId2);
          try {
            const { status, body } = await fpServerApiGet(`/events/${rawRequestId2}`);
            console.log('[FP] Server API response status:', status);
            console.log('[FP] Server API body ok:', !!body, '| has products:', !!(body && body.products));
            if (status === 200 && body.products) {
              products  = body.products;
              signals   = extractSignalsFromProducts(products);
              visitorId = signals.visitorId;
              requestId = rawRequestId2;
              console.log(`[FP] Server API fallback succeeded — visitorId: ${visitorId}`);
            } else {
              console.warn('[FP] Server API returned non-200 or no products:', status, JSON.stringify(body).slice(0, 200));
            }
          } catch(apiErr) {
            console.warn('[FP] Server API fallback exception:', apiErr.message);
          }
        } else {
          console.warn('[FP] Skipping Server API fallback — rawRequestId2:', rawRequestId2, '| FP_API_KEY set:', !!process.env.FP_API_KEY);
        }
      }
    }

    // ── Path B: No sealed result and no visitorId ─────────────────────────────
    // This should only happen if: sealed key is active, sealed decryption failed,
    // AND Server API fallback failed. Log everything to help diagnose.
    if (!visitorId) {
      console.error('[FP] No visitorId available. sealedPayload present:', !!sealedPayload,
        '| rawVisitorId:', rawVisitorId, '| eventId:', rawRequestId2);
      return res.status(400).json({
        ok: false,
        error: sealedPayload
          ? 'Could not identify device — sealed decryption failed and Server API fallback failed. Check FP_SEALED_KEY and FP_API_KEY in .env.'
          : 'visitorId required.',
      });
    }

    const sessionToken = crypto.randomUUID();
    const now          = new Date();

    // freshScore/freshVpn for device record columns
    // suspectScore from sealed may be null if the Smart Signal isn't enabled on the account.
    // In that case compute a client-side estimate from the available signals.
    const computedSuspectScore = () => {
      const s = signals || {};
      let score = 0;
      if (s.bot === 'bad')              score += 6;
      if (s.vpn === true)               score += 4;
      if (s.incognito === true)         score += 3;
      if ((s.confidence ?? 1) < 0.5)   score += 4;
      if (s.tampering === true)         score += 3;
      if (s.proxy === true)             score += 2;
      if (s.tor === true)               score += 3;
      return score;
    };

    const freshScore    = signals?.suspectScore ?? (signals ? computedSuspectScore() : (suspectScore ?? 0));
    const freshVpn      = signals?.vpn          ?? vpn          ?? false;
    const freshIncognito= signals?.incognito     ?? incognito    ?? null;
    const freshBot      = signals?.bot           ?? bot          ?? null;
    const freshConf     = signals?.confidence    ?? confidence   ?? null;

    // fpSignals stored in devices.fp_signals JSONB — use consistent field names
    // so /api/me cachedSignals can read them back without mapping
    const fpSignals = {
      source:       usedSealed ? 'sealed' : 'js-agent',
      cachedAt:     Date.now(),
      requestId:    requestId  || null,
      visitorId:    visitorId  || null,
      confidence:   freshConf,
      incognito:    freshIncognito,
      bot:          freshBot,           // "notDetected", "bad", or null
      vpn:          freshVpn,           // boolean
      suspectScore: freshScore,
      ipTimezone:   signals?.ipTimezone || null,
      ipCountry:    signals?.ipCountry  || null,
      ipCity:       signals?.ipCity     || null,
      ipAddress:    signals?.ipAddress  || null,
    };

    // Persist device record with session token
    await upsertDevice(visitorId, {
      activeEmail:         req.session.email,
      suspectScore:        freshScore,
      vpn:                 freshVpn,
      highActivity:        signals?.highActivity ?? highActivity ?? false,
      fpSignals,
      activeSessionToken:  sessionToken,
      sessionStartedAt:    now,
      sessionLastSeenAt:   now,  // initialise heartbeat
      lastApiCallAt:       usedSealed ? now : undefined,  // sealed = fresh signals
    });

    // Cross-device enforcement: mark this device as the active one for this user
    await db.query(
      'UPDATE users SET active_visitor_id = $1 WHERE email = $2',
      [visitorId, req.session.email]
    );

    req.session.visitorId = visitorId;

    // ── Email inheritance on device re-use ────────────────────────────────────
    // If this visitorId was previously used by a different account, copy those
    // video_views and certifications rows to the current user's email.
    // This ensures that when the current user later logs in on a new device/browser,
    // the email-based lookup still finds the correct counts.
    try {
      const currentEmail = req.session.email.toLowerCase().trim();

      // Copy video views: update any rows for this visitorId that have a different email
      await db.query(`
        UPDATE video_views
        SET email = $1
        WHERE visitor_id = $2
          AND LOWER(email) != $1
      `, [currentEmail, visitorId]);

      // Also ensure there's a cert row tied to this email if one exists for the visitorId
      await db.query(`
        UPDATE certifications
        SET email = $1
        WHERE visitor_id = $2
          AND LOWER(email) != $1
      `, [currentEmail, visitorId]);

      console.log(`[login] email inheritance applied — visitorId: ${visitorId}, email: ${currentEmail}`);
    } catch(e) {
      console.warn('[login] email inheritance failed (non-fatal):', e.message);
    }

    // Persist signals to smart_signals table when we have them
    if (usedSealed && signals) {
      try {
        await db.query(`
          INSERT INTO smart_signals (
            visitor_id, request_id, ui_trigger,
            confidence, first_seen_at, last_seen_at,
            incognito, vpn, proxy, tor, tampering, high_activity, location_spoofing,
            bot_result, bot_type, suspect_score,
            ip_v4_address, ip_country, ip_city, ip_timezone, vpn_origin_country, raw
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
          [ visitorId, requestId, 'sign-in-sealed',
            signals.confidence ?? null, signals.firstSeenAt ?? null, signals.lastSeenAt ?? null,
            signals.incognito ?? null, signals.vpn ?? null, signals.proxy ?? null,
            signals.tor ?? null, signals.tampering ?? null, signals.highActivity ?? null,
            signals.locationSpoofing ?? null, signals.bot ?? null, signals.botType ?? null,
            signals.suspectScore ?? null, signals.ipAddress ?? null, signals.ipCountry ?? null,
            signals.ipCity ?? null, signals.ipTimezone ?? null, signals.originCountry ?? null,
            JSON.stringify(products || {}) ]);
      } catch(e) { console.error('[saveSmartSignals sealed]', e.message); }
    }

    await logFpApiCall(
      usedSealed ? 'identify (sealed result)' : 'identify (JS agent)',
      visitorId, 'sign-in-button',
      { email: req.session.email, suspectScore: freshScore, vpn: freshVpn,
        incognito: signals?.incognito ?? incognito, bot: signals?.bot ?? bot, usedSealed }
    );

    res.json({
      ok: true, visitorId, sessionToken, usedSealed,
      suspectScore: freshScore,
      // Return flat signals to client so it can update sessionStorage
      // (only safe to expose because sealed result is server-verified)
      signals: usedSealed ? signals : null,
    });
  } catch (e) {
    console.error('[fp/identify]', e.message);
    res.status(500).json({ ok: false, error: 'Identification failed.' });
  }
});

// ── Sealed signals — authenticated (cert submit, review submit) ───────────────
// Accepts sealed_result_base64 from v4 agent, unseals server-side, returns flat
// signals. Updates devices.fp_signals with fresh values. No session management.
app.post('/api/fp/signals', requireAuthAndSession, async (req, res) => {
  const { sealed_result_base64, event_id, uiTrigger } = req.body;
  if (!sealed_result_base64 && !event_id)
    return res.status(400).json({ ok: false, error: 'sealed_result_base64 or event_id required.' });

  const vid = req.session.visitorId;
  let signals    = null;
  let usedSealed = false;
  let fallback   = false;

  // ── Path A: Unseal sealed result ─────────────────────────────────────────────
  if (sealed_result_base64) {
    try {
      const unsealed = await unsealResult(sealed_result_base64);
      signals   = extractSignalsFromProducts(unsealed);
      usedSealed = true;
      console.log(`[FP /signals sealed] ${uiTrigger} — visitorId: ${signals.visitorId}, suspect: ${signals.suspectScore}, vpn: ${signals.vpn}`);
    } catch(sealErr) {
      console.warn(`[FP /signals] Sealed unseal failed (${uiTrigger}): ${sealErr.message}`);
      fallback = true;
    }
  }

  // ── Path B: Server API fallback ───────────────────────────────────────────────
  if (!signals && event_id && process.env.FP_API_KEY) {
    try {
      console.log(`[FP /signals] Falling back to Server API for event ${event_id}`);
      const { status, body } = await fpServerApiGet(`/events/${event_id}`);
      if (status === 200 && body.products) {
        signals = extractSignalsFromProducts(body.products);
        console.log(`[FP /signals] Server API fallback succeeded — visitorId: ${signals.visitorId}`);
      } else {
        console.warn(`[FP /signals] Server API returned ${status}`);
      }
    } catch(apiErr) {
      console.warn(`[FP /signals] Server API fallback failed: ${apiErr.message}`);
    }
  }

  if (!signals) {
    return res.status(500).json({
      ok: false,
      error: 'Both sealed decryption and Server API fallback failed. Check FP_SEALED_KEY and FP_API_KEY in .env.',
      usedSealed: false, fallback: true,
    });
  }

  // Update device record with fresh signals
  if (vid) {
    await upsertDevice(vid, {
      suspectScore: signals.suspectScore ?? 0,
      vpn:          signals.vpn ?? false,
      fpSignals: {
        source: usedSealed ? 'sealed' : 'server-api-fallback',
        cachedAt: Date.now(), requestId: signals.requestId, visitorId: signals.visitorId,
        confidence: signals.confidence, incognito: signals.incognito,
        bot: signals.bot, vpn: signals.vpn, suspectScore: signals.suspectScore,
        ipTimezone: signals.ipTimezone, ipCountry: signals.ipCountry,
        ipCity: signals.ipCity, ipAddress: signals.ipAddress,
      },
      lastApiCallAt: new Date(),
    }).catch(e => console.error('[upsertDevice signals]', e.message));
  }

  await logFpApiCall(
    usedSealed ? `signals/sealed (${uiTrigger})` : `signals/server-api-fallback (${uiTrigger})`,
    vid || signals.visitorId, uiTrigger || 'unknown',
    { suspectScore: signals.suspectScore, vpn: signals.vpn, incognito: signals.incognito, bot: signals.bot }
  );

  res.json({ ok: true, signals, updatedSuspectScore: signals.suspectScore, usedSealed, fallback });
});

app.post('/api/fp/signals/public', async (req, res) => {
  const { sealed_result_base64, event_id, uiTrigger } = req.body;
  if (!sealed_result_base64 && !event_id)
    return res.status(400).json({ ok: false, error: 'sealed_result_base64 or event_id required.' });

  let signals    = null;
  let usedSealed = false;
  let fallback   = false;

  // ── Path A: Unseal sealed result ─────────────────────────────────────────────
  if (sealed_result_base64) {
    try {
      const unsealed = await unsealResult(sealed_result_base64);
      signals    = extractSignalsFromProducts(unsealed);
      usedSealed = true;
      console.log(`[FP /signals/public sealed] visitorId: ${signals.visitorId}, suspect: ${signals.suspectScore}`);
    } catch(sealErr) {
      console.warn(`[FP /signals/public] Sealed unseal failed: ${sealErr.message}`);
      fallback = true;
    }
  }

  // ── Path B: Server API fallback ───────────────────────────────────────────────
  if (!signals && event_id && process.env.FP_API_KEY) {
    try {
      console.log(`[FP /signals/public] Falling back to Server API for event ${event_id}`);
      const { status, body } = await fpServerApiGet(`/events/${event_id}`);
      if (status === 200 && body.products) {
        signals = extractSignalsFromProducts(body.products);
        console.log(`[FP /signals/public] Server API fallback succeeded — visitorId: ${signals.visitorId}`);
      }
    } catch(apiErr) {
      console.warn(`[FP /signals/public] Server API fallback failed: ${apiErr.message}`);
    }
  }

  if (!signals) {
    return res.status(500).json({ ok: false, error: 'Both sealed decryption and Server API fallback failed.', usedSealed: false, fallback: true });
  }

  await logFpApiCall(
    usedSealed ? 'signals/public (sealed)' : 'signals/public (server-api-fallback)',
    signals.visitorId, uiTrigger || 'contact-form',
    { suspectScore: signals.suspectScore, vpn: signals.vpn, incognito: signals.incognito, bot: signals.bot }
  );

  res.json({ ok: true, signals, updatedSuspectScore: signals.suspectScore, usedSealed, fallback });
});
// The requireValidSession middleware checks session_last_seen_at against
// HEARTBEAT_TTL_MINS. No heartbeat for 5 min = session considered stale.
app.post('/api/session/heartbeat', requireAuthAndSession, async (req, res) => {
  const vid = req.session.visitorId;
  if (!vid) return res.json({ ok: true }); // no visitorId yet — still logging in
  try {
    await db.query(
      'UPDATE devices SET session_last_seen_at = NOW() WHERE visitor_id = $1', [vid]);
    res.json({ ok: true, ts: new Date().toISOString() });
  } catch(e) {
    console.error('[heartbeat]', e.message);
    res.json({ ok: true }); // non-fatal
  }
});

// ── /api/me ───────────────────────────────────────────────────────────────────
app.get('/api/me', async (req, res) => {
  if (!req.session.email) return res.status(401).json({ ok: false });

  // Check session token displacement
  const clientToken = req.headers['x-session-token'];
  const vid         = req.session.visitorId;
  if (clientToken && vid) {
    try {
      const dev = await getDevice(vid);
      if (dev?.active_session_token && dev.active_session_token !== clientToken) {
        return res.status(401).json({
          ok: false, reason: 'session_displaced',
          error: 'You have been signed in on another window or device. This session has ended.',
        });
      }
    } catch(e) { /* non-fatal */ }
  }
  try {
    const { rows: userRows } = await db.query('SELECT name FROM users WHERE email = $1', [req.session.email]);
    if (!userRows.length) return res.status(401).json({ ok: false });
    const vid = req.session.visitorId;
    if (!vid) {
      return res.json({ ok: true, email: req.session.email, name: userRows[0].name, visitorId: null,
        freeLimit: CONFIG.VIDEO_LIMIT, videosWatched: 0, remaining: CONFIG.VIDEO_LIMIT, watchedIds: [],
        certified: false, certAttempts: 0, certScore: null, certSubmittedAt: null, suspectScore: 0 });
    }
    const [dev, watchedIds, cert] = await Promise.all([
      getDevice(vid),
      getVideoViews(vid, req.session.email),
      getCert(vid, req.session.email),
    ]);
    // Parse fp_signals for client-side fpCache seeding
    const fpSigs = dev?.fp_signals || {};
    res.json({
      ok: true, email: req.session.email, name: userRows[0].name, visitorId: vid,
      freeLimit:       CONFIG.VIDEO_LIMIT,
      videosWatched:   watchedIds.length,
      remaining:       Math.max(0, CONFIG.VIDEO_LIMIT - watchedIds.length),
      watchedIds,
      certified:       cert?.passed       || false,
      certAttempts:    cert?.attempts     || 0,
      certScore:       cert?.score        ?? null,
      certSubmittedAt: cert?.submitted_at || null,
      suspectScore:    dev?.suspect_score || 0,
      signalsFresh:    signalsAreFresh(dev),
      lastApiCallAt:   dev?.last_api_call_at || null,
      // Return cached signals so client can seed fpCache even if sessionStorage is stale
      cachedSignals: {
        visitorId:    vid,
        confidence:   fpSigs.confidence   ?? null,
        incognito:    fpSigs.incognito     ?? null,
        vpn:          fpSigs.vpn           ?? null,
        bot:          fpSigs.bot           ?? null,  // "notDetected", "bad", or null
        suspectScore: dev?.suspect_score   ?? 0,
        _ipTimezone:  fpSigs.ipTimezone    || null,
        _ipCountry:   fpSigs.ipCountry     || null,
        _ipCity:      fpSigs.ipCity        || null,
        _ipAddress:   fpSigs.ipAddress     || null,
        _lastServerApiCallAt: dev?.last_api_call_at ? new Date(dev.last_api_call_at).getTime() : null,
      },
    });
  } catch (e) {
    console.error('[/api/me]', e.message);
    res.status(500).json({ ok: false, error: 'Failed to load profile.' });
  }
});

// ── Smart Signals — respects TTL cache ───────────────────────────────────────
// Clients should pass ?requestId=... for a fresh call.
// If no requestId is passed AND signals are fresh, returns cached DB values.
app.get('/api/smart-signals', requireAuthAndSession, async (req, res) => {
  const vid       = req.session.visitorId;
  const dev       = await getDevice(vid);
  const requestId = req.query.requestId || dev?.fp_signals?.requestId;
  const uiTrigger = req.query.uiTrigger || 'unknown';

  if (!requestId)
    return res.status(400).json({ ok: false, error: 'No requestId on record. Please log out and log in again.' });
  if (!process.env.FP_API_KEY)
    return res.status(503).json({ ok: false, error: 'FP_API_KEY not configured.' });

  // If a fresh requestId was passed by the client, always fetch.
  // If using the stored requestId and signals are still fresh, return cached values.
  const isOnDemand = !!req.query.requestId;
  if (!isOnDemand && signalsAreFresh(dev)) {
    console.log(`[FP] Signals fresh for ${vid} — serving from DB cache`);
    return res.json({
      ok: true, cached: true,
      signals: {
        visitorId:    vid,
        suspectScore: dev.suspect_score,
        vpn:          dev.vpn,
        incognito:    dev.fp_signals?.incognito,
        bot:          dev.fp_signals?.bot,
        confidence:   dev.fp_signals?.confidence,
      },
      requestId,
      updatedSuspectScore: dev.suspect_score,
      updatedVpn:          dev.vpn,
    });
  }

  try {
    const result = await fetchAndCacheSignals(vid, requestId, uiTrigger);
    if (!result)
      return res.status(503).json({ ok: false, error: 'Server API unavailable.' });

    const { products: p, freshScore, freshVpn } = result;
    const flat = {
      visitorId:        p.identification?.data?.visitorId,
      confidence:       p.identification?.data?.confidence?.score,
      firstSeenAt:      p.identification?.data?.firstSeenAt?.global,
      lastSeenAt:       p.identification?.data?.lastSeenAt?.global,
      incognito:        p.incognito?.data?.result,
      bot:              p.botd?.data?.bot?.result,
      botType:          p.botd?.data?.bot?.type,
      vpn:              p.vpn?.data?.result,
      vpnMethods:       p.vpn?.data?.methods,
      originCountry:    p.vpn?.data?.originCountry,
      proxy:            p.proxy?.data?.result,
      tor:              p.tor?.data?.result,
      tampering:        p.tampering?.data?.result,
      highActivity:     p.highActivity?.data?.result,
      locationSpoofing: p.locationSpoofing?.data?.result,
      suspectScore:     freshScore,
      ipInfo:           { v4: p.ipInfo?.data?.v4, v6: p.ipInfo?.data?.v6 },
    };
    res.json({ ok: true, cached: false, signals: flat, requestId,
      updatedSuspectScore: freshScore, updatedVpn: freshVpn });
  } catch (e) {
    console.error('[smart-signals]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── Suspect score cache update (client-side computed score) ───────────────────
app.post('/api/fp/suspect', requireAuthAndSession, async (req, res) => {
  const { suspectScore, vpn, highActivity, tab } = req.body;
  try {
    const dev = await getDevice(req.session.visitorId);
    await upsertDevice(req.session.visitorId, {
      suspectScore: suspectScore ?? dev?.suspect_score,
      vpn:          vpn !== undefined ? vpn : dev?.vpn,
      highActivity: highActivity !== undefined ? highActivity : dev?.high_activity,
      fpSignals:    { ...dev?.fp_signals, lastCheckedTab: tab, lastCheckedAt: Date.now() },
    });
    res.json({ ok: true, suspectScore: suspectScore ?? dev?.suspect_score });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Smart Signals — public endpoint (no auth, used by contact page) ───────────
// Calls the Server API using the requestId and returns signals.
// No session token required — used pre-login on the contact form.
app.get('/api/smart-signals/public', async (req, res) => {
  const { requestId, uiTrigger } = req.query;
  if (!requestId) return res.status(400).json({ ok: false, error: 'requestId required.' });
  if (!process.env.FP_API_KEY) return res.status(503).json({ ok: false, error: 'FP_API_KEY not configured.' });

  try {
    const { status, body } = await fpServerApiGet(`/events/${requestId}`);
    if (status !== 200)
      return res.status(status).json({ ok: false, error: body?.error?.message || 'Server API error' });

    const p = body.products || {};
    const freshScore = p.suspectScore?.data?.result ?? null;
    const freshVpn   = p.vpn?.data?.result === true;
    const ipV4       = p.ipInfo?.data?.v4 || {};
    const geo        = ipV4.geolocation   || {};

    await logFpApiCall('smart-signals/public (Server API)', null, uiTrigger || 'contact-form', {
      suspectScore: freshScore, vpn: freshVpn,
      incognito: p.incognito?.data?.result,
      bot: p.botd?.data?.bot?.result,
    });

    res.json({
      ok: true,
      updatedSuspectScore: freshScore,
      updatedVpn: freshVpn,
      signals: {
        visitorId:    p.identification?.data?.visitorId || null,
        confidence:   p.identification?.data?.confidence?.score ?? null,
        incognito:    p.incognito?.data?.result        ?? null,
        bot:          p.botd?.data?.bot?.result        ?? null,
        botType:      p.botd?.data?.bot?.type          ?? null,
        vpn:          p.vpn?.data?.result              ?? null,
        proxy:        p.proxy?.data?.result            ?? null,
        tor:          p.tor?.data?.result              ?? null,
        tampering:    p.tampering?.data?.result        ?? null,
        suspectScore: freshScore,
        // Return full ipInfo so client can extract all geo fields
        ipInfo: {
          v4: {
            address:     ipV4.address || null,
            geolocation: {
              timezone:     geo.timezone    || null,
              // v3 Server API uses nested objects: country.name, city.name
              country_name: geo.country?.name || null,
              city_name:    geo.city?.name    || null,
              // Also pass raw for client flexibility
              country:      geo.country || null,
              city:         geo.city    || null,
            },
          },
        },
      },
    });
  } catch(e) {
    console.error('[smart-signals/public]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// CONTACT ENQUIRY ROUTE (pre-login — no auth required)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/contact', async (req, res) => {
  const { name, email, company, teamSize, message,
          visitorId, requestId, confidence, incognito, bot, vpn, suspectScore,
          ipCountry, ipTimezone, ipCity, ipAddress, rawSignals } = req.body;

  // Diagnostic log — confirm what fields arrived from the client
  console.log('[contact] received:', {
    visitorId: visitorId || '(empty)',
    requestId: requestId || '(empty)',
    confidence, incognito, vpn, bot, suspectScore,
    ipCountry: ipCountry || '(empty)',
    ipTimezone: ipTimezone || '(empty)',
  });

  if (!name || !email)
    return res.status(400).json({ ok: false, error: 'Name and email are required.' });

  try {
    let isDuplicate = false;
    let flagReason  = null;

    if (visitorId) {
      const { rows: byDevice } = await db.query(
        'SELECT id, email FROM contact_enquiries WHERE visitor_id = $1', [visitorId]);
      if (byDevice.length) {
        isDuplicate = true;
        flagReason  = `Device already enquired (previous email: ${byDevice[0].email})`;
      }
    }

    if (!isDuplicate) {
      const { rows: byEmail } = await db.query(
        'SELECT id FROM contact_enquiries WHERE LOWER(email) = LOWER($1)', [email]);
      if (byEmail.length) {
        isDuplicate = true;
        flagReason  = 'Email already used in a previous enquiry';
      }
    }

    const isSuspicious = (suspectScore >= CONFIG.SUSPECT_THRESHOLD) || (vpn === true) || (bot === 'bad');
    if (!flagReason && isSuspicious) {
      flagReason = [
        vpn              && 'VPN detected',
        bot === 'bad'    && 'Bot detected',
        (suspectScore >= CONFIG.SUSPECT_THRESHOLD) && `Suspect score ${suspectScore}`,
      ].filter(Boolean).join(', ');
    }

    const status = isDuplicate ? 'spam' : isSuspicious ? 'flagged' : 'new';

    // Store all available IP fields — populated from Server API call on the client
    await db.query(`
      INSERT INTO contact_enquiries
        (visitor_id, request_id, confidence, incognito, vpn, bot_result, suspect_score,
         ip_country, ip_timezone, name, email, company, team_size, message,
         status, flag_reason, is_duplicate, raw_signals)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
    `, [ visitorId || null, requestId || null,
         confidence ?? null, incognito ?? null, vpn ?? null, bot || null, suspectScore ?? null,
         ipCountry  || rawSignals?.ipCountry   || rawSignals?._ipCountry  || null,
         ipTimezone || rawSignals?.ipTimezone  || rawSignals?._ipTimezone || null,
         name.trim(), email.toLowerCase().trim(), company || null, teamSize || null, message || null,
         status, flagReason || null, isDuplicate, JSON.stringify(rawSignals || {}) ]);

    if (visitorId) {
      await logFpApiCall('contact-enquiry submitted', visitorId, 'contact-form', {
        email, status, flagReason, suspectScore, vpn, bot, ipCountry, ipTimezone,
      });
    }

    res.json({
      ok: true, status,
      message: isDuplicate
        ? 'Thank you — we already have your details on file and will be in touch.'
        : 'Thank you! A member of our team will reach out within 1 business day.',
    });
  } catch (e) {
    console.error('[contact]', e.message);
    res.status(500).json({ ok: false, error: 'Submission failed. Please try again.' });
  }
});

// ── API: count contact enquiries for a visitorId (pre-login, no auth) ─────────
app.get('/api/contact/count', async (req, res) => {
  const { visitorId } = req.query;
  if (!visitorId) return res.json({ ok: true, count: 0 });
  try {
    const { rows } = await db.query(
      'SELECT COUNT(*) FROM contact_enquiries WHERE visitor_id = $1', [visitorId]);
    res.json({ ok: true, count: parseInt(rows[0].count, 10) });
  } catch(e) {
    res.json({ ok: true, count: 0 }); // non-fatal
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VIDEO ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/video/watch', requireAuthAndSession, async (req, res) => {
  const { videoId } = req.body;
  const vid   = req.session.visitorId;
  const email = req.session.email;
  try {
    // Check watched videos by visitor_id OR email — prevents multi-account abuse
    const watchedIds = await getVideoViews(vid, email);
    if (watchedIds.includes(videoId)) {
      return res.json({ ok: true, rewatch: true, videoId,
        watched: watchedIds.length, limit: CONFIG.VIDEO_LIMIT,
        remaining: Math.max(0, CONFIG.VIDEO_LIMIT - watchedIds.length), watchedIds });
    }
    if (watchedIds.length >= CONFIG.VIDEO_LIMIT)
      return res.status(403).json({ ok: false, reason: 'limit_reached',
        watched: watchedIds.length, limit: CONFIG.VIDEO_LIMIT });

    // Store both visitor_id and email so future lookups can match on either
    await db.query(
      `INSERT INTO video_views (visitor_id, email, video_id)
       VALUES ($1, $2, $3)
       ON CONFLICT DO NOTHING`,
      [vid, email.toLowerCase().trim(), videoId]
    );
    const newWatched = [...watchedIds, videoId];
    res.json({ ok: true, rewatch: false, videoId,
      watched: newWatched.length, limit: CONFIG.VIDEO_LIMIT,
      remaining: CONFIG.VIDEO_LIMIT - newWatched.length, watchedIds: newWatched });
  } catch (e) {
    console.error('[video/watch]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// CERTIFICATION ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/cert/submit', requireAuthAndSession, async (req, res) => {
  const { answers, visitorIdAtSubmission } = req.body;
  const vid   = req.session.visitorId;
  const email = req.session.email;
  try {
    // Check by visitor_id OR email — prevents creating a new account to retry
    const cert = await getCert(vid, email);
    if (cert?.passed) return res.json({ ok: true, alreadyCertified: true, score: cert.score });
    if (cert?.attempts >= 1)
      return res.status(403).json({
        ok: false, reason: 'no_attempts',
        message: 'No attempts remaining for this device or account.',
      });

    if (visitorIdAtSubmission && visitorIdAtSubmission !== vid) {
      return res.status(403).json({ ok: false, reason: 'visitor_id_mismatch',
        error: 'Device mismatch detected. Please log out and log in again.' });
    }

    const CORRECT = [1, 0, 2, 1, 3];
    const score   = answers.reduce((n, a, i) => n + (a === CORRECT[i] ? 1 : 0), 0);
    const passed  = score >= 4;
    const now     = new Date();

    // Store email so future lookups can match on either visitor_id or email
    await db.query(`
      INSERT INTO certifications (visitor_id, email, attempts, passed, score, submitted_at)
      VALUES ($1,$2,1,$3,$4,$5)
      ON CONFLICT (visitor_id) DO UPDATE SET
        attempts = certifications.attempts + 1, passed = $3, score = $4, submitted_at = $5
    `, [vid, email.toLowerCase().trim(), passed, score, now]);

    res.json({ ok: true, passed, score, total: 5, submittedAt: now.toISOString() });
  } catch (e) {
    console.error('[cert/submit]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// REVIEW ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/review/submit', requireAuthAndSession, async (req, res) => {
  const { email, rating, subject, body: reviewBody, visitorIdAtSubmission, suspectScore, vpn } = req.body;
  const vid       = req.session.visitorId;
  const sessEmail = req.session.email;
  if (!email) return res.status(400).json({ ok: false, error: 'Email is required.' });
  try {
    // Check by visitor_id OR session email — prevents creating a new account to re-submit
    const byDevice = await getReview(vid, sessEmail);
    if (byDevice) return res.status(403).json({ ok: false, reason: 'device_already_submitted',
      error: `This device or account has already submitted a review from: ${byDevice.email}`,
      submittedEmail: byDevice.email });

    // Also check the gift card email they typed, in case it differs from account email
    if (email.toLowerCase().trim() !== sessEmail.toLowerCase().trim()) {
      const { rows: byGiftEmail } = await db.query(
        'SELECT visitor_id FROM reviews WHERE LOWER(email) = LOWER($1)', [email]);
      if (byGiftEmail.length) return res.status(403).json({ ok: false, reason: 'email_already_used',
        error: 'This email address has already been used to claim a gift card.' });
    }

    if (visitorIdAtSubmission && visitorIdAtSubmission !== vid)
      return res.status(403).json({ ok: false, reason: 'visitor_id_mismatch',
        error: 'Device mismatch detected. Please log out and log in again.' });

    const isFlagged = (suspectScore >= CONFIG.SUSPECT_THRESHOLD) || (vpn === true);
    const status    = isFlagged ? 'flagged' : 'approved';
    const now       = new Date();

    await db.query(`
      INSERT INTO reviews
        (visitor_id, email, rating, subject, body, status,
         suspect_score_at_submission, vpn_at_submission, visitor_id_at_submission, submitted_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `, [vid, email.toLowerCase().trim(), rating || null, subject || null, reviewBody || null,
        status, suspectScore ?? null, vpn ?? null, visitorIdAtSubmission || vid, now]);

    await logFpApiCall('review submitted', vid, 'review-submit-button', { email, suspectScore, vpn, status });

    res.json({
      ok: true, giftCardEmail: status === 'approved' ? email : null,
      giftCardGranted: status === 'approved', status,
      submittedAt: now.toISOString(),
      flagReason: isFlagged ? (vpn ? 'VPN usage detected' : `Suspect score ${suspectScore} above threshold`) : null,
    });
  } catch (e) {
    console.error('[review/submit]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/review/status', requireAuthAndSession, async (req, res) => {
  try {
    const review = await getReview(req.session.visitorId, req.session.email);
    if (review) return res.json({ ok: true, submitted: true, email: review.email,
      status: review.status, submittedAt: review.submitted_at });
    res.json({ ok: true, submitted: false });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ─────────────────────────────────────────────────────────────────────────────
// REPORT + LOG ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/report', requireAuthAndSession, async (req, res) => {
  const vid = req.session.visitorId;
  try {
    const [dev, watchedIds, cert, review] = await Promise.all([
      getDevice(vid), getVideoViews(vid), getCert(vid), getReview(vid)]);
    res.json({ ok: true, visitorId: vid,
      activeEmail: dev?.active_email, videosWatched: watchedIds.length, watchedIds,
      certAttempts: cert?.attempts||0, certified: cert?.passed||false,
      certScore: cert?.score??null, suspectScore: dev?.suspect_score||0,
      vpn: dev?.vpn||false, highActivity: dev?.high_activity||false,
      fpSignals: dev?.fp_signals||null,
      signalsFresh: signalsAreFresh(dev),
      review: review ? { email: review.email, status: review.status, submittedAt: review.submitted_at } : null,
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/fp-log', requireAuthAndSession, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT id, visitor_id, event, ui_trigger, signals, called_at
       FROM fp_api_log ORDER BY called_at DESC LIMIT 200`);
    res.json({ ok: true, log: rows.map(r => ({
      ts: r.called_at, event: r.event, visitorId: r.visitor_id,
      uiTrigger: r.ui_trigger, ...(r.signals || {}),
    }))});
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`\n🎓  Fingerprint University → http://localhost:${PORT}\n`));
