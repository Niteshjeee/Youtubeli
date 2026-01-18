// functions/[[path]].js
// Cloudflare Pages Function (single-file):
// - Serves static index.html via context.next() for non-API routes
// - Public OAuth routes: /oauth/start, /oauth/callback
// - Admin API (bot backend): /api/profile/* (Bearer BOT_BACKEND_KEY)
// - HF-private API (HF server -> Pages): /api/* (Bearer HF_API_KEY)
// - KV binding name: KV
// Secrets:
//   BOT_BACKEND_KEY, MASTER_KEY_B64, STATE_HMAC_KEY_B64, TICKET_HMAC_KEY_B64
//   HF_API_KEY

const GOOGLE_META_VERIFICATION = "wKQAMhWWNs7wVEzhfTcFgt0GzpeHBrWX3JvQFf_NUBk";

function getBotUrl(env) {
  const v = env && env.BOT_URL ? String(env.BOT_URL) : "";
  if (v && /^https?:\/\//i.test(v)) return v;
  return "https://t.me/StudyTube_Bot";
}


// ---- HF-private keys ----
const USERS_KEY = "users:all";
const USERS_MAX = 5000;
const ERRORS_KEY = "errors:last20";

export async function onRequest(context) {
  const { request, env } = context;

  try {
    const url = new URL(request.url);
    const path = url.pathname;

    // ============================================================
    // STATIC WEBSITE
    // ============================================================
    // Let Cloudflare serve index.html and other static files.
    // Only intercept for known API / OAuth routes.

    // Health endpoint (easy ping)
    if (path === "/health") {
      return json(
        {
          ok: true,
          host: url.host,
          ts: Date.now(),
          ver: "pages-single",
        },
        200
      );
    }

    // Small built-in manual (no extra files)
    if (path === "/help") {

      const botUrl = getBotUrl(env);
      return html(
        `<!doctype html><html><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="google-site-verification" content="${GOOGLE_META_VERIFICATION}" />
<title>Authonyt • Help</title>
<style>body{font-family:Arial,system-ui,sans-serif;margin:24px;line-height:1.5}code{background:rgba(0,0,0,.08);padding:2px 6px;border-radius:6px}</style>
</head><body>
<h2>Authonyt Pages Backend</h2>
<p>This Pages project hosts OAuth + APIs for the Telegram bot.</p>
<h3>Public routes</h3>
<ul>
<li><code>GET /oauth/start?t=...</code> user clicks login link</li>
<li><code>GET /oauth/callback</code> Google redirects back here</li>
<li><code>GET /health</code> status</li>
</ul>
<h3>Admin (bot backend) routes</h3>
<p>Require header: <code>Authorization: Bearer BOT_BACKEND_KEY</code></p>
<ul>
<li><code>POST /api/profile/add</code> create profile + mint login link</li>
<li><code>POST /api/profile/login_link</code> mint new login link for existing profile</li>
<li><code>POST /api/profile/list</code> list profiles</li>
<li><code>POST /api/profile/set_default</code> set default profile</li>
<li><code>POST /api/profile/remove</code> remove profile</li>
</ul>
<h3>HF-private routes (HF server -> Pages)</h3>
<p>Require header: <code>Authorization: Bearer HF_API_KEY</code></p>
<ul>
<li><code>POST /api/allow_user</code>, <code>/api/disallow_user</code>, <code>/api/is_allowed</code>, <code>/api/list_allowed</code></li>
<li><code>POST /api/list_users</code>, <code>/api/touch_user</code></li>
<li><code>POST /api/list_profiles</code>, <code>/api/pick_profile</code>, <code>/api/access_token</code></li>
<li><code>POST /api/record_upload</code>, <code>/api/stats_today</code>, <code>/api/log_error</code></li>
</ul>
<p><a href="/">Back to home</a></p>
</body></html>`,
        200
      );
    }

    // ============================================================
    // ROUTES: Admin profile API (bot backend)
    // ============================================================
    // POST /api/profile/add
    // POST /api/profile/login_link
    // POST /api/profile/list
    // POST /api/profile/set_default
    // POST /api/profile/remove

    if (path.startsWith("/api/profile/")) {
      if (!authGuard(request, env.BOT_BACKEND_KEY)) return text("Unauthorized", 401);

      const protocol = url.protocol; // "https:"
      const currentHost = url.host;

      // /api/profile/add
      if (path === "/api/profile/add" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = String(body.tg_id || "").trim();
        const client_id = String(body.client_id || "").trim();
        const client_secret = String(body.client_secret || "").trim();
        const label = String(body.label || "").slice(0, 40).trim();
        const ttl_sec = clampInt(body.ttl_sec ?? 600, 60, 600); // ticket TTL

        if (!tg_id || !client_id || !client_secret) {
          return json({ ok: false, err: "missing tg_id/client_id/client_secret" }, 400);
        }

        const encGuard = encryptGuard(env);
        if (encGuard) return encGuard;

        const profile_id = crypto.randomUUID();
        const now = Date.now();

        const profile = {
          ver: 4,
          profile_id,
          tg_id,
          label: label || `profile-${profile_id.slice(0, 6)}`,

          client_id,
          client_id_hint: maskMid(client_id, 8, 10),

          client_secret_enc: await encryptJson(env, { client_secret }),
          client_secret_hint: maskSecret(client_secret),

          refresh_token_enc: null,
          channel_id: null,
          channel_title: null,

          created_at: now,
          updated_at: now,
          last_ok_at: null,
          last_error: null,
        };

        // store permanently
        await env.KV.put(kProfile(profile_id), JSON.stringify(profile));

        const idx = await getTgIndex(env, tg_id);
        if (!idx.profile_ids.includes(profile_id)) idx.profile_ids.push(profile_id);
        idx.updated_at = now;
        if (!idx.default_profile_id) idx.default_profile_id = profile_id;
        await env.KV.put(kTgIndex(tg_id), JSON.stringify(idx));

        const ticket = await mintLoginTicket(env, { tg_id, profile_id, ttlSec: ttl_sec });
        const login_url = `${protocol}//${currentHost}/oauth/start?t=${encodeURIComponent(ticket)}`;

        return json({ ok: true, profile_id, ttl_sec, login_url }, 200);
      }

      // /api/profile/login_link
      if (path === "/api/profile/login_link" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = String(body.tg_id || "").trim();
        const profile_id = String(body.profile_id || "").trim();
        const ttl_sec = clampInt(body.ttl_sec ?? 600, 60, 600);
        const force = body.force ? 1 : 0;

        if (!tg_id || !profile_id) return json({ ok: false, err: "missing tg_id/profile_id" }, 400);

        const profile = await getProfile(env, profile_id);
        if (!profile || profile.tg_id !== tg_id) return json({ ok: false, err: "profile_not_found" }, 404);

        const ticket = await mintLoginTicket(env, { tg_id, profile_id, ttlSec: ttl_sec });
        const login_url = `${protocol}//${currentHost}/oauth/start?t=${encodeURIComponent(ticket)}${force ? "&force=1" : ""}`;

        return json({ ok: true, profile_id, ttl_sec, login_url }, 200);
      }

      // /api/profile/list
      if (path === "/api/profile/list" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = String(body.tg_id || "").trim();
        if (!tg_id) return json({ ok: false, err: "missing_tg_id" }, 400);

        const only_connected = body.only_connected !== undefined ? Boolean(body.only_connected) : true;

        const idx = await getTgIndex(env, tg_id);
        const unique_ids = Array.from(new Set(idx.profile_ids || []));
        const profs = await Promise.all(unique_ids.map((id) => getProfile(env, id)));

        const kept_ids = [];
        const out = [];
        for (let i = 0; i < unique_ids.length; i++) {
          const id = unique_ids[i];
          const p = profs[i];
          if (!p) continue;
          kept_ids.push(id);

          out.push({
            profile_id: p.profile_id,
            label: p.label,

            client_id_hint: p.client_id_hint || maskMid(p.client_id, 8, 10),
            client_secret_hint: p.client_secret_hint || "****…****",

            has_refresh: Boolean(p.refresh_token_enc),
            channel_id: p.channel_id || null,
            channel_title: p.channel_title || null,
            last_ok_at: p.last_ok_at,
            last_error: p.last_error,
            created_at: p.created_at,

            is_default: idx.default_profile_id === p.profile_id,
          });
        }

        const changed =
          kept_ids.length !== (idx.profile_ids || []).length ||
          kept_ids.some((v, k) => v !== (idx.profile_ids || [])[k]);

        if (changed) {
          idx.profile_ids = kept_ids;
          if (idx.default_profile_id && !kept_ids.includes(idx.default_profile_id)) {
            idx.default_profile_id = kept_ids[0] || null;
          }
          idx.updated_at = Date.now();
          await env.KV.put(kTgIndex(tg_id), JSON.stringify(idx));
        }

        const filtered = only_connected ? out.filter((p) => p.has_refresh && p.channel_id) : out;

        return json(
          {
            ok: true,
            tg_id,
            default_profile_id: idx.default_profile_id || null,
            profiles: filtered,
          },
          200
        );
      }

      // /api/profile/set_default
      if (path === "/api/profile/set_default" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = String(body.tg_id || "").trim();
        const profile_id = String(body.profile_id || "").trim();
        if (!tg_id || !profile_id) return json({ ok: false, err: "missing" }, 400);

        const idx = await getTgIndex(env, tg_id);
        if (!idx.profile_ids.includes(profile_id)) return json({ ok: false, err: "not_owned" }, 403);

        idx.default_profile_id = profile_id;
        idx.updated_at = Date.now();
        await env.KV.put(kTgIndex(tg_id), JSON.stringify(idx));

        return json({ ok: true }, 200);
      }

      // /api/profile/remove
      if (path === "/api/profile/remove" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = String(body.tg_id || "").trim();
        const profile_id = String(body.profile_id || "").trim();
        if (!tg_id || !profile_id) return json({ ok: false, err: "missing" }, 400);

        const idx = await getTgIndex(env, tg_id);
        if (!idx.profile_ids.includes(profile_id)) return json({ ok: false, err: "not_owned" }, 403);

        idx.profile_ids = idx.profile_ids.filter((x) => x !== profile_id);
        if (idx.default_profile_id === profile_id) idx.default_profile_id = idx.profile_ids[0] || null;
        idx.updated_at = Date.now();

        await env.KV.put(kTgIndex(tg_id), JSON.stringify(idx));
        await env.KV.delete(kProfile(profile_id));

        return json({ ok: true }, 200);
      }

      return text("Not found", 404);
    }

    // ============================================================
    // ROUTES: OAuth Start/Callback (Public)
    // ============================================================
    if (path === "/oauth/start") {

      const botUrl = getBotUrl(env);
      const protocol = url.protocol;
      const currentHost = url.host;

      const t = String(url.searchParams.get("t") || "");
      if (!t) return text("Missing ticket", 400);

      const force = url.searchParams.get("force") === "1";

      const vt = await verifyTicket(env, t);
      if (!vt.ok) return text(`Invalid/expired ticket: ${vt.err}`, 400);

      const profile = await getProfile(env, vt.profile_id);
      if (!profile || profile.tg_id !== vt.tg_id) return text("Profile not found", 404);

      if (profile.refresh_token_enc && !force) {
        return html(
          `<!doctype html><html><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Already authorized</title></head><body style="font-family:Arial;max-width:640px;margin:24px">
<h3>Already authorized ✅</h3>
<p>This profile already has a token.</p>
<p>Go back to Telegram and upload. If you want fresh consent, use <b>Re-auth</b> in the bot.</p>
<p><a href="/">Home</a></p>
</body></html>`,
          200
        );
      }

      const redirect_uri = `${protocol}//${currentHost}/oauth/callback`;

      const scope = [
        "https://www.googleapis.com/auth/youtube.upload",
        "https://www.googleapis.com/auth/youtube.readonly",
      ].join(" ");

      const state = await makeState(env, {
        tg_id: vt.tg_id,
        profile_id: vt.profile_id,
        ticket_nonce: vt.nonce,
        force: force ? 1 : 0,
      });

      const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      authUrl.searchParams.set("client_id", profile.client_id);
      authUrl.searchParams.set("redirect_uri", redirect_uri);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("scope", scope);
      authUrl.searchParams.set("access_type", "offline");
      authUrl.searchParams.set("prompt", "consent");
      authUrl.searchParams.set("state", state);

      return Response.redirect(authUrl.toString(), 302);
    }

    if (path === "/oauth/callback") {

      const botUrl = getBotUrl(env);
      const protocol = url.protocol;
      const currentHost = url.host;

      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!code || !state) return text("Missing code/state", 400);

      const st = await verifyState(env, state);
      if (!st.ok) return text("Invalid state", 400);

      const tg_id = String(st.tg_id);
      const profile_id = String(st.profile_id);
      const ticket_nonce = String(st.ticket_nonce || "");
      const force = Boolean(st.force);

      const profile = await getProfile(env, profile_id);
      if (!profile || profile.tg_id !== tg_id) return text("Profile not found", 404);

      if (profile.refresh_token_enc && !force) {
        return html(
          `<!doctype html><html><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Already authorized</title></head><body style="font-family:Arial;max-width:640px;margin:24px">
<h3>Already authorized ✅</h3>
<p>Token already exists. Use bot → Re-auth for fresh login.</p>
<p style="margin-top:14px"><a href="${botUrl}" style="display:inline-block;padding:10px 14px;border:1px solid #999;border-radius:10px;text-decoration:none">Open Telegram Bot</a></p>
<p><a href="/">Home</a></p>
</body></html>`,
          200
        );
      }

      const encGuard = encryptGuard(env);
      if (encGuard) return encGuard;

      const { client_secret } = await decryptJson(env, profile.client_secret_enc);
      const redirect_uri = `${protocol}//${currentHost}/oauth/callback`;

      const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: profile.client_id,
          client_secret,
          redirect_uri,
          grant_type: "authorization_code",
        }),
      });

      const tokenJson = await tokenResp.json().catch(() => ({}));

      if (!tokenResp.ok) {
        profile.last_error = `token_exchange_failed:${tokenJson.error || "unknown"}`.slice(0, 200);
        profile.updated_at = Date.now();
        await env.KV.put(kProfile(profile_id), JSON.stringify(profile));
        return text("Authorization failed. Try again from bot.", 400);
      }

      // Google may not return refresh_token on re-auth.
      const got_refresh_token = tokenJson.refresh_token || null;

      if (!got_refresh_token) {
        if (!profile.refresh_token_enc) {
          profile.last_error = "no_refresh_token_returned";
          profile.updated_at = Date.now();
          await env.KV.put(kProfile(profile_id), JSON.stringify(profile));
          return text("No refresh token returned. Revoke old grant and retry.", 400);
        }
        // keep existing refresh token
      } else {
        profile.refresh_token_enc = await encryptJson(env, { refresh_token: got_refresh_token });
      }

      profile.last_ok_at = Date.now();
      profile.last_error = null;
      profile.updated_at = Date.now();

      // fetch channel
      const ch = await fetchChannelMine(tokenJson.access_token);
      if (ch && ch.channel_id) {
        profile.channel_id = ch.channel_id;
        profile.channel_title = ch.channel_title;
      }

      await env.KV.put(kProfile(profile_id), JSON.stringify(profile));

      // consume ticket nonce
      if (ticket_nonce) {
        await consumeTicketNonce(env, ticket_nonce);
      }

      return html(
        `<!doctype html><html><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Authorized</title>
<style>body{font-family:Arial,system-ui,sans-serif;max-width:680px;margin:24px}a.btn{display:inline-block;margin-top:14px;padding:10px 12px;border:1px solid #ccc;border-radius:10px;text-decoration:none}</style>
</head><body>
<h3>Authorized ✅</h3>
<p>Go back to Telegram and upload now.</p>
<p style="color:#666;font-size:12px">You can close this tab.</p>
<a class="btn" href="${botUrl}">Open Telegram Bot</a> <a class="btn" href="/">Home</a>
</body></html>`,
        200
      );
    }

    // ============================================================
    // ROUTES: HF-private API (HF server only)
    // ============================================================
    if (path.startsWith("/api/")) {
      // HF-only guard
      const g = hfGuard(request, env);
      if (g) return g;

      // ===================== Allowlist =====================
      if (path === "/api/allow_user" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);
        await env.KV.put(kAllow(tg_id), "1");
        await touchUser(env, tg_id);
        return json({ ok: true }, 200);
      }

      if (path === "/api/disallow_user" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);
        await env.KV.delete(kAllow(tg_id));
        await touchUser(env, tg_id);
        return json({ ok: true }, 200);
      }

      if (path === "/api/is_allowed" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);
        const v = await env.KV.get(kAllow(tg_id));
        return json({ ok: true, allowed: v === "1" }, 200);
      }

      if (path === "/api/list_allowed" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const offset = clampInt(body.offset ?? 0, 0, 1_000_000);
        const limit = clampInt(body.limit ?? 200, 1, 500);
        const users = await getUsersIndex(env);

        const slice = users.slice(offset, offset + limit);
        const allowed = [];
        for (const tg_id of slice) {
          const v = await env.KV.get(kAllow(tg_id));
          if (v === "1") allowed.push(tg_id);
        }
        return json({ ok: true, total_known: users.length, offset, limit, allowed }, 200);
      }

      // ===================== Users index =====================
      if (path === "/api/touch_user" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);
        await touchUser(env, tg_id);
        return json({ ok: true }, 200);
      }

      if (path === "/api/list_users" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const offset = clampInt(body.offset ?? 0, 0, 1_000_000);
        const limit = clampInt(body.limit ?? 200, 1, 1000);
        const users = await getUsersIndex(env);
        const slice = users.slice(offset, offset + limit);
        return json({ ok: true, total: users.length, offset, limit, users: slice }, 200);
      }

      // ===================== Profiles listing =====================
      // POST /api/list_profiles
      // Body: { tg_id, only_connected? }  // default: true
      if (path === "/api/list_profiles" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);

        const only_connected = body.only_connected !== undefined ? Boolean(body.only_connected) : true;

        const idx = await getTgIndex(env, tg_id);
        const dayKey = todayKeyUTC();

        // prune dead profiles
        const kept_ids = [];
        const out = [];

        for (const id of idx.profile_ids || []) {
          const p = await getProfile(env, id);
          if (!p) continue;
          kept_ids.push(id);

          const has_refresh = Boolean(p.refresh_token_enc);
          const connected = has_refresh && Boolean(p.channel_id);

          if (only_connected && !connected) continue;

          const used = await getDailyProfileCount(env, dayKey, p.profile_id);

          out.push({
            profile_id: p.profile_id,
            label: p.label,

            client_id_hint: p.client_id_hint || maskMid(p.client_id || "", 8, 10),
            client_secret_hint: p.client_secret_hint || "****…****",

            has_refresh,
            channel_id: p.channel_id || null,
            channel_title: p.channel_title || null,
            used_today: used,
            created_at: p.created_at || null,
            last_ok_at: p.last_ok_at || null,
            last_error: p.last_error || null,
          });
        }

        if (kept_ids.length !== (idx.profile_ids || []).length) {
          idx.profile_ids = kept_ids;
          if (idx.default_profile_id && !kept_ids.includes(idx.default_profile_id)) {
            idx.default_profile_id = kept_ids[0] || null;
          }
          idx.updated_at = Date.now();
          await env.KV.put(kTgIndex(tg_id), JSON.stringify(idx));
        }

        return json({ ok: true, tg_id, default_profile_id: idx.default_profile_id || null, day: dayKey, profiles: out }, 200);
      }

      // ===================== Rotation pick =====================
      if (path === "/api/pick_profile" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);
        const channel_id = String(body.channel_id || "");
        const rotate_after = clampInt(body.rotate_after ?? 30, 1, 300);
        if (!channel_id) return json({ ok: false, err: "missing_channel_id" }, 400);

        const idx = await getTgIndex(env, tg_id);

        const profiles = (await Promise.all((idx.profile_ids || []).map((id) => getProfile(env, id)))).filter(Boolean);

        const sameChannel = profiles
          .filter((p) => (p.tg_id || p.uid) === tg_id && p.refresh_token_enc && p.channel_id === channel_id)
          .sort((a, b) => (a.created_at || 0) - (b.created_at || 0));

        if (sameChannel.length === 0) return json({ ok: false, err: "no_authorized_profile_for_channel" }, 404);

        const dayKey = todayKeyUTC();

        let cur = sameChannel.find((p) => p.profile_id === idx.default_profile_id) || sameChannel[0];

        const curCount = await getDailyProfileCount(env, dayKey, cur.profile_id);
        if (curCount < rotate_after) {
          return json({ ok: true, day: dayKey, profile_id: cur.profile_id, used_today: curCount, rotate_after }, 200);
        }

        for (const p of sameChannel) {
          const c = await getDailyProfileCount(env, dayKey, p.profile_id);
          if (c < rotate_after) {
            return json({ ok: true, day: dayKey, profile_id: p.profile_id, used_today: c, rotate_after }, 200);
          }
        }

        let best = sameChannel[0];
        let bestC = await getDailyProfileCount(env, dayKey, best.profile_id);
        for (let i = 1; i < sameChannel.length; i++) {
          const c = await getDailyProfileCount(env, dayKey, sameChannel[i].profile_id);
          if (c < bestC) {
            best = sameChannel[i];
            bestC = c;
          }
        }
        return json({ ok: true, day: dayKey, profile_id: best.profile_id, used_today: bestC, rotate_after }, 200);
      }

      // ===================== Access token =====================
      if (path === "/api/access_token" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);
        let profile_id = String(body.profile_id || "");

        const idx = await getTgIndex(env, tg_id);
        if (!profile_id) profile_id = String(idx.default_profile_id || "");
        if (!profile_id) return json({ ok: false, err: "no_default_profile" }, 404);

        const p = await getProfile(env, profile_id);
        if (!p || (p.tg_id || p.uid) !== tg_id) return json({ ok: false, err: "profile_not_found" }, 404);
        if (!p.refresh_token_enc) return json({ ok: false, err: "not_authorized" }, 403);

        const dec = decryptGuard(env);
        if (dec) return dec;

        const { client_secret } = await decryptJson(env, p.client_secret_enc);
        const { refresh_token } = await decryptJson(env, p.refresh_token_enc);

        const token = await refreshAccessToken(p.client_id, client_secret, refresh_token);
        if (!token.ok) {
          p.last_error = token.err;
          p.updated_at = Date.now();
          await env.KV.put(kProfile(profile_id), JSON.stringify(p));
          await pushError(env, { tg_id, profile_id, where: "refreshAccessToken", err: token.err });
          return json({ ok: false, err: token.err }, 401);
        }

        p.last_ok_at = Date.now();
        p.last_error = null;
        p.updated_at = Date.now();
        await env.KV.put(kProfile(profile_id), JSON.stringify(p));

        return json(
          {
            ok: true,
            access_token: token.access_token,
            expires_in: token.expires_in,
            profile_id: p.profile_id,
            channel_id: p.channel_id || null,
            channel_title: p.channel_title || null,
          },
          200
        );
      }

      // ===================== Record upload =====================
      if (path === "/api/record_upload" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);
        const profile_id = String(body.profile_id || "");
        if (!profile_id) return json({ ok: false, err: "missing_profile_id" }, 400);

        await touchUser(env, tg_id);

        const p = await getProfile(env, profile_id);
        if (!p || (p.tg_id || p.uid) !== tg_id) return json({ ok: false, err: "profile_not_found" }, 404);

        const dayKey = todayKeyUTC();
        const used_profile = await incrDailyProfileCount(env, dayKey, profile_id);
        const used_user = await incrDailyUserCount(env, dayKey, tg_id);

        return json({ ok: true, day: dayKey, profile_id, used_today_profile: used_profile, used_today_user: used_user }, 200);
      }

      // ===================== Stats =====================
      if (path === "/api/stats_today" && request.method === "POST") {
        const dayKey = todayKeyUTC();
        const total = toInt(await env.KV.get(kDailyTotal(dayKey)));
        const active = toInt(await env.KV.get(kDailyActive(dayKey)));
        const errors = await getErrors(env);
        return json({ ok: true, day: dayKey, uploads_today_total: total, active_users_today: active, errors_last20: errors }, 200);
      }

      if (path === "/api/log_error" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const tg_id = mustId(body.tg_id || body.uid);
        const profile_id = String(body.profile_id || "");
        const where = String(body.where || "unknown").slice(0, 60);
        const err = String(body.err || "unknown").slice(0, 220);
        await touchUser(env, tg_id);
        await pushError(env, { tg_id, profile_id, where, err });
        return json({ ok: true }, 200);
      }

      return text("Not found", 404);
    }

    // For everything else (/, assets), serve static.
    return context.next();
  } catch (e) {
    if (e instanceof Response) return e;
    return json({ ok: false, err: "internal_error", detail: String(e && e.message ? e.message : e) }, 500);
  }
}

// ============================================================
// COMMON HELPERS
// ============================================================

function text(s, code = 200) {
  return new Response(s, { status: code, headers: { "content-type": "text/plain; charset=utf-8" } });
}
function html(s, code = 200) {
  return new Response(s, { status: code, headers: { "content-type": "text/html; charset=utf-8" } });
}
function json(obj, code = 200) {
  return new Response(JSON.stringify(obj), { status: code, headers: { "content-type": "application/json" } });
}

function clampInt(x, lo, hi) {
  const n = Number(x);
  if (!Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, Math.floor(n)));
}

function toInt(x) {
  const n = Number(x || "0");
  return Number.isFinite(n) ? n : 0;
}

function mustId(x) {
  const s = String(x || "").trim();
  if (!s)
    throw new Response(JSON.stringify({ ok: false, err: "missing_tg_id" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  return s;
}

function maskMid(s, head = 8, tail = 10) {
  s = String(s || "");
  if (s.length <= head + tail) return s;
  return s.slice(0, head) + "…" + s.slice(-tail);
}

function maskSecret(s) {
  s = String(s || "");
  if (!s) return "****…****";
  if (s.length <= 8) return "********";
  return s.slice(0, 4) + "…" + s.slice(-4);
}

// ============================================================
// AUTH GUARDS
// ============================================================

function authGuard(req, secret) {
  const h = req.headers.get("authorization") || "";
  return h.startsWith("Bearer ") && h.slice(7) === String(secret || "");
}

function hfGuard(req, env) {
  if (!env.HF_API_KEY) return text("Server misconfigured: HF_API_KEY missing", 500);
  const h = req.headers.get("authorization") || "";
  const ok = h.startsWith("Bearer ") && h.slice(7) === String(env.HF_API_KEY);
  if (!ok) return text("Unauthorized", 401);
  return null;
}

function decryptGuard(env) {
  if (!env.MASTER_KEY_B64) return text("Server misconfigured: MASTER_KEY_B64 missing", 500);
  return null;
}

function encryptGuard(env) {
  if (!env.MASTER_KEY_B64) return text("Server misconfigured: MASTER_KEY_B64 missing", 500);
  if (!env.STATE_HMAC_KEY_B64) return text("Server misconfigured: STATE_HMAC_KEY_B64 missing", 500);
  if (!env.TICKET_HMAC_KEY_B64) return text("Server misconfigured: TICKET_HMAC_KEY_B64 missing", 500);
  return null;
}

// ============================================================
// KV KEYS
// ============================================================

function kTgIndex(tg_id) {
  return `tg:${tg_id}`;
}
function kProfile(profile_id) {
  return `p:${profile_id}`;
}
function kAllow(tg_id) {
  return `allow:${tg_id}`;
}
function kUserSeen(tg_id) {
  return `user:${tg_id}`;
}
function kTicketNonce(nonce) {
  return `t:${nonce}`;
}

function kDailyProfile(dayKey, profile_id) {
  return `d:${dayKey}:p:${profile_id}`;
}
function kDailyUser(dayKey, tg_id) {
  return `d:${dayKey}:u:${tg_id}`;
}
function kDailyTotal(dayKey) {
  return `d:${dayKey}:total`;
}
function kDailyActive(dayKey) {
  return `d:${dayKey}:active_users`;
}
function kDailyActiveFlag(dayKey, tg_id) {
  return `d:${dayKey}:activeflag:${tg_id}`;
}

// ============================================================
// STORAGE READS
// ============================================================

async function getTgIndex(env, tg_id) {
  const raw = await env.KV.get(kTgIndex(tg_id));
  if (raw) {
    try {
      const j = JSON.parse(raw);
      if (Array.isArray(j.profile_ids)) return j;
    } catch {}
  }
  const now = Date.now();
  return { ver: 1, tg_id, profile_ids: [], default_profile_id: null, created_at: now, updated_at: now };
}

async function getProfile(env, profile_id) {
  const raw = await env.KV.get(kProfile(profile_id));
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ============================================================
// UTC DAY KEY
// ============================================================

function todayKeyUTC() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

// ============================================================
// COUNTERS
// ============================================================

async function getDailyProfileCount(env, dayKey, profile_id) {
  return toInt(await env.KV.get(kDailyProfile(dayKey, profile_id)));
}

async function incrDailyProfileCount(env, dayKey, profile_id) {
  const key = kDailyProfile(dayKey, profile_id);
  const next = (await getDailyProfileCount(env, dayKey, profile_id)) + 1;
  await env.KV.put(key, String(next), { expirationTtl: 2 * 24 * 3600 });
  await incrKVInt(env, kDailyTotal(dayKey), 2 * 24 * 3600);
  return next;
}

async function incrDailyUserCount(env, dayKey, tg_id) {
  const key = kDailyUser(dayKey, tg_id);
  const next = toInt(await env.KV.get(key)) + 1;
  await env.KV.put(key, String(next), { expirationTtl: 2 * 24 * 3600 });

  const flagKey = kDailyActiveFlag(dayKey, tg_id);
  const seen = await env.KV.get(flagKey);
  if (!seen) {
    await env.KV.put(flagKey, "1", { expirationTtl: 2 * 24 * 3600 });
    await incrKVInt(env, kDailyActive(dayKey), 2 * 24 * 3600);
  }
  return next;
}

async function incrKVInt(env, key, ttl) {
  const next = toInt(await env.KV.get(key)) + 1;
  await env.KV.put(key, String(next), { expirationTtl: ttl });
  return next;
}

// ============================================================
// GLOBAL USERS INDEX (BEST-EFFORT)
// ============================================================

async function getUsersIndex(env) {
  const raw = await env.KV.get(USERS_KEY);
  if (!raw) return [];
  try {
    const j = JSON.parse(raw);
    return Array.isArray(j) ? j.map(String) : [];
  } catch {
    return [];
  }
}

async function touchUser(env, tg_id) {
  tg_id = String(tg_id);

  const seenKey = kUserSeen(tg_id);
  const already = await env.KV.get(seenKey);
  if (!already) {
    await env.KV.put(seenKey, "1", { expirationTtl: 365 * 24 * 3600 });
  }

  const users = await getUsersIndex(env);
  if (users.includes(tg_id)) return;
  users.push(tg_id);
  const trimmed = users.slice(-USERS_MAX);
  await env.KV.put(USERS_KEY, JSON.stringify(trimmed));
}

// ============================================================
// ERRORS LAST20
// ============================================================

async function pushError(env, item) {
  const raw = await env.KV.get(ERRORS_KEY);
  let arr = [];
  if (raw) {
    try {
      arr = JSON.parse(raw);
    } catch {
      arr = [];
    }
    if (!Array.isArray(arr)) arr = [];
  }
  arr.unshift({
    ts: Date.now(),
    tg_id: String(item.tg_id || ""),
    profile_id: String(item.profile_id || ""),
    where: String(item.where || "unknown"),
    err: String(item.err || "unknown"),
  });
  arr = arr.slice(0, 20);
  await env.KV.put(ERRORS_KEY, JSON.stringify(arr), { expirationTtl: 7 * 24 * 3600 });
}

async function getErrors(env) {
  const raw = await env.KV.get(ERRORS_KEY);
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

// ============================================================
// GOOGLE TOKEN REFRESH
// ============================================================

async function refreshAccessToken(client_id, client_secret, refresh_token) {
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id,
      client_secret,
      refresh_token,
      grant_type: "refresh_token",
    }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const err = `${j.error || "refresh_failed"}:${j.error_description || ""}`.slice(0, 220);
    return { ok: false, err };
  }
  return { ok: true, access_token: j.access_token, expires_in: j.expires_in || 3600 };
}

// ============================================================
// ENCRYPT/DECRYPT (AES-GCM)
// ============================================================

async function encryptJson(env, obj) {
  const key = await importAesKey(env.MASTER_KEY_B64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
  return { iv: b64urlEncode(iv), ct: b64urlEncode(new Uint8Array(ct)) };
}

async function decryptJson(env, enc) {
  const key = await importAesKey(env.MASTER_KEY_B64);
  const iv = b64urlDecode(enc.iv);
  const ct = b64urlDecode(enc.ct);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(new Uint8Array(pt)));
}

async function importAesKey(keyB64) {
  const raw = Uint8Array.from(atob(String(keyB64)), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function b64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ============================================================
// STATE + TICKET (HMAC)
// ============================================================

async function hmacSign(keyB64, msg) {
  const keyRaw = Uint8Array.from(atob(String(keyB64)), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", keyRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return b64urlEncode(new Uint8Array(sigBuf));
}

function timingSafeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function makeState(env, payload) {
  const obj = {
    tg_id: String(payload.tg_id),
    profile_id: String(payload.profile_id),
    ticket_nonce: String(payload.ticket_nonce || ""),
    force: payload.force ? 1 : 0,
    iat: Date.now(),
    nonce: crypto.randomUUID(),
  };
  const msg = b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
  const sig = await hmacSign(env.STATE_HMAC_KEY_B64, msg);
  return `${msg}.${sig}`;
}

async function verifyState(env, state) {
  const [msg, sig] = String(state).split(".");
  if (!msg || !sig) return { ok: false };

  const expSig = await hmacSign(env.STATE_HMAC_KEY_B64, msg);
  if (!timingSafeEq(sig, expSig)) return { ok: false };

  let obj;
  try {
    obj = JSON.parse(new TextDecoder().decode(b64urlDecode(msg)));
  } catch {
    return { ok: false };
  }

  if (!obj.tg_id || !obj.profile_id || !obj.iat || !obj.ticket_nonce) return { ok: false };
  if (Date.now() - obj.iat > 10 * 60 * 1000) return { ok: false };

  return {
    ok: true,
    tg_id: obj.tg_id,
    profile_id: obj.profile_id,
    ticket_nonce: obj.ticket_nonce,
    force: obj.force === 1,
  };
}

async function mintLoginTicket(env, { tg_id, profile_id, ttlSec }) {
  const obj = {
    tg_id: String(tg_id),
    profile_id: String(profile_id),
    exp: Date.now() + ttlSec * 1000,
    nonce: crypto.randomUUID(),
  };
  await env.KV.put(kTicketNonce(obj.nonce), "1", { expirationTtl: ttlSec });
  const msg = b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
  const sig = await hmacSign(env.TICKET_HMAC_KEY_B64, msg);
  return `${msg}.${sig}`;
}

async function verifyTicket(env, ticket) {
  const [msg, sig] = String(ticket).split(".");
  if (!msg || !sig) return { ok: false, err: "bad_format" };

  const expSig = await hmacSign(env.TICKET_HMAC_KEY_B64, msg);
  if (!timingSafeEq(sig, expSig)) return { ok: false, err: "bad_sig" };

  let obj;
  try {
    obj = JSON.parse(new TextDecoder().decode(b64urlDecode(msg)));
  } catch {
    return { ok: false, err: "bad_payload" };
  }

  if (!obj.nonce || !obj.tg_id || !obj.profile_id || !obj.exp) return { ok: false, err: "missing_fields" };
  if (Date.now() > obj.exp) return { ok: false, err: "expired" };

  const key = kTicketNonce(obj.nonce);
  const exists = await env.KV.get(key);
  if (!exists) return { ok: false, err: "already_used_or_ttl_expired" };

  return { ok: true, tg_id: obj.tg_id, profile_id: obj.profile_id, nonce: obj.nonce };
}

async function consumeTicketNonce(env, nonce) {
  const key = kTicketNonce(nonce);
  const exists = await env.KV.get(key);
  if (!exists) return false;
  await env.KV.delete(key);
  return true;
}

// ============================================================
// YOUTUBE: FETCH CHANNEL
// ============================================================

async function fetchChannelMine(accessToken) {
  try {
    const r = await fetch("https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!r.ok) return null;
    const j = await r.json().catch(() => ({}));
    const it = j.items && j.items[0];
    if (!it) return null;
    return { channel_id: it.id, channel_title: it.snippet && it.snippet.title };
  } catch {
    return null;
  }
}
