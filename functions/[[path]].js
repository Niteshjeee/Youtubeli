// PATH: functions/[[path]].js

const GOOGLE_META_VERIFICATION = "wKQAMhWWNs7wVEzhfTcFgt0GzpeHBrWX3JvQFf_NUBk";

/**
 * Cloudflare Pages Functions Entry Point
 * Replaces 'export default { fetch }' from Workers
 */
export async function onRequest(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname;

    // ✅ DYNAMIC HOST DETECTION
    const currentHost = url.host;
    const protocol = url.protocol; // "https:"

    // ============================================================
    // ROUTE 1: Google Verification / Homepage
    // ============================================================
    if (path === "/") {
      return html(
        `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="google-site-verification" content="${GOOGLE_META_VERIFICATION}" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${currentHost}</title>
</head>
<body>
OK: ${currentHost} (Running on Pages Functions)
</body>
</html>`,
        200
      );
    }

    // ============================================================
    // ROUTE 2: Add profile + mint login link (PENDING TTL auto-clean)
    // POST /api/profile/add
    // Body: { tg_id, client_id, client_secret, label?, ttl_sec?, pending_ttl_sec? }
    // ============================================================
    if (path === "/api/profile/add" && request.method === "POST") {
      if (!authGuard(request, env.BOT_BACKEND_KEY)) return text("Unauthorized", 401);

      const body = await request.json().catch(() => ({}));
      const tg_id = String(body.tg_id || "");
      const client_id = String(body.client_id || "");
      const client_secret = String(body.client_secret || "");
      const label = String(body.label || "").slice(0, 40);

      // Ticket TTL (login link) — max 10 min
      const ttl_sec = clampInt(body.ttl_sec ?? 600, 60, 600);

      // Pending Profile TTL — default 15 min, min 5 min, max 60 min
      const pending_ttl_sec = clampInt(body.pending_ttl_sec ?? 900, 300, 3600);

      if (!tg_id || !client_id || !client_secret) {
        return json({ ok: false, err: "missing tg_id/client_id/client_secret" }, 400);
      }

      const profile_id = crypto.randomUUID();
      const now = Date.now();

      const profile = {
        ver: 3,
        profile_id,
        tg_id,
        label: label || `profile-${profile_id.slice(0, 6)}`,

        // full client_id needed for OAuth, but bot/UI should use hint
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

      // ✅ Pending auto-clean: if user never authorizes, this profile will disappear
      await env.KV.put(kProfile(profile_id), JSON.stringify(profile), { expirationTtl: pending_ttl_sec });

      const idx = await getTgIndex(env, tg_id);
      idx.profile_ids.push(profile_id);
      idx.updated_at = now;
      if (!idx.default_profile_id) idx.default_profile_id = profile_id;
      await env.KV.put(kTgIndex(tg_id), JSON.stringify(idx));

      const ticket = await mintLoginTicket(env, { tg_id, profile_id, ttlSec: ttl_sec });
      const login_url = `${protocol}//${currentHost}/oauth/start?t=${encodeURIComponent(ticket)}`;

      return json({ ok: true, profile_id, ttl_sec, pending_ttl_sec, login_url }, 200);
    }

    // ============================================================
    // ROUTE 2.5: Regenerate login link without creating new profile
    // POST /api/profile/login_link
    // Body: { tg_id, profile_id, ttl_sec?, force? }
    // ============================================================
    if (path === "/api/profile/login_link" && request.method === "POST") {
      if (!authGuard(request, env.BOT_BACKEND_KEY)) return text("Unauthorized", 401);

      const body = await request.json().catch(() => ({}));
      const tg_id = String(body.tg_id || "");
      const profile_id = String(body.profile_id || "");
      const ttl_sec = clampInt(body.ttl_sec ?? 600, 60, 600);
      const force = body.force ? 1 : 0;

      if (!tg_id || !profile_id) return json({ ok: false, err: "missing tg_id/profile_id" }, 400);

      const profile = await getProfile(env, profile_id);
      if (!profile || profile.tg_id !== tg_id) return json({ ok: false, err: "profile_not_found" }, 404);

      const ticket = await mintLoginTicket(env, { tg_id, profile_id, ttlSec: ttl_sec });
      const login_url = `${protocol}//${currentHost}/oauth/start?t=${encodeURIComponent(ticket)}${force ? "&force=1" : ""}`;

      return json({ ok: true, profile_id, ttl_sec, login_url }, 200);
    }

    // ============================================================
    // ROUTE 3: List profiles (default: only connected)
    // POST /api/profile/list
    // Body: { tg_id, only_connected? }
    // ============================================================
    if (path === "/api/profile/list" && request.method === "POST") {
      if (!authGuard(request, env.BOT_BACKEND_KEY)) return text("Unauthorized", 401);

      const body = await request.json().catch(() => ({}));
      const tg_id = String(body.tg_id || "");
      if (!tg_id) return json({ ok: false, err: "missing_tg_id" }, 400);

      // default true: show only profiles that have refresh + channel_id
      const only_connected = body.only_connected !== undefined ? Boolean(body.only_connected) : true;

      const idx = await getTgIndex(env, tg_id);
      const profiles = await Promise.all(idx.profile_ids.map((id) => getProfile(env, id)));

      let out = profiles
        .filter(Boolean)
        .map((p) => ({
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
        }));

      if (only_connected) {
        out = out.filter((p) => p.has_refresh && p.channel_id);
      }

      return json(
        {
          ok: true,
          tg_id,
          default_profile_id: idx.default_profile_id || null,
          profiles: out,
        },
        200
      );
    }

    // ============================================================
    // ROUTE 4: Set default profile
    // POST /api/profile/set_default
    // ============================================================
    if (path === "/api/profile/set_default" && request.method === "POST") {
      if (!authGuard(request, env.BOT_BACKEND_KEY)) return text("Unauthorized", 401);

      const body = await request.json().catch(() => ({}));
      const tg_id = String(body.tg_id || "");
      const profile_id = String(body.profile_id || "");
      if (!tg_id || !profile_id) return json({ ok: false, err: "missing" }, 400);

      const idx = await getTgIndex(env, tg_id);
      if (!idx.profile_ids.includes(profile_id)) return json({ ok: false, err: "not_owned" }, 403);

      idx.default_profile_id = profile_id;
      idx.updated_at = Date.now();
      await env.KV.put(kTgIndex(tg_id), JSON.stringify(idx));

      return json({ ok: true }, 200);
    }

    // ============================================================
    // ROUTE 5: Remove profile
    // POST /api/profile/remove
    // ============================================================
    if (path === "/api/profile/remove" && request.method === "POST") {
      if (!authGuard(request, env.BOT_BACKEND_KEY)) return text("Unauthorized", 401);

      const body = await request.json().catch(() => ({}));
      const tg_id = String(body.tg_id || "");
      const profile_id = String(body.profile_id || "");
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

    // ============================================================
    // ROUTE 6: OAuth Start (User Click)
    // GET /oauth/start?t=... (&force=1 optional)
    // ============================================================
    if (path === "/oauth/start") {
      const t = String(url.searchParams.get("t") || "");
      if (!t) return text("Missing ticket", 400);

      const force = url.searchParams.get("force") === "1";

      const vt = await verifyTicket(env, t);
      if (!vt.ok) return text(`Invalid/expired ticket: ${vt.err}`, 400);

      const profile = await getProfile(env, vt.profile_id);
      if (!profile || profile.tg_id !== vt.tg_id) return text("Profile not found", 404);

      if (profile.refresh_token_enc && !force) {
        return html(
          `<html><body style="font-family:Arial">
<h3>Already authorized ✅</h3>
<p>This profile already has a token.</p>
<p>Use bot → Re-auth to force new consent.</p>
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

    // ============================================================
    // ROUTE 7: OAuth Callback
    // GET /oauth/callback
    // ============================================================
    if (path === "/oauth/callback") {
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
          `<html><body style="font-family:Arial">
<h3>Already authorized ✅</h3>
<p>Token already exists. Use bot → Re-auth for fresh login.</p>
</body></html>`,
          200
        );
      }

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
        return text("Authorization failed. Try again.", 400);
      }

      const refresh_token = tokenJson.refresh_token || null;
      if (!refresh_token) {
        profile.last_error = "no_refresh_token_returned";
        profile.updated_at = Date.now();
        await env.KV.put(kProfile(profile_id), JSON.stringify(profile));
        return text("No refresh token returned. Revoke old grant and retry.", 400);
      }

      profile.refresh_token_enc = await encryptJson(env, { refresh_token });
      profile.last_ok_at = Date.now();
      profile.last_error = null;
      profile.updated_at = Date.now();

      const ch = await fetchChannelMine(tokenJson.access_token);
      if (ch && ch.channel_id) {
        profile.channel_id = ch.channel_id;
        profile.channel_title = ch.channel_title;
      }

      // ✅ Make profile "permanent": remove pending TTL by writing again without expiration
      await env.KV.put(kProfile(profile_id), JSON.stringify(profile));

      // consume ticket nonce
      if (ticket_nonce) {
        await consumeTicketNonce(env, ticket_nonce);
      }

      return html(
        `<html><body style="font-family:Arial">
<h3>Authorized ✅</h3>
<p>Go back to Telegram and upload now.</p>
<p style="color:#666;font-size:12px">You can close this tab now.</p>
</body></html>`,
        200
      );
    }

    // Catch-all
    return text("Path not found", 404);
  } catch (e) {
    return text(`Internal error: ${e && e.message ? e.message : String(e)}`, 500);
  }
}

// ============================================================
// HELPERS
// ============================================================

function kTgIndex(tg_id) {
  return `tg:${tg_id}`;
}
function kProfile(profile_id) {
  return `p:${profile_id}`;
}
function kTicketNonce(nonce) {
  return `t:${nonce}`;
}

function clampInt(x, lo, hi) {
  const n = Number(x);
  if (!Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, Math.floor(n)));
}

function text(s, code = 200) {
  return new Response(s, { status: code, headers: { "content-type": "text/plain; charset=utf-8" } });
}
function html(s, code = 200) {
  return new Response(s, { status: code, headers: { "content-type": "text/html; charset=utf-8" } });
}
function json(obj, code = 200) {
  return new Response(JSON.stringify(obj), { status: code, headers: { "content-type": "application/json" } });
}

function authGuard(req, secret) {
  const h = req.headers.get("authorization") || "";
  return h.startsWith("Bearer ") && h.slice(7) === String(secret || "");
}

// Mask helpers for bot/UI (no full secrets)
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

  return { ok: true, tg_id: obj.tg_id, profile_id: obj.profile_id, ticket_nonce: obj.ticket_nonce, force: obj.force === 1 };
}

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
