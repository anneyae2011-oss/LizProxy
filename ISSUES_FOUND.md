# Issues Found and Fixed

## Fixed in this pass

### 1. **Frontend – `index.html` nav structure**
- **Issue:** Invalid HTML: `<div class="nav-links"></div>` was self-closing, so the two `<a>` links were outside the nav-links div, and there was an extra `</div>`.
- **Fix:** Wrapped the Home/Admin links in `<div class="nav-links">...</div>`.

### 2. **run.py – unused import**
- **Issue:** `sys` was imported but never used.
- **Fix:** Removed the `sys` import.

### 3. **Backend – bare `except` in streaming handler**
- **Issue:** `except:` in the stream error handler (around line 827) catches everything including `KeyboardInterrupt`/`SystemExit`.
- **Fix:** Replaced with `except (json_module.JSONDecodeError, TypeError):`.

### 4. **Backend – OAuth callback leaking exception details**
- **Issue:** On OAuth failure, redirect used `message={str(e)}` in the URL, exposing server-side error text.
- **Fix:** Redirect to `/?error=oauth_failed` only (no `message` query param).

### 5. **Database – `create_api_key` type hint**
- **Issue:** `google_email` was typed as `str` but the code passes `None` for IP-based (non-Google) keys.
- **Fix:** Changed to `Optional[str]` in the abstract method and both SQLite/PostgreSQL implementations.

### 6. **Admin – config form required target key**
- **Issue:** Target API Key input had `required`, so config could not be saved without re-entering the key (e.g. when only changing URL or max context).
- **Fix:** Removed `required` from the target key input; backend already keeps existing key when field is omitted.

### 7. **Admin – unban IP and XSS**
- **Issue:** Unban button used `onclick="unbanIp('${escapeHtml(ip.ip_address)}')"`. `escapeHtml` doesn’t escape single quotes, so a value like `1.2.3.4'` could break the attribute and allow injection.
- **Fix:** Use a `data-ip` attribute and attach the click handler in JS with `addEventListener`, and add `escapeAttr()` for attribute values.

---

## Recommendations (not changed)

### Security / config

- **SESSION_SECRET:** If `SESSION_SECRET` is not set, the app generates a new secret on each restart, so all sessions (e.g. OAuth) are invalidated. **Recommendation:** Set `SESSION_SECRET` in production (e.g. in Zeabur env) to a long random string and keep it stable.

- **Debug endpoint:** `GET /debug/ip` returns all request headers and the detected IP. Useful for debugging proxy headers but can expose sensitive data. **Recommendation:** Disable in production (e.g. only when `DEBUG=true`) or remove.

- **CORS:** App uses `allow_origins=["*"]` with `allow_credentials=True`. Some browsers may reject credentials with a wildcard origin. **Recommendation:** If you use cookies/OAuth from a specific frontend origin, set `allow_origins` to that origin (e.g. `["https://lizley.zeabur.app"]`).

### Code / UX

- **Theme key mismatch:** Public `script.js` uses `localStorage` key `ai_proxy_theme`; admin `admin.js` uses `theme`. Theme doesn’t sync between index and admin. You could align on one key if you want shared theme.

- **Periodic save task:** `periodic_save()` only logs; it doesn’t trigger a DB write. Comment says “database auto-persists.” If that’s accurate, consider renaming to something like `periodic_heartbeat` or removing if not needed.

- **Full key in /api/me:** The `/api/me` endpoint returns `full_key` when the user is logged in. That means the full key is sent on every “me” request and may be stored in frontend state. If you want to minimize exposure, you could stop returning `full_key` from `/api/me` and only show it once at generation (and/or from localStorage if already stored there).

### Multiple-account abuse

- **Implemented:** **Max keys per IP** is now enforced. Set `MAX_KEYS_PER_IP` (env, default 2, range 1–20). New key creation (Google OAuth and `/api/generate-key`) is rejected when the client IP already has that many keys. Admin config shows the current limit; frontend shows a clear error when `error=too_many_keys`.

---

## Summary

| Category   | Fixed | Recommendations |
|-----------|-------|------------------|
| HTML      | 1     | 0                |
| Python    | 4     | 2                |
| Frontend  | 2     | 1                |
| Security  | 2     | 3                |

All listed fixes have been applied in the codebase.
