# Security Fix: Stored/DOM XSS in `server/static/ui.html`

**Status:** Open — to be fixed
**File:** `server/static/ui.html`
**Class:** Stored / DOM-based Cross-Site Scripting (CWE-79)
**Severity:** High (operator-console compromise in a C2/red-team tool)

---

## 1. The problem in one sentence

The UI builds DOM via `element.innerHTML = \`...${value}...\`` template literals, and many of
those interpolated values come from **untrusted sources** (agents running on remote/possibly
compromised hosts, uploaded filenames, user-supplied fields) **without HTML-escaping**. A
malicious or compromised agent can inject markup that executes JavaScript **inside the
authenticated operator's browser session**.

### Why this matters here specifically

This is not a generic "escape your output" nit. In a red-team / C2 console the data shown in the
UI — agent **hostname**, **username**, **command output**, **error strings**, **uploaded
filenames** — originates from the *target side*. An agent that checks in with a hostname like:

```
<img src=x onerror="fetch('/api/agents',{method:'DELETE',...})">
```

gets script execution in the operator's session: session-riding the console, tampering with
operations, exfiltrating data the operator can see, or pivoting from a compromised target back
into the C2 server. Treat all agent-reported data as hostile input.

### What is NOT the problem

- Doing UI logic in client-side JS is fine. The page (`/`) is `@login_required`
  (`server/app.py:1150`) and no secrets are baked into the HTML — data is pulled at runtime from
  authenticated `/api/*` endpoints. There is no inherent "source disclosure" issue.

---

## 2. The escaping helper — and its limitation

`ui.html` defines `escapeHtml()` **twice** (lines 2366 and 3793), both identical:

```js
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
```

**Important limitation:** the `textContent → innerHTML` trick escapes `&`, `<`, `>` but **does NOT
escape quotes (`"` `'`)**. That makes it safe for **element-text context** but **unsafe for
attribute context** (e.g. `title="${x}"`, `data-foo="${x}"`, `src="${x}"`) where a `"` in the
value breaks out of the attribute.

### Recommended: replace both definitions with one quote-aware version

```js
function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```

Delete the duplicate so there is a single definition. This makes it safe for both text and
double/single-quoted attribute contexts.

---

## 3. Three distinct contexts — three different fixes

Escaping depends on *where* the value lands. Do not blindly wrap everything in `escapeHtml`.

| Context | Example | Fix |
|---|---|---|
| **Element text** | `<td>${hostname}</td>` | `escapeHtml(hostname)` |
| **Quoted attribute** | `title="${tactic.name}"` | `escapeHtml(tactic.name)` (quote-aware version above) **or** set via `el.setAttribute()` / `el.textContent` after creating the node |
| **Inline JS handler** | `onchange="fn('${techId}')"` | **HTML escaping is NOT enough.** Remove the inline handler; attach via `addEventListener` and pass the value from a `data-*` attribute. (See §5.) |

The cleanest long-term fix for many rows is to stop concatenating HTML strings and instead create
elements and assign `.textContent` (which is injection-proof for text). Use `innerHTML` only for
the static skeleton.

---

## 4. Prioritized remediation checklist (by data source)

### P1 — Untrusted, agent/remote/user-sourced (fix first)

| Line(s) | Sink | Untrusted value(s) | Source |
|---|---|---|---|
| 1689 | agents table row | `hostname`, `username`, `a.id` | agent check-in |
| 2100 | execute-tab agent table | `hostname`, `username`, `a.id` | agent check-in |
| 3527 | emulation agent table | `hostname`, `username`, `a.id` | agent check-in |
| 2589 | uploaded-files table | `f.file` (filename) | uploaded file name |
| 2859 | operation error banner | `op.error` | agent/exec output |
| 2899 | operation detail card | `op.id`, `op.plan` | partly agent/exec |
| 2318 | operations table row | `op.plan`, `op.id`, `agents`, `op.status` | partly agent/exec |
| 3205 | user-info panel | `data.user.username`, `data.user.role` | stored user record |
| 2972 / 3234 | error banners | `err.message` | may contain reflected server text |

### P2 — Server/MITRE-sourced (trusted today, fix as defense-in-depth)

These come from MITRE data and emulation-plan JSON. Lower risk *if* those files are trusted, but
emulation plans are loaded from a folder and could be attacker-supplied in some deployments —
escape them too.

| Line(s) | Sink | Values |
|---|---|---|
| 2478 | task-history table row | `t.id`, `t.agent`, `t.plan`, `t.techniques[].id` |
| 2551 | task-history list item | `t.id`, `t.agent`, `t.plan`, technique/test names |
| 2824 | heatmap tactic header | `tactic.name` (**attribute context** — `title="..."`) |
| 2833 | heatmap technique cell | `tech.name`, `tech.id` |
| 1844 / 1910 / 1974 / 2049 | technique browser | technique ids/names |
| 3246 | emulation plan cards | plan fields |
| 3303 | emulation plan detail | plan fields |
| 3412 | emulation tactic accordion | `tactic` (also `title`-attribute usage) |
| 3445 | emulation technique row | `techData.name`, `techId` (**+ inline `onchange` JS context — see §5**) |
| 2161 / 2937 / 3937 | task/emulation status banners | `logData.status`, `op.status` (enum, low risk but cheap to fix) |

### Already correct (reference patterns — do not change)

Lines 810–897, 1329, 1496, 2404, 2996, 3960 already route values through `escapeHtml()`. Match this
style.

---

## 5. Special case: inline `onchange` handler at line 3445

```js
techRow.innerHTML = `...<input ... onchange="toggleEmulationTechnique(this, '${techId}', ${currentTacIdx})">...`;
```

Here `techId` is interpolated into a **JavaScript string inside an HTML attribute**. HTML-escaping
alone does not make this safe (a value containing `')` etc. breaks the JS). Fix by removing the
inline handler:

```js
// In the template, carry the value as a data-attribute (HTML-escaped):
`<input type="checkbox" class="emulation-tech-cb" data-techid="${escapeHtml(techId)}" data-tactic-idx="${currentTacIdx}" ...>`

// Then wire the listener after insertion:
container.querySelectorAll('.emulation-tech-cb').forEach(cb => {
  cb.addEventListener('change', () =>
    toggleEmulationTechnique(cb, cb.dataset.techid, Number(cb.dataset.tacticIdx)));
});
```

Audit the file for other inline `on*="...${...}..."` handlers and convert them the same way.

---

## 6. Example fixes (before → after)

**Agent table (line 1689) — element-text context:**

```js
// BEFORE
tr.innerHTML = `
  <td><img src="${agentIconForOS(os)}" style="height:22px;" /></td>
  <td>${a.id}</td>
  <td>${hostname}</td>
  <td>${username}</td>
  ...`;

// AFTER
tr.innerHTML = `
  <td><img src="${agentIconForOS(os)}" style="height:22px;" /></td>
  <td>${escapeHtml(a.id)}</td>
  <td>${escapeHtml(hostname)}</td>
  <td>${escapeHtml(username)}</td>
  ...`;
```

**Heatmap tactic header (line 2824) — attribute context:**

```js
// BEFORE
tacticDiv.innerHTML = `<div class="mitre-tactic-header" title="${tactic.name}">${shortLabel}...`;

// AFTER (quote-aware escapeHtml from §2)
tacticDiv.innerHTML = `<div class="mitre-tactic-header" title="${escapeHtml(tactic.name)}">${escapeHtml(shortLabel)}...`;
```

**Uploaded filename (line 2589):**

```js
// BEFORE
tr.innerHTML = `<td class="py-1 px-2 font-mono">${f.file}</td>...`;

// AFTER
tr.innerHTML = `<td class="py-1 px-2 font-mono">${escapeHtml(f.file)}</td>...`;
// Note: the download href already uses encodeURIComponent(f.file) — keep that.
```

---

## 7. Defense-in-depth (recommended, server-side)

Add a Content-Security-Policy so that even a missed sink cannot run inline/injected script. In
`server/app.py` (e.g. an `after_request` hook):

```python
@app.after_request
def set_security_headers(resp):
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "          # blocks inline <script>/onerror= execution
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    return resp
```

> CSP with `script-src 'self'` will break **inline event handlers** (`onclick="..."`,
> `onchange="..."`) and inline `<script>` blocks. `ui.html` currently uses both, so adopting a
> strict CSP requires moving that JS to external files / `addEventListener` first. Do the §5 work,
> then tighten CSP. Until then, even a relaxed CSP plus the escaping fixes is a real improvement.

Also confirm the session cookie is hardened (`HttpOnly`, `Secure`, `SameSite=Lax/Strict`) so a
successful XSS cannot trivially read the session token — check `app.config` /
`SESSION_COOKIE_*` in `server/app.py`.

---

## 8. Verification after fixing

1. Register a test agent (or craft an agent record) with hostname/username set to:
   `<img src=x onerror=alert(document.domain)>` and confirm it renders as inert text in the agent
   tables (tabs: dashboard, execute, emulation).
2. Upload a file named `"><img src=x onerror=alert(1)>.txt` and confirm the uploaded-files table
   shows it as text and the download link still works.
3. Trigger an operation error containing markup and confirm the error banner does not execute it.
4. With CSP enabled, open DevTools console and confirm no CSP violations on normal use, and that
   any injected inline handler is reported blocked.

---

## 9. Quick grep to find remaining raw interpolations

```bash
# innerHTML assignments whose template interpolates a value NOT wrapped in escapeHtml/encodeURIComponent:
grep -nE "innerHTML *\+?= *\`" server/static/ui.html

# Inline event handlers with interpolation (JS-context — must be converted, not just escaped):
grep -nE "on[a-z]+=\"[^\"]*\\\$\{" server/static/ui.html
```

Work top-to-bottom through §4, fixing P1 first.
