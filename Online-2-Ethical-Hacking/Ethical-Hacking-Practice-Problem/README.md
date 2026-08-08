# Ethical Hacking Practice Problem

This is a deliberately vulnerable lab environment for a classroom
injection exercise. It runs two small Node.js web apps against MySQL:

- **Result site** (`http://localhost:3000`) — a student result portal.
  Its login is intentionally SQL-injection vulnerable.
- **Social Media site** (`http://localhost:3001`) — a small social feed
  with normal (parameterized-query) login. It has **no CSRF protection**
  on posting, by design.

Only use this against the instance you run yourself. Do not deploy this
anywhere public or point these techniques at systems you don't own or
have explicit authorization to test.

## Prerequisites

First, you have to understand [SQL Injection](https://textbook.cs161.org/web/sqli.html), [Cross-Site Scripting (XSS)](https://textbook.cs161.org/web/xss.html) and [Cross-Site Request Forgery (CSRF)](https://textbook.cs161.org/web/csrf.html). Please read through the provided material.

Then, before attempting this problem, complete the **Injection** lesson set in
[OWASP WebGoat](https://owasp.org/www-project-webgoat/). That's where
you'll learn the mechanics of SQL injection and XSS. This problem is where you
apply that against a realistic, full application instead of an isolated
lesson.

You'll also need on your own machine:

- Docker and Docker Compose
- Node.js (any recent version) — used only to generate seed data, not to
  run the apps themselves

## Setup Options

### Option 1: Docker Setup (Recommended)

```bash
node scripts/generate-seed-sql.js
docker compose up --build
```

This starts MySQL plus both web apps:

- Result site: http://localhost:3000
- Social Media site: http://localhost:3001

The database lives entirely in memory (`tmpfs`) and is reseeded from
scratch every time the containers are (re)created, so you always start
from a clean slate. To fully reset:

```bash
docker compose down
node scripts/generate-seed-sql.js   # optional: rerolls everyone's CGPA
docker compose up --build
```

---

### Option 2: Manual Setup (Without Docker)

Follow these steps to run MySQL and the Node.js application servers natively on your host machine.

#### Step 1: Install & Start MySQL Server
Ensure you have MySQL Server (MySQL 8.0, MariaDB, or XAMPP) installed and running locally on port `3306`.

#### Step 2: Install Node.js Dependencies
In the root directory of the project, run:
```bash
npm install
```

#### Step 3: Generate & Import Seed Data into MySQL
1. Run the seed generation script to create the SQL database initialization files:
   ```bash
   npm run generate-seed
   ```
   *(This generates `mysql-init/01-result-schema.sql` and `mysql-init/02-social-schema.sql`)*

2. Import the initialization scripts into your local MySQL server:
   ```bash
   mysql -u root -p < mysql-init/00-init.sql
   mysql -u root -p < mysql-init/01-result-schema.sql
   mysql -u root -p < mysql-init/02-social-schema.sql
   ```
   *(Alternatively, open and execute `00-init.sql`, `01-result-schema.sql`, and `02-social-schema.sql` in order using a MySQL GUI client like MySQL Workbench, phpMyAdmin, or DBeaver).*

#### Step 4: Start the Node.js Applications
By default, the apps look for database host `MYSQL_HOST=mysql`, `MYSQL_USER=appuser`, `MYSQL_PASSWORD=apppassword`. For local manual setup, set `MYSQL_HOST=localhost`.

Open **two separate terminal windows** in the project root:

- **Terminal 1: Start Result Site (Port 3000)**
  - **Windows (PowerShell):**
    ```powershell
    $env:MYSQL_HOST="localhost"; npm run start:result
    ```
  - **Windows (CMD):**
    ```cmd
    set MYSQL_HOST=localhost && npm run start:result
    ```
  - **Linux / macOS / Git Bash:**
    ```bash
    MYSQL_HOST=localhost npm run start:result
    ```

- **Terminal 2: Start Social Media Site (Port 3001)**
  - **Windows (PowerShell):**
    ```powershell
    $env:MYSQL_HOST="localhost"; npm run start:social
    ```
  - **Windows (CMD):**
    ```cmd
    set MYSQL_HOST=localhost && npm run start:social
    ```
  - **Linux / macOS / Git Bash:**
    ```bash
    MYSQL_HOST=localhost npm run start:social
    ```

*(Note: If your local MySQL instance uses different credentials instead of `appuser`/`apppassword`, set `MYSQL_USER` and `MYSQL_PASSWORD` environment variables accordingly, e.g. `$env:MYSQL_USER="root"; $env:MYSQL_PASSWORD="yourpassword"`).*

Once started, access the web applications:
- **Result site:** http://localhost:3000
- **Social Media site:** http://localhost:3001

## Credentials

There are 100 seeded students/users. The same username/password works
on both sites — use the Student ID to log into the Result site, and the
Social Username to log into the Social Media site.

| Student ID | Name | Social Username | Password |
|---|---|---|---|
| 3005001 | Liam Smith | liam_smith | Smith123 |
| 3005002 | Olivia Johnson | olivia_johnson | Johnson123 |
| 3005003 | Noah Williams | noah_williams | Williams123 |
| 3005004 | Emma Brown | emma_brown | Brown123 |
| 3005005 | Oliver Jones | oliver_jones | Jones123 |
| 3005006 | Ava Garcia | ava_garcia | Garcia123 |
| 3005007 | Elijah Miller | elijah_miller | Miller123 |
| 3005008 | Sophia Davis | sophia_davis | Davis123 |
| 3005009 | James Rodriguez | james_rodriguez | Rodriguez123 |
| 3005010 | Isabella Martinez | isabella_martinez | Martinez123 |
| 3005011 | William Hernandez | william_hernandez | Hernandez123 |
| 3005012 | Mia Lopez | mia_lopez | Lopez123 |
| 3005013 | Benjamin Gonzalez | benjamin_gonzalez | Gonzalez123 |
| 3005014 | Charlotte Wilson | charlotte_wilson | Wilson123 |
| 3005015 | Lucas Anderson | lucas_anderson | Anderson123 |
| 3005016 | Amelia Thomas | amelia_thomas | Thomas123 |
| 3005017 | Henry Taylor | henry_taylor | Taylor123 |
| 3005018 | Harper Moore | harper_moore | Moore123 |
| 3005019 | Alexander Jackson | alexander_jackson | Jackson123 |
| 3005020 | Evelyn Martin | evelyn_martin | Martin123 |
| 3005021 | Mason Lee | mason_lee | Lee123 |
| 3005022 | Abigail Perez | abigail_perez | Perez123 |
| 3005023 | Michael Thompson | michael_thompson | Thompson123 |
| 3005024 | Emily White | emily_white | White123 |
| 3005025 | Ethan Harris | ethan_harris | Harris123 |
| 3005026 | Elizabeth Sanchez | elizabeth_sanchez | Sanchez123 |
| 3005027 | Daniel Clark | daniel_clark | Clark123 |
| 3005028 | Avery Ramirez | avery_ramirez | Ramirez123 |
| 3005029 | Jacob Lewis | jacob_lewis | Lewis123 |
| 3005030 | Sofia Robinson | sofia_robinson | Robinson123 |
| 3005031 | Logan Walker | logan_walker | Walker123 |
| 3005032 | Ella Young | ella_young | Young123 |
| 3005033 | Jackson Allen | jackson_allen | Allen123 |
| 3005034 | Madison King | madison_king | King123 |
| 3005035 | Levi Wright | levi_wright | Wright123 |
| 3005036 | Scarlett Scott | scarlett_scott | Scott123 |
| 3005037 | Sebastian Torres | sebastian_torres | Torres123 |
| 3005038 | Victoria Nguyen | victoria_nguyen | Nguyen123 |
| 3005039 | Mateo Hill | mateo_hill | Hill123 |
| 3005040 | Aria Flores | aria_flores | Flores123 |
| 3005041 | Jack Green | jack_green | Green123 |
| 3005042 | Grace Adams | grace_adams | Adams123 |
| 3005043 | Owen Nelson | owen_nelson | Nelson123 |
| 3005044 | Chloe Baker | chloe_baker | Baker123 |
| 3005045 | Theodore Hall | theodore_hall | Hall123 |
| 3005046 | Camila Rivera | camila_rivera | Rivera123 |
| 3005047 | Aiden Campbell | aiden_campbell | Campbell123 |
| 3005048 | Penelope Mitchell | penelope_mitchell | Mitchell123 |
| 3005049 | Samuel Carter | samuel_carter | Carter123 |
| 3005050 | Riley Roberts | riley_roberts | Roberts123 |
| 3005051 | Joseph Gomez | joseph_gomez | Gomez123 |
| 3005052 | Layla Phillips | layla_phillips | Phillips123 |
| 3005053 | John Evans | john_evans | Evans123 |
| 3005054 | Lillian Turner | lillian_turner | Turner123 |
| 3005055 | David Diaz | david_diaz | Diaz123 |
| 3005056 | Nora Parker | nora_parker | Parker123 |
| 3005057 | Wyatt Cruz | wyatt_cruz | Cruz123 |
| 3005058 | Zoey Edwards | zoey_edwards | Edwards123 |
| 3005059 | Matthew Collins | matthew_collins | Collins123 |
| 3005060 | Mila Reyes | mila_reyes | Reyes123 |
| 3005061 | Luke Stewart | luke_stewart | Stewart123 |
| 3005062 | Aubrey Morris | aubrey_morris | Morris123 |
| 3005063 | Asher Morales | asher_morales | Morales123 |
| 3005064 | Hannah Murphy | hannah_murphy | Murphy123 |
| 3005065 | Carter Cook | carter_cook | Cook123 |
| 3005066 | Lily Rogers | lily_rogers | Rogers123 |
| 3005067 | Julian Gutierrez | julian_gutierrez | Gutierrez123 |
| 3005068 | Addison Ortiz | addison_ortiz | Ortiz123 |
| 3005069 | Grayson Morgan | grayson_morgan | Morgan123 |
| 3005070 | Eleanor Cooper | eleanor_cooper | Cooper123 |
| 3005071 | Leo Peterson | leo_peterson | Peterson123 |
| 3005072 | Natalie Bailey | natalie_bailey | Bailey123 |
| 3005073 | Jayden Reed | jayden_reed | Reed123 |
| 3005074 | Luna Kelly | luna_kelly | Kelly123 |
| 3005075 | Gabriel Howard | gabriel_howard | Howard123 |
| 3005076 | Savannah Ramos | savannah_ramos | Ramos123 |
| 3005077 | Isaac Kim | isaac_kim | Kim123 |
| 3005078 | Brooklyn Cox | brooklyn_cox | Cox123 |
| 3005079 | Lincoln Ward | lincoln_ward | Ward123 |
| 3005080 | Leah Richardson | leah_richardson | Richardson123 |
| 3005081 | Anthony Watson | anthony_watson | Watson123 |
| 3005082 | Zoe Brooks | zoe_brooks | Brooks123 |
| 3005083 | Hudson Chavez | hudson_chavez | Chavez123 |
| 3005084 | Stella Wood | stella_wood | Wood123 |
| 3005085 | Dylan James | dylan_james | James123 |
| 3005086 | Hazel Bennett | hazel_bennett | Bennett123 |
| 3005087 | Ezra Gray | ezra_gray | Gray123 |
| 3005088 | Ellie Mendoza | ellie_mendoza | Mendoza123 |
| 3005089 | Thomas Ruiz | thomas_ruiz | Ruiz123 |
| 3005090 | Paisley Hughes | paisley_hughes | Hughes123 |
| 3005091 | Charles Price | charles_price | Price123 |
| 3005092 | Audrey Alvarez | audrey_alvarez | Alvarez123 |
| 3005093 | Christopher Castillo | christopher_castillo | Castillo123 |
| 3005094 | Skylar Sanders | skylar_sanders | Sanders123 |
| 3005095 | Jaxon Patel | jaxon_patel | Patel123 |
| 3005096 | Violet Myers | violet_myers | Myers123 |
| 3005097 | Maverick Long | maverick_long | Long123 |
| 3005098 | Claire Ross | claire_ross | Ross123 |
| 3005099 | Josiah Foster | josiah_foster | Foster123 |
| 3005100 | Bella Jimenez | bella_jimenez | Jimenez123 |

These credentials let you log in anywhere as anyone, which you'll want
so you can check a second account's Social Media feed in another
browser/session while testing whether your payload actually fires. But
**the attack itself is only to be carried out as student 3005001, Liam
Smith** — don't just log into other accounts to read their CGPA or post
on their behalf directly; that's not the exercise.

## Tasks

### Task 1 — Get everyone's CGPA

Log into the Result site only as **3005001 / Smith123**. From there,
extract the CGPA of all 100 students in one shot via SQL injection —
not by logging into each account one at a time.

### Task 2 — Stored XSS to CSRF

The Social Media site has no CSRF protection on creating a post. Acting
only as **3005001 / Smith123** on both sites, get your own act of
checking your result on the Result site to automatically publish a post
on your own Social Media feed reading exactly

```
I got <CGPA>
```

with no other interaction on your part. (Hint: think about what gets
stored in the Result database, and where it ends up being displayed.)
Use the other accounts above in a second browser/session only to help
you verify a payload fires correctly for a logged-in viewer in general
— the graded exploit still has to work end-to-end as 3005001.

## Notes

- Application source code is included in this repo — you're welcome to
  read it.
- CGPAs are not listed anywhere in this README or committed to the
  repo (see `.gitignore`) — that's the one piece of data you actually
  have to go get yourself.
- No solutions or walkthroughs are provided here.


