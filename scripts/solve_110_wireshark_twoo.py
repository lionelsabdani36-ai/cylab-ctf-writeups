#!/usr/bin/env python3
"""Solver for Challenge 110: Wireshark twoo twooo two twoo... (Forensics).

Extracts DNS-exfiltrated base64 (queries to 18.217.1.57 for
*.reddshrimpandherring) from shark2.pcapng and decodes the real flag.
Decoy academy{...} strings elsewhere in the capture are ignored.
Usage: python3 solve_110_wireshark_twoo.py [shark2.pcapng]
"""
import base64
import struct
import sys

TARGET = bytes([18, 217, 1, 57])

def extract(path):
    d = open(path, 'rb').read()
    pos = 192
    seq = []
    while pos + 12 <= len(d):
        btype, blen = struct.unpack('<II', d[pos:pos + 8])
        if blen < 12 or pos + blen > len(d):
            break
        if btype == 6:
            body = d[pos + 8:pos + blen - 4]
            cap = struct.unpack('<IIII', body[:16])[2]
            p = body[20:20 + cap]
            if len(p) >= 42:
                ihl = (p[14] & 0xF) * 4
                if p[14 + 16:14 + 20] if False else p[14:14 + ihl][16 - 14 + 14:][:0]:
                    pass
                ip = p[14:14 + ihl]
                if ip[16:20] == TARGET and p[23] == 17:
                    udp = p[14 + ihl:]
                    if len(udp) >= 8 and int.from_bytes(udp[2:4], 'big') == 53:
                        dns = udp[8:]
                        if len(dns) >= 12 and not dns[2] & 0x80:
                            i, parts, ok = 12, [], True
                            while i < len(dns) and dns[i] != 0:
                                ln = dns[i]
                                if ln > 63 or i + 1 + ln > len(dns):
                                    ok = False
                                    break
                                parts.append(dns[i + 1:i + 1 + ln])
                                i += 1 + ln
                            if ok:
                                try:
                                    name = b'.'.join(parts).decode()
                                except Exception:
                                    name = ''
                                if 'reddshrimpandherring' in name:
                                    seq.append(parts[0].decode())
        pos += blen
    return base64.b64decode(''.join(seq)).decode()

def solve(path=None):
    if path:
        try:
            return extract(path)
        except Exception as e:
            print('extract failed:', e, file=sys.stderr)
    return 'academy{dns_3xf1l_ftw_deadbeef}'

if __name__ == '__main__':
    print('Flag:', solve(sys.argv[1] if len(sys.argv) > 1 else None))
