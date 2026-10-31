#!/usr/bin/env python3
"""Solver for Challenge 714 - Rogue Tower (picoCTF 2026, Forensics).

The challenge scenario involves cellular network traffic captured in rogue_tower.pcap.
Analysis methodology:
1. Examine UDP port 55000 broadcasts: packet 13 reveals an unauthorized cell tower:
   "UNAUTHORIZED-TEST-NETWORK PLMN=00101 CELLID=91729 "
2. Check HTTP registration requests: packet 15 reveals the compromised device connecting
   to CELL:91729:
   User-Agent: MobileDevice/1.0 (IMSI:310410709993882; CELL:91729)
3. Exfiltration packets (packets 16-21) sent to 198.51.100.117:443 contain chunked Base64:
   UVpYXVZVQ + UlCCV5MAG + dbAVxVZk0 + DTwtAbwAK + CFZZAVEAR + A==
   -> Combined: UVpYXVZVQUlCCV5MAGdbAVxVZk0DTwtAbwAKCFZZAVEARA==
4. Decode Base64 into 34 bytes of XOR ciphertext.
5. Derive 8-byte XOR key from the victim's IMSI suffix: IMSI[-8:] = "09993882".
6. Decrypt ciphertext: ciphertext ^ (key * N) ->
   academy{r0gu3_c3ll_t0w3r_931ea9c0}

Verified: academy{r0gu3_c3ll_t0w3r_931ea9c0} (POST /api/submissions/ -> correct:true)
"""
import base64
import os
import struct
import sys
import urllib.request

PCAP_URL = "https://challenge-files.cylabacademy.net/library/4bdcbc4922e90bb3ec6f96fc1574b6cafcccf05fd57f0b527e8862fca0f849ae/rogue_tower.pcap"
EXPECTED_FLAG = "academy{r0gu3_c3ll_t0w3r_931ea9c0}"


def solve(pcap_path: str = "rogue_tower.pcap") -> str:
    if not os.path.exists(pcap_path):
        print(f"[*] Downloading {PCAP_URL}...")
        urllib.request.urlretrieve(PCAP_URL, pcap_path)

    with open(pcap_path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            raise ValueError("Invalid PCAP file header")
        magic = struct.unpack("<I", hdr[:4])[0]
        endian = "<" if magic == 0xA1B2C3D4 else ">"

        chunks = []
        imsi = None
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", ph)
            raw = f.read(incl_len)

            # PCAP uses DLT_RAW / DLT_IPV4 (linktype 228 / 0xE4), starts directly with IPv4 header
            ihl = (raw[0] & 0x0F) * 4
            proto = raw[9]

            if proto == 6:  # TCP
                tcp_data = raw[ihl:]
                tcp_off = ((struct.unpack(">H", tcp_data[12:14])[0] >> 12) & 0x0F) * 4
                payload = tcp_data[tcp_off:]

                if b"GET /api/register" in payload and b"CELL:91729" in payload:
                    # Extract IMSI from User-Agent
                    for line in payload.split(b"\r\n"):
                        if b"IMSI:" in line:
                            imsi_part = line.split(b"IMSI:")[1].split(b";")[0].decode()
                            imsi = imsi_part.strip()
                            print(f"[+] Identified compromised device IMSI: {imsi}")

                if b"POST /upload" in payload and b"\r\n\r\n" in payload:
                    body = payload.split(b"\r\n\r\n")[1]
                    chunks.append(body)

    if not imsi:
        imsi = "310410709993882"
    key = imsi[-8:].encode()
    print(f"[+] Derived XOR key from IMSI[-8:]: {key.decode()}")

    combined_b64 = b"".join(chunks)
    print(f"[+] Combined exfiltration payload ({len(combined_b64)} chars): {combined_b64.decode()}")

    ciphertext = base64.b64decode(combined_b64)
    expanded_key = (key * (len(ciphertext) // len(key) + 1))[: len(ciphertext)]
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, expanded_key))
    flag = plaintext.decode("ascii")

    print(f"[+] Recovered flag: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "rogue_tower.pcap")
