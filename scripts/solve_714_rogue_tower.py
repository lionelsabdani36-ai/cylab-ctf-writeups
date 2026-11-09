#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Rogue Tower (Challenge ID: 714)
Category: Forensics / Rogue Cellular Base Station (Fake BTS / IMSI Catcher) & Repeating-Key XOR Exfiltration
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
3GPP TS 33.501 (Security Architecture and Procedures for 5G System),
3GPP TS 33.102 (3G Security Architecture), RFC 791 (IPv4 Protocol),
CWE-321 (Use of Hard-coded Cryptographic Key), CWE-327 (Use of Broken Cryptographic Algorithm - Repeating XOR),
& MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol).

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge distributes a raw network capture `rogue_tower.pcap` (DLT_RAW / DLT_IPV4, linktype 228 / 0xE4).
   - In legacy cellular network architectures (GSM/2G/3G and LTE pre-authentication states), mobile stations
     do not enforce mutual authentication prior to identity disclosure.
   - Packet 13: An unauthorized cell tower broadcasts on UDP port 55000:
     `UNAUTHORIZED-TEST-NETWORK PLMN=00101 CELLID=91729`
   - Packet 15: A compromised mobile device connects and issues an HTTP registration request:
     `GET /api/register HTTP/1.1`
     `Host: network.carrier.com`
     `User-Agent: MobileDevice/1.0 (IMSI:310410709993882; CELL:91729)`
     revealing the victim's International Mobile Subscriber Identity: `310410709993882`.
2. Chunked Exfiltration & Insecure Suffix-Key XOR (CWE-321 / CWE-327 / T1048):
   - Packets 16 to 21 transmit chunked Base64 payloads over HTTP `POST /upload` to `198.51.100.117:443`:
     Fragments: `UVpYXVZVQ` + `UlCCV5MAG` + `dbAVxVZk0` + `DTwtAbwAK` + `CFZZAVEAR` + `A==`
     Combined Base64: `UVpYXVZVQUlCCV5MAGdbAVxVZk0DTwtAbwAKCFZZAVEARA==` (48 characters -> 34 bytes).
   - The cipher relies on a static repeating 8-byte XOR key derived from the last 8 digits of the victim's IMSI:
     `key = IMSI[-8:] = "09993882"`.
   - Applying repeating-key XOR yields: `academy{r0gu3_c3ll_t0w3r_931ea9c0}`.
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import os
import sys
import json
import base64
import struct
import itertools
import urllib.request
import urllib.error

CHALLENGE_ID = 714
CHALLENGE_NAME = "Rogue Tower"
VERIFIED_FLAG = "academy{r0gu3_c3ll_t0w3r_931ea9c0}"
COMMUNITY_FLAG = "CTF{r0gu3_c3ll_t0w3r_931ea9c0}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
PCAP_URL = "https://challenge-files.cylabacademy.net/library/4bdcbc4922e90bb3ec6f96fc1574b6cafcccf05fd57f0b527e8862fca0f849ae/rogue_tower.pcap"

FALLBACK_IMSI = "310410709993882"
FALLBACK_CELL_ID = "91729"
FALLBACK_B64_FRAGMENTS = [
    "UVpYXVZVQ",
    "UlCCV5MAG",
    "dbAVxVZk0",
    "DTwtAbwAK",
    "CFZZAVEAR",
    "A=="
]


class RogueTowerSimulator:
    """
    Forensics parser and cryptographic reconstruction engine for Rogue Tower capture.
    """
    def __init__(self, pcap_path: str = "rogue_tower.pcap"):
        self.pcap_path = pcap_path
        self.imsi = None
        self.cell_id = None
        self.b64_chunks = []

    def ensure_pcap(self) -> bool:
        if os.path.exists(self.pcap_path):
            return True
        print(f"[*] Mengunduh artefak PCAP dari {PCAP_URL}...")
        try:
            req = urllib.request.Request(PCAP_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp, open(self.pcap_path, "wb") as f:
                f.write(resp.read())
            print(f"[+] PCAP tersimpan: {self.pcap_path} ({os.path.getsize(self.pcap_path)} bytes)")
            return True
        except Exception as e:
            print(f"[!] Gagal mengunduh PCAP: {e}. Menggunakan fallback artefak transkrip.")
            return False

    def parse_pcap(self) -> bool:
        if not os.path.exists(self.pcap_path):
            return False

        with open(self.pcap_path, "rb") as f:
            hdr = f.read(24)
            if len(hdr) < 24:
                return False
            magic = struct.unpack("<I", hdr[:4])[0]
            endian = "<" if magic == 0xA1B2C3D4 else ">"
            network = struct.unpack(f"{endian}I", hdr[20:24])[0]

            while True:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", ph)
                raw = f.read(incl_len)

                ip_data = raw
                if network == 1 and len(raw) >= 14:
                    ip_data = raw[14:]

                if len(ip_data) < 20:
                    continue

                ihl = (ip_data[0] & 0x0F) * 4
                proto = ip_data[9]

                if proto == 17:  # UDP
                    udp_payload = ip_data[ihl + 8:]
                    if b"UNAUTHORIZED-TEST-NETWORK" in udp_payload:
                        text = udp_payload.decode("latin1", errors="ignore")
                        if "CELLID=" in text:
                            self.cell_id = text.split("CELLID=")[1].split()[0]
                            print(f"[+] Rogue Base Station terdeteksi: CELLID={self.cell_id}")

                elif proto == 6:  # TCP
                    tcp_data = ip_data[ihl:]
                    if len(tcp_data) >= 20:
                        tcp_off = ((struct.unpack(">H", tcp_data[12:14])[0] >> 12) & 0x0F) * 4
                        payload = tcp_data[tcp_off:]

                        if b"GET /api/register" in payload and b"CELL:" in payload:
                            for line in payload.split(b"\r\n"):
                                if b"IMSI:" in line:
                                    part = line.split(b"IMSI:")[1].split(b";")[0].decode()
                                    self.imsi = part.strip()
                                    print(f"[+] Perangkat terkompromi teridentifikasi: IMSI={self.imsi}")

                        if b"POST /upload" in payload and b"\r\n\r\n" in payload:
                            body = payload.split(b"\r\n\r\n")[1].strip()
                            if body:
                                self.b64_chunks.append(body.decode("ascii", errors="ignore"))

        return bool(self.imsi and self.b64_chunks)

    def decrypt(self) -> str:
        imsi = self.imsi or FALLBACK_IMSI
        chunks = self.b64_chunks if self.b64_chunks else FALLBACK_B64_FRAGMENTS

        key_str = imsi[-8:]
        key_bytes = key_str.encode("ascii")
        print(f"[+] Kunci XOR 8-byte diturunkan dari IMSI[-8:]: {key_str}")

        combined_b64 = "".join(chunks)
        print(f"[+] Payload Base64 gabungan ({len(combined_b64)} karakter): {combined_b64}")

        ciphertext = base64.b64decode(combined_b64)
        print(f"[+] Panjang ciphertext biner: {len(ciphertext)} bytes")

        plaintext = bytes(c ^ k for c, k in zip(ciphertext, itertools.cycle(key_bytes)))
        recovered = plaintext.decode("ascii", errors="replace")
        return recovered


def submit_to_cylab(flag: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode()
    cookie_header = ""
    csrf_token = ""

    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    if not cookie_header or not csrf_token:
        print("[!] Autentikasi sesi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status") or (data.get("correct") is True)
            print(f"[+] Status submisi CyLab (HTTP {resp.status}): {data}")
            return bool(status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[-] Submisi gagal (HTTP {e.code}): {body}")
        return False


def main():
    print(f"=== [CyLab Academy] Solusi Modul #{CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    pcap_path = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "rogue_tower.pcap"

    engine = RogueTowerSimulator(pcap_path)
    if os.path.exists(pcap_path) or engine.ensure_pcap():
        print(f"[*] Melakukan forensik paket pada berkas {pcap_path}...")
        engine.parse_pcap()
    else:
        print("[*] Berkas PCAP lokal tidak tersedia, menggunakan artefak transkrip embedded.")

    flag = engine.decrypt()
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    if flag != VERIFIED_FLAG:
        print(f"[!] Peringatan: Flag hasil rekonstruksi ({flag}) berbeda dengan VERIFIED_FLAG ({VERIFIED_FLAG})")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
