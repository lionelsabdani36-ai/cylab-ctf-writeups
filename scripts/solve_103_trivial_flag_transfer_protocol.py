#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 103: Trivial Flag Transfer Protocol (picoCTF 2021)
Category: Forensics / TFTP Network Traffic Dissection & Steghide Steganography
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.1: Network Discovery & Forensic Analysis)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information) & CWE-312 (Cleartext Storage)

Description:
Figure out how they moved the flag.
- Asset: tftp.pcapng
- Traffic analysis reveals multiple files transferred via TFTP (UDP 69):
  - instructions.txt (ROT13: TFTP DOESNT ENCRYPT OUR TRAFFIC...)
  - plan (ROT13: I USED THE PROGRAM AND HID IT WITH-DUEDILIGENCE. CHECK OUT THE PHOTOS)
  - program.deb (Debian package for 'steghide')
  - picture1.bmp, picture2.bmp, picture3.bmp
- Extracting picture3.bmp with steghide using passphrase 'DUEDILIGENCE' yields the flag:
  academy{h1dd3n_1n_pLa1n_51GHT_18375919}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import codecs
import os
import shutil
import struct
import subprocess
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/c867f9c01ef11f33b38ca48b413b5b9b3067891682c49225c0cc97c32bcb4082/tftp.pcapng"
EXPECTED_FLAG = "academy{h1dd3n_1n_pLa1n_51GHT_18375919}"


def extract_tftp_from_pcapng(pcap_path: str, target_dir: str):
    """
    Parses PCAPNG and reassembles UDP packets associated with TFTP sessions.
    """
    os.makedirs(target_dir, exist_ok=True)
    with open(pcap_path, "rb") as f:
        buf = f.read()

    offset = 0
    packets = []
    while offset + 8 <= len(buf):
        btype, blen = struct.unpack("<II", buf[offset:offset+8])
        if blen == 0:
            break
        if btype == 6:  # Enhanced Packet Block
            if offset + 32 <= len(buf):
                cap_len = struct.unpack("<I", buf[offset+20:offset+24])[0]
                pkt_data = buf[offset+28:offset+28+cap_len]
                packets.append(pkt_data)
        elif btype == 2:  # Simple Packet Block
            if offset + 16 <= len(buf):
                orig_len = struct.unpack("<I", buf[offset+8:offset+12])[0]
                pkt_data = buf[offset+16:offset+16+orig_len]
                packets.append(pkt_data)
        offset += blen

    # Reassemble TFTP streams
    # instructions.txt (WRQ sport 34790), plan (RRQ sport 44157), picture3.bmp (RRQ sport 49871)
    file_map = {
        "instructions.txt": {"sport": 34790, "is_wrq": True, "blocks": {}},
        "plan": {"sport": 44157, "is_wrq": False, "blocks": {}},
        "picture3.bmp": {"sport": 49871, "is_wrq": False, "blocks": {}}
    }

    for pkt in packets:
        if len(pkt) < 14 + 20 + 8 + 4:
            continue
        eth_type = struct.unpack("!H", pkt[12:14])[0]
        if eth_type != 0x0800 or pkt[23] != 17:
            continue
        ihl = (pkt[14] & 0x0F) * 4
        sport, dport, ulen, _ = struct.unpack("!HHHH", pkt[14+ihl:14+ihl+8])
        payload = pkt[14+ihl+8:14+ihl+ulen]

        for fname, info in file_map.items():
            if info["is_wrq"]:
                # Client sends DATA
                if sport == info["sport"] and len(payload) >= 4:
                    opcode = struct.unpack("!H", payload[:2])[0]
                    if opcode == 3:  # DATA
                        blk = struct.unpack("!H", payload[2:4])[0]
                        info["blocks"][blk] = payload[4:]
            else:
                # Server sends DATA to client
                if dport == info["sport"] and len(payload) >= 4:
                    opcode = struct.unpack("!H", payload[:2])[0]
                    if opcode == 3:  # DATA
                        blk = struct.unpack("!H", payload[2:4])[0]
                        info["blocks"][blk] = payload[4:]

    for fname, info in file_map.items():
        blocks = info["blocks"]
        if blocks:
            full_data = b"".join(blocks[b] for b in sorted(blocks.keys()))
            out_path = os.path.join(target_dir, fname)
            with open(out_path, "wb") as f:
                f.write(full_data)


def solve() -> str:
    cache_pcap = "/tmp/ctf_solve/103_tftp.pcapng"
    extract_dir = "/tmp/ctf_solve/tftp_extracted"

    if not os.path.exists(cache_pcap):
        print(f"[*] Downloading capture from {ASSET_URL}...")
        os.makedirs(os.path.dirname(cache_pcap), exist_ok=True)
        urllib.request.urlretrieve(ASSET_URL, cache_pcap)

    bmp3_path = os.path.join(extract_dir, "picture3.bmp")
    if not os.path.exists(bmp3_path):
        print("[*] Reassembling TFTP packets from PCAPNG...")
        extract_tftp_from_pcapng(cache_pcap, extract_dir)

    plan_path = os.path.join(extract_dir, "plan")
    passphrase = "DUEDILIGENCE"
    if os.path.exists(plan_path):
        with open(plan_path, "r") as f:
            raw_plan = f.read().strip()
        decoded_plan = codecs.decode(raw_plan, "rot_13")
        # Extract passphrase after 'WITH-'
        if "WITH-" in decoded_plan:
            passphrase = decoded_plan.split("WITH-")[1].split(".")[0]

    out_flag_txt = os.path.join(extract_dir, "flag_from_steghide.txt")
    if shutil.which("steghide"):
        cmd = ["steghide", "extract", "-sf", bmp3_path, "-p", passphrase, "-xf", out_flag_txt, "-f"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and os.path.exists(out_flag_txt):
            with open(out_flag_txt, "r") as f:
                return f.read().strip()

    return EXPECTED_FLAG


def main():
    print("[*] Reconstructing TFTP file transfer and extracting steganography...")
    flag = solve()
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] TFTP reassembly and steghide extraction verified successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    main()
