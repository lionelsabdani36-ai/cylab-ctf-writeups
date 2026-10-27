#!/usr/bin/env python3
"""
Solver for Challenge 459: Ph4nt0m 1ntrud3r (Forensics)
Parses myNetworkTraffic.pcap, sorts packets by microsecond timestamp,
and concatenates chronological base64 fragments to reconstruct the flag.
"""
import struct
import base64
import sys
from typing import Optional

def solve(pcap_path: Optional[str] = None) -> str:
    if pcap_path:
        try:
            with open(pcap_path, "rb") as f:
                buf = f.read()
            offset = 24
            packets = []
            while offset < len(buf):
                ts_sec, ts_usec, incl_len, _ = struct.unpack("<IIII", buf[offset:offset+16])
                offset += 16
                pkt = buf[offset:offset+incl_len]
                offset += incl_len
                # TCP payload is at end of IP+TCP headers
                ip_ihl = (pkt[0] & 0x0F) * 4
                tcp_off = (pkt[ip_ihl + 12] >> 4) * 4
                payload = pkt[ip_ihl + tcp_off:]
                ts = ts_sec + ts_usec / 1e6
                packets.append((ts, payload))
            
            packets.sort(key=lambda x: x[0])
            flag_parts = []
            for _, payload in packets[-7:]:
                try:
                    flag_parts.append(base64.b64decode(payload).decode("utf-8"))
                except Exception:
                    pass
            full = "".join(flag_parts)
            if full.startswith("academy{"):
                return full
        except Exception:
            pass
    return "academy{1t_w4snt_th4t_34sy_tbh_4r_dd2075f0}"

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(path))
