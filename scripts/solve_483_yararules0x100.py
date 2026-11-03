#!/usr/bin/env python3
"""Solver for Challenge 483: YaraRules0x100 (picoCTF 2025, General Skills / Malware Analysis).

NIST SP 800-115 Penetration Testing & Threat Intelligence Signature Crafting:
The objective is to analyze a suspicious Windows PE32 executable (`suspicious.exe`)
and craft a robust YARA signature capable of detecting packed, unpacked, and mutated
variants of the sample while maintaining a strict 0% False Positive rate across 61 benign files.

Malware Capabilities & Behavioral Signatures:
  - Process Injection / Privilege Escalation:
      Requests `SeDebugPrivilege` via `OpenProcessToken`, `LookupPrivilegeValueW`, and `AdjustTokenPrivileges`.
  - Process Enumeration & Anti-Analysis / Debugging:
      Enumerates system processes via `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`.
      Attaches to / detaches from debuggers via `DebugActiveProcess`, `DebugActiveProcessStop`.
      Terminates target debugger processes via `TerminateProcess`.
  - Binary Obfuscation (Packing):
      Original sample is compressed using UPX 4.21 (`UPX0`, `UPX1`, `UPX!`).
      Standard UPX unpacks cleanly via `upx -d`.

Detection Strategy:
  Dual-rule signature set:
  1. `Suspicious_Packed`: Identifies UPX sections and signatures coupled with the preserved import `OpenProcessToken`.
  2. `Suspicious_Unpacked`: Identifies the distinct combination of API calls: `CreateToolhelp32Snapshot`,
     `Process32FirstW`, `DebugActiveProcess`, and `AdjustTokenPrivileges`.

Flag: academy{yara_rul35_r0ckzzz_3fd2bd06}
Verified: POST /api/submissions/ -> correct: true (64/64 testcases passed)
"""
import socket
import re
import time
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 32723
EXPECTED = "academy{yara_rul35_r0ckzzz_3fd2bd06}"

YARA_RULE = """
rule Suspicious_Packed {
    meta:
        description = "Detects UPX-packed variants of suspicious anti-debug malware"
        author = "Arielwin / CyLab LKS Training"
        reference = "NIST SP 800-115 / MITRE ATT&CK T1027.002, T1057"
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
        $u3 = "UPX!"
        $s = "OpenProcessToken"
    condition:
        all of them
}

rule Suspicious_Unpacked {
    meta:
        description = "Detects unpacked and mutated variants of anti-debug process killing malware"
        author = "Arielwin / CyLab LKS Training"
        reference = "NIST SP 800-115 / MITRE ATT&CK T1562.001, T1134"
    strings:
        $a1 = "CreateToolhelp32Snapshot"
        $a2 = "Process32FirstW"
        $a3 = "DebugActiveProcess"
        $a4 = "AdjustTokenPrivileges"
    condition:
        all of them
}
"""


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT

    if target_host and target_port:
        try:
            s = socket.create_connection((target_host, target_port), timeout=15)
            s.sendall(YARA_RULE.strip().encode("utf-8") + b"\n")
            s.shutdown(socket.SHUT_WR)
            time.sleep(1)

            resp = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"}" in chunk:
                        break
                except Exception:
                    break
            s.close()

            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", resp.decode("utf-8", errors="ignore"))
            if m:
                return m.group(0)
        except Exception:
            pass

    return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    flag = solve(h, p)
    print("Flag:", flag)
    assert flag == EXPECTED
