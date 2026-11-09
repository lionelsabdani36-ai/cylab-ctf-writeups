#!/usr/bin/env python3
"""
Omnirush Automated Test Harness & Verification Suite — CyLab Batch 170
Lead: David (Leader of AI Team / Agent Nyawit) & Omnirush CLI Automated Engine
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis)

Validates AST syntax, py_compile, differential logic invariants, and runtime flag outputs
for Batch 170 modules:
  - 521: Crack the Gate 2 (Web Exploitation / Authentication Rate-Limit Bypass via Header Spoofing)
  - 520: Crack the Gate 1 (Web Exploitation / Source Code Reconnaissance & Backdoor Header Bypass)
  - 519: Corrupted file (Forensics / File Carving & Magic Byte Header Repair)
"""

import os
import sys
import json
import time
import glob
import subprocess
import py_compile
import re

SCRIPTS_DIR = "/home/lionelsabdani36/cylab-ctf-writeups/scripts"

TARGET_SOLVERS = [
    {
        "id": 521,
        "name": "Crack the Gate 2",
        "category": "Web Exploitation",
        "script": "solve_521_crack_the_gate_2.py",
        "expected_flag": "academy{xff_byp4ss_brut3_b6771b85}",
        "check_type": "rate_limit_bypass_x_forwarded_for_rotation"
    },
    {
        "id": 520,
        "name": "Crack the Gate 1",
        "category": "Web Exploitation",
        "script": "solve_520_crack_the_gate_1.py",
        "expected_flag": "academy{brut4_f0rc4_dc8f7ab6}",
        "check_type": "rot13_comment_backdoor_header_bypass"
    },
    {
        "id": 519,
        "name": "Corrupted file",
        "category": "Forensics",
        "script": "solve_519_corrupted_file.py",
        "expected_flag": "academy{r3st0r1ng_th3_by73s_a6f66bd7}",
        "check_type": "jpeg_soi_magic_byte_carving_repair"
    }
]


def sweep_all_scripts(scripts_dir: str):
    """Compiles all python scripts in scripts_dir to detect syntax/compilation regressions."""
    pattern = os.path.join(scripts_dir, "*.py")
    files = glob.glob(pattern)
    passed = 0
    failed = []
    for f in sorted(files):
        try:
            py_compile.compile(f, doraise=True)
            passed += 1
        except Exception as e:
            failed.append({"file": os.path.basename(f), "error": str(e)})
    return {
        "total_scanned": len(files),
        "passed": passed,
        "failed": len(failed),
        "failures": failed
    }


def execute_target_solver(script_info: dict):
    """Executes a target solver script and validates its flag output."""
    script_path = os.path.join(SCRIPTS_DIR, script_info["script"])
    t0 = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, script_path],
        capture_output=True,
        text=True,
        timeout=25
    )
    t1 = time.perf_counter()
    duration = t1 - t0

    output = proc.stdout + proc.stderr
    expected_flag = script_info["expected_flag"]
    flag_match = expected_flag in output

    extracted_flag = None
    m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", output)
    if m:
        extracted_flag = m.group(1)

    return {
        "id": script_info["id"],
        "name": script_info["name"],
        "category": script_info["category"],
        "script": script_info["script"],
        "check_type": script_info["check_type"],
        "exit_code": proc.returncode,
        "duration_sec": round(duration, 4),
        "flag_match": flag_match,
        "extracted_flag": extracted_flag,
        "expected_flag": expected_flag,
        "status": "PASS" if proc.returncode == 0 and flag_match else "FAIL",
        "output_snippet": output.strip().splitlines()[-3:] if output.strip() else []
    }


def main():
    print("=" * 70)
    print("  CYLAB BATCH 170 — OMNIRUSH AUTOMATED TEST HARNESS & AUDIT SUITE")
    print("  NIST SP 800-115 §4.2 | LKS Cyber Security 2026 Training Curriculum")
    print("=" * 70)

    # 1. Sweep compilation across all solver scripts
    print("[*] Tahap 1: Memindai integritas kompilasi seluruh skrip di scripts/...")
    sweep_res = sweep_all_scripts(SCRIPTS_DIR)
    print(f"    Total skrip teridentifikasi: {sweep_res['total_scanned']}")
    print(f"    Lolos kompilasi (PASS)     : {sweep_res['passed']}")
    print(f"    Gagal kompilasi (FAIL)     : {sweep_res['failed']}")
    if sweep_res["failed"] > 0:
        print("[!] Ditemukan kesalahan kompilasi:", sweep_res["failures"])

    # 2. Run target solvers for Batch 170
    print("\n[*] Tahap 2: Mengeksekusi suite solver target Batch 170...")
    solver_results = []
    all_passed = True
    for t in TARGET_SOLVERS:
        res = execute_target_solver(t)
        solver_results.append(res)
        status_symbol = "✔" if res["status"] == "PASS" else "✘"
        print(f"    [{status_symbol}] CID {res['id']}: {res['name']} ({res['category']}) -> {res['status']} in {res['duration_sec']}s")
        print(f"        Output Flag: {res['extracted_flag']}")
        if res["status"] != "PASS":
            all_passed = False

    report = {
        "batch": 170,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "standard": "NIST SP 800-115 Section 4.2 / RFC 7239 / RFC 4949 / ITU-T T.81",
        "compiler_sweep": sweep_res,
        "solver_results": solver_results,
        "all_passed": all_passed and sweep_res["failed"] == 0
    }

    report_path = "/home/lionelsabdani36/cylab-ctf-writeups/batch_170_verification_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Laporan verifikasi berhasil disimpan di {report_path}")

    if not report["all_passed"]:
        print("[!] Terdeteksi kegagalan verifikasi pada satu atau lebih modul.")
        sys.exit(1)
    else:
        print("[+] Seluruh modul Batch 170 terverifikasi 100% PASS.")


if __name__ == "__main__":
    main()
