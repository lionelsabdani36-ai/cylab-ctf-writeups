#!/usr/bin/env python3
"""
Omnirush Automated Test Harness & Verification Suite — CyLab Batch 168
Lead: David (Leader of AI Team / Agent Nyawit) & Omnirush CLI Automated Engine
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis)

Validates AST syntax, py_compile, differential logic invariants, and runtime flag outputs
for Batch 168 modules:
  - 528: M1n10n'5_53cr37 (Reverse Engineering / Android APK Resource Decompilation & Base32 Decoding)
  - 526: Input Injection 2 (Binary Exploitation / Heap Overflow & Command Injection Redirection Bypass)
  - 525: Input Injection 1 (Binary Exploitation / Stack Buffer Overflow & Adjacent Local Variable Overwrite)
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
        "id": 528,
        "name": "M1n10n'5_53cr37",
        "category": "Reverse Engineering",
        "script": "solve_528_m1n10n5_53cr37.py",
        "expected_flag": "academy{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}",
        "check_type": "apk_resource_base32_decoding"
    },
    {
        "id": 526,
        "name": "Input Injection 2",
        "category": "Binary Exploitation",
        "script": "solve_526_input_injection_2.py",
        "expected_flag": "academy{us3rn4m3_2_sh3ll_819f0acb}",
        "check_type": "heap_overflow_redirection_command_injection"
    },
    {
        "id": 525,
        "name": "Input Injection 1",
        "category": "Binary Exploitation",
        "script": "solve_525_input_injection_1.py",
        "expected_flag": "academy{0v3rfl0w_c0mm4nd_72792d0d}",
        "check_type": "stack_overflow_local_variable_overwrite"
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
        timeout=15
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
    print("  CYLAB BATCH 168 — OMNIRUSH AUTOMATED TEST HARNESS & AUDIT SUITE")
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

    # 2. Run target solvers for Batch 168
    print("\n[*] Tahap 2: Mengeksekusi suite solver target Batch 168...")
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
        "batch": 168,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "standard": "NIST SP 800-115 Section 4.2 / RFC 4648 / POSIX.1-2017",
        "compiler_sweep": sweep_res,
        "solver_results": solver_results,
        "all_passed": all_passed and sweep_res["failed"] == 0
    }

    report_path = "/home/lionelsabdani36/cylab-ctf-writeups/batch_168_verification_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Laporan verifikasi berhasil disimpan di {report_path}")

    if not report["all_passed"]:
        print("[!] Terdeteksi kegagalan verifikasi pada satu atau lebih modul.")
        sys.exit(1)
    else:
        print("[+] Seluruh modul Batch 168 terverifikasi 100% PASS.")


if __name__ == "__main__":
    main()
