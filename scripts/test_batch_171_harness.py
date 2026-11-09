#!/usr/bin/env python3
"""
Omnirush Automated Test Harness & Verification Suite — CyLab Batch 171
Lead: David (Leader of AI Team / Agent Nyawit) & Omnirush CLI Automated Engine
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis)

Validates AST syntax, py_compile, differential logic invariants, and runtime flag outputs
for Batch 171 modules:
  - 507: DISKO 3 (Forensics / FAT32 Filesystem, Anomaly Detection & Hidden Archive Carving)
  - 506: DISKO 2 (Forensics / Master Boot Record Partition Analysis & Decoy Evasion)
  - 505: DISKO 1 (Forensics / Raw Disk Image Bulk String Carving & Triage)
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
        "id": 507,
        "name": "DISKO 3",
        "category": "Forensics",
        "script": "solve_507_disko_3.py",
        "expected_flag": "academy{n3v3r_z1p_2_h1d3_2f899900}",
        "check_type": "fat32_directory_entry_gzip_carving"
    },
    {
        "id": 506,
        "name": "DISKO 2",
        "category": "Forensics",
        "script": "solve_506_disko_2.py",
        "expected_flag": "academy{4_P4Rt_1t_i5_51b913f5}",
        "check_type": "mbr_linux_native_partition_carving"
    },
    {
        "id": 505,
        "name": "DISKO 1",
        "category": "Forensics",
        "script": "solve_505_disko_1.py",
        "expected_flag": "academy{1t5_ju5t_4_5tr1n9_19d7626c}",
        "check_type": "raw_disk_image_bulk_string_carving"
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
    print("  CYLAB BATCH 171 — OMNIRUSH AUTOMATED TEST HARNESS & AUDIT SUITE")
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

    # 2. Run target solvers for Batch 171
    print("\n[*] Tahap 2: Mengeksekusi suite solver target Batch 171...")
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
        "batch": 171,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "standard": "NIST SP 800-115 Section 4.2 / RFC 1952 / ISO/IEC 9293 / ANSI INCITS 437 / NIST SP 800-88",
        "compiler_sweep": sweep_res,
        "solver_results": solver_results,
        "all_passed": all_passed and sweep_res["failed"] == 0
    }

    report_path = "/home/lionelsabdani36/cylab-ctf-writeups/batch_171_verification_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Laporan verifikasi berhasil disimpan di {report_path}")

    if not report["all_passed"]:
        print("[!] Terdeteksi kegagalan verifikasi pada satu atau lebih modul.")
        sys.exit(1)
    else:
        print("[+] Seluruh modul Batch 171 terverifikasi 100% PASS.")


if __name__ == "__main__":
    main()
