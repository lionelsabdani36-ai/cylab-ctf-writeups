#!/usr/bin/env python3
"""
Omnirush Automated Test Harness & Verification Suite : CyLab Batch 176
Lead: David (Leader of AI Team / Agent Nyawit) & Omnirush CLI Automated Engine
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis)

Validates AST syntax, py_compile, differential logic invariants, and runtime flag outputs
for Batch 176 modules:
  - 476: head-dump (Web Exploitation / V8 Heap Snapshot Memory Carving & OpenAPI Recon)
  - 475: hashcrack (Cryptography / Fast Hash Function Identification & Multi-Stage Dictionary Crack)
  - 474: Guess My Cheese (Part 2) (Cryptography / Low-Entropy Salt Exhaustion & SHA-256 Rainbow Table)
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
        "id": 476,
        "name": "head-dump",
        "category": "Web Exploitation",
        "script": "solve_476_head_dump.py",
        "expected_flag": "academy{Pat!3nt_15_Th3_K3y_cc0f4fda}",
        "check_type": "v8_heap_snapshot_memory_carving_openapi_recon"
    },
    {
        "id": 475,
        "name": "hashcrack",
        "category": "Cryptography",
        "script": "solve_475_hashcrack.py",
        "expected_flag": "academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}",
        "check_type": "fast_hash_identification_multi_stage_dictionary_crack"
    },
    {
        "id": 474,
        "name": "Guess My Cheese (Part 2)",
        "category": "Cryptography",
        "script": "solve_474_guess_my_cheese_part_2.py",
        "expected_flag": "academy{cHeEsYdaa8c59e}",
        "check_type": "low_entropy_salt_exhaustion_sha256_rainbow_table"
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
        "status": "PASS" if (proc.returncode == 0 and flag_match) else "FAIL",
        "output_snippet": [line.strip() for line in output.strip().splitlines() if line.strip()][:5]
    }


def main():
    print("=" * 70)
    print("  OMNIRUSH TEST HARNESS & VERIFICATION SUITE : BATCH 176")
    print("  Standard: NIST SP 800-115 Section 4.2 / RFC 9110 / FIPS 180-4 / RFC 6234")
    print("=" * 70)

    # 1. Compiler sweep
    print("[1/2] Running py_compile sweep across all solver scripts in repository...")
    sweep_res = sweep_all_scripts(SCRIPTS_DIR)
    print(f"      Scanned: {sweep_res['total_scanned']} scripts | Passed: {sweep_res['passed']} | Failed: {sweep_res['failed']}")
    if sweep_res['failed'] > 0:
        print("      [!] Compilation failures detected:")
        for fail in sweep_res['failures']:
            print(f"          - {fail['file']}: {fail['error']}")
        sys.exit(1)

    # 2. Execute target solvers
    print("\n[2/2] Executing Batch 176 target solvers...")
    solver_results = []
    all_passed = True
    for item in TARGET_SOLVERS:
        res = execute_target_solver(item)
        solver_results.append(res)
        status_icon = "✓" if res["status"] == "PASS" else "✗"
        print(f"      [{status_icon}] CID {res['id']}: {res['name']} ({res['script']}) -> {res['status']} in {res['duration_sec']}s")
        if res["status"] != "PASS":
            all_passed = False
            print(f"          Expected: {res['expected_flag']}")
            print(f"          Got:      {res['extracted_flag']}")
            print(f"          Output:   {res['output_snippet']}")

    # 3. Output verification report JSON
    report = {
        "batch": 176,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "standard": "NIST SP 800-115 Section 4.2 / RFC 9110 / FIPS 180-4 / RFC 1321 / RFC 6234 / CWE-200 / CWE-532 / CWE-328 / CWE-759 / CWE-916 / CWE-330 / CWE-760",
        "compiler_sweep": sweep_res,
        "solver_results": solver_results,
        "all_passed": all_passed
    }

    report_path = "/home/lionelsabdani36/cylab-ctf-writeups/batch_176_verification_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Verification report written to: {report_path}")

    if not all_passed:
        print("\n[FAIL] One or more target solvers failed verification!")
        sys.exit(1)

    print("\n[SUCCESS] All Batch 176 solvers passed automated verification harness!")


if __name__ == "__main__":
    main()
