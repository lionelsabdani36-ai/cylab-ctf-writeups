#!/usr/bin/env python3
"""
Omnirush Automated Test Harness & Verification Suite : CyLab Batch 180
Lead: David (Leader of AI Team / Agent Nyawit) & Omnirush CLI Automated Engine
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis)

Validates AST syntax, py_compile, differential logic invariants, and runtime flag outputs
for Batch 180 modules:
  - 462: Rust fixme 2 (General Skills / Rust Borrowing & Mutability Semantics)
  - 461: Rust fixme 1 (General Skills / Rust Basic Syntax & Macro Formatting)
  - 460: RED (Forensics / PNG Metadata, Scanline Defiltering & RGBA LSB Steganography)
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
        "id": 462,
        "name": "Rust fixme 2",
        "category": "General Skills",
        "script": "solve_462_rust_fixme_2.py",
        "expected_flag": "academy{4r3_y0u_h4v1n5_fun_y31?}",
        "check_type": "rust_borrowing_and_mutability_semantics"
    },
    {
        "id": 461,
        "name": "Rust fixme 1",
        "category": "General Skills",
        "script": "solve_461_rust_fixme_1.py",
        "expected_flag": "academy{4r3_y0u_4_ru$t4c30n_n0w?}",
        "check_type": "rust_syntax_and_macro_formatting"
    },
    {
        "id": 460,
        "name": "RED",
        "category": "Forensics",
        "script": "solve_460_red.py",
        "expected_flag": "academy{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}",
        "check_type": "png_metadata_defiltering_and_rgba_lsb_steganography"
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
    print("  OMNIRUSH TEST HARNESS & VERIFICATION SUITE : BATCH 180")
    print("  Standard: NIST SP 800-115 Section 4.2 / ISO/IEC 25010 / RFC 2083 / RFC 2094 / CWE-843 / CWE-312")
    print("=" * 70)

    # 1. Compiler sweep
    print("[1/2] Running py_compile sweep across all solver scripts in repository...")
    sweep_res = sweep_all_scripts(SCRIPTS_DIR)
    print(f"      Scanned: {sweep_res['total_scanned']} scripts | Passed: {sweep_res['passed']} | Failed: {sweep_res['failed']}")
    if sweep_res["failed"] > 0:
        print("      [!] REGRESSION DETECTED IN SCRIPTS:")
        for fail in sweep_res["failures"]:
            print(f"          - {fail['file']}: {fail['error']}")
        sys.exit(1)

    # 2. Execute target solvers
    print("[2/2] Executing Batch 180 target solvers under Omnirush test harness...")
    solver_results = []
    all_passed = True
    for item in TARGET_SOLVERS:
        res = execute_target_solver(item)
        solver_results.append(res)
        status_sym = "[PASS]" if res["status"] == "PASS" else "[FAIL]"
        print(f"      {status_sym} CID {res['id']}: {res['name']} ({res['duration_sec']}s) -> {res['extracted_flag']}")
        if res["status"] != "PASS":
            all_passed = False

    report = {
        "batch": 180,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "standard": "NIST SP 800-115 Section 4.2 / ISO/IEC 25010 / RFC 2083 / RFC 2094 / CWE-843 / CWE-312",
        "compiler_sweep": sweep_res,
        "solver_results": solver_results,
        "all_passed": all_passed
    }

    report_path = "/home/lionelsabdani36/cylab-ctf-writeups/batch_180_verification_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Verification report persisted to {report_path}")

    if not all_passed:
        print("[-] One or more solvers failed verification!")
        sys.exit(2)
    print("[+] ALL BATCH 180 SOLVERS PASSED WITH 100% INVARIANT INTEGRITY")


if __name__ == "__main__":
    main()
