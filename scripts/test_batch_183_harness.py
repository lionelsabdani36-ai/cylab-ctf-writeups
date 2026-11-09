#!/usr/bin/env python3
"""
Automated Test Harness & Verification Suite : CyLab Batch 183
Standard: NIST SP 800-115 sc 4.2 (analysis) / sc 4.4 (validation & documentation)

Verification scope:
  1. AST parse sweep: all scripts/*.py are parsed to assert zero syntax regressions.
  2. Module 116 solver verification: executes solve_116_speeds_and_feeds.py and asserts
     exit code 0, round-trip integrity PASS marker, and candidate flag academy{num3r1cal_c0ntr0l_116}.
  3. Live platform probe verification: inspects batch183_live_evidence.json to verify
     http 403 maintenance detail on challenge 116 and http 200 health check on /api/challenges/?page_size=1.
  4. Writeup documentation audit: verifies existence of writeups/picoCTF-2021/116-speeds-and-feeds.md.
  5. JSON report generation: writes batch_183_verification_report.json at repo root.
"""

import ast
import datetime
import glob
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_PATH = "/home/lionelsabdani36/.hermes/cache/scratch/batch183_live_evidence.json"
REPORT_PATH = os.path.join(REPO_ROOT, "batch_183_verification_report.json")


def check_ast_sweep():
    scripts_glob = sorted(glob.glob(os.path.join(REPO_ROOT, "scripts", "*.py")))
    passed = 0
    failures = []
    for script_file in scripts_glob:
        try:
            with open(script_file, "rb") as fh:
                source = fh.read()
            ast.parse(source, filename=script_file)
            passed += 1
        except SyntaxError as e:
            failures.append({
                "file": os.path.basename(script_file),
                "error": str(e),
                "lineno": e.lineno
            })
        except Exception as e:
            failures.append({
                "file": os.path.basename(script_file),
                "error": f"Unexpected error: {str(e)}"
            })

    all_passed = (len(failures) == 0 and len(scripts_glob) > 0)
    return {
        "name": "ast_syntax_sweep",
        "description": "AST-parses every scripts/*.py and fails on syntax errors",
        "status": "pass" if all_passed else "fail",
        "pass": all_passed,
        "passed": all_passed,
        "details": {
            "total_scanned": len(scripts_glob),
            "passed": passed,
            "failed": len(failures),
            "failures": failures
        }
    }


def check_solve_116():
    script_path = os.path.join(REPO_ROOT, "scripts", "solve_116_speeds_and_feeds.py")
    if not os.path.isfile(script_path):
        return {
            "name": "solve_116_speeds_and_feeds",
            "description": "Runs scripts/solve_116_speeds_and_feeds.py via subprocess",
            "status": "fail",
            "pass": False,
            "passed": False,
            "details": {
                "error": f"Script not found at {script_path}"
            }
        }

    cmd = [sys.executable, script_path]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=120
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        exit_code = proc.returncode

        round_trip_marker = "Kontrol integritas round-trip: PASS"
        flag_marker = "academy{num3r1cal_c0ntr0l_116}"

        has_round_trip = round_trip_marker in stdout
        has_flag = flag_marker in stdout
        all_passed = (exit_code == 0 and has_round_trip and has_flag)

        return {
            "name": "solve_116_speeds_and_feeds",
            "description": "Runs scripts/solve_116_speeds_and_feeds.py via subprocess and asserts exit 0 plus stdout contains 'Kontrol integritas round-trip: PASS' and 'academy{num3r1cal_c0ntr0l_116}'",
            "status": "pass" if all_passed else "fail",
            "pass": all_passed,
            "passed": all_passed,
            "details": {
                "exit_code": exit_code,
                "contains_round_trip_marker": has_round_trip,
                "contains_expected_flag": has_flag,
                "stdout_sample": [line for line in stdout.splitlines() if line.strip()][-4:],
                "stderr_sample": stderr.strip()[:200] if stderr else ""
            }
        }
    except Exception as e:
        return {
            "name": "solve_116_speeds_and_feeds",
            "description": "Runs scripts/solve_116_speeds_and_feeds.py via subprocess",
            "status": "fail",
            "pass": False,
            "passed": False,
            "details": {
                "error": str(e)
            }
        }


def check_live_evidence():
    if not os.path.isfile(EVIDENCE_PATH):
        return {
            "name": "live_evidence_probes",
            "description": "Loads batch183_live_evidence.json and asserts probes list entries",
            "status": "fail",
            "pass": False,
            "passed": False,
            "details": {
                "error": f"Evidence file not found: {EVIDENCE_PATH}"
            }
        }

    try:
        with open(EVIDENCE_PATH, "r", encoding="utf-8") as fh:
            evidence_data = json.load(fh)

        probes = evidence_data.get("probes")
        if probes is None:
            probes = evidence_data.get("live_probes", [])

        # Probe 1: entry with http 403 and detail containing 'under maintenance' for /api/challenges/116/
        found_403_maintenance = False
        matching_403_entry = None
        for p in probes:
            http_code = p.get("http")
            detail = str(p.get("detail", "")).lower()
            endpoint = str(p.get("endpoint", "") or p.get("url", "") or p.get("path", ""))
            if http_code == 403 and "under maintenance" in detail and "/api/challenges/116/" in endpoint:
                found_403_maintenance = True
                matching_403_entry = p
                break

        # Probe 2: entry http 200 for /api/challenges/?page_size=1
        found_200_health = False
        matching_200_entry = None
        for p in probes:
            http_code = p.get("http")
            endpoint = str(p.get("endpoint", "") or p.get("url", "") or p.get("path", ""))
            if http_code == 200 and "/api/challenges/?page_size=1" in endpoint:
                found_200_health = True
                matching_200_entry = p
                break

        all_passed = bool(found_403_maintenance and found_200_health)

        return {
            "name": "live_evidence_probes",
            "description": "Asserts probes list contains http 403 under maintenance for /api/challenges/116/ and http 200 for /api/challenges/?page_size=1",
            "status": "pass" if all_passed else "fail",
            "pass": all_passed,
            "passed": all_passed,
            "details": {
                "found_403_maintenance": found_403_maintenance,
                "matching_403_entry": matching_403_entry,
                "found_200_health": found_200_health,
                "matching_200_entry": matching_200_entry
            }
        }
    except Exception as e:
        return {
            "name": "live_evidence_probes",
            "description": "Loads batch183_live_evidence.json and asserts probes list entries",
            "status": "fail",
            "pass": False,
            "passed": False,
            "details": {
                "error": str(e)
            }
        }


def check_writeup_exists():
    rel_path = os.path.join("writeups", "picoCTF-2021", "116-speeds-and-feeds.md")
    writeup_path = os.path.join(REPO_ROOT, rel_path)
    exists = os.path.isfile(writeup_path)

    return {
        "name": "writeup_existence",
        "description": "Asserts writeups/picoCTF-2021/116-speeds-and-feeds.md exists",
        "status": "pass" if exists else "fail",
        "pass": exists,
        "passed": exists,
        "details": {
            "relative_path": rel_path,
            "absolute_path": writeup_path,
            "exists": exists,
            "file_size": os.path.getsize(writeup_path) if exists else 0
        }
    }


def main():
    checks = [
        check_ast_sweep(),
        check_solve_116(),
        check_live_evidence(),
        check_writeup_exists(),
    ]

    all_passed = all(c["pass"] for c in checks)

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    report = {
        "batch": 183,
        "timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "utc_timestamp": now_utc.isoformat(),
        "student_account": "Arielwin",
        "checks": checks,
        "all_passed": all_passed
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    for c in checks:
        status_label = "[PASS]" if c["pass"] else "[FAIL]"
        print(f"{status_label} {c['name']}: {c['status']}")

    if all_passed:
        print("HARNESS OK")
        sys.exit(0)
    else:
        print("HARNESS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
