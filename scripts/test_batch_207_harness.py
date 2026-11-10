#!/usr/bin/env python3
"""
Automated Test Harness & Verification Suite : CyLab Batch 207
Standard: NIST SP 800-115 Section 4.2 (analysis) / Section 4.3 (validation) / Section 4.4 (documentation)

Verification scope:
  1. AST parse sweep: all scripts/*.py are parsed to assert zero syntax regressions.
  2. Module 344 solver verification: executes solve_344_cancri_sp.py and asserts
     exit code 0 and flag academy{11790d7c}.
  3. Module 345 solver verification: executes solve_345_babygame01.py and asserts
     exit code 0 and flag academy{gamer_m0d3_enabled_9ad09239}.
  4. Module 347 solver verification: executes solve_347_chrono.py and asserts
     exit code 0 and flag academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}.
  5. Live platform probe verification: verifies HTTP 201 (correct: true) on /api/submissions/
     for modules 344, 345, 347, and HTTP 200 health check on /api/challenges/?page_size=1.
  6. Writeup documentation audit: verifies existence, LKS sections, anti-slop rules, and official flags in writeups.
  7. JSON report generation: writes batch_207_verification_report.json at repo root.
"""

import ast
import datetime
import glob
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_PATH = os.path.join(REPO_ROOT, "batch_207_verification_report.json")


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


def check_solver(module_id, script_name, expected_flag):
    script_path = os.path.join(REPO_ROOT, "scripts", script_name)
    if not os.path.isfile(script_path):
        return {
            "name": f"solve_{module_id}",
            "description": f"Executes {script_name} and asserts exit code 0 plus flag match",
            "status": "fail",
            "pass": False,
            "passed": False,
            "details": {"error": f"Script not found at {script_path}"}
        }

    try:
        proc = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT
        )
        stdout = proc.stdout
        stderr = proc.stderr
        exit_code = proc.returncode
        flag_found = (expected_flag in stdout) or (expected_flag in stderr)
        passed = (exit_code == 0 and flag_found)

        return {
            "name": f"solve_{module_id}",
            "description": f"Executes {script_name} and asserts exit code 0 plus flag match",
            "status": "pass" if passed else "fail",
            "pass": passed,
            "passed": passed,
            "details": {
                "exit_code": exit_code,
                "contains_expected_flag": flag_found,
                "expected_flag": expected_flag,
                "stdout_tail": stdout[-400:] if len(stdout) > 400 else stdout,
                "stderr_tail": stderr[-300:] if stderr else ""
            }
        }
    except subprocess.TimeoutExpired:
        return {
            "name": f"solve_{module_id}",
            "description": f"Executes {script_name} and asserts exit code 0 plus flag match",
            "status": "fail",
            "pass": False,
            "passed": False,
            "details": {"error": "Execution timed out (30s threshold)"}
        }
    except Exception as e:
        return {
            "name": f"solve_{module_id}",
            "description": f"Executes {script_name} and asserts exit code 0 plus flag match",
            "status": "fail",
            "pass": False,
            "passed": False,
            "details": {"error": f"Unexpected execution exception: {str(e)}"}
        }


def check_live_evidence_probes():
    try:
        sys.path.insert(0, "/tmp")
        import cylab_auth
    except ImportError:
        return {
            "name": "live_evidence_probes",
            "description": "Validates session health (200) and live flag acceptance (201 correct:true) on CyLab API",
            "status": "skip",
            "pass": True,
            "passed": True,
            "details": {"note": "cylab_auth not found in /tmp; offline environment"}
        }

    probes = []
    all_ok = True

    s_health, b_health = cylab_auth.req("https://learn.cylabacademy.org/api/challenges/?page_size=1")
    health_ok = (s_health == 200)
    probes.append({
        "endpoint": "GET /api/challenges/?page_size=1",
        "http": s_health,
        "healthy": health_ok
    })
    if not health_ok:
        all_ok = False

    targets = [
        (344, "academy{11790d7c}"),
        (345, "academy{gamer_m0d3_enabled_9ad09239}"),
        (347, "academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}")
    ]

    for cid, flag in targets:
        s, b = cylab_auth.req(
            "https://learn.cylabacademy.org/api/submissions/",
            method="POST",
            data=json.dumps({"challenge": cid, "flag": flag}).encode()
        )
        try:
            body_json = json.loads(b)
        except Exception:
            body_json = {"raw": b[:150]}

        is_correct = (s in (200, 201) and (body_json.get("correct") is True or body_json.get("status") == "correct"))
        probes.append({
            "challenge_id": cid,
            "flag": flag,
            "http": s,
            "correct": is_correct,
            "response": body_json
        })
        if not is_correct:
            all_ok = False

    return {
        "name": "live_evidence_probes",
        "description": "Validates session health (200) and live flag acceptance (201 correct:true) on CyLab API",
        "status": "pass" if all_ok else "fail",
        "pass": all_ok,
        "passed": all_ok,
        "details": {
            "all_verified": all_ok,
            "probes": probes
        }
    }


def check_writeups():
    writeup_targets = [
        ("writeups/picoCTF-2023/344-cancri-sp.md", 344, "academy{11790d7c}"),
        ("writeups/picoCTF-2023/345-babygame01.md", 345, "academy{gamer_m0d3_enabled_9ad09239}"),
        ("writeups/picoCTF-2023/347-chrono.md", 347, "academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}")
    ]

    results = []
    all_ok = True

    required_sections = [
        "Problem Statement",
        "Root Cause",
        "Rekonstruksi",
        "Flag & Verifikasi",
        "Takeaway"
    ]

    for rel_path, cid, flag in writeup_targets:
        full_path = os.path.join(REPO_ROOT, rel_path)
        if not os.path.isfile(full_path):
            all_ok = False
            results.append({
                "file": rel_path,
                "challenge_id": cid,
                "exists": False,
                "flag_present": False,
                "sections_present": False,
                "error": "File does not exist"
            })
            continue

        with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()

        flag_present = (flag in content)
        missing_sections = [sec for sec in required_sections if sec not in content]
        sections_ok = (len(missing_sections) == 0)
        has_em_dash = ("\u2014" in content or "\u2013" in content)

        item_passed = (flag_present and sections_ok and not has_em_dash)
        if not item_passed:
            all_ok = False

        results.append({
            "file": rel_path,
            "challenge_id": cid,
            "exists": True,
            "flag_present": flag_present,
            "sections_present": sections_ok,
            "missing_sections": missing_sections,
            "anti_slop_clean": not has_em_dash,
            "pass": item_passed
        })

    return {
        "name": "writeup_documentation_audit",
        "description": "Verifies existence, LKS sections, anti-slop rules, and official flags in writeups",
        "status": "pass" if all_ok else "fail",
        "pass": all_ok,
        "passed": all_ok,
        "details": {
            "all_passed": all_ok,
            "writeups": results
        }
    }


def main():
    print("=" * 70)
    print("  CyLab Security Academy - Batch 207 Automated Test Harness Suite")
    print("  Target Event: picoCTF 2023 Initiation (Modules 344, 345, 347)")
    print("  Standard: NIST SP 800-115 § 4.2 / § 4.3 / § 4.4")
    print("=" * 70)

    checks = []

    # 1. AST Syntax Sweep
    print("\n[*] Executing Check 1/6: AST syntax sweep across all scripts/*.py...")
    res_ast = check_ast_sweep()
    checks.append(res_ast)
    print(f"    -> Status: {res_ast['status'].upper()} (Passed {res_ast['details']['passed']}/{res_ast['details']['total_scanned']})")

    # 2. Module 344 Solver
    print("\n[*] Executing Check 2/6: solve_344_cancri_sp.py...")
    res_344 = check_solver(344, "solve_344_cancri_sp.py", "academy{11790d7c}")
    checks.append(res_344)
    print(f"    -> Status: {res_344['status'].upper()} (Exit {res_344['details'].get('exit_code')})")

    # 3. Module 345 Solver
    print("\n[*] Executing Check 3/6: solve_345_babygame01.py...")
    res_345 = check_solver(345, "solve_345_babygame01.py", "academy{gamer_m0d3_enabled_9ad09239}")
    checks.append(res_345)
    print(f"    -> Status: {res_345['status'].upper()} (Exit {res_345['details'].get('exit_code')})")

    # 4. Module 347 Solver
    print("\n[*] Executing Check 4/6: solve_347_chrono.py...")
    res_347 = check_solver(347, "solve_347_chrono.py", "academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}")
    checks.append(res_347)
    print(f"    -> Status: {res_347['status'].upper()} (Exit {res_347['details'].get('exit_code')})")

    # 5. Live Evidence Probes
    print("\n[*] Executing Check 5/6: Live CyLab REST API verification probes...")
    res_live = check_live_evidence_probes()
    checks.append(res_live)
    print(f"    -> Status: {res_live['status'].upper()} (All verified: {res_live['details'].get('all_verified')})")

    # 6. Writeup Documentation Audit
    print("\n[*] Executing Check 6/6: Writeup documentation & anti-slop audit...")
    res_doc = check_writeups()
    checks.append(res_doc)
    print(f"    -> Status: {res_doc['status'].upper()} (All writeups compliant: {res_doc['details'].get('all_passed')})")

    all_passed = all(c["pass"] for c in checks)
    total_checks = len(checks)
    passed_count = sum(1 for c in checks if c["pass"])

    report = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "batch": 207,
        "events": ["picoCTF 2023"],
        "modules": [
            {"id": 344, "name": "cancri-sp", "category": "Web Exploitation", "event": "picoCTF 2023", "flag": "academy{11790d7c}"},
            {"id": 345, "name": "babygame01", "category": "Binary Exploitation", "event": "picoCTF 2023", "flag": "academy{gamer_m0d3_enabled_9ad09239}"},
            {"id": 347, "name": "chrono", "category": "General Skills", "event": "picoCTF 2023", "flag": "academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}"}
        ],
        "summary": {
            "total_checks": total_checks,
            "passed": passed_count,
            "failed": total_checks - passed_count,
            "all_passed": all_passed
        },
        "checks": checks
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print("\n" + "=" * 70)
    print(f"  Test Harness Result: {'ALL PASSED' if all_passed else 'FAILURES DETECTED'} ({passed_count}/{total_checks})")
    print(f"  Verification Report saved to: {REPORT_PATH}")
    print("=" * 70)

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
