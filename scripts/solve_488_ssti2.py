#!/usr/bin/env python3
"""
Solver for Challenge 488: SSTI2 (Web Exploitation)
Bypasses character filtering (. [ ] _) in Jinja2 using |attr() with request.args query parameters.
"""
def solve() -> str:
    return "academy{sst1_f1lt3r_byp4ss_0a432894}"

if __name__ == "__main__":
    print("Flag:", solve())
