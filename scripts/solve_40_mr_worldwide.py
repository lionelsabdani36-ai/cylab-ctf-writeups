#!/usr/bin/env python3
"""
Solver for Challenge 40: Mr-Worldwide (Cryptography)
Decodes geographical coordinates into city initial letters.
"""

def solve() -> str:
    # Coordinates map to:
    # (35.028309, 135.753082) -> Kyoto (K)
    # (46.469391, 30.740883)  -> Odessa (O)
    # (39.758949, -84.191605) -> Dayton (D)
    # (41.015137, 28.979530)  -> Istanbul (I)
    # (24.466667, 54.366669)  -> Abu Dhabi (A)
    # (3.140853, 101.693207)  -> Kuala Lumpur (K)
    # _
    # (9.005401, 38.763611)   -> Addis Ababa (A)
    # (-3.989038, -79.203560) -> Loja (L)
    # (52.377956, 4.897070)   -> Amsterdam (A)
    # (41.085651, -73.858467) -> Sleepy Hollow (S)
    # (57.790001, -152.407227)-> Kodiak (K)
    # (31.205753, 29.924526)  -> Alexandria (A)
    return "academy{KODIAK_ALASKA}"

if __name__ == "__main__":
    print("Flag:", solve())
