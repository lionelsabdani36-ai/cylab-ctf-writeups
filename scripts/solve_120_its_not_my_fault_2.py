#!/usr/bin/env python3
"""Solver for Challenge 120 It's Not My Fault 2 (picoCTF 2021, Cryptography).

Server flow (not_my_fault_again.py):
  1. MD5 proof-of-work: send a string starting with the given 5-digit prefix
     whose md5 hex digest ends with the given 6 hex digits.
  2. Server generates 512-bit primes p, q (GCD(p-1,q-1)==2), prints n = p*q
     and a clue e = d^{-1} mod (p-1)(q-1) where d = CRT(d_p, d_q) and
     d_p is only BITS=36 bits (d_q full size). Same parity enforced.
  3. Send p+q within 15 minutes -> server prints the flag.

Attack (Pinch / Galbraith "Mathematics of Public Key Cryptography" s.19.6):
  e*d_p = 1 + k*(p-1), so for any m with gcd(m,n)=1,
  m^(e*d_p) = m (mod p)  =>  gcd(m^(e*d_p) - m, n) = p.
  d_p <= 2^36 rules out naive brute force (2^36 GCDs), so split
  d_p = l + L*l' with L = 2^18. With A = m^e mod n, B = A^L mod n:
    y_l = A^l            (inner, L values)
    z_j = m * B^{-j}     (outer, L+1 values, +1 covers the dp == 2^36 edge)
  F(x) = prod_l (x - y_l); F(z_j) = 0 (mod p) exactly for the right j'.
  Build F with a product tree and evaluate at all z_j with one FLINT
  subproduct-tree multipoint evaluation (fmpz_mod_poly_evaluate_fmpz_vec_fast),
  one pass of gcd(eval_j, n) finds p, then scan l for (y_l - z_j) = 0 mod p to
  recover d_p and verify e*d_p = 1 mod (p-1). Single connection must be kept
  open end-to-end: PoW -> key -> factor (in-process) -> send p+q, because the
  container closes the session on TCP disconnect.

Requires: gcc, libflint-dev, libgmp-dev. nmf2.c is compiled on first run.
Verified: academy{p0lyn0m14l_4r17hm371c_73chn1qu35_4r3_u53ful_1n_m4ny_f13ld5!!!}
  (POST /api/submissions/ -> correct:true)
Usage: solve_120_its_not_my_fault_2.py [host] [port]
"""
import hashlib
import itertools
import os
import re
import socket
import subprocess
import sys
import time

HOST = "chatelaine.cylabacademy.net"
PORT = 24303
LOGL = 18
EXPECTED = "academy{p0lyn0m14l_4r17hm371c_73chn1qu35_4r3_u53ful_1n_m4ny_f13ld5!!!}"
FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")
HERE = os.path.dirname(os.path.abspath(__file__))

C_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <flint/fmpz.h>
#include <flint/fmpz_mod.h>
#include <flint/fmpz_mod_poly.h>
static void read_decimal(mpz_t out, const char *fname, int lineno) {
    FILE *f = fopen(fname, "r");
    if (!f) { fprintf(stderr, "cannot open %s\n", fname); exit(1); }
    char *line = NULL; size_t cap = 0; ssize_t n;
    int cur = 0;
    while ((n = getline(&line, &cap, f)) > 0) {
        cur++;
        if (cur == lineno) {
            while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r' || line[n-1] == ' ')) line[--n] = 0;
            if (mpz_set_str(out, line, 10) != 0) { fprintf(stderr, "bad int\n"); exit(1); }
            free(line); fclose(f); return;
        }
    }
    fprintf(stderr, "line %d missing\n", lineno); exit(1);
}
int main(int argc, char **argv) {
    long LOGL = argc > 1 ? atol(argv[1]) : 18;
    long L = 1L << LOGL;
    long NPTS = L + 1;
    mpz_t n, e, m, A, B, Binv, g, t;
    mpz_inits(n, e, m, A, B, Binv, g, t, NULL);
    read_decimal(n, "key.txt", 1);
    read_decimal(e, "key.txt", 2);
    gmp_randstate_t rs;
    gmp_randinit_default(rs);
    gmp_randseed_ui(rs, 12345);
    do { mpz_urandomb(m, rs, 512); mpz_setbit(m, 0); mpz_gcd(g, m, n); }
    while (mpz_cmp_ui(g, 1) != 0);
    mpz_powm(A, m, e, n);
    { mpz_t LL; mpz_init_set_ui(LL, 1); mpz_mul_2exp(LL, LL, LOGL);
      mpz_powm(B, A, LL, n);
      if (mpz_invert(Binv, B, n) == 0) { fprintf(stderr, "B not invertible\n"); return 1; }
      mpz_clear(LL); }
    mpz_t *y = malloc(sizeof(mpz_t) * L);
    mpz_t *z = malloc(sizeof(mpz_t) * NPTS);
    for (long i = 0; i < L; i++) mpz_init(y[i]);
    for (long j = 0; j < NPTS; j++) mpz_init(z[j]);
    mpz_set_ui(y[0], 1);
    for (long i = 1; i < L; i++) { mpz_mul(y[i], y[i-1], A); mpz_mod(y[i], y[i], n); }
    mpz_set(z[0], m);
    for (long j = 1; j < NPTS; j++) { mpz_mul(z[j], z[j-1], Binv); mpz_mod(z[j], z[j], n); }
    fmpz_t mod; fmpz_init(mod); fmpz_set_mpz(mod, n);
    fmpz_mod_ctx_t ctx; fmpz_mod_ctx_init(ctx, mod);
    long cnt = L;
    fmpz_mod_poly_t *cur = malloc(sizeof(fmpz_mod_poly_t) * cnt);
    fmpz_t cf; fmpz_init(cf);
    for (long i = 0; i < L; i++) {
        fmpz_mod_poly_init(cur[i], ctx);
        fmpz_set_mpz(cf, y[i]);
        fmpz_neg(cf, cf); fmpz_add(cf, cf, mod);
        fmpz_mod_poly_set_coeff_fmpz(cur[i], 0, cf, ctx);
        fmpz_mod_poly_set_coeff_ui(cur[i], 1, 1, ctx);
    }
    while (cnt > 1) {
        long nxt = (cnt + 1) / 2;
        fmpz_mod_poly_t *nv = malloc(sizeof(fmpz_mod_poly_t) * nxt);
        for (long i = 0; i + 1 < cnt; i += 2) {
            fmpz_mod_poly_init(nv[i/2], ctx);
            fmpz_mod_poly_mul(nv[i/2], cur[i], cur[i+1], ctx);
            fmpz_mod_poly_clear(cur[i], ctx);
            fmpz_mod_poly_clear(cur[i+1], ctx);
        }
        if (cnt & 1) {
            fmpz_mod_poly_init(nv[nxt-1], ctx);
            fmpz_mod_poly_set(nv[nxt-1], cur[cnt-1], ctx);
            fmpz_mod_poly_clear(cur[cnt-1], ctx);
        }
        free(cur); cur = nv; cnt = nxt;
    }
    fmpz *xs = malloc(sizeof(fmpz) * NPTS);
    for (long j = 0; j < NPTS; j++) { xs[j] = 0; fmpz_set_mpz(xs + j, z[j]); }
    fmpz *ys = malloc(sizeof(fmpz) * NPTS);
    for (long j = 0; j < NPTS; j++) ys[j] = 0;
    fmpz_mod_poly_evaluate_fmpz_vec_fast(ys, cur[0], xs, NPTS, ctx);
    fmpz_t one, gv;
    fmpz_init_set_ui(one, 1);
    fmpz_init(gv);
    long found_j = -1;
    for (long j = 0; j < NPTS; j++) {
        fmpz_gcd(gv, ys + j, mod);
        if (fmpz_cmp(gv, one) != 0 && fmpz_cmp(gv, mod) != 0) { found_j = j; break; }
    }
    if (found_j < 0) { fprintf(stderr, "NOT FOUND\n"); return 2; }
    mpz_t p, q, pm1;
    mpz_inits(p, q, pm1, NULL);
    fmpz_get_mpz(p, gv);
    mpz_divexact(q, n, p);
    mpz_sub_ui(pm1, p, 1);
    mpz_t diff; mpz_init(diff);
    long found_l = -1;
    for (long i = 0; i < L; i++) {
        mpz_sub(diff, y[i], z[found_j]); mpz_mod(diff, diff, p);
        if (mpz_cmp_ui(diff, 0) == 0) { found_l = i; break; }
    }
    if (found_l < 0) { fprintf(stderr, "l not found\n"); return 3; }
    mpz_t dp, edp;
    mpz_inits(dp, edp, NULL);
    mpz_set_ui(dp, (unsigned long)found_l);
    { mpz_t LL; mpz_init(LL); mpz_set_ui(LL, 1); mpz_mul_2exp(LL, LL, LOGL);
      mpz_addmul_ui(dp, LL, (unsigned long)found_j); mpz_clear(LL); }
    mpz_t sum; mpz_init(sum); mpz_add(sum, p, q);
    printf("P=%s\nQ=%s\nDP=%s\nSUM=%s\n",
        mpz_get_str(NULL, 10, p), mpz_get_str(NULL, 10, q),
        mpz_get_str(NULL, 10, dp), mpz_get_str(NULL, 10, sum));
    return 0;
}
"""


def ensure_binary(tmpdir):
    src = os.path.join(tmpdir, "nmf2.c")
    exe = os.path.join(tmpdir, "nmf2")
    if not os.path.exists(exe):
        open(src, "w").write(C_SRC)
        subprocess.run(["gcc", "-O2", "-o", exe, src, "-lflint", "-lgmp"],
                       check=True, cwd=tmpdir)
    return exe


def solve(host=HOST, port=PORT):
    tmpdir = "/home/lionelsabdani36/.hermes/cache/scratch/b25"
    exe = ensure_binary(tmpdir)
    s = socket.create_connection((host, int(port)), timeout=60)
    try:
        f = s.makefile("r", encoding="utf-8", errors="replace")
        line = f.readline()
        pre = re.search(r'starts with "(\d+)"', line).group(1)
        suf = re.search(r"ends in these six hex digits: (\w+)", line).group(1)
        found = next(c for i in itertools.count()
                     for c in ["%s%d" % (pre, i)]
                     if hashlib.md5(c.encode()).hexdigest()[-6:] == suf)
        s.sendall((found + "\n").encode())
        time.sleep(3)
        s.settimeout(60)
        data = b""
        while True:
            try:
                ch = s.recv(4096)
            except socket.timeout:
                break
            if not ch:
                break
            data += ch
            if b"Clue" in data and data.count(b"\n") >= 3:
                break
        txt = data.decode(errors="replace")
        n = re.search(r"Public Modulus :\s*(\d+)", txt).group(1)
        e = re.search(r"Clue :\s*(\d+)", txt).group(1)
        open(os.path.join(tmpdir, "key.txt"), "w").write(n + "\n" + e + "\n")
        r = subprocess.run([exe, str(LOGL)], capture_output=True, text=True,
                           timeout=900, cwd=tmpdir)
        sm = re.search(r"SUM=(\d+)", r.stdout).group(1)
        s.sendall((sm + "\n").encode())
        time.sleep(2)
        resp = b""
        s.settimeout(30)
        try:
            while True:
                ch = s.recv(4096)
                if not ch:
                    break
                resp += ch
        except socket.timeout:
            pass
        m = FLAG_RE.search(resp.decode(errors="replace"))
        return m.group(0) if m else resp.decode(errors="replace")
    finally:
        s.close()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(host, port))
