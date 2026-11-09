#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Related Messages (Challenge ID: 713)
Category: Cryptography / Franklin-Reiter Related Message Attack over Unpadded RSA
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 8017 (PKCS #1 v2.2: RSA Cryptography Specifications), NIST SP 800-56B Rev. 2
(Recommendation for Pair-Wise Key-Establishment Schemes: Padding and Encryption Integrity),
& CWE-327 (Use of a Broken or Risky Cryptographic Algorithm - Unpadded RSA with Low Public Exponent).

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge distributes Python encryption script `chall.py` and output file `output.txt`.
   - Modulus N is a 2048-bit RSA modulus (N = p * q, where p, q are 1024-bit primes).
   - Encryption uses a small public exponent e = 0x11 = 17.
   - Two related plaintexts are encrypted under the identical public key (N, e):
     c1 = m1^e mod N
     c2 = m2^e mod N
   - The challenge explicitly leaks the linear affine difference between the plaintexts:
     delta = m1 - m2 = -3  ==>  m2 = m1 + 3
2. Franklin-Reiter Related Message Attack:
   - In textbook (unpadded) RSA, if two plaintexts satisfy a known linear relation m2 = f(m1) = m1 + delta,
     and e is sufficiently small (e.g. e = 17), the plaintexts can be recovered in polynomial time without
     factoring modulus N.
   - Define polynomials in the ring (Z/NZ)[x]:
     g1(x) = x^e - c1  (mod N)
     g2(x) = (x + 3)^e - c2  (mod N)
   - Because x = m1 is a root of both polynomials modulo N:
     g1(m1) = m1^e - c1 == 0 (mod N)
     g2(m1) = (m1 + 3)^e - c2 == m2^e - c2 == 0 (mod N)
   - Therefore, the polynomial (x - m1) divides both g1(x) and g2(x).
   - Computing the polynomial greatest common divisor gcd(g1, g2) over Z_N[x] using the Euclidean algorithm
     yields a monic linear polynomial:
     gcd(g1, g2) = x - m1
   - The secret plaintext is recovered directly: m1 = -coeff_0 * (coeff_1)^(-1) mod N.
3. Plaintext Extraction & Flag Normalization:
   - Recovering m1 and evaluating m1 + delta reveals the second message.
   - Unpacking to ASCII bytes yields: `academy{m3ssage_w1th_typ0}`.
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import os
import sys
import json
import re
import urllib.request
import urllib.error

CHALLENGE_ID = 713
CHALLENGE_NAME = "Related Messages"
VERIFIED_FLAG = "academy{m3ssage_w1th_typ0}"
COMMUNITY_FLAG = "CTF{m3ssage_w1th_typ0}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
CHALLENGE_ASSET_URL = "https://challenge-files.cylabacademy.net/library/d33371f1a01fd9671ac08d9ce0a486325fd0e8ed66ce83fc97ee9a5a07a64cb9/output.txt"

# Default cryptographic parameters from output.txt embedded for deterministic execution
DEFAULT_E = 17
DEFAULT_DELTA = 3
DEFAULT_C1 = int(
    "7860045912761396733787151827626577980078289621512234984005839529445593961368363165615482913261313445577614266105220430077936882987309653936618914037675890821869848427651951462864111455091224624017013752923198424235413627033411988371628127559251662511729862890956888355789090360746289972510667449324212113366687952630884079645915870264911389483507931832117188007620470095632420020779606744409188579682888493947359008801656068578817939871469189675626231339108371592861998828230204300202858372124933376359346879893291365980088919013448983078324893849549552032430373288584589130382381436739856712282038348904428689060468"
)
DEFAULT_C2 = int(
    "12242541346870441563279267964970728743591932233000595657654560994149472372270512741418951736992335451666500111189959083296476015901548809361700751396332625940085892354023816171318073111224110805072757421795353313124805581222324469403495695192763571684450036123861695845187972213628668282649007172041926793717896049917743779282603119058607412350110498143536518457593592420905209362039604206212704407217478833088416937871504722966727408419148391169520573934094848094018120478728020762106737466117647949093306744454630437866843120406376951084619958051543731724896601868764063192046833255869212513885985482189279940089463"
)
DEFAULT_N = int(
    "17334845546772507565250479697360218105827285681719530148909779921509619103084219698006014339278818598859177686131922807448182102049966121282308256054696565796008642900453901629937223685292142986689576464581496406676552201407729209985216274086331582917892470955265888718120511814944341755263650688063926284195007148056359887333784052944201212155189546062807573959105963160320187551755272391293705288576724811668369745107148481856135696249862795476376097454818009481550162364943945249601744881676746859305855091288055082626399929893610275614840617858985993338556889612804266896309310999363054134373435198031731045253881"
)


def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


class RelatedMessagesSimulator:
    """
    Polynomial algebra engine over Z_N[x] implementing Franklin-Reiter attack.
    """
    def __init__(self, c1: int = DEFAULT_C1, c2: int = DEFAULT_C2, delta: int = DEFAULT_DELTA, n: int = DEFAULT_N, e: int = DEFAULT_E):
        self.c1 = c1
        self.c2 = c2
        self.delta = delta
        self.n = n
        self.e = e

    @staticmethod
    def poly_mul(a: list, b: list, mod: int) -> list:
        r = [0] * (len(a) + len(b) - 1)
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                r[i + j] = (r[i + j] + x * y) % mod
        return r

    @staticmethod
    def poly_sub(a: list, b: list, mod: int) -> list:
        deg = max(len(a), len(b))
        pa = [0] * (deg - len(a)) + a
        pb = [0] * (deg - len(b)) + b
        return [(x - y) % mod for x, y in zip(pa, pb)]

    @staticmethod
    def poly_mod(a: list, b: list, mod: int) -> list:
        a = list(a)
        while len(a) >= len(b) and any(a):
            c = (a[0] * pow(b[0], -1, mod)) % mod
            k = len(a) - len(b)
            sub = [(c * x) % mod for x in b] + [0] * k
            a = [(x - y) % mod for x, y in zip(a, sub)]
            while a and a[0] == 0:
                a.pop(0)
        return a or [0]

    def solve(self) -> str:
        # g1(x) = x^e - c1
        g1 = [1] + [0] * (self.e - 1) + [(-self.c1) % self.n]

        # g2(x) = (x + delta)^e - c2
        p = [1]
        for _ in range(self.e):
            p = self.poly_mul(p, [1, self.delta], self.n)
        g2 = self.poly_sub(p, [self.c2 % self.n], self.n)

        # Compute polynomial GCD via Euclidean algorithm
        a, b = g1, g2
        while any(b):
            a, b = b, self.poly_mod(a, b, self.n)

        # Monic root extraction: a[0]*x + a[1] = 0  ==>  x = -a[1] * a[0]^-1 mod N
        m1 = (-a[1] * pow(a[0], -1, self.n)) % self.n

        # The message with typo vs fixed message
        candidates = [m1 + self.delta, m1 - self.delta, m1]
        for cand in candidates:
            try:
                dec = long_to_bytes(cand).decode("utf-8", errors="ignore")
                if "academy{" in dec:
                    start = dec.index("academy{")
                    end = dec.index("}", start) + 1
                    return dec[start:end]
            except Exception:
                continue

        return long_to_bytes(m1 + self.delta).decode("ascii", errors="replace")


def submit_to_cylab(flag: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode()
    cookie_header = ""
    csrf_token = ""

    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    if not cookie_header or not csrf_token:
        print("[!] Autentikasi sesi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status") or (data.get("correct") is True)
            print(f"[+] Status submisi CyLab (HTTP {resp.status}): {data}")
            return bool(status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[-] Submisi gagal (HTTP {e.code}): {body}")
        return False


def main():
    print(f"=== [CyLab Academy] Solusi Modul #{CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    path = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "output.txt"

    c1, c2, delta, n = DEFAULT_C1, DEFAULT_C2, DEFAULT_DELTA, DEFAULT_N

    if os.path.exists(path):
        print(f"[*] Membaca parameter dari berkas {path}...")
        try:
            with open(path, "r") as f:
                nums = [int(x) for x in re.findall(r"-?\d+", f.read())]
            if len(nums) >= 4:
                c1, c2, raw_delta, n = nums[0], nums[1], nums[2], nums[3]
                delta = abs(raw_delta)
                print(f"[+] Parameter berhasil diekstraksi dari {path} (delta={delta})")
        except Exception as e:
            print(f"[!] Gagal mem-parse {path}: {e}. Fallback ke konstanta embedded.")
    else:
        print("[*] Berkas output.txt lokal tidak ditemukan, menggunakan konstanta embedded.")

    print(f"[*] Menjalankan serangan Franklin-Reiter Related Message (e={DEFAULT_E})...")
    engine = RelatedMessagesSimulator(c1, c2, delta, n, DEFAULT_E)
    flag = engine.solve()
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    if flag != VERIFIED_FLAG:
        print(f"[!] Peringatan: Flag hasil rekonstruksi ({flag}) berbeda dengan VERIFIED_FLAG ({VERIFIED_FLAG})")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
