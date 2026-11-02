# Writeup: Very Smooth (Challenge ID: 315)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Medium (2)
- **Author:** CyLab Team
- **Event:** picoCTF 2022
- **Points:** 300
- **Flag:** `academy{p0ll4rd_f4ct0r1z4at10n_FTW_48d4cbdf}`

---

## Deskripsi Tantangan
> Forget safe primes... Here, we like to live life dangerously... >:)
> Download the artifacts:
> - `gen.py`: Generator pasangan kunci RSA dengan pembuatan bilangan prima "smooth".
> - `output.txt`: Berisi modulus publik $n = p \times q$ dan ciphertext $c$.
>
> Hint:
> 1. Don't look at me... Go ask Mr. Pollard if you need a hint!

---

## Analisis Kerentanan & Konsep Teknis (Root Cause Theory)
1. **Kegagalan Safe Prime Generation:**
   - Dalam standar industri (misal NIST SP 800-56B Rev. 2), bilangan prima untuk RSA harus berupa *strong primes* atau dihasilkan melalui pengujian ketat di mana $p - 1$ memiliki setidaknya satu faktor prima besar (menghindari kerentanan terhadap algoritma faktorisasi khusus).
   - Pada `gen.py`, fungsi `get_smooth_prime(state, 1024, smoothness=16)` mengakumulasikan faktor-faktor prima kecil berukuran 16-bit hingga mendekati 1024-bit, lalu mengalikan dua faktor berukuran $\le 24$-bit sebelum menambahkan 1:
     $$p = 2 \times \prod f_i \times \text{prime}_1 \times \text{prime}_2 + 1$$
   - Akibatnya, nilai $p - 1$ sepenuhnya merupakan bilangan yang halus (*$B$-smooth*), di mana semua faktor prima dari $p - 1$ bernilai $\le B$ dengan $B \approx 2^{17} = 131072$.
2. **Algoritma Faktorisasi Pollard's $p - 1$:**
   - Dikemukakan oleh John Pollard pada tahun 1974, algoritma ini memanfaatkan Teorema Kecil Fermat (*Fermat's Little Theorem*):
     $$\text{Jika } \gcd(a, p) = 1, \text{ maka } a^{p-1} \equiv 1 \pmod p$$
   - Misalkan $M = \prod_{q \le B} q^{\lfloor \log_q B \rfloor}$ adalah kelipatan persekutuan terkecil dari bilangan-bilangan bulat hingga $B$.
   - Jika $p - 1$ adalah $B$-smooth, maka $p - 1$ membagi $M$, sehingga:
     $$a^M \equiv 1 \pmod p \implies p \mid (a^M - 1)$$
   - Selama $q - 1$ tidak membagi $M$ secara bersamaan ($a^M \not\equiv 1 \pmod q$), maka:
     $$\gcd(a^M - 1, n) = p$$
   - Dengan memilih basis acak (misal $a = 2$) dan menghitung $a \leftarrow a^k \pmod n$ secara sekuensial untuk setiap faktor basis prima, faktor non-trivial $p$ dapat ditemukan dalam hitungan detik tanpa perlu melakukan pembagian faktorisasi brute-force.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Parameter Publik:**
   - Mengambil representasi nilai heksadesimal modulus $n$ (2048-bit) dan ciphertext $c$ dari `output.txt`.
   - Menetapkan eksponen publik standar $e = 65537$ (`0x10001`).
2. **Pembangkitan Daftar Bilangan Prima Sieve:**
   - Membangkitkan bilangan prima hingga batas kehalusan $B = 2^{17} = 131072$ menggunakan Sieve of Eratosthenes (menghasilkan 12.251 bilangan prima).
3. **Eksekusi Eksponensiasi Pollard's $p - 1$:**
   - Menginisialisasi basis $a = 2$.
   - Untuk setiap bilangan prima $r \le B$, tentukan eksponen $k = r^{\lfloor \log_r B \rfloor}$, lalu perbarui $a \leftarrow a^k \pmod n$.
   - Mengevaluasi $g = \gcd(a - 1, n)$ secara periodik. Pada iterasi prime $70663$, algoritma berhasil mengisolasi faktor prima $p$ (1024-bit).
4. **Faktorisasi Lengkap & Dekripsi Plaintext:**
   - Menghitung $q = n // p$, memastikan bahwa $p \times q == n$.
   - Menghitung $\phi(n) = \text{lcm}(p - 1, q - 1)$.
   - Menghitung kunci privat dekripsi $d = \text{pow}(e, -1, \phi)$.
   - Mendekripsi ciphertext $m = \text{pow}(c, d, n)$ dan mengonversi integer hasil ke string ASCII untuk memulihkan flag.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{p0ll4rd_f4ct0r1z4at10n_FTW_48d4cbdf}`
- **Bukti Validasi REST API:**
  - Metode: `POST /api/submissions/`
  - Payload: `{"challenge": 315, "flag": "academy{p0ll4rd_f4ct0r1z4at10n_FTW_48d4cbdf}"}`
  - Respons: `HTTP 201 Created` — `{"user": 1072359, "challenge": 315, "flag": "academy{...}", "correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Integritas Pembangkitan Bilangan Prima Kriptografis:**
   - Dalam kompetensi LKS Cyber Security bidang Kriptografi Terapan dan NIST SP 800-115, siswa harus memahami bahwa ukuran modulus (misal 2048-bit atau 4096-bit) tidak menjamin keamanan jika entropi dan struktur prima di dalamnya cacat (*smooth primes*).
2. **Rekomendasi Remediasi / Hardening:**
   - Patuhi spesifikasi FIPS 186-5 dan RFC 8017 (PKCS #1 v2.2) dalam pembangkitan kunci RSA.
   - Pastikan bahwa $|p - q| > 2^{nlen/2 - 100}$ dan $p - 1$ memiliki faktor prima besar $p_1$ di mana $p_1 - 1$ juga memiliki faktor prima besar (*Gordon's algorithm for strong primes*).
   - Selalu gunakan implementasi *cryptographic service provider* (CSP) bawaan sistem operasi atau pustaka tersertifikasi seperti OpenSSL / BoringSSL daripada algoritma pembangkitan prima kustom (*custom pseudo-random generator*).
