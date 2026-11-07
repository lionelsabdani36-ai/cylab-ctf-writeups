# Writeup: rsa-pop-quiz (Challenge ID: 61)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Asymmetric Key Algebra & Feasibility Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 200
- **Author:** wparks / nmontierth
- **Flag:** `academy{wA8_th4t$_ill3aGal..oCfEd0082}`

---

## Problem Statement & Scope
Tantangan `rsa-pop-quiz` menyediakan layanan interaktif melalui koneksi TCP socket (`nc xebec.cylabacademy.net <port>`). Pada skenario latihan, asisten virtual "Ms. Adleman-Shamir-Rivest" menyelenggarakan kuis interaktif mengenai prinsip matematika dan batas kelayakan komputasi (*computational feasibility*) pada algoritma kunci publik RSA. Peserta diminta mengevaluasi apakah suatu parameter kriptografi dapat dihitung secara efisien (*feasible*) berdasarkan sekumpulan parameter input yang diberikan, dan jika layak, mengirimkan hasil perhitungan dalam bentuk bilangan bulat desimal.

Ruang lingkup audit ini berfokus pada evaluasi pemahaman relasi aljabar RSA, kelemahan ketergantungan parameter, dan mitigasi risiko komputasi berdasarkan standar **NIST SP 800-115 Section 4.3** (*Application Security Assessment & Cryptographic Review*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur Fundamental Algoritma RSA (RFC 8017):**
   Pada sistem kriptografi RSA:
   - Modulus publik: $n = p \times q$, di mana $p$ dan $q$ adalah bilangan prima rahasia.
   - Fungsi Euler Totient: $\phi(n) = (p - 1)(q - 1)$.
   - Eksponen enkripsi publik: $e$, di mana $\gcd(e, \phi(n)) = 1$.
   - Eksponen dekripsi privat: $d \equiv e^{-1} \pmod{\phi(n)}$, dihitung menggunakan Extended Euclidean Algorithm.
   - Operasi Enkripsi: $c = m^e \pmod n$.
   - Operasi Dekripsi: $m = c^d \pmod n$.

2. **Batas Kelayakan Komputasi & Kerentanan Pemisahan Kunci (CWE-326: Inadequate Encryption Strength):**
   - **Kasus 1 (Faktorisasi Terbalik):** Jika nilai $n$ dan salah satu faktor prima $p$ diketahui, maka faktor prima kedua dapat dihitung secara instan dalam waktu $O(1)$:
     $$q = \frac{n}{p}$$
   - **Kasus 2 (Dekripsi Penuh dengan Faktor Diketahui):** Jika penyerang mengetahui salah satu faktor prima $p$, totient $\phi(n) = (p - 1)(\frac{n}{p} - 1)$ dapat langsung dibentuk. Akibatnya, kunci privat $d$ dapat diturunkan dan pesan sandi $c$ dapat didekripsi sepenuhnya tanpa perlu memecahkan masalah faktorisasi modulus besar.
   - **Kasus 3 (Masalah Faktorisasi Modulus 1024-bit):** Jika hanya diberikan $n$ (1024 bit) dan eksponen publik $e$ tanpa faktor prima $p, q$, pemulihan pesan $m$ dari ciphertext $c$ tergolong tidak layak komputasi (*infeasible*) dengan teknologi komputasi klasik saat ini.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Otomasi Pemrosesan Dialog & Evaluasi Masalah:**
   Dibangun script otomasi soket TCP (`solve_61_rsa_pop_quiz.py`) yang melakukan parsing secara dinamis terhadap setiap putaran kuis:
   - **Putaran 1:** Diberikan $p = 76753, q = 60413$, target $n$.
     - Kelayakan: **Y**
     - Perhitungan: $n = p \times q = 4636878989$.
   - **Putaran 2:** Diberikan $p = 54269, n = 5051846941$, target $q$.
     - Kelayakan: **Y**
     - Perhitungan: $q = n // p = 93089$.
   - **Putaran 3:** Diberikan $n$ (1024-bit composite), $e = 3$, target $p, q$.
     - Kelayakan: **N** (faktorisasi bilangan komposit 1024-bit tidak layak).
   - **Putaran 4:** Diberikan $p = 12611, q = 66347$, target $\text{totient}(n)$.
     - Kelayakan: **Y**
     - Perhitungan: $\phi(n) = (p - 1)(q - 1) = 836623060$.
   - **Putaran 5:** Diberikan $e = 3, m = 6357\dots, n = 2912\dots$, target $c$.
     - Kelayakan: **Y**
     - Perhitungan: $c = \text{pow}(m, e, n)$.
   - **Putaran 6:** Diberikan $e = 3, c = 1075\dots, n = 2756\dots$, target $m$ tanpa faktor prima.
     - Kelayakan: **N** (dekripsi tanpa kunci privat atau faktor adalah RSA problem).
   - **Putaran 7:** Diberikan $e = 65537, p, q$, target $d$.
     - Kelayakan: **Y**
     - Perhitungan: $d = \text{pow}(e, -1, (p - 1)(q - 1))$.
   - **Putaran 8:** Diberikan $e = 65537, p, n, c$, target plaintext $m$.
     - Kelayakan: **Y**
     - Perhitungan:
       $$q = n // p$$
       $$\phi(n) = (p - 1)(q - 1)$$
       $$d = \text{pow}(e, -1, \phi(n))$$
       $$m = \text{pow}(c, d, n)$$
     - Nilai $m$ yang diperoleh berupa integer desimal:
       $$12398954807676569242017981049973013411282548937863661020322858792013937079707326371134452349$$

2. **Konversi Format Flag:**
   - Konversikan integer desimal $m$ ke representasi heksadesimal:
     `0x61636164656d797b7741385f74683474245f696c6c336147616c2e2e6f43664564303038327d`
   - Dekode heksadesimal ke karakter ASCII:
     `academy{wA8_th4t$_ill3aGal..oCfEd0082}`

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{wA8_th4t$_ill3aGal..oCfEd0082}`
- **Komunitas Standar (CTF Format):** `CTF{wA8_th4t$_ill3aGal..oCfEd0082}`
- **Status Verifikasi:** REST API CyLab `POST /api/submissions/` mengembalikan `HTTP 201 Created` dengan `correct: true`.
- **Catatan Karakter Khusus:** Flag memuat karakter dollar sign (`$`). Dalam scripting Bash/shell, flag harus di-escape (`\$`) atau dibungkus single-quote agar tidak terpotong oleh ekspansi variabel environment shell.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Perlindungan Faktor Prima Kunci Publik:**
   Kerahasiaan sistem RSA bergantung sepenuhnya pada ketidakmampuan pihak luar memfaktorkan modulus $n$. Jika salah satu faktor prima ($p$ atau $q$) bocor atau dapat ditebak melalui kelemahan generator bilangan acak, seluruh sistem kriptografi hancur seketika.
2. **Kepatuhan Parameter NIST (SP 800-56B Rev. 2):**
   NIST merekomendasikan penggunaan modulus minimal 2048-bit atau 3072-bit untuk penggunaan industri modern, serta memastikan pembangkitan bilangan prima dilakukan dengan generator pseudorandom yang terakreditasi FIPS 140-3.
3. **Pencegahan Oracle Dekripsi:**
   Dalam pengujian keamanan sistem komunikasi, pastikan server tidak merespons query yang memungkinkan penyerang memperoleh informasi totient atau melakukan serangan *chosen-ciphertext attack* (CCA) tanpa skema padding yang aman seperti RSA-OAEP.
