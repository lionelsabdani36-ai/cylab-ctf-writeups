# Writeup: Shared Secrets (Challenge ID: 715)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Diffie-Hellman Key Agreement & Sensitive Exponent Leakage
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{dh_s3cr3t_e3954beb}`
- **Flag Komunitas:** `CTF{dh_s3cr3t_e3954beb}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 2631 (Diffie-Hellman Key Agreement Method), RFC 3526 (More Modular Exponential (MODP) Diffie-Hellman groups for IKE), & CWE-312 / CWE-200 (Cleartext Storage and Exposure of Sensitive Information).

---

## Problem Statement & Scope

Pada modul bimbingan teknis persiapan lomba LKS `Shared Secrets`, peserta diuji dalam menganalisis mekanisme pertukaran kunci kriptografi asimetris Diffie-Hellman (DH) serta implikasi fatal dari kebocoran material kunci privat (*private exponent leakage*):
- Skenario lingkungan: Diberikan dua berkas artefak penyelidikan:
  1. Skrip enkripsi Python: `encrypt.py`.
  2. Berkas transkrip komunikasi: `transcript.txt` yang memuat parameter publik modulus prima $p$ (768 bit), generator $g = 2$, kunci publik Server $A$, eksponen privat Klien $b$ yang bocor, dan ciphertext $c$ dalam format heksadesimal.
- Pernyataan tantangan:
  > *"A message was encrypted using a shared secret... but it looks like one side of the exchange leaked something. Can you piece together the secret and get the flag?"*
- Sasaran pengujian:
  1. Menganalisis alur pembentukan rahasia bersama (*shared secret*) Diffie-Hellman di atas grup siklik $\mathbb{Z}_p^*$.
  2. Memanfaatkan kebocoran eksponen privat $b$ untuk merekonstruksi nilai rahasia bersama $K = A^b \pmod p$ tanpa harus memecahkan *Discrete Logarithm Problem* (DLP).
  3. Menganalisis kelemahan fungsi derivasi kunci (*Key Derivation Function / KDF*) berbasis reduksi modulo 256.
  4. Mendekripsi pesan rahasia melalui operasi byte-wise XOR terbalik.
  5. Memvalidasi token plaintext resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Pertukaran Kunci Diffie-Hellman (RFC 2631):**
   Protokol pertukaran kunci Diffie-Hellman memungkinkan dua pihak membangun rahasia bersama melalui saluran komunikasi yang tidak aman tanpa mengirimkan rahasia tersebut secara langsung:
   - Parameter publik: Bilangan prima besar $p$ dan generator $g \in \mathbb{Z}_p^*$.
   - Pihak A (Server) memilih rahasia privat $a$ acak dan mengirimkan kunci publik:
     $$A = g^a \pmod p$$
   - Pihak B (Klien) memilih rahasia privat $b$ acak dan mengirimkan kunci publik:
     $$B = g^b \pmod p$$
   - Kedua pihak menghitung nilai rahasia bersama yang identik:
     $$K = B^a \equiv (g^b)^a \equiv g^{ab} \equiv (g^a)^b \equiv A^b \pmod p$$
   Keamanan matematis protokol ini bergantung pada asumsi ketidakterpecahan masalah logaritma diskret (*Computational Diffie-Hellman Assumption / CDH*): pihak ketiga yang hanya menyadap $(p, g, A, B)$ tidak dapat menghitung $g^{ab} \pmod p$ dalam waktu polinomial.

2. **Kebocoran Material Rahasia Klien (CWE-312 / CWE-200):**
   Dalam berkas `transcript.txt`, pihak klien secara ceroboh mencatat eksponen privatnya $b$:
   ```text
   b = 8061082410187142729717928037614887875835...
   ```
   Karena penyerang memiliki akses terhadap kunci publik server $A$ dan eksponen privat $b$, perhitungan rahasia bersama tidak lagi memerlukan pemecahan logaritma diskret $a = \log_g(A) \pmod p$. Penyerang cukup mengevaluasi eksponensiasi modular langsung:
   $$K = A^b \pmod p$$
   yang dapat dihitung dalam kompleksitas waktu logaritmik $\mathcal{O}(\log b)$ menggunakan algoritma *square-and-multiply* (< 1 milidetik).

3. **Cacat Arsitektur Derivasi Kunci Simetris (CWE-326):**
   Skrip `encrypt.py` tidak menerapkan algoritma KDF terstandarisasi (seperti HKDF berbasis SHA-256). Pengembang hanya mengambil byte terendah dari integer rahasia bersama:
   ```python
   key = shared % 256  # Hanya 8-bit entropi
   ```
   Operasi ini menyederhanakan enkripsi menjadi XOR satu-byte monoalfabetik. Meskipun $K$ bernilai ratusan digit, kunci simetris aktualnya terbatas pada interval $[0, 255]$ ($k = 214$).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Berkas `transcript.txt`:**
   Membaca parameter kriptografis:
   - Modulus prima $p$ (768 bit):
     `2188545828481232917915233525806579818209760678972220490921380750542193455665345717562182558864409541451041964360901352616297280654258287473010375935406137903689564954762347824228761657501247248979653142698163854882116855521952627898416433209318642163322021284188040749653581645061299781147685165607754045402815547537`
   - Kunci publik Server $A$:
     `529022054504968019469968111961692103333962097204384321062327406113469798583084528471911087369430603184315616289885944538403549216006196112599856159910375335838601931262259012757936708816266131815368447196183194865289491972488369456495842428832190461512811822688595599282473173695956797450916384282506132120013828366`
   - Eksponen privat Klien $b$ yang terekspos:
     `806108241018714272971792803761488787583500782708354296181179175643414634637904065955198182937625129233790050616136051643206357851994861572647233251265904450054206496643678855386739080010799844605476667118318730605723614207809884834764849344555331442139243115610235608110485560140584263429781350962431123512110941522`
   - Ciphertext heksadesimal:
     `b7b5b7b2b3bbafadb2be89a5e5b5a4e5a289b3e5efe3e2b4b3b4ab` (panjang 27 byte).

2. **Rekonstruksi Rahasia Bersama:**
   Mengeksekusi eksponensiasi modular pada Python:
   ```python
   shared_secret = pow(A, b, p)
   key_byte = shared_secret % 256  # key_byte = 214 (0xD6)
   ```

3. **Dekripsi Ciphertext:**
   Melakukan operasi XOR bita ciphertext dengan `key_byte`:
   ```python
   enc_bytes = bytes.fromhex(
       "b7b5b7b2b3bbafadb2be89a5e5b5a4e5a289b3e5efe3e2b4b3b4ab"
   )
   recovered_flag = bytes([x ^ key_byte for x in enc_bytes]).decode()
   ```
   Teks terang yang dipulihkan adalah:
   `academy{dh_s3cr3t_e3954beb}`.

4. **Validasi Submisi ke REST API CyLab Academy:**
   Mengirimkan token ke endpoint `POST /api/submissions/` dengan payload JSON `{"challenge": 715, "flag": "academy{dh_s3cr3t_e3954beb}"}`:
   ```bash
   python3 scripts/solve_715_shared_secrets.py --submit
   ```
   Server mengembalikan kode status HTTP `201 Created` dengan konfirmasi validasi `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{dh_s3cr3t_e3954beb}`
- **Flag Komunitas:** `CTF{dh_s3cr3t_e3954beb}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 715,
    "flag": "academy{dh_s3cr3t_e3954beb}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif pada basis data penilaian.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Perlindungan Rahasia Ephemeral (Zero-Leak Policy):** Eksponen privat Diffie-Hellman ($a, b$) wajib disimpan secara eksklusif dalam memori yang diamankan (*secure volatile memory / enclave*) dan segera dihapus (*zeroed out*) setelah rahasia bersama selesai dihitung. Log aplikasi, transkrip komunikasi, atau pesan diagnostik dilarang keras mencatat parameter privat.
   - **Penerapan KDF Standar Industri (RFC 5869 / HKDF):** Rahasia bersama $K$ tidak boleh digunakan langsung atau dipotong menggunakan modulo integer sederhana. Terapkan HMAC-based Extract-and-Expand Key Derivation Function (HKDF) dengan cryptographic hash function kuat (SHA-256) untuk mengekstraksi kunci simetris 256-bit berdaya tahan tinggi.
   - **Peningkatan Ukuran Parameter Grup (RFC 3526 / NIST SP 800-56A):** Modulus prima 768-bit tidak lagi aman terhadap serangan *General Number Field Sieve* (GNFS). Standar NIST mewajibkan modulus minimal 2048-bit (MODP Group 14) atau beralih ke Elliptic Curve Diffie-Hellman (ECDH) dengan kurva standar Curve25519 (X25519 / RFC 7748) atau NIST P-256.

2. **Relevansi Modul LKS Cyber Security:**
   - **Analisis Audit Protokol Kriptografi:** Peserta LKS Cyber Security dituntut mampu membedah transkrip lalu lintas komunikasi kriptografi, mengidentifikasi kebocoran rahasia (*information disclosure*), dan merekonstruksi alur kalkulasi matematis kunci bersama.
   - **Pemahaman Batas Antara Kriptografi Asimetris dan Derivasi Kunci Simetris:** Mengajarkan peserta bahwa integritas algoritma asimetris menjadi sia-sia jika antarmuka penghubung menuju enkripsi simetris dirancang dengan kecacatan pereduksian entropi.
