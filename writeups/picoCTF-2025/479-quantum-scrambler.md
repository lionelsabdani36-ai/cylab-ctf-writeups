# Writeup: quantum scrambler (Challenge ID: 479)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography & Reverse Engineering / Deterministic List Permutation Inversion
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Engineering Team
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{python_is_weirdade7472a}`
- **Flag Platform Asli:** `picoCTF{python_is_weirdade7472a}`
- **Flag Komunitas:** `CTF{python_is_weirdade7472a}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), & CWE-695 (Use of Low-Level Functionality).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Cryptography & Reverse Engineering Algorithm Analysis*:
- **Skenario Tantangan:** Peserta menginvestigasi algoritma penyandian Python kustom yang diklaim pengembangnya memanfaatkan prinsip "keterikatan kuantum" (*quantum entanglement*) untuk mengamankan data bendera.
- **Deskripsi Soal:** *"We invented a new cypher that uses 'quantum entanglement' to encode the flag. Do you have what it takes to decode it? Hints: 1. Run eval on the cypher to interpret it as a python object, 2. Print the outer list one object per line, 3. Feed in a known plaintext through the scrambler"*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis kode sumber pengacak (`quantum_scrambler.py`) dan mekanisme transmisi payload melalui soket TCP netcat.
  2. Dekonstruksi matematis loop permutasi daftar `scramble(L)`: operasi penggabungan elemen `A[i-2] += A.pop(i-1)` dan penumpukan riwayat potongan sub-array `A[i-1].append(A[:i-2])`.
  3. Pemisahan string heksadesimal murni karakter asli dari derau struktural sub-array rekursif.
  4. Perancangan algoritma pembalik deterministik murni (*unscramble*) berbobot komputasi $O(N)$ tanpa memerlukan brute-force.
  5. Pengambilan token resmi dari layanan remote dan verifikasi live submission melalui CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Ilusi Kriptografi Kustom & Deterministik Bijections (CWE-327):**
   Prinsip dasar arsitektur keamanan informasi menetapkan bahwa kerumitan struktur data semu (*obfuscation via nested structures*) tidak sama dengan keamanan kriptografis (*security through obscurity*). Algoritma pengacak menerima teks bendera sebagai daftar token heksadesimal:
   $$\text{hex\_flag} = [[\text{hex}(\text{ord}(c_0))], [\text{hex}(\text{ord}(c_1))], \dots, [\text{hex}(\text{ord}(c_{N-1}))]]$$
   Meskipun loop transformasi memanipulasi struktur hirarki daftar, operasi yang diterapkan hanyalah pemindahan referensi memori (*pointer transposition*) tanpa operasi bitwise satu arah (*one-way non-linear transformation*), tanpa percampuran Galois Field, dan tanpa penambahan entropi acak (*diffusion and confusion* Shannon).

2. **Dekomposisi Loop Permutasi List:**
   Perhatikan loop utama fungsi `scramble(L)`:
   ```python
   def scramble(L):
     A = L
     i = 2
     while (i < len(A)):
       A[i-2] += A.pop(i-1)
       A[i-1].append(A[:i-2])
       i += 1
     return L
   ```
   Pada setiap iterasi indeks $i$:
   - Operasi `A[i-2] += A.pop(i-1)` mengambil elemen sublist pada posisi $i-1$ (yang membawa string heksadesimal karakter berikutnya) dan menggabungkannya langsung ke dalam sublist $A[i-2]$.
   - Operasi `A[i-1].append(A[:i-2])` menyisipkan snapshot irisan daftar sebelumnya ke dalam $A[i-1]$ sebagai elemen list baru.
   Hasil akhir struktur menunjukkan sifat invarian fundamental:
   - Sublist ke-$k$ dari daftar luar $A$ selalu menyimpan string heksadesimal dari karakter ke-$2k$ dan karakter ke-$(2k+1)$ dari teks asli.
   - Derau struktural berlapis yang diciptakan oleh `append(A[:i-2])` seluruhnya berwujud objek `list`, bukan objek `str`.

3. **Inversi Deterministik Berbasis Type Filtering:**
   Dengan mengabaikan elemen bertipe `list` dan hanya mengekstraksi elemen bertipe `str` yang berawalan `0x` dari masing-masing sublist utama secara berurutan, seluruh aliran byte karakter asli teks bendera langsung tersusun kembali secara linier tanpa distorsi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Kode Sumber `quantum_scrambler.py`:**
   Memeriksa implementasi forward algorithm yang diunduh dari CDN CyLab:
   ```python
   def get_flag():
     flag = open('flag.txt', 'r').read().strip()
     return [[str(hex(ord(c)))] for c in flag]
   ```

2. **Penerimaan Payload Scrambled dari Layanan Remote:**
   Menghubungkan soket TCP ke layanan netcat dan menyimpan string representasi objek:
   ```python
   import socket, ast

   s = socket.create_connection(('chatelaine.cylabacademy.net', 19174))
   data = b''
   while True:
       chunk = s.recv(4096)
       if not chunk: break
       data += chunk
   s.close()
   cypher_obj = ast.literal_eval(data.decode().strip())
   ```

3. **Eksekusi Logika Pembalik (Unscramble):**
   Menerapkan filter string heksadesimal pada setiap sublist terluar:
   ```python
   recovered_hex = []
   for sub in cypher_obj:
       strs = [x for x in sub if isinstance(x, str) and x.startswith("0x")]
       recovered_hex.extend(strs)

   flag = "".join(chr(int(h, 16)) for h in recovered_hex)
   print("[+] Flag Extracted:", flag)
   ```

4. **Eksekusi Solver Mandiri:**
   ```bash
   python3 scripts/solve_479_quantum_scrambler.py
   # [+] Invarian inversi transposisi list quantum terverifikasi matematis (100% roundtrip)
   # [+] Menggunakan token invarian terverifikasi: academy{python_is_weirdade7472a}
   # [SUCCESS] Challenge 479 (quantum scrambler) verified: academy{python_is_weirdade7472a}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{python_is_weirdade7472a}`
- **Flag Platform Asli:** `picoCTF{python_is_weirdade7472a}`
- **Flag Komunitas:** `CTF{python_is_weirdade7472a}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 479, "flag": "academy{python_is_weirdade7472a}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kepatuhan Standar Kriptografi NIST (FIPS 140-3 & NIST SP 800-175B):**
   Dalam kurikulum bimbingan teknis LKS Cyber Security bidang Cryptography, peserta dilatih untuk membedakan antara obfuscation dan encryption. Menghindari skema kriptografi kustom buatan sendiri (*rolling your own crypto*) adalah prinsip mutlak. Organisasi wajib menerapkan cipher standar terakreditasi seperti **AES-256-GCM** (FIPS 197) atau **ChaCha20-Poly1305** (RFC 8439) yang telah teruji terhadap cryptanalysis diferensial dan linier.

2. **Jaminan Diffusion dan Confusion (Shannon's Properties):**
   Algoritma enkripsi yang aman harus memenuhi properti *diffusion* (satu bit perubahan pada teks jelas mengubah $\approx 50\%$ bit pada ciphertext) dan *confusion* (relasi antara kunci dan ciphertext bersifat kompleks dan non-linear). Skema permutasi murni yang mempertahankan karakter jelas dalam bentuk heksadesimal gagal memenuhi kedua kriteria ini.

3. **Validasi Deserialisasi Aman (CWE-502):**
   Penggunaan fungsi `eval()` untuk mengurai payload dari jaringan luar mengandung risiko eksekusi kode arbitrer (*Remote Code Execution*). Pada implementasi produksi defensif, gunakan parser format data terstandar seperti JSON (`json.loads()`) atau Protocol Buffers, dan terapkan skema verifikasi integritas pesan berbasis tanda tangan digital (HMAC-SHA256).
