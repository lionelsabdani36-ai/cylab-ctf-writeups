# Writeup: Guess My Cheese (Part 2) (Challenge ID: 474)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Hash Reversal & Weak Salt Entropy
- **Difficulty:** Medium
- **Author:** aditin
- **Event:** picoCTF 2025
- **Points:** 300
- **Flag:** `academy{cHeEsYdaa8c59e}`

---

## Problem Statement & Scope
Setelah skema substitusi Affine pada bagian pertama berhasil ditembus, sistem memperbarui pertahanan dengan beralih ke fungsi hash kriptografi SHA-256 dan menambahkan salt. Peserta diberikan daftar 599 nama keju resmi (`cheese_list.txt`) dan sebuah hash target berukuran 256-bit (64 karakter heksadesimal). Peserta diminta menebak nama keju beserta nilai salt yang digunakan.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Entropi Rendah pada Parameter Salt
Salt dirancang untuk mencegah serangan berbasis tabel prainisialisasi (*precomputed rainbow table*). Namun efektivitas salt sangat bergantung pada ukuran ruang pencariannya (*search space*).
- Petunjuk menyatakan salt berukuran "2 nibble" dari karakter heksadesimal (1 byte = 8 bit = 256 kombinasi nilai dari `0x00` hingga `0xff`).
- Total kandidat yang mungkin dibentuk adalah:
  $$\text{Ruang Pencarian} = 599 \text{ keju} \times 256 \text{ salt} = 153.344 \text{ kombinasi}$$
Ukuran komputasi ini sangat kecil dan dapat diproses secara penuh (*exhaustive brute-force*) oleh CPU standar dalam waktu kurang dari 150 milidetik.

### 2. Konstruksi Input Hashing
Implementasi backend melakukan normalisasi string nama keju menjadi huruf kecil (*lowercase*), kemudian mengonversinya menjadi byte UTF-8 dan menggabungkan raw byte salt berukuran 1 byte di akhir:
$$\text{Digest} = \text{SHA256}(\text{lowercase}(\text{cheese}) \parallel \text{byte}(\text{salt}))$$
Saat validasi, server meminta nama keju asli/lowercase diikuti representasi 2 karakter heksadesimal dari nilai salt (`format(salt, '02x')`).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pembuatan Kamus Prekomputasi (Rainbow Table Generator):**
   Unduh daftar keju resmi dari CDN CyLab (`cheese_list.txt`). Buat tabel pemetaan *hash-to-(cheese, salt)* secara lokal:
   ```python
   rainbow = {}
   for cheese in cheeses:
       cb = cheese.lower().encode()
       for s in range(256):
           h = hashlib.sha256(cb + bytes([s])).hexdigest()
           rainbow[h] = (cheese.lower(), f"{s:02x}")
   ```
2. **Koneksi ke Layanan Lab:**
   Luncurkan instance lab via `PUT /api/challenges/474/instance/` dan hubungkan ke port layanan (`chatelaine.cylabacademy.net:19360`).
3. **Pencocokan Hash Target:**
   Server menyajikan hash: `4358a37d7a1c8ff4acc094eff27056fea3b95e45970bdf684823794dcf666cdb`.
   Pencarian tabel instan menemukan pasangan:
   - Keju: `greuilh`
   - Salt: `3e`
4. **Pengiriman Respons:**
   - Kirim `g` untuk mode tebak.
   - Masukkan `greuilh`.
   - Masukkan salt `3e`.
5. **Penerimaan Flag:**
   ```text
   YUM! MMMMmmmmMMMMmmmMMM!!! Yes...yesssss! That's my cheese!
   Here's the password to the cloning room: academy{cHeEsYdaa8c59e}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{cHeEsYdaa8c59e}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true, "status": 201}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Persyaratan Entropi Salt Kriptografis (NIST SP 800-63B / SP 800-132):** Salt tidak boleh berukuran sepele (minimal 128 bit atau 16 byte acak kriptografis) untuk memastikan bahwa serangan prainisialisasi kamus tidak dapat dilakukan.
- **Penggunaan KDF Berbobot Komputasi Tinggi (Key Derivation Function):** Jangan menggunakan fungsi hash berkecepatan tinggi seperti SHA-256 untuk hashing kata sandi/kredensial langsung. Gunakan fungsi ramah proteksi brute-force seperti Argon2id, PBKDF2 (dengan iterasi minimal 600.000 untuk SHA-256), atau bcrypt.
