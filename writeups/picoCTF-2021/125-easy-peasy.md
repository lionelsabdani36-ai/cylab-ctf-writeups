# Writeup: Easy Peasy (Challenge ID: 125)

- Platform: CyLab Security Academy (picoCTF)
- Category: Cryptography / One-Time Pad Key Reuse & Keystream Recovery
- Difficulty: Medium (diff=2)
- Author: MadStacks
- Event: picoCTF 2021
- Points: 40
- Flag: `academy{b81c6135ae8d388b5edc7cbd387d05a2}` (Komunitas: `CTF{b81c6135ae8d388b5edc7cbd387d05a2}`)

---

## Problem Statement & Scope

Tantangan menguji pemahaman terhadap batasan keamanan algoritma kriptografi One-Time Pad (OTP) dan konsekuensi fatal penggunaan ulang kunci (*keystream reuse*):
> *"A one-time pad is unbreakable, but can you manage to recover the flag? (Wrap with academy{})"*
> 
> Service: Netcat on-demand container lab
> Berkas sumber: `otp.py`
> 
> Petunjuk:
> *"Maybe there's a way to make this a 2x pad."*

Peserta diberikan skrip layanan Python yang membaca berkas kunci statis (`key`, panjang 50.000 byte) dan berkas flag (`flag`, 32 byte). Saat inisialisasi, server mengenkripsi flag menggunakan irisan awal kunci ($k_0 \dots k_{31}$) melalui operasi XOR ($\oplus$). Peserta kemudian diizinkan mengirimkan data sembarang untuk dienkripsi berulang kali. Lingkup pengujian mencakup analisis batasan buffer kunci, manipulasi pointer posisi kunci (*key pointer wrap-around*), serta pemulihan kunci XOR dari teks terang yang diketahui (*known-plaintext attack*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Keamanan Mutlak Shannon & Kegagalan OTP (CWE-326 / CWE-329):**
   - Teorema Shannon (1949) membuktikan bahwa One-Time Pad memiliki kerahasiaan sempurna (*perfect secrecy*) hanya jika tiga syarat terpenuhi:
     1. Kunci benar-benar acak secara seragam (*uniformly random*).
     2. Panjang kunci minimal sama dengan panjang pesan ($|K| \ge |M|$).
     3. **Kunci tidak boleh digunakan lebih dari satu kali (*never reuse the key*)**.
   - Jika satu blok keystream $K$ digunakan untuk mengenkripsi dua pesan berbeda $C_1 = M_1 \oplus K$ dan $C_2 = M_2 \oplus K$, maka:
     $$C_1 \oplus C_2 = (M_1 \oplus K) \oplus (M_2 \oplus K) = M_1 \oplus M_2$$
     Kerahasiaan sempurna seketika hancur (*Two-Time Pad attack*). Bila penyerang mengetahui salah satu pesan $M_2$ (*chosen/known plaintext*), kunci pulih secara langsung:
     $$K = C_2 \oplus M_2 \implies M_1 = C_1 \oplus K$$

2. **Celah Logika Modulo Buffer Wrap-Around pada Implementasi Layanan:**
   - Dalam berkas `otp.py`:
     ```python
     KEY_LEN = 50000
     start = key_location
     stop = key_location + len(ui)
     if stop >= KEY_LEN:
         stop = stop % KEY_LEN
         key = kf[start:] + kf[:stop]
     else:
         key = kf[start:stop]
     key_location = stop
     ```
   - Flag berukuran $L = 32$ byte dikonsumsi pada indeks $0 \dots 31$, meninggalkan pointer `key_location = 32`.
   - Ukuran total file kunci adalah 50.000 byte. Jika penyerang mengirimkan data berukuran:
     $$\Delta = \text{KEY\_LEN} - L = 50000 - 32 = 49968 \text{ byte}$$
     Maka posisi akhir pointer menjadi:
     $$\text{stop} = (32 + 49968) \pmod{50000} = 50000 \pmod{50000} = 0$$
   - Pointer kembali tepat ke indeks 0. Pada permintaan enkripsi berikutnya, irisan kunci yang digunakan adalah $k_0 \dots k_{31}$—sama persis dengan irisan yang dipakai untuk menyandikan flag.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Koneksi & Ekstraksi Ciphertext Flag:**
   - Hubungkan soket TCP ke instance kontainer:
     ```bash
     nc chatelaine.cylabacademy.net 41867
     ```
   - Server menampilkan ciphertext flag dalam heksadesimal:
     ```text
     ******************Welcome to our OTP implementation!******************
     This is the encrypted flag!
     0b8b3ff1c225f9e6a3bde1df3f6d0c333e004f73535f026a1a5f5c1b45df7cfb
     ```
   - Panjang string heksadesimal adalah 64 karakter $\implies 32$ byte ciphertext.

2. **Perhitungan Offset Wrap-Around:**
   - Panjang kunci: 50.000 byte.
   - Posisi pointer setelah enkripsi flag: 32.
   - Karakter dummy yang perlu dikirim untuk mereset pointer ke 0:
     $$50000 - 32 = 49968 \text{ byte}$$

3. **Pengiriman Payload Putaran Kunci:**
   - Kirim 49.968 karakter `A` ke terminal interaktif.
   - Server menyelesaikan enkripsi blok besar dan menyetel `key_location = 0`.

4. **Ekstraksi Keystream Melalui Known-Plaintext Probe:**
   - Kirim probe 32 byte yang diketahui (misal 32 karakter `a` / `0x61`).
   - Server merespons ciphertext probe:
     ```text
     08d26ff39575abb2a3b9b8da6d3455306a044a71055d016f48060a1e148b7ca8
     ```

5. **Dekripsi Flag via XOR:**
   - Hitung irisan kunci $K = C_{\text{probe}} \oplus P_{\text{probe}}$.
   - Hitung plaintext flag $M = C_{\text{flag}} \oplus K$:
     $$\text{Flag Raw} = \text{b81c6135ae8d388b5edc7cbd387d05a2}$$
   - Format flag akhir:
     ```text
     academy{b81c6135ae8d388b5edc7cbd387d05a2}
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{b81c6135ae8d388b5edc7cbd387d05a2}`
- **Flag Komunitas:** `CTF{b81c6135ae8d388b5edc7cbd387d05a2}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 125, "flag": "academy{b81c6135ae8d388b5edc7cbd387d05a2}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Jaminan Anti-Reuse pada Stream Cipher & OTP:**
   - Dalam arsitektur kriptografi modern (seperti ChaCha20 atau AES-CTR), penggunaan kembali kombinasi Key dan Nonce/IV adalah kerentanan berisiko kritis (CWE-329). Setiap sesi enkripsi wajib menghasilkan nonce acak unik atau menghentikan generator stream bila batas siklus tercapai.
2. **Kepatuhan NIST SP 800-38A / NIST SP 800-131A:**
   - Pedoman manajemen kunci NIST mewajibkan penegakan batas umur kriptografi (*cryptoperiod*). Sistem harus menolak permintaan enkripsi dan membuang kunci (*zeroize key in memory*) daripada melakukan rotasi siklik (*cyclic wrap-around*) saat buffer habis.
3. **Relevansi Modul LKS Cyber Security:**
   - Analisis keystream reuse adalah materi inti pada kompetisi LKS Cyber Security bidang Cryptographic Analysis. Peserta dilatih membongkar asumsi keamanan bahwa "kunci panjang selalu aman" jika logika pembaruan posisi kunci dapat diprediksi atau dimanipulasi oleh input pengguna.

---

## Solver Script

Solusi reproduktif tersedia pada file terlampir:
`scripts/solve_125_easy_peasy.py`
