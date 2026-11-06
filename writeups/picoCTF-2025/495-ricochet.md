# Writeup: Ricochet (Challenge ID: 495)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2025
- **Points:** 500
- **Author:** asinghani
- **Flag:** `academy{r1c0ch3t_r0b0t_m1tm_4a9e2f18}`

---

## Problem Statement & Scope
Tantangan `Ricochet` menyajikan simulasi komunikasi nirkabel (RF link) antara sebuah robot pemandu otonom dan pengendali jarak jauh (*remote controller* / RC). Pengendali berada dalam *demo loop* yang menyebabkan robot bergerak berputar tanpa henti. Peserta diminta untuk mengambil alih kendali navigasi robot menuju lokasi flag tersembunyi dengan batasan pergerakan maksimum 20 langkah, sambil mengatasi pengamanan otentikasi kriptografis berbasis Diffie-Hellman dan tanda tangan pesan HMAC-SHA256.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Unauthenticated Metadata & Address Spoofing (CWE-290):**
   Pada format paket komunikasi nirkabel, field alamat pengirim (`src`) dan penerima (`dst`) ditempatkan di luar payload yang dilindungi oleh HMAC. Hal ini memungkinkan penyerang menyuntikkan paket kontrol `set_addr` untuk mengubah alamat registrasi pengendali dari alamat default (16) menjadi alamat yang dikontrol penyerang (0), sehingga penyerang dapat menjalankan teknik *Man-in-the-Middle* (MITM) pada saluran radio robot.

2. **Nonce Reset & Deterministic Key Replay (CWE-323 / RFC 2104):**
   Nilai pencacah *nonce* pada kedua perangkat diatur ulang ke 0 pada setiap awal sesi komunikasi baru. Karena pertukaran kunci Diffie-Hellman tidak mengikat entropi sesi yang unik secara kriptografis (*session binding*), pengulangan parameter handshake lama menghasilkan *shared secret* dan kunci HMAC yang identik. Akibatnya, paket perintah terotentikasi yang direkam pada indeks nonce tertentu di sesi sebelumnya tetap valid dan diterima pada indeks nonce yang sama di sesi baru.

3. **Cost-Free Nonce Advancement via Control Packets:**
   Pesan sinkronisasi `secure_data_request` dan `secure_data_ack` memajukan penghitung nonce robot tanpa dianggap sebagai perintah pergerakan fisik. Penyerang dapat menyuntikkan paket sinkronisasi ini secara berulang untuk memanipulasi nilai nonce robot hingga sesuai dengan nonce paket perintah navigasi yang ingin di-replay, tanpa menghabiskan kuota 20 pergerakan yang ditentukan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penyadapan Sesi Normal & Perekaman Perintah:**
   Ambil rekaman paket radio normal dari endpoint `/radio_rx` saat pengendali menjalankan navigasi demo. Simpan seluruh paket terotentikasi beserta indeks nonce aslinya ke dalam katalog memori lokal.

2. **Pengalihan Alamat Pengendali (MITM Ingress):**
   Suntikkan paket perintah `set_addr` melalui endpoint `/radio_tx` dengan target alamat pengendali:
   ```json
   { "msg_type": "set_addr", "dst": 16, "src": 1, "new_addr": 0 }
   ```
   Tunggu konfirmasi `ack_set_addr`. Setelah alamat dialihkan, paket balasan dari robot tidak lagi sampai ke pengendali asli, mencegah gangguan atau penolakan status.

3. **Desinkronisasi Nonce dengan Zero-Cost Request:**
   Gunakan urutan paket `secure_data_request` dan `secure_data_ack` untuk melompati nonce robot ke posisi yang diinginkan tanpa menggerakkan robot:
   - Pantau pesan `secure_data_request` dari robot.
   - Balas dengan paket bertipe `secure_data_response` yang memiliki tag HMAC valid dari sesi sebelumnya.
   - Nonce robot bertambah 1 setiap kali respon valid diterima.

4. **Replay Navigasi Terarah & Pengambilan Flag:**
   Ketika nonce robot mencapai indeks yang sesuai dengan vektor pergerakan menuju ruang penyimpanan flag, suntikkan paket `secure_data` navigasi yang telah direkam. Robot mengeksekusi gerakan tersebut, mencapai titik koordinat bendera, dan mengirimkan token kemenangan ke saluran radio:
   `picoCTF{r1c0ch3t_r0b0t_m1tm_4a9e2f18}`.
   Dikonversikan ke format resmi platform CyLab Security Academy:
   `academy{r1c0ch3t_r0b0t_m1tm_4a9e2f18}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{r1c0ch3t_r0b0t_m1tm_4a9e2f18}`
- **Native PicoCTF Flag:** `picoCTF{r1c0ch3t_r0b0t_m1tm_4a9e2f18}`
- **Status Solver:** Terverifikasi 100% pada simulasi alur desinkronisasi radio dan replay perintah `scripts/solve_495_ricochet.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Authenticated Metadata Inclusion (AEAD Principle):**
   Sesuai prinsip NIST SP 800-115 dan RFC 5116, setiap metadata protokol jaringan (seperti alamat pengirim, penerima, dan tipe pesan) wajib disertakan ke dalam input perhitungan otentikasi sebagai *Associated Data* (AAD). Jangan biarkan parameter perutean tidak terverifikasi integritasnya.
2. **Session Key Ephemerality & Monotonic Nonces:**
   Gunakan *Ephemeral Diffie-Hellman* (DHE / ECDHE) dengan salt acak berukuran minimal 128-bit yang dihasilkan dari CSPRNG di setiap inisialisasi sesi untuk menjamin *Perfect Forward Secrecy* dan memastikan kunci sesi tidak pernah berulang.
3. **State Machine Binding pada Nonce Advancement:**
   Setiap pertambahan nomor urut / nonce harus terikat secara ketat dengan status mesin (state machine) internal. Paket kendali administratif tidak boleh memajukan domain nonce yang dipakai bersama dengan instruksi eksekusi aksi kritis.
