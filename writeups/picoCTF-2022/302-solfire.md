# Writeup: solfire (Challenge ID: 302)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Solana Blockchain Smart Contract eBPF Memory Corruption (CWE-125 / CWE-805 / CWE-287)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 500
- **Author:** notdeghost
- **Flag:** `academy{bpf_s0l4n4_v4ult_dr41n3d_f7e8a9c1}`

---

## Problem Statement & Scope
Tantangan `solfire` menyajikan arsitektur keamanan kontrak pintar (*smart contract*) berbasis *blockchain* Solana. Program dikompilasi ke format biner eBPF (*extended Berkeley Packet Filter*) bersama pustaka C SDK resmi Solana (`solana_sdk.h`):
1. Kontrak target `solfire.so` bertindak sebagai pengelola brankas (*vault*) dan buku besar (*ledger*) transaksi lamport (satuan terkecil SOL, $1 \text{ SOL} = 10^9 \text{ lamports}$).
2. Lingkungan uji menyediakan *test harness* lokal yang mendistribusikan:
   - Akun brankas (`vault`) yang diawali dengan saldo 50.000 lamports.
   - Akun pengguna/peserta (`user`) yang diawali dengan modal 10 lamports.
   - Anggaran komputasi transaksi (*compute budget*) yang dibatasi maksimum 200.000 *compute units*.
3. Syarat kemenangan (*winning condition*): Peserta dapat mengeksekusi instruksi kustom apa pun dalam satu transaksi, dan saldo akhir akun pengguna wajib melebihi 50.000 lamports (`balance > 50,000`).

Tantangan menguji kompetensi peserta dalam menganalisis *reverse engineering* biner instruksi eBPF tingkat rendah, memahami model memori *runtime* mesin virtual Solana BPF (*deserialization padding*), membypass mekanisme validasi jam sistem (*sysvar clock*), serta mengeksploitasi pembacaan memori di luar batas (*out-of-bounds read*) untuk menguras brankas.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemeriksaan Jam Menggunakan Verifikasi Substring Lemah (CWE-287 / CWE-305):**
   Fungsi penarikan dana `handle_withdraw` memeriksa keabsahan akun penunjuk waktu (akun indeks 0) dengan memvalidasi apakah representasi teks Base58 dari kunci publiknya memuat substring `"C1ock"`. Logika ini bermaksud memastikan bahwa akun tersebut adalah `SysvarC1ock11111111111111111111111111111111`. Namun, jika akun resmi `SysvarClock` diberikan, program mem-parsing data timestamp aktif dan menolak penarikan cepat karena pembatasan interval waktu (*cooldown lock*). Sebaliknya, dengan menyediakan akun kosong sembarang yang alamat publiknya memuat kata `"C1ock"`, pemeriksaan string berhasil lolos tanpa memicu validasi data waktu aktif.

2. **Pengurasan Anggaran Komputasi & Pembuatan Akun Berukuran Nol (CWE-805):**
   Fungsi inisialisasi resmi `handle_create` mengonsumsi lebih dari 20% total *compute budget* karena eksekusi rutin pengkodean `b58encode` internal. Untuk menghemat komputasi, penyerang dapat membuat akun buku besar (*ledger*) sendiri menggunakan instruksi bawaan sistem `system_instruction::create_account`, dengan parameter `space = 0` byte dan menetapkan kepemilikan (*owner*) ke program `solfire.so`. Kontrak `solfire` hanya memverifikasi bahwa akun buku besar dimiliki oleh programnya sendiri, tanpa memvalidasi panjang byte data yang dialokasikan.

3. **Bantalan Memori Runtime Solana & Pembacaan di Luar Batas (Out-of-Bounds Read, CWE-125):**
   Dalam model eksekusi Solana BPF runtime, ketika akun-akun transaksi dideserialisasi ke dalam ruang alamat memori VM, *runtime* secara otomatis menambahkan bantalan (*memory padding*) sebesar 10.240 byte (10 KB) pada setiap segmen data akun.
   Pada fungsi `handle_withdraw`, program membaca entri saldo deposit dan penarikan:
   ```c
   struct ledger_entry {
       uint64_t deposits;
       uint64_t withdraws;
   };
   ```
   Program menerima parameter offset indeks dari pengguna tanpa membandingkannya dengan ukuran data akun (`account_data_len`). Jika pengguna meminta penarikan dengan indeks `0x280` (offset 640), pointer pembacaan melompati data 0-byte akun dan mendarat pada area memori bantalan runtime serta metadata akun tetangga.

4. **Pemalsuan Catatan Saldo & Penarikan Lamport Tanpa Setoran:**
   Byte-byte non-nol pada area metadata tersebut diinterpretasikan oleh struktur `ledger_entry` sebagai nilai setoran historis yang sangat besar ($\text{deposits} \gg 50.000$). Akibatnya, kondisi penjaga:
   $$\text{deposits} \ge \text{withdraws}$$
   terpenuhi secara otomatis untuk permintaan penarikan 50.000 lamports, meskipun pengguna tidak pernah menyetorkan dana satu pun ke brankas.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur eBPF & Fungsi Internal Kontrak:**
   Ekstrak dan dekompilasi segmen `.text` dari biner `solfire.so`:
   - `entrypoint`: Mengurai parameter SolParameters dan meneruskan panggilan berdasarkan kode fungsi di `buf[0]`.
   - `handle_create` (`buf[0] = 0`): Membuat akun buku besar PDA.
   - `handle_deposit` (`buf[0] = 1`): Menambah saldo `deposits` pada entri buku besar.
   - `handle_withdraw` (`buf[0] = 2`): Memeriksa saldo dan mentransfer lamport dari brankas ke pengguna.

2. **Penyusunan Akun Clock Palsu:**
   Hasilkan atau temukan kunci publik ed25519 yang memuat karakter `"C1ock"` pada representasi Base58:
   - Alamat ini dipetakan sebagai akun indeks 0 pada metadata instruksi `handle_withdraw`.
   - Pemeriksaan string `strstr(b58_key, "C1ock")` menghasilkan kecocokan valid, membypass validasi sysvar resmi.

3. **Alokasi Mandiri Buku Besar (Zero-Size Ledger Creation):**
   Susun instruksi `CreateAccount` melalui System Program:
   - `payer`: Akun pengguna (`user`).
   - `new_account`: Kunci publik Program Derived Address (PDA) untuk buku besar dengan seed `nonce`.
   - `lamports`: 0 (atau saldo sewa minimum).
   - `space`: `0` (alokasi data kosong untuk menghemat komputasi dan memicu padding runtime).
   - `owner`: Kunci publik program `solfire.so`.

4. **Eksekusi Penarikan di Luar Batas (OOB Read Withdraw):**
   Bangun instruksi panggilan ke `solfire.so` dengan operasi `handle_withdraw`:
   - Akun yang disertakan:
     - [0]: Akun `*C1ock*` (clock bypass).
     - [1]: Akun `System Program`.
     - [2]: Akun buku besar PDA (ukuran 0 byte).
     - [3]: Akun brankas (`vault`).
     - [4]: Akun pengguna (`user`).
   - Parameter data instruksi:
     - `code`: `2` (`handle_withdraw`).
     - `entry_index`: `0x280` (640, melompat ke memori metadata runtime).
     - `amount`: `50,000` lamports.
     - `vault_nonce`: nonce PDA brankas.

5. **Transfer Dana & Verifikasi Saldo Kemenangan:**
   - Mesin virtual Solana BPF mengeksekusi `handle_withdraw`.
   - Verifikasi saldo setoran membaca byte memori offset `0x280` yang bernilai $\ge 50.000$, meloloskan pemeriksaan logika.
   - Program memanggil CPI (`sol_invoke_signed`) untuk mentransfer 50.000 lamports dari akun brankas ke akun pengguna.
   - Saldo akhir akun pengguna menjadi $10 + 50.000 = 50.010$ lamports.
   - *Test harness* mendeteksi bahwa saldo pengguna $> 50.000$ dan mencetak token kemenangan:
     - Native Flag: `picoCTF{bpf_s0l4n4_v4ult_dr41n3d_f7e8a9c1}`
     - Token Platform CyLab: `academy{bpf_s0l4n4_v4ult_dr41n3d_f7e8a9c1}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{bpf_s0l4n4_v4ult_dr41n3d_f7e8a9c1}`
- **Native PicoCTF Flag:** `picoCTF{bpf_s0l4n4_v4ult_dr41n3d_f7e8a9c1}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_302_solfire.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Validasi Kunci Publik Sysvar Resmi (Strict Pubkey Equality):**
   Hindari menggunakan pencarian substring (`strstr` / `.contains()`) untuk memvalidasi akun sistem Solana. Bandingkan kunci publik secara mutlak menggunakan perbandingan byte identik:
   ```c
   if (memcmp(params->ka[CLOCK].key, &solana_sysvar_clock_id, sizeof(SolPubkey)) != 0) {
       return ERROR_INVALID_ARGUMENT;
   }
   ```
2. **Pemeriksaan Batas Ukuran Data Akun (Strict Account Bounds Checking):**
   Sebelum melakukan dereferensi array atau offset pada data akun, periksa selalu panjang data aktual:
   ```c
   size_t required_len = (entry_index + 1) * sizeof(struct ledger_entry);
   if (params->ka[LEDGER].data_len < required_len) {
       return ERROR_ACCOUNT_DATA_TOO_SMALL;
   }
   ```
3. **Penggunaan Framework Aman (Anchor / Native Rust SDK):**
   Pada pengembangan aplikasi berbasis Solana tingkat industri, gunakan framework seperti Anchor yang secara otomatis memvalidasi diskriminator tipe akun, panjang data teralokasi, kepemilikan akun program (*owner check*), dan sysvar constraint tanpa mengandalkan deserialisasi memori manual dalam bahasa C.
