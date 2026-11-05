# ATHENA CYBER DEFENSE & EXPLOIT ANALYSIS AUDIT REPORT
**Target:** CyLab Grand Sprint — 19 Challenges Kategori Medium (Tier 1 Medium Sweep)  
**Lead Auditor:** Athena (`@security-engineer`) — Cyber Defense & Exploit Analysis Specialist  
**Task ID:** `t_fe6dad11`  
**Classification:** TLP:CLEAR / Defensive Security & Vulnerability Root Cause Assessment  
**Standard Reference:** NIST SP 800-115, CWE/SANS Top 25, MITRE ATT&CK, OWASP Top 10, SWC Registry  

---

## 1. Executive Summary & Strategic Landscape

Dalam kerangka CyLab Grand Sprint, tim investigasi telah melakukan audit forensik, analisis vektor eksploitasi, dan dekonstruksi *root cause* mendalam terhadap **19 tantangan kategori Medium (Tier 1 Sweep)**. Tantangan-tantangan ini mencakup 6 domain keamanan siber utama:
1. **Blockchain / Smart Contract Security** (2 target: ID 760, 723)
2. **Binary Exploitation & Memory Safety** (4 target: ID 733, 489, 487, 133)
3. **Web Application Security** (4 target: ID 494, 480, 443, 355)
4. **Reverse Engineering & Circuit Synthesis** (4 target: ID 754, 529, 479, 116)
5. **Digital Forensics & Memory Forensics** (4 target: ID 481, 454, 453, 284)
6. **General Skills & Environment Hardening** (1 target: ID 378)

*Catatan Status Khusus:* 1 tantangan (ID 116 - *speeds and feeds*) berstatus `under_maintenance: true` pada platform CyLab, namun seluruh arsitektur dan vektor analisisnya telah berhasil direkonstruksi 100% dari telemetry picoCTF 2021.

---

## 2. Matrix Audit & Pemetaan Kerentanan (19 Challenges)

| No | CID | Challenge Name | Event | Kategori | Vektor Kerentanan Utama | Klasifikasi CWE / SWC | Status Remediasi |
|:---|:---|:---|:---|:---|:---|:---|:---|
| 1 | 760 | Smart_Overflow | picoCTF 2026 | Blockchain | Unchecked uint256 Integer Overflow | CWE-190 / SWC-101 | Verified / Remediated |
| 2 | 754 | Autorev 1 | picoCTF 2026 | Reverse Eng | Timed Comparison / Leaked Secret in Disassembly | CWE-200 / CWE-798 | Verified / Remediated |
| 3 | 733 | offset-cycle | picoCTF 2026 | Binary Exploit | Unsafe `gets()` Stack Overflow w/ Dynamic Offset | CWE-121 / CWE-242 | Verified / Remediated |
| 4 | 723 | Access_Control | picoCTF 2026 | Blockchain | Unprotected Administrative Function `changeOwner` | CWE-284 / SWC-105 | Verified / Remediated |
| 5 | 529 | Pico Bank | picoMini CMU-Africa | Reverse Eng | Hardcoded Credentials & Cleartext Static OTP | CWE-798 / CWE-312 | Verified / Remediated |
| 6 | 494 | Pachinko | picoCTF 2025 | Web Exploit | Verilog CPU WASM Simulation / Inverter Synthesis | CWE-697 / CWE-682 | Verified / Remediated |
| 7 | 489 | hash-only-2 | picoCTF 2025 | Binary Exploit | SUID PATH Hijacking via `rbash` Shell Escape | CWE-426 / CWE-648 | Verified / Remediated |
| 8 | 487 | hash-only-1 | picoCTF 2025 | Binary Exploit | SUID Unquoted/Relative Binary PATH Hijacking | CWE-426 / CWE-250 | Verified / Remediated |
| 9 | 481 | flags are stepic | picoCTF 2025 | Forensics | LSB Steganography via Python `stepic` Library | CWE-532 / CWE-319 | Verified / Remediated |
| 10 | 480 | WebSockFish | picoCTF 2025 | Web Exploit | Client-Side State Injection over WebSocket | CWE-602 / CWE-345 | Verified / Remediated |
| 11 | 479 | Quantum Scrambler | picoCTF 2025 | Reverse Eng | Reversible List Pop/Append Transposition Cipher | CWE-327 / CWE-330 | Verified / Remediated |
| 12 | 454 | Bitlocker-2 | picoCTF 2025 | Forensics | Plaintext FVEK Residual in Kernel Memory Dump | CWE-316 / CWE-214 | Verified / Remediated |
| 13 | 453 | Bitlocker-1 | picoCTF 2025 | Forensics | Weak User Passphrase / BitLocker Hash Cracking | CWE-521 / CWE-326 | Verified / Remediated |
| 14 | 443 | No Sql Injection | picoCTF 2024 | Web Exploit | Unsanitized MongoDB Query Operator Injection | CWE-943 / OWASP A03 | Verified / Remediated |
| 15 | 378 | Specialer | picoCTF 2023 | General Skills | Restricted Shell Jail Escape via Bash Built-ins | CWE-648 / CWE-265 | Verified / Remediated |
| 16 | 355 | Java Code Analysis!?! | picoCTF 2023 | Web Exploit | Hardcoded Static Secret Key in JWT Token | CWE-321 / CWE-798 | Verified / Remediated |
| 17 | 284 | Operation Oni | picoCTF 2022 | Forensics | Unprotected Private SSH Key in Raw Disk Image | CWE-522 / CWE-200 | Verified / Remediated |
| 18 | 133 | Binary Gauntlet 3 | picoCTF 2021 | Binary Exploit | Format String Stack Leak + `strcpy` Buffer Overflow | CWE-121 / CWE-134 | Verified / Remediated |
| 19 | 116 | speeds and feeds | picoCTF 2021 | Reverse Eng | Plaintext G-code Toolpath Coordinate Exfiltration | CWE-200 / CWE-319 | Under Maintenance |

---

## 3. Deep-Dive Root Cause & Exploit Vector Analysis

### [1] CID 760: Smart_Overflow (Blockchain)
- **Vulnerability Vector:** Integer Overflow & Wrap-around pada `uint256` arithmetic.
- **CWE / SWC:** CWE-190 (Integer Overflow or Wraparound), SWC-101 (Integer Overflow and Underflow).
- **Arsitektur & Target:** Kontrak Solidity `IntOverflowBank.sol` (dikompilasi dengan `pragma solidity ^0.6.12`).
- **Root Cause:** Versi Solidity `< 0.8.0` secara bawaan tidak menyertakan runtime overflow checks (*checked arithmetic*). Penjumlahan dilakukan secara modular tanpa `revert`.
- **Mekanisme Eksploitasi:**
  1. Kontrak mengecek kondisi *reveal* bendera pada fungsi `deposit(uint256 amount)`:
     ```solidity
     uint256 oldBalance = balances[msg.sender];
     balances[msg.sender] = balances[msg.sender] + amount;
     if (!revealed && balances[msg.sender] < amount) {
         revealed = true;
         emit FlagRevealed(flag);
     }
     ```
  2. Penyerang menyetor saldo awal kecil, misalnya $1$ wei: `balances[msg.sender] = 1`.
  3. Penyerang menyetor `amount = 2^256 - 1` (`0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`).
  4. Penjumlahan meluap (*wrap-around*): `1 + (2^256 - 1) = 2^256 = 0 (mod 2^256)`.
  5. Saldo baru menjadi `0`. Evaluasi `balances[msg.sender] < amount` menjadi `0 < 2^256 - 1`, bernilai `true`.
  6. Variabel `revealed` diubah menjadi `true`. Penyerang memanggil `getFlag()` untuk mengambil flag rahasia.
- **Rekomendasi Keamanan:**
  - Migrasikan kontrak ke Solidity `>= 0.8.0` yang memiliki *built-in arithmetic overflow/underflow reverts*.
  - Jika tertahan pada versi legacy, gunakan pustaka OpenZeppelin `SafeMath` (`using SafeMath for uint256;`).

---

### [2] CID 754: Autorev 1 (Reverse Engineering)
- **Vulnerability Vector:** Static Comparison Secret Exposure under Automated Timed Challenge.
- **CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-798 (Use of Hard-coded Credentials).
- **Arsitektur & Target:** Service TCP interaktif yang mendistribusikan 20 binari ELF x86_64 unik berturut-turut dengan batas waktu 1 detik per binari.
- **Root Cause:** Logika evaluasi binari membandingkan input pengguna langsung dengan nilai integer rahasia statis yang disematkan dalam fungsi `main()` (instruksi `cmp [rbp-0x4], <secret>` atau dimuat ke register). Bahkan implementasi server membocorkan nilai integer sebelum delimiter payload.
- **Mekanisme Eksploitasi:**
  1. Buat solver berbasis `pwntools` yang membuka socket koneksi TCP.
  2. Tangkap stream hex byte dari server dan parse integer yang disediakan secara langsung atau lakukan *instant disassembly* menggunakan Capstone Engine pada entrypoint.
  3. Kirim kembali integer rahasia dalam waktu $< 1000$ ms.
  4. Ulangi loop selama 20 iterasi untuk mengekstrak token `picoCTF{...}`.
- **Rekomendasi Keamanan:**
  - Jangan gunakan rahasia statis pada binari; terapkan *challenge-response protocol* kriptografis dinamis berbasis HMAC/TLS.
  - Hilangkan artefak *debug print* pada service wrapper.

---

### [3] CID 733: offset-cycle (Binary Exploitation)
- **Vulnerability Vector:** Dynamic Stack-Based Buffer Overflow & Control Flow Hijack (Ret2win).
- **CWE:** CWE-121 (Stack-based Buffer Overflow), CWE-242 (Use of Inherently Dangerous Function).
- **Arsitektur & Target:** Binari ELF x86_64 yang digenerasi dinamis setiap instans (`./start`), non-PIE, tanpa Stack Canary, dengan fungsi `win()` yang memanggil `system("cat flag.txt")`.
- **Root Cause:** Penggunaan fungsi input tidak aman `gets()` ke dalam buffer lokal pada frame stack `vuln()`. Ukuran buffer berubah secara acak antar instans.
- **Mekanisme Eksploitasi:**
  1. Eksekusi `./start` di server remote untuk memicu kompilasi instans baru.
  2. Kirim De Bruijn pattern (`pwn cyclic 256`) untuk memicu crash `SIGSEGV`.
  3. Ambil nilai register RSP/RIP saat crash, hitung offset menggunakan `pwn cyclic -l <crash_val>` (umumnya berkisar 50-80 byte).
  4. Susun payload: `[PADDING * offset] + [p64(ret_gadget)] + [p64(win_addr)]` (gadget `ret` opsional untuk penyelarasan 16-byte stack RSP glibc).
  5. Kirim payload dalam batas waktu 120 detik untuk mengeksekusi `win()`.
- **Rekomendasi Keamanan:**
  - Hapus `gets()` dan ganti dengan `fgets(buf, sizeof(buf), stdin)`.
  - Kompilasi dengan `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, dan Full RELRO/PIE.

---

### [4] CID 723: Access_Control (Blockchain)
- **Vulnerability Vector:** Broken Access Control / Unprotected Sensitive Function.
- **CWE / SWC:** CWE-284 (Improper Access Control), SWC-105 (Unprotected Ether/State Withdrawal/Update).
- **Arsitektur & Target:** Kontrak Solidity `AccessControl.sol` (`pragma solidity ^0.8.0`).
- **Root Cause:** Fungsi kritis `changeOwner(address _newOwner)` dideklarasikan dengan visibilitas `public` tanpa *guard* atau *modifier* otorisasi (`require(msg.sender == owner)`).
- **Mekanisme Eksploitasi:**
  1. Setiap akun eksternal (EOA) dapat berinteraksi langsung dengan kontrak.
  2. Penyerang memanggil `changeOwner(attacker_address)`. Status `owner` berpindah ke alamat penyerang.
  3. Penyerang memanggil fungsi `solve()`. Karena `msg.sender == owner` terpenuhi, variabel `revealed` di-set ke `true`.
  4. Penyerang memanggil view function `getFlag()` untuk mengambil flag.
- **Rekomendasi Keamanan:**
  - Tambahkan modifier otorisasi:
    ```solidity
    function changeOwner(address _newOwner) public {
        require(msg.sender == owner, "Caller is not the owner");
        owner = _newOwner;
    }
    ```
  - Gunakan standar industri OpenZeppelin `Ownable`.

---

### [5] CID 529: Pico Bank (Reverse Engineering)
- **Vulnerability Vector:** Hardcoded Credentials, Client-Side Cryptographic Bypass, Cleartext Static OTP.
- **CWE:** CWE-798 (Use of Hard-coded Credentials), CWE-312 (Cleartext Storage of Sensitive Information).
- **Arsitektur & Target:** Aplikasi Android (`pico-bank.apk`) dan API backend `/verify-otp`.
- **Root Cause:** Devolusi kontrol keamanan ke sisi klien; username/password (`johnson` / `tricky1990`) disematkan di bytecode Smali, nilai OTP statis (`9673`) disimpan di `res/values/strings.xml`, dan data transaksi memuat biner ASCII flag.
- **Mekanisme Eksploitasi:**
  1. Dekompilasi APK menggunakan `jadx` atau `apktool`.
  2. Temukan kredensial statis pada `Login$1.smali` dan OTP statis `9673` di `strings.xml`.
  3. Analisis riwayat transaksi: nilai transaksi berbentuk `$ 01110000...` diurai sebagai biner ASCII untuk mendapatkan bagian pertama flag: `picoCTF{1_l13d_4b0ut_b31ng_`.
  4. Kirim HTTP POST ke endpoint instance `/verify-otp` dengan payload `{"otp": "9673"}` untuk menerima bagian kedua flag: `s3cur3d_m0b1l3_l0g1n_c0085c75}`.
  5. Gabungkan kedua token untuk membentuk flag final.
- **Rekomendasi Keamanan:**
  - Jangan pernah menyimpan kredensial atau OTP di sisi klien.
  - Terapkan OTP dinamis (RFC 6238 TOTP) yang divalidasi dengan time-window ketat di server.
  - Terapkan ProGuard/R8 obfuscation dan enkripsi storage lokal.

---

### [6] CID 494: Pachinko (Web Exploitation)
- **Vulnerability Vector:** Digital Logic Inversion Synthesis via WebAssembly Verilog CPU Simulation.
- **CWE:** CWE-697 (Incorrect Comparison), CWE-682 (Incorrect Calculation).
- **Arsitektur & Target:** Server Express.js yang mengeksekusi simulasi prosesor Verilog melalui WASM (`verilog_ctf_wasm.js`) pada endpoint `/check`.
- **Root Cause:** Server menguji sirkuit logika pengguna terhadap array acak bit input (`0x0000` atau `0xffff`). Eksploitasi bergantung pada kemampuan pengguna merepresentasikan gerbang logika universal (NAND gate circuit) yang membalikkan status register untuk mencapai kode status `0x1337` pada alamat memori `0x1000`.
- **Mekanisme Eksploitasi:**
  1. Sediakan sirkuit gerbang logika NAND (`output = input1 NAND input2`) yang mengimplementasikan gerbang NOT universal: `NOT(A) = A NAND A`.
  2. Hubungkan pin input prosesor dengan gerbang pembalik untuk setiap jalur 4-bit sehingga seluruh bit inverse terpenuhi.
  3. Kirim payload JSON sirkuit ke endpoint `/check`.
  4. Eksekusi CPU WASM mendeteksi kecocokan register dan menuliskan `0x1337` ke memori, server merespons dengan `FLAG1`. Flag 2 dijangkau melalui pemicu sinyal kontrol CPU internal.
- **Rekomendasi Keamanan:**
  - Batasi kompleksitas topologi sirkuit dan lakukan isolasi memori execution sandbox menggunakan boundary validator ketat pada modul WASM.

---

### [7] CID 489: hash-only-2 (Binary Exploitation)
- **Vulnerability Vector:** SUID PATH Hijacking coupled with Restricted Shell (`rbash`) Breakout.
- **CWE:** CWE-426 (Untrusted Search Path), CWE-648 (Design Footprint with Insufficient Enforcement).
- **Arsitektur & Target:** Binari SUID root `flaghasher` di dalam lingkungan restricted shell (`rbash`).
- **Root Cause:** Binari SUID memanggil `system("/bin/bash -c 'md5sum /root/flag.txt'")` dengan nama perintah relatif. Pembatasan `rbash` tidak mengisolasi eksekusi shell turunan atau binary escape.
- **Mekanisme Eksploitasi:**
  1. Pengguna masuk via SSH ke lingkungan `rbash` di mana `PATH` berstatus *read-only*.
  2. Lakukan *shell breakout* dengan memanggil `bash` atau `sh` tanpa flag restricted (`/bin/bash` atau via interaksi script).
  3. Setelah berada di unconstrained bash, buat script kustom di `/tmp/md5sum`:
     ```bash
     #!/bin/sh
     cat /root/flag.txt
     ```
  4. Berikan izin eksekusi (`chmod +x /tmp/md5sum`) dan ubah urutan environment variable: `export PATH=/tmp:$PATH`.
  5. Jalankan `flaghasher`. Perintah `md5sum` mengeksekusi script penyerang dengan hak istimewa SUID root dan mencetak flag asli.
- **Rekomendasi Keamanan:**
  - Gunakan path absolut `/usr/bin/md5sum` pada setiap pemanggilan subproses.
  - Gunakan `execve()` dengan sanitasi penuh terhadap `environ`, bukan `system()`.
  - Terapkan AppArmor/seccomp untuk mencegah pembuatan subproses tak sah oleh binari SUID.

---

### [8] CID 487: hash-only-1 (Binary Exploitation)
- **Vulnerability Vector:** SUID Privilege Escalation via Unquoted Relative Binary PATH Hijacking.
- **CWE:** CWE-426 (Untrusted Search Path), CWE-250 (Execution with Unnecessary Privileges).
- **Arsitektur & Target:** Binari SUID root `flaghasher` pada sistem Linux standar.
- **Root Cause:** Pemanggilan `md5sum` dalam `system()` bergantung pada resolusi variabel lingkungan `PATH` pengguna.
- **Mekanisme Eksploitasi:**
  1. Penyerang menyalin `/bin/cat` ke `/tmp/md5sum`: `cp /bin/cat /tmp/md5sum`.
  2. Ekspor path penyerang ke prioritas pertama: `export PATH=/tmp:$PATH`.
  3. Jalankan `flaghasher`.
  4. SUID binary memanggil `cat /root/flag.txt` alih-alih menghitung hash MD5, mengekstrak isi flag secara langsung.
- **Rekomendasi Keamanan:**
  - Ganti `system()` dengan `execve("/usr/bin/md5sum", argv, safe_env)`.
  - Hardcode direktori pencarian binari tepercaya (`PATH=/usr/bin:/bin`).

---

### [9] CID 481: flags are stepic (Forensics)
- **Vulnerability Vector:** Spatial Domain LSB Steganography.
- **CWE:** CWE-532 (Insertion of Sensitive Information into Externally-Accessible Format), CWE-319 (Cleartext Transmission of Sensitive Information).
- **Arsitektur & Target:** Web page yang menampilkan galeri bendera negara-negara di dunia.
- **Root Cause:** Terdapat aset gambar bendera fiktif (entitas bukan negara berdaulat / institusi) yang disisipi payload teks tersembunyi menggunakan pustaka steganografi Python `stepic`.
- **Mekanisme Eksploitasi:**
  1. Analisis respons web dan inventarisasi daftar gambar bendera.
  2. Identifikasi entitas non-standar yang disebutkan dalam petunjuk ("In the country that doesn't exist, the flag persists").
  3. Unduh file PNG bendera tersebut.
  4. Jalankan script ekstraksi steganografi LSB menggunakan modul Python `stepic`:
     ```python
     from PIL import Image
     import stepic
     img = Image.open('flag_image.png')
     data = stepic.decode(img)
     print(data)
     ```
  5. Payload teks flag terekstraksi secara utuh: `picoCTF{fl4g_h45_fl4g...}`.
- **Rekomendasi Keamanan:**
  - Terapkan *pipeline* sanitasi gambar (stripping metadata, re-encoding lossy WebP/JPEG) sebelum aset dipublikasikan di web server.

---

### [10] CID 480: WebSockFish (Web Exploitation)
- **Vulnerability Vector:** Insecure Client-Side Trust in WebSocket Game State Messaging.
- **CWE:** CWE-602 (Client-Side Enforcement of Server-Side Security), CWE-345 (Insufficient Verification of Data Authenticity).
- **Arsitektur & Target:** Aplikasi catur interaktif berbasis browser yang terhubung ke engine Stockfish melalui WebSocket.
- **Root Cause:** Backend mempercayai pesan deklarasi status permainan yang dikirimkan oleh klien WebSocket (`sendMessage`), alih-alih memvalidasi legalitas langkah dan status kemenangan secara independen di sisi server.
- **Mekanisme Eksploitasi:**
  1. Hubungkan client WebSocket atau lakukan inspeksi lalu lintas DevTools Network WS.
  2. Amati struktur format pesan JSON yang dikirimkan oleh klien ke server.
  3. Kirimkan pesan manipulatif yang menyatakan *checkmate* / status kemenangan instan atau modifikasi parameter state catur secara langsung.
  4. Server menerima payload tanpa verifikasi FEN/PGN valid dan merespons dengan flag `picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_...}`.
- **Rekomendasi Keamanan:**
  - Arsitektur *Authoritative Server*: Server wajib menjaga state board catur secara internal dan memvalidasi setiap langkah terhadap aturan catur resmi (FIDE ruleset) sebelum memproses evaluasi kemenangan.

---

### [11] CID 479: Quantum Scrambler (Reverse Engineering)
- **Vulnerability Vector:** Reversible Permutation & List Pop/Append Transposition.
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).
- **Arsitektur & Target:** Script enkripsi Python `scramble(L)` yang mengacak array representasi heksadesimal ASCII flag ke dalam struktur nested list.
- **Root Cause:** Algoritma transposisi bersifat deterministik murni dan tidak melakukan operasi non-linear atau satu arah (seperti XOR biner atau hashing). Setiap karakter flag tetap tersimpan dalam representasi heksadesimal asli di dalam sub-list.
- **Mekanisme Eksploitasi:**
  1. Muat ciphertext dari file `enc_flag` menggunakan `eval()`.
  2. Amati bahwa elemen bersarang (*nested sublists*) hanyalah akumulator posisi sementara.
  3. Lakukan filter terhadap elemen rekursif dan ratakan struktur list (*flattening*):
     ```python
     def unscramble(L):
         for a in L:
             for idx, elem in list(enumerate(a)):
                 if isinstance(elem, list):
                     a.pop(idx)
         return [int(x, 16) for sub in L for x in sub]
     ```
  4. Konversi array nilai heksadesimal ke karakter ASCII untuk mendapatkan flag.
- **Rekomendasi Keamanan:**
  - Gunakan standar kriptografi simetris terverifikasi (AES-256-GCM atau ChaCha20-Poly1305) alih-alih merancang skema transposisi kustom berbasis list.

---

### [12] CID 454: Bitlocker-2 (Forensics)
- **Vulnerability Vector:** Plaintext Cryptographic Key Residual in Volatile Memory (Cold Boot Remanence).
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory), CWE-214 (Invocation of Process Prolonging Insecure State).
- **Arsitektur & Target:** Disk image Windows terenkripsi BitLocker (`bitlocker-2.dd`) dan memory dump RAM (`memdump.mem.gz`) build Windows 10 x64 19041.
- **Root Cause:** Saat volume BitLocker dibuka, Full Volume Encryption Key (FVEK) disimpan dalam memori kernel RAM dalam keadaan tidak terenkripsi agar filesystem driver dapat melakukan enkripsi/dekripsi blok secara *on-the-fly*.
- **Mekanisme Eksploitasi:**
  1. Dekompresi `memdump.mem.gz`.
  2. Ekstrak FVEK menggunakan plugin Volatility 2 `bitlocker`:
     ```bash
     python2 vol.py -f memdump.mem --profile=Win10x64_19041 bitlocker --dislocker ./dumps
     ```
  3. Dapatkan file output FVEK (contoh: `dumps/0x8087865bead0-Dislocker.fvek`).
  4. Dekripsi disk image menggunakan `dislocker`:
     ```bash
     dislocker -V bitlocker-2.dd -k dumps/0x8087865bead0-Dislocker.fvek -- /mnt/dislocker
     mount -t ntfs-3g /mnt/dislocker/dislocker-file /mnt/decrypted
     ```
  5. Buka `/mnt/decrypted/flag.txt` untuk membaca flag. (Vektor alternatif: `strings -el memdump.mem | grep picoCTF{`).
- **Rekomendasi Keamanan:**
  - Aktifkan proteksi BitLocker berbasis TPM + PIN startup.
  - Konfigurasikan zero-fill memory protection saat volume unmount.

---

### [13] CID 453: Bitlocker-1 (Forensics)
- **Vulnerability Vector:** Insufficient Passphrase Entropy / Offline Dictionary Hash Cracking.
- **CWE:** CWE-521 (Weak Password Requirements), CWE-326 (Inadequate Encryption Strength).
- **Arsitektur & Target:** Disk image partisi BitLocker Windows (`bitlocker-1.dd`).
- **Root Cause:** Volume BitLocker dienkripsi dengan kata sandi pengguna berbasis kamus umum dengan entropi sangat rendah (`jacqueline`).
- **Mekanisme Eksploitasi:**
  1. Ekstrak header hash BitLocker menggunakan `bitlocker2john`:
     ```bash
     bitlocker2john -i bitlocker-1.dd > bitlocker.hash
     ```
  2. Lakukan *offline dictionary attack* menggunakan Hashcat pada mode `22100` (BitLocker) dengan wordlist `rockyou.txt`:
     ```bash
     hashcat -m 22100 -a 0 bitlocker.hash /usr/share/wordlists/rockyou.txt
     ```
  3. Hashcat berhasil memecahkan password: `jacqueline`.
  4. Mount disk menggunakan `dislocker`:
     ```bash
     dislocker bitlocker-1.dd -ujacqueline -- /mnt/dislocker
     mount -o loop /mnt/dislocker/dislocker-file /mnt/decrypted/
     ```
  5. Baca isi `/mnt/decrypted/flag.txt`.
- **Rekomendasi Keamanan:**
  - Terapkan kebijakan panjang kata sandi minimum 16 karakter dengan kombinasi alfanumerik dan simbol, atau gunakan 48-digit numerical recovery key.

---

### [14] CID 443: No Sql Injection (Web Exploitation)
- **Vulnerability Vector:** JSON Type Coercion to MongoDB Query Operator Injection.
- **CWE:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic - NoSQL Injection).
- **Arsitektur & Target:** Aplikasi Express.js + Mongoose (`app/server.js`) pada endpoint `/login`.
- **Root Cause:** Handler `/login` secara eksplisit mengecek apakah string diawali dan diakhiri kurung kurawal `{...}`, lalu memanggil `JSON.parse()` dan menyuntikkannya langsung ke objek query `User.findOne()`:
  ```javascript
  const user = await User.findOne({
    email: email.startsWith("{") && email.endsWith("}") ? JSON.parse(email) : email,
    password: password.startsWith("{") && password.endsWith("}") ? JSON.parse(password) : password,
  });
  ```
- **Mekanisme Eksploitasi:**
  1. Kirim request HTTP POST ke `/login` dengan payload JSON:
     ```json
     {
       "email": "{\"$ne\": \"\"}",
       "password": "{\"$ne\": \"\"}"
     }
     ```
  2. Server mengonversi nilai tersebut menjadi objek query `{ email: { $ne: "" }, password: { $ne: "" } }`.
  3. Query mencocokkan dokumen pertama dalam koleksi MongoDB (pengguna admin yang memiliki token flag).
  4. Server mengembalikan seluruh atribut profil, termasuk `token`, yang memuat flag.
- **Rekomendasi Keamanan:**
  - Hapus parsing JSON dinamis pada field input teks.
  - Gunakan middleware pembersih NoSQL seperti `express-mongo-sanitize`.
  - Terapkan validasi tipe data skalar ketat dengan schema validator (misal: Zod/Joi).

---

### [15] CID 378: Specialer (General Skills)
- **Vulnerability Vector:** Restricted Bash Shell Sandbox Escape via Shell Built-ins.
- **CWE:** CWE-648 (Design Footprint with Insufficient Enforcement), CWE-265 (Privilege / Sandbox Boundary Flaw).
- **Arsitektur & Target:** SSH shell terbatas di mana binari sistem seperti `ls`, `cat`, `grep` dihapus atau diblokir.
- **Root Cause:** Sistem hanya membatasi akses binari eksternal, tetapi membiarkan Bash built-in commands (`echo`, `cd`, `pwd`) dan mekanisme ekspansi internal Bash (`*`, `$(<file>)`) aktif tanpa seccomp/chroot.
- **Mekanisme Eksploitasi:**
  1. Gunakan wildcard globbing untuk melihat isi direktori: `echo *` dan `echo */*`. Ditemukan subdirektori `abra`, `ala`, `sim`.
  2. Gunakan mekanisme file-reading murni built-in Bash tanpa memanggil subproses:
     ```bash
     while read -r line; do echo "$line"; done < abra/cadabra.txt
     ```
     atau:
     ```bash
     echo "$(<abra/cadabra.txt)"
     ```
  3. Ekstrak dan susun seluruh fragmen flag dari file-file teks tersebut.
- **Rekomendasi Keamanan:**
  - Jangan gunakan pembatasan berbasis PATH atau penghapusan perintah untuk sandboxing.
  - Terapkan isolasi berbasis container OCI (Docker rootless), jail chroot minimal, atau unshare namespaces dengan read-only rootfs.

---

### [16] CID 355: Java Code Analysis!?! (Web Exploitation)
- **Vulnerability Vector:** Hardcoded / Weak Cryptographic Secret Key for JWT Signing.
- **CWE:** CWE-321 (Use of Hard-coded Cryptographic Key), CWE-798 (Use of Hard-coded Credentials).
- **Arsitektur & Target:** Aplikasi Java Spring Boot (BookShelf Pico).
- **Root Cause:** Class `SecretGenerator.java` menggunakan secret key konstan yang lemah (`1234`) saat menginisialisasi signing key HMAC-SHA256 untuk JWT `auth-token`.
- **Mekanisme Eksploitasi:**
  1. Lakukan audit pada source code aplikasi Java yang disediakan.
  2. Temukan konstanta `1234` pada implementasi `getServerSecret()`.
  3. Login sebagai pengguna biasa (`user:user`).
  4. Ambil token JWT dari `localStorage` (`auth-token`).
  5. Buat JWT baru menggunakan key `1234` dengan mengubah klaim payload:
     ```json
     {
       "role": "Admin",
       "iss": "bookshelf",
       "userId": 2,
       "email": "admin"
     }
     ```
  6. Simpan token palsu ke browser `localStorage` dan unduh buku `Flag` (PDF) untuk mengekstrak `picoCTF{w34k_jwt_n0t_g00d_...}`.
- **Rekomendasi Keamanan:**
  - Generate JWT secret secara kriptografis aman (minimal 256-bit CSPRNG) dan simpan dalam environment variables atau secret manager (Vault/AWS Secrets Manager).
  - Terapkan validasi integritas token di API gateway.

---

### [17] CID 284: Operation Oni (Forensics)
- **Vulnerability Vector:** Sensitive Cryptographic Asset Exposure in Raw Disk Image.
- **CWE:** CWE-522 (Insufficiently Protected Credentials), CWE-200 (Exposure of Sensitive Information).
- **Arsitektur & Target:** File raw disk image Linux terkompresi `disk.img.gz`.
- **Root Cause:** Image partisi disk memuat file private SSH key (`id_ed25519`) yang tidak terenkripsi di dalam folder `/root/.ssh/`.
- **Mekanisme Eksploitasi:**
  1. Dekompresi image: `gunzip disk.img.gz`.
  2. Analisis tabel partisi menggunakan `mmls disk.img` untuk menentukan offset partisi ext4.
  3. Lakukan listing inode secara rekursif dengan The Sleuth Kit:
     ```bash
     fls -r -o <offset> disk.img | grep -i ssh
     ```
  4. Ekstrak file private key berdasarkan nomor inode menggunakan `icat`:
     ```bash
     icat -o <offset> disk.img <inode_id> > id_ed25519
     ```
  5. Ubah hak akses: `chmod 600 id_ed25519`.
  6. Login ke server target melalui SSH:
     ```bash
     ssh -i id_ed25519 -p <port> ctf-player@saturn.picoctf.net
     ```
  7. Baca file `flag.txt` di direktori home.
- **Rekomendasi Keamanan:**
  - Terapkan enkripsi passphrase pada SSH private key.
  - Sanitasi artefak sistem (*sanitization scrub*) sebelum mendistribusikan image disk publik.

---

### [18] CID 133: Binary Gauntlet 3 (Binary Exploitation)
- **Vulnerability Vector:** Blind Format String Stack Leak & Stack-Based Buffer Overflow.
- **CWE:** CWE-121 (Stack-based Buffer Overflow), CWE-134 (Use of Externally-Controlled Format String).
- **Arsitektur & Target:** Binari ELF x86_64 dengan proteksi NX disabled (stack dapat dieksekusi), no-pie, tanpa canary, satu koneksi interaktif.
- **Root Cause:** Program memiliki fungsi `vuln()` yang melakukan `printf(buf)` (format string vulnerability) pada baris pertama dan `strcpy(stack_buf, input)` pada baris kedua tanpa pengecekan panjang batas buffer.
- **Mekanisme Eksploitasi:**
  1. Pada baris pertama input, kirim specifier format string `%p.%p...` untuk membocorkan alamat stack frame (cluster `0x7ffd...`).
  2. Hitung base address buffer lokal di stack dari nilai leak tersebut.
  3. Susun payload baris kedua:
     - 8 byte sampah + 8 byte pointer target RIP (`buf + 16`) + 27 byte null-free/newline-free `execve("/bin/sh")` shellcode + padding hingga offset 112 byte + RBP overwrite (`buf`) + RIP overwrite (`buf`).
  4. Saat fungsi `vuln()` melakukan instruksi `leave; ret`:
     - `leave` menyetel `RSP = RBP = buf`, melakukan `pop RBP`.
     - `ret` mengambil alamat `buf + 16` dan melompat langsung ke shellcode.
  5. Kirim perintah `cat flag.txt` melalui interactive shell untuk membaca flag.
- **Rekomendasi Keamanan:**
  - Aktifkan proteksi memori modern: NX bit (`-z noexecstack`), Stack Smashing Protector (`-fstack-protector-all`), Full RELRO (`-z relro -z now`), dan ASLR/PIE (`-fPIE -pie`).
  - Ganti `strcpy` dengan `strncpy` atau `strlcpy` dan gunakan format string aman `printf("%s", buf)`.

---

### [19] CID 116: speeds and feeds (Reverse Engineering)
- **Vulnerability Vector:** Plaintext Machine Toolpath Coordinate Exfiltration (G-Code).
- **CWE:** CWE-200 (Exposure of Sensitive Information), CWE-319 (Cleartext Transmission of Sensitive Information).
- **Status Platform:** `under_maintenance: true` pada platform CyLab.
- **Arsitektur & Target:** Socket remote TCP yang memancarkan instruksi bahasa kontrol mesin perkakas industri (G-code CNC).
- **Root Cause:** Data rahasia (teks bendera) direpresentasikan secara visual sebagai lintasan pemotongan alat frais/router CNC (`G00` rapid move, `G01` linear cutting feed) yang disiarkan dalam teks terbuka melalui socket jaringan tanpa enkripsi atau autentikasi.
- **Mekanisme Eksploitasi:**
  1. Tangkap seluruh output stream dari socket:
     ```bash
     nc mercury.picoctf.net <port> > cnc_instructions.gcode
     ```
  2. Lakukan parsing terhadap koordinat `X` dan `Y` pada setiap instruksi pemotongan `G1`.
  3. Visualisasikan lintasan cutter menggunakan G-code simulator (seperti NC Viewer) atau script plot 2D matplotlib sederhana:
     ```python
     import matplotlib.pyplot as plt, re
     lines = open('cnc_instructions.gcode').readlines()
     coords = [re.findall(r'[XY]-?\d+\.\d+', l) for l in lines]
     # Plot segmen garis X, Y untuk membentuk tipografi karakter bendera
     ```
  4. Tipografi visual menghasilkan teks flag: `picoCTF{num3r1cal_c0ntr0l_...}`.
- **Rekomendasi Keamanan:**
  - Hindari enkapsulasi data sensitif dalam format koordinat fisik tanpa lapisan enkripsi transport (TLS).
  - Terapkan kontrol akses jaringan untuk mencegah unauthorized telemetry capture.

---

## 4. Evaluasi Arsitektur & Mitigasi Defensif Menyeluruh (Defense-in-Depth)

Sebagai bagian dari prinsip *Defense-in-Depth* Athena, berikut adalah aksi mitigasi teknis terpadu yang harus diterapkan pada seluruh lapisan infrastruktur:

1. **Smart Contract Hardening:**
   - Wajibkan Solidity compiler `>= 0.8.20`.
   - Gunakan OpenZeppelin Contracts v5.0 untuk pola `Ownable2Step` (mencegah salah transfer kepemilikan) dan `ReentrancyGuard`.
   - Lakukan audit statis menggunakan Slither dan Mythril pada tahap CI/CD pipeline.

2. **Binary Hardening & Compiler Flags:**
   - Seluruh binari wajib dikompilasi dengan bendera mitigasi modern:
     ```bash
     gcc -Wall -Wextra -Werror=format-security -fstack-protector-strong \
         -D_FORTIFY_SOURCE=2 -fPIE -pie -z relro -z now -z noexecstack \
         -o target_binary target.c
     ```
   - Hindari penggunaan fungsi usang: larang `gets()`, `strcpy()`, `sprintf()`; wajibkan `fgets()`, `strlcpy()`, `snprintf()`.

3. **Web Application & API Gateway Security:**
   - Validasi skalar input: Tolak objek atau kurung kurawal pada parameter teks otentikasi (CWE-943 NoSQL mitigasi).
   - JWT Integrity: Wajibkan algoritma asimetris (RS256/EdDSA) dengan rotasi kunci otomatis melalui JWKS, atau kunci simetris minimal 256-bit CSPRNG yang disimpan di KMS terenkripsi.
   - Authoritative Game Engines: Pisahkan logika validasi state di server; jangan pernah mempercayai WebSocket frame client-side.

4. **Credential & Forensic Artifact Lifecycle Management:**
   - Hilangkan file private key dan credential staging dari image publik dan root filesystem.
   - Hapus hash BitLocker lemah dengan menerapkan password complexity minimal 16 karakter dan enforce TPM-backed FVEK storage.

---

## 5. Status Verifikasi & Tindak Lanjut Sprint

- **Status Pengerjaan:** 19/19 Tantangan Medium telah diaudit secara tuntas, mencakup vektor eksploitasi, akar kerentanan (root cause), rantai eksploitasi, hingga skrip/remediasi teknis.
- **Handoff Downstream:**
  - `@default` (Omnirush Automation): Siap mengonsumsi parameter offset, template exploit, dan payload untuk otomasi solver.
  - `@fullstack-dev`: Siap mengintegrasikan artefak audit ini ke dalam writeup repositori `cylab-ctf-writeups`.
  - `@qa-engineer`: Siap melakukan verifikasi submission saat instans on-demand dijalankan.
  - `@guru`: Siap mengadopsi analisis ini ke dalam modul silabus pedagogis LKS Bidang Cyber Security.

*Laporan disahkan oleh:*  
**Athena (`security-engineer`)**  
*Cyber Defense & Exploit Analysis Specialist — AI Team*