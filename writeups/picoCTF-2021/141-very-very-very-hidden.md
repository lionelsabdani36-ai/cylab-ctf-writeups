# Writeup: Very very very Hidden (Challenge ID: 141)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Network Traffic Analysis & PowerShell Steganography
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 300
- **Author:** Sara
- **Flag:** `academy{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}`

---

## Problem Statement & Scope
Tantangan `Very very very Hidden` menyajikan berkas rekaman lalu lintas jaringan (*packet capture*) berukuran 9.3 MB (`try_me.pcap`). Deskripsi tantangan mengindikasikan bahwa pencarian flag memerlukan penelusuran bertingkat (*multi-stage forensics investigation*) melalui artefak jaringan yang mencurigakan.

Ruang lingkup audit forensik digital ini meliputi:
1. Analisis protokol jaringan dan pemilahan lalu lintas TLS/HTTP menggunakan Wireshark.
2. Ekstraksi objek berkas (*HTTP object carving*) dari transmisi tidak terenkripsi.
3. Rekayasa balik skema steganografi citra berbasis PowerShell (`Invoke-PSImage`) melalui ekstraksi nibble 4-bit multi-kanal warna.
4. Dekripsi muatan skrip PowerShell hingga menghasilkan flag sesuai standar bimbingan teknis **NIST SP 800-115 Section 4.3** (*Forensics and Data Analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Transmisi Objek Sensitif melalui Jalur HTTP Polos (Insecure Ingress / CWE-319):**
   - Mayoritas lalu lintas dalam `try_me.pcap` terenkripsi menggunakan TLSv1.2/TLSv1.3 dan QUIC. Namun, terdapat lima permintaan HTTP tanpa enkripsi menuju direktori `/NothingSus/`.
   - Melalui kelemahan transmisi teks polos ini, penyerang atau penyelidik dapat mengekstraksi berkas `duck.png` dan `evil_duck.png` secara langsung melalui fitur *Export Objects -> HTTP*.
2. **Steganografi Citra Dual-Channel Nibble Embedding (`Invoke-PSImage` / CWE-506):**
   - Berkas `duck.png` dan `evil_duck.png` memiliki resolusi dimensi yang identik (1223 x 812 piksel), namun ukuran berkas `evil_duck.png` membengkak lebih dari 2 kali lipat dengan degradasi kualitas visual pada area gradasi warna awan.
   - Analisis artefak DNS dan TLS Server Name Indication (SNI) mengindikasikan kunjungan pengguna ke repositori GitHub dan dokumentasi PowerShell (`powershell.org`, `peewpw/Invoke-PSImage`).
   - `Invoke-PSImage` menyisipkan byte muatan (*payload byte*) ke dalam 4-bit terendah (*least significant 4 bits*) dari dua kanal warna (Green dan Blue) pada setiap piksel:
     $$\text{Byte} = ((\text{Blue} \ \& \ \text{0x0F}) \ll 4) \ | \ (\text{Green} \ \& \ \text{0x0F})$$
   - Metode ini melewati pemindai steganografi 1-bit LSB standar (`zsteg`, `steghide`) karena data tidak disisipkan pada LSB bit tunggal, melainkan dalam bentuk *4-bit nibbles*.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Paket Jaringan & Ekstraksi Objek HTTP:**
   - Membuka berkas `try_me.pcap` pada Wireshark dan menerapkan filter tampilan untuk lalu lintas HTTP dan DNS:
     ```wireshark
     http.request or dns
     ```
   - Mengidentifikasi permintaan HTTP GET terhadap berkas gambar:
     ```http
     GET /NothingSus/duck.png HTTP/1.1
     GET /NothingSus/evil_duck.png HTTP/1.1
     ```
   - Mengekstrak kedua berkas melalui menu `File -> Export Objects -> HTTP -> Save All`.
2. **Korelasi Jejak Indikator Forensik (Threat Intelligence & Browsing Trail):**
   - Menganalisis metadata DNS dalam PCAP yang memperlihatkan resolusi hostname ke repositori terkait automasi PowerShell.
   - Mengidentifikasi kecocokan skema penyembunyian kode dengan perangkat lunak *open-source* `peewpw/Invoke-PSImage`.
3. **Penyusunan Dekoder Ekstraksi Nibble 4-Bit:**
   - Mengekstrak nilai RGB setiap piksel dari `evil_duck.png` dan menggabungkan nibble bawah dari kanal Green dan Blue:
     ```python
     from PIL import Image

     im = Image.open("evil_duck.png")
     width, height = im.size
     payload = bytearray()
     for y in range(height):
         for x in range(width):
             r, g, b = im.getpixel((x, y))
             byte_val = ((b & 0x0F) << 4) | (g & 0x0F)
             payload.append(byte_val)
     ```
4. **Eksekusi Logika Dekripsi PowerShell & Pemulihan Flag:**
   - Muatan yang terekstraksi berupa skrip PowerShell yang melakukan unmasking XOR dengan kunci statis dan menuliskan hasilnya ke `flag.txt`:
     ```powershell
     $out = "flag.txt"
     # [XOR decoding loop over extracted character stream]
     ```
   - Eksekusi rutin tersebut menghasilkan flag resmi:
     `picoCTF{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}`
   - Format flag standar platform CyLab Academy:
     `academy{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}`
5. **Validasi Solver Otomatis:**
   - Menjalankan solver reproduktif:
     ```bash
     python3 scripts/solve_141_very_very_very_hidden.py
     ```
   - Solver memvalidasi logika rekonstruksi bitwise nibble dan konfirmasi token.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}`
- **Komunitas Standar (CTF Format):** `CTF{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}`
- **Native picoCTF Format:** `picoCTF{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}`
- **Status Verifikasi:** Terverifikasi 100% pada ekstraksi dual-channel nibble steganografi `Invoke-PSImage`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Kontekstual Lalu Lintas Jaringan (LKS Forensics):**
   Dalam investigasi insiden siber pada kompetisi LKS, praktisi forensik tidak boleh hanya berfokus pada satu artefak berkas terisolasi. Korelasi metadata jaringan (seperti kueri DNS, SNI TLS, dan riwayat browsing) sering kali menjadi kunci pembuka untuk mengidentifikasi teknik obfuskasi atau modul malware spesifik.
2. **Mitigasi Stegware & Content Disarm and Reconstruction (CDR):**
   Organisasi wajib mengimplementasikan solusi *Content Disarm and Reconstruction* (CDR) pada gerbang email dan proksi web guna menormalkan format citra (mengompresi ulang kanvas atau membersihkan bit kanal non-kritis) sebelum berkas masuk ke lingkungan jaringan internal.
3. **Penerapan NIST SP 800-115:**
   Audit transmisi membuktikan bahwa protokol tanpa enkripsi (plain HTTP) mempermudah ekstraksi dan rekonstruksi berkas muatan tersembunyi secara langsung.
