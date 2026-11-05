# Writeup: Trivial Flag Transfer Protocol (Challenge ID: 103)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / TFTP Network Traffic Dissection & Steghide Steganography
- **Difficulty:** Medium (diff=2)
- **Author:** Danny
- **Event:** picoCTF 2021
- **Points:** 90
- **Flag:** `academy{h1dd3n_1n_pLa1n_51GHT_18375919}`

---

## Problem Statement & Scope

Tantangan menguji kemampuan analisis lalu lintas jaringan protokol transfer berkas sederhana (TFTP) dan steganografi media citra:
> *"Figure out how they moved the flag."*
> Artefak: `tftp.pcapng`
> Petunjuk: *What are some other ways to hide data?*

Peserta diberikan tangkapan paket berukuran sekitar 50 MB berformat PCAP Next Generation (`tftp.pcapng`). Analisis forensik jaringan diarahkan untuk mengidentifikasi berkas yang ditransfer via TFTP (UDP port 69), merekonstruksi dokumen instruksi terenkripsi/terobfuskasi, serta mengekstraksi data rahasia dari citra penampung menggunakan perkakas yang ditransfer di dalam jaringan.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kelemahan Trivial File Transfer Protocol (RFC 1350 / RFC 2347):**
   - TFTP dirancang untuk transfer file sederhana tanpa otentikasi, otorisasi, atau enkripsi transport data. Sesi dimulai melalui port UDP 69 dengan pesan *Read Request* (RRQ, opcode 1) atau *Write Request* (WRQ, opcode 2), kemudian dilanjutkan melalui *ephemeral port* menggunakan paket data (DATA, opcode 3) dan acknowledgment (ACK, opcode 4).
   - Mengacu pada standar NIST SP 800-115 (*Section 5.1: Network Discovery and Verification*), protokol warisan (*legacy protocols*) seperti TFTP rentan terhadap intersepsi penuh dan rekonstruksi berkas tanpa kehilangan integritas (CWE-319).

2. **Rantai Eksfiltrasi Multi-Layer & Steganografi LSB:**
   - Rekonstruksi aliran transfer file mengungkap beberapa artefak yang dipindahkan:
     1. `instructions.txt`: Berisi instruksi teks terobfuskasi ROT13:
        $$\texttt{GSGCQBRFAGRAPELCGBHEGENSSVPFBJRZHFGQVFTHVFRBHESYNTGENAFSRE...}$$
        Didekodekan menjadi:
        $$\texttt{TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN}$$
     2. `plan`: Berisi kelanjutan rencana:
        $$\texttt{VHFRQGURCEBTENZNAQUVQVGJVGU-QHRQVYVTRAPR.PURPXBHGGURCUBGBF}$$
        Didekodekan menjadi:
        $$\texttt{IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS}$$
     3. `program.deb`: Paket Debian resmi untuk utilitas steganografi biner `steghide` (versi 0.5.1-9.1).
     4. `picture1.bmp`, `picture2.bmp`, `picture3.bmp`: Tiga citra penampung (*cover image*).
   - Penggunaan kata sandi `DUEDILIGENCE` pada `picture3.bmp` dengan algoritma `steghide` (yang memodifikasi *least significant bits* dari koordinat warna piksel berdasarkan kunci Blowfish dan hash MD5 dari passphrase) menyembunyikan payload teks flag resmi:
     $$\text{Steghide Extract}(\texttt{picture3.bmp}, \texttt{DUEDILIGENCE}) \implies \texttt{academy\{h1dd3n\_1n\_pLa1n\_51GHT\_18375919\}}$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak PCAPNG:**
   ```bash
   wget https://challenge-files.cylabacademy.net/library/c867f9c01ef11f33b38ca48b413b5b9b3067891682c49225c0cc97c32bcb4082/tftp.pcapng
   ```

2. **Ekstraksi Sesi TFTP Menggunakan Skrip Python:**
   Membedah paket UDP dan menyatukan blok DATA (opcode 3):
   ```bash
   python3 scripts/solve_103_trivial_flag_transfer_protocol.py
   ```
   Berkas yang berhasil direkonstruksi:
   - `instructions.txt` (116 bytes)
   - `plan` (59 bytes)
   - `program.deb` (138,310 bytes)
   - `picture1.bmp`, `picture2.bmp`, `picture3.bmp`

3. **Dekode Instruksi Sandi ROT13:**
   - Instruksi awal: `TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN`
   - Dokumen plan: `IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS`
   - Kunci steganografi yang diidentifikasi: `DUEDILIGENCE`

4. **Ekstraksi Steganografi Menggunakan Steghide:**
   Mengekstraksi data tersembunyi dari ketiga citra bitmap:
   ```bash
   steghide extract -sf picture3.bmp -p "DUEDILIGENCE" -xf flag.txt -f
   cat flag.txt
   ```
   Output:
   ```
   academy{h1dd3n_1n_pLa1n_51GHT_18375919}
   ```

---

## Flag & Verifikasi

- **Flag:** `academy{h1dd3n_1n_pLa1n_51GHT_18375919}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 103, "flag": "academy{h1dd3n_1n_pLa1n_51GHT_18375919}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pencegahan Penggunaan Protokol TFTP Tanpa Pengawasan (Network Hardening):**
   - TFTP tidak boleh diekspos keluar atau diizinkan beroperasi di segmen jaringan produksi tanpa segmentasi VLAN ketat dan aturan *Stateful Firewall*.
   - Gantikan protokol TFTP dengan protokol terotentikasi dan terenkripsi seperti SFTP (SSH File Transfer Protocol) atau HTTPS API.
2. **Deteksi Anomali Steganografi & DLP (Data Loss Prevention):**
   - Transmisi berkas citra berukuran besar (BMP/PNG) yang tidak terkompresi merupakan salah satu vektor utama *covert channels* dan eksfiltrasi data.
   - Pasang Network Intrusion Detection System (NIDS seperti Suricata/Snort) untuk memonitor lalu lintas TFTP dan lakukan kompresi ulang atau re-encoding citra di gateway perimeter guna merusak struktur LSB bitstream tersembunyi.
