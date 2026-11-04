# 424 - Super SSH (General Skills, picoCTF 2024, Easy)

## Challenge Metadata
- ID: 424 | Event: picoCTF 2024
- Category: General Skills | Difficulty: Easy (1)
- Author: CyLab Academy / picoCTF
- Points: 100 Pts
- Flag: `academy{s3cur3_c0nn3ct10n_a827223e}`

## Problem Statement & Scope
Tantangan menguji pemahaman operasional Secure Shell (SSH) untuk administrasi sistem jarak jauh secara aman.
Deskripsi menyatakan:
*"Using a Secure Shell (SSH) is going to be pretty important. Can you `ssh` as `ctf-player` to `xebec.cylabacademy.net` at port `32798` to get the flag? You'll also need the password `647e170e`. If asked, accept the fingerprint with `yes`."*

Objektif pengujian (NIST SP 800-115 / MITRE ATT&CK T1021.004 Remote Services: SSH):
Memverifikasi fungsionalitas remote terminal access berbasis OpenSSH, parameter port non-standar, mekanisme pertukaran host key (ED25519), serta otomatisasi sesi terminal non-interaktif untuk membaca output MOTD/banner sesi secara tepat.

## Teori & Analisis Arsitektur Layanan
1. **Arsitektur Protokol OpenSSH (RFC 4251 - RFC 4254):**
   Protokol SSH-2 mengamankan komunikasi jarak jauh melalui tiga layer utama:
   - *Transport Layer Protocol* (RFC 4253): Menyediakan enkripsi simetris, integritas pesan (MAC), dan autentikasi host server melalui kunci publik ED25519/RSA.
   - *User Authentication Protocol* (RFC 4252): Memvalidasi identitas klien ke server menggunakan kata sandi (`password authentication`) atau pasangan kunci publik-privat.
   - *Connection Protocol* (RFC 4254): Melakukan multiplexing kanal terenkripsi ke dalam sesi shell interaktif, forwarding TCP, atau transfer berkas SFTP.
2. **Handling Non-Standard Port & StrictHostKeyChecking:**
   Klien OpenSSH secara default menghubungi port `22/TCP`. Ketika server dijalankan pada port ephemeral yang dialokasikan dinamis (seperti port `32798`), opsi `-p <port>` harus didefinisikan secara eksplisit.
   Dalam otomatisasi CI/CD atau script reproduktif headless tanpa alokasi TTY, flag `-o StrictHostKeyChecking=no` dan `-o UserKnownHostsFile=/dev/null` mencegah proses terhenti menunggu konfirmasi interaktif host fingerprint.
3. **Session Banner & Message of the Day (MOTD):**
   Setelah proses otentikasi kata sandi berhasil diselesaikan oleh PAM / SSH daemon, sistem mengeksekusi script login shell atau menampilkan MOTD yang memuat token rahasia flag sebelum memulai loop shell.

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Probing Status & Inisiasi Lab:
   - Memeriksa status endpoint on-demand melalui CyLab REST API: `GET /api/challenges/424/instance/`.
   - Mengaktifkan kontainer dengan metode `PUT /api/challenges/424/instance/`.
   - Menerima rincian endpoint koneksi: host `xebec.cylabacademy.net`, port `32798`, user `ctf-player`, pass `647e170e`.
2. Tahap 2 — Koneksi Remote SSH:
   - Melakukan eksekusi koneksi remote terenkripsi menggunakan utility `sshpass` untuk otomasi password login:
     ```bash
     sshpass -p '647e170e' ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -p 32798 ctf-player@xebec.cylabacademy.net
     ```
   - Server memvalidasi kredensial dan mencetak banner sambutan:
     ```text
     Welcome ctf-player, here's your flag: academy{s3cur3_c0nn3ct10n_a827223e}
     ```
3. Tahap 3 — Validasi Flag & Terminasi Sesi:
   - Mengirim token flag ke REST API platform: `POST /api/submissions/` dengan payload:
     `{"challenge": 424, "flag": "academy{s3cur3_c0nn3ct10n_a827223e}"}`.
   - Respons platform: `HTTP 201 Created` (`correct: true`, user 1072359).
   - Mengirim permintaan `DELETE /api/challenges/424/instance/` untuk membersihkan kontainer lab secara bersih.

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{s3cur3_c0nn3ct10n_a827223e}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created (`correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Disable Password Authentication:** Pada konfigurasi produksi server Linux, selalu nonaktifkan otentikasi kata sandi (`PasswordAuthentication no` pada `/etc/ssh/sshd_config`) dan wajibkan penggunaan autentikasi Public Key berbasis Ed25519.
- **Root Login Restriction:** Larang login langsung sebagai pengguna superuser dengan parameter `PermitRootLogin no`.
- **Brute-Force & Rate Limiting Defense:** Terapkan perlindungan brute-force seperti `fail2ban` atau socket rate limiting pada firewall (iptables/nftables) untuk menangkal serangan credential stuffing otomatis.
- **Port Security & Bastion Host:** Tempatkan layanan administratif SSH di balik Virtual Private Network (VPN) atau Zero Trust Network Access (ZTNA) alih-alih mengekspos port secara langsung ke internet publik.
