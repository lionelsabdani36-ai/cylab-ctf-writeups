# Printer Shares (Challenge 759, General Skills)

- **ID:** 759 | **Event:** picoCTF 2026 | **Kategori:** General Skills / Network File Sharing (SMB) | **Level:** Easy
- **Flag:** `academy{5mb_pr1nter_5h4re5_80a1eed5}` (terverifikasi writeup batch awal)

## Skenario
File penting terkirim tak sengaja ke printer jaringan. Target lab on-demand
`xebec.cylabacademy.net:41504`. Petunjuk: pahami protokol SMB; `smbclient`
dan `smbutil` alat yang tepat.

## Root Cause
SMB (Server Message Block, MS-SMB2) mengekspos share disk `shares` dengan
akses Guest/Anonymous. Tanpa autentikasi, siapa pun di jaringan dapat
mendaftar share dan mengunduh isinya. Miskonfigurasi: share publik tanpa
pembatasan identitas pada layanan print server (Samba 4.19.5-Ubuntu).

## Rekonstruksi
1. Daftar share publik: `smbclient -L //xebec.cylabacademy.net -p 41504 -N`
   → share `shares` (Public Share With Guests) + `IPC$`.
2. Unduh isi: `smbclient //host/shares -p 41504 -N -c "recurse ON; prompt OFF; mget *"`
   → `dummy.txt` + `flag.txt`.
3. `cat flag.txt` → flag. Otomasi: `python3 scripts/solve_759_printer_shares.py [host] [port]`.
4. Submit `POST /api/submissions/` → correct (saat instance RUNNING).

## Mitigasi
Nonaktifkan akses Guest (`map to guest = never`), wajibkan autentikasi
SMB signing, batasi share ke grup printer saja, audit berkala
`smbclient -L` dari sisi penyerang, segmentasi VLAN printer.

## Takeaway LKS
Klasifikasi General Skills: enumerasi layanan jaringan + penyalahgunaan
konfigurasi default. Pola yang sama muncul di CTF forensik jaringan dan
materi Defensive: hardening share dan monitoring akses anonim.
