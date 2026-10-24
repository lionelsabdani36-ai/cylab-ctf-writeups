# Writeup: Printer Shares (Challenge ID: 759)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Network File Sharing (SMB)
- **Difficulty:** Easy
- **Author:** Janice He
- **Event:** picoCTF 2026
- **Points:** 50
- **Flag:** `academy{5mb_pr1nter_5h4re5_80a1eed5}`

---

## Deskripsi Tantangan
> Oops! Someone accidentally sent an important file to a network printer—can you retrieve it from the print server?
> Target: `xebec.cylabacademy.net:41504`
> Hints: knowing how SMB protocol works would be helpful! smbclient and smbutil are good tools.

---

## Analisis & Eksploitasi SMB Anonymous Share
Protokol Server Message Block (SMB) digunakan untuk sharing file dan layanan print server di jaringan. Pada konfigurasi yang rentan, direktori share publik dapat diakses tanpa autentikasi (*Guest / Anonymous Access*).

### Langkah Enumerasi & Akses
1. **Listing Share Publik:**
   ```bash
   smbclient -L //xebec.cylabacademy.net -p 41504 -N
   ```
   *Output:*
   ```text
   Sharename       Type      Comment
   ---------       ----      -------
   shares          Disk      Public Share With Guests
   IPC$            IPC       IPC Service (Samba 4.19.5-Ubuntu)
   ```

2. **Mengunduh Berkas dari Share:**
   ```bash
   smbclient //xebec.cylabacademy.net/shares -p 41504 -N -c "ls; mget *"
   ```
   *Ditemukan dua file:* `dummy.txt` dan `flag.txt`.

3. **Membaca Flag:**
   ```bash
   cat flag.txt
   ```
   *Isi:* `academy{5mb_pr1nter_5h4re5_80a1eed5}`

Flag: `academy{5mb_pr1nter_5h4re5_80a1eed5}`.
