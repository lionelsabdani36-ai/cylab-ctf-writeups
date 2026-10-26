# Writeup: Commitment Issues (Challenge ID: 411)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Git Diff & Revision Analysis
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 50
- **Flag:** `academy{s@n1t1z3_21c298e5}`

---

## Problem Statement & Scope
Diberikan repositori Git `drop-in/`. Pengembang mengaku tidak sengaja menuliskan flag pada berkas teks, kemudian segera menghapusnya pada commit berikutnya dan menganggap data rahasia tersebut sudah aman.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Retensi Snapshot Berkas Git:** Sistem kontrol versi dirancang untuk menjaga riwayat mutasi berkas secara persisten. Operasi `git commit` yang menghapus baris teks hanya menambahkan commit baru yang mencatat delta penghapusan, tanpa menghapus blob objek asal dari database Git (`.git/objects/`).
2. **Kekeliruan Asumsi Deletion:** Menghapus berkas atau baris teks dalam commit lanjutan tidak menghilangkan data historis dari cabang repositori.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Masuk ke direktori repositori:
   ```bash
   cd drop-in
   ```
2. Tampilkan patch perubahan penuh lintas commit menggunakan `git log -p`:
   ```bash
   git log -p
   ```
3. Commit `fac6593923abc511b5eb5a214edf2019fb8e7c5a` ("remove sensitive info") menampilkan baris merah (penghapusan):
   ```diff
   diff --git a/message.txt b/message.txt
   index 7571590..d552d1e 100644
   --- a/message.txt
   +++ b/message.txt
   @@ -1 +1 @@
   -academy{s@n1t1z3_21c298e5}
   +TOP SECRET
   ```
4. Dapatkan flag dari baris diff yang dihapus.

---

## Flag & Verifikasi
- **Flag:** `academy{s@n1t1z3_21c298e5}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Bahaya Shallow Sanitization:** Menghapus kunci kriptografi atau password dari kode sumber lalu melakukan push commit "remove password" adalah celah fatal incident response. Penyerang cukup menjalankan `git diff` atau `git log -p` untuk mengambil kunci lama.
- **SOP Insiden Leak Kredensial:** Setiap kali kredensial tersentuh oleh Git dan dipublikasikan, kredensial tersebut harus dianggap telah disusupi (*compromised*). Lakukan pencabutan (revocation) dan pergantian kunci (rotation) seketika, bukan sekadar menghapus teksnya di repositori.
