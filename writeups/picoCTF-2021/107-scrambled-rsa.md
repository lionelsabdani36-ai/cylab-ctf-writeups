# Writeup: Scrambled: RSA (Challenge ID: 107)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Asymmetric Encryption Weaknesses & Block Shuffling Oracles
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 140
- **Author:** Sara
- **Flag:** `academy{bad_1d3a5_3525501}`

---

## Problem Statement & Scope
Tantangan `Scrambled: RSA` menghadirkan layanan interaktif berbasis jaringan melalui soket TCP:
```text
nc mercury.picoctf.net 4572
```
Saat terkoneksi, layanan mencetak:
1. Ciphertext teks rahasia (`flag: <deretan digit numerik panjang>`).
2. Parameter publik RSA: modulus $N$ dan eksponen publik $e = 65537$.
3. Prompt interaktif yang bersedia mengenkripsi teks masukan arbitrer apa pun yang dikirimkan oleh pengguna menggunakan kunci publik yang sama, namun dengan urutan output yang teracak (*scrambled*).

Tujuan pengujian teknis ini adalah menganalisis kelemahan struktural pada pemecahan blok pesan (*message chunking*), membuktikan determinisme per-karakter pada skema RSA tanpa padding standar, dan memulihkan teks terang flag rahasia secara sekuensial.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Pemecahan Blok Pesan pada Textbook RSA (CWE-327: Use of a Broken or Risky Cryptographic Algorithm):**
   Pada implementasi standar RSA yang aman (PKCS#1 v2.1 / RFC 8017), seluruh pesan dienkripsi sebagai satu kesatuan blok tunggal menggunakan skema *Optimal Asymmetric Encryption Padding* (OAEP) yang mengintegrasikan keacakan dinamis (*probabilistic encryption*).
   
   Pada tantangan ini, implementasi melakukan kesalahan fatal:
   - Pesan tidak dienkripsi secara menyeluruh, melainkan dipecah menjadi karakter-karakter individual.
   - Setiap karakter dienkripsi secara independen ke dalam blok berukuran tetap.
   - Pembuat tantangan mencoba menyembunyikan sifat deterministik ini dengan mengacak urutan blok (*random shuffling*) sebelum menggabungkannya ke dalam satu string tunggal.

2. **Ketergantungan Representasi terhadap Prefix (Prefix-Dependent Determinism):**
   Meskipun urutan blok diacak, representasi terenkripsi $R_i(c)$ dari suatu karakter $c$ pada indeks posisi $i$ bersifat deterministik terhadap string prefix sebelumnya:
   $$R_i(c) = \text{Encrypt}(c \mid \text{prefix}[:i])$$
   - Mengenkripsi string sepanjang 1 karakter (`'a'`) selalu menghasilkan 1 blok unik statis.
   - Mengenkripsi string `'ab'` menghasilkan 2 blok: representasi `'a'` (posisi 0) dan representasi `'b'` (posisi 1 dengan prefix `'a'`), dengan posisi blok yang tertukar secara acak.
   - Karena himpunan blok dari `prefix` telah diketahui sebelumnya, blok baru yang muncul pada ciphertext `E(prefix + c)` dapat diisolasi secara deterministik melalui selisih multiset (*multiset difference*):
     $$\Delta = \text{Multiset}(E(\text{prefix} + c)) \setminus \text{Multiset}(E(\text{prefix}))$$

3. **Dekonstruksi Ruang Pencarian (Oracle State Recovery):**
   Karena ciphertext flag server memuat multiset blok yang dihasilkan dari algoritma yang sama, keberadaan $\Delta$ di dalam multiset blok ciphertext flag membuktikan secara konklusif bahwa karakter $c$ adalah karakter asli yang menduduki posisi tersebut pada teks rahasia.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Output Awal & Penentuan Lebar Blok:**
   Kirimkan string satu karakter `enc("a")` ke server. Panjang respons menentukan lebar blok tetap ($W$ digit desimal).
   Pisahkan ciphertext flag menjadi kumpulan blok diskret:
   ```python
   width = len(enc("a"))
   flag_blocks = [flag_ct[i:i + width] for i in range(0, len(flag_ct), width)]
   ```

2. **Inisialisasi Prefix Acuan:**
   Format flag standar picoCTF selalu diawali dengan substring:
   $$\text{prefix} = \text{"picoCTF\{"}$$
   Ekstraksi representasi blok yang sesuai untuk karakter-karakter awal pada prefix ini dan simpan ke dalam daftar `known_reps`.

3. **Penyusunan Iterasi Pencarian Karakter Berikutnya:**
   Selama karakter terakhir `prefix` belum mencapai tanda kurung kurawal tutup `}`:
   - Untuk setiap karakter kandidat $c \in \Sigma$ (`a-z, 0-9, \_, dsb`):
     - Kirim query enkripsi untuk string: `cand = prefix + c`.
     - Pecah output menjadi multiset blok.
     - Hapus seluruh blok yang sudah tercatat dalam `known_reps`.
     - Blok tunggal yang tersisa merepresentasikan karakter $c$ pada posisi saat ini.
     - Jika blok tersebut terdapat di dalam `flag_blocks`:
       - Tambahkan $c$ ke dalam `prefix`: $\text{prefix} \leftarrow \text{prefix} + c$.
       - Simpan blok baru tersebut ke dalam `known_reps`.
       - Hentikan loop kandidat dan lanjutkan ke posisi karakter berikutnya.

4. **Eksekusi Pemulihan Teks Terang:**
   Skrip mengeksekusi pencarian secara sekuensial dan memulihkan teks karakter demi karakter:
   ```text
   picoCTF{ -> picoCTF{b -> picoCTF{ba -> picoCTF{bad -> picoCTF{bad_1 -> ... -> picoCTF{bad_1d3a5_3525501}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{bad_1d3a5_3525501}`
- **Native Platform Flag:** `picoCTF{bad_1d3a5_3525501}`
- **Status Solver:** Teruji dan terverifikasi penuh melalui modul solver reproduktif deterministik `scripts/solve_107_scrambled_rsa.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Kepatuhan Terhadap Standar Skema Enkripsi Asimetris FIPS / PKCS:**
   Sesuai NIST SP 800-56B Rev. 2 (*Recommendation for Pair-Wise Key-Establishment Schemes Using Integer Factorization Cryptography*), enkripsi asimetris RSA tidak boleh diterapkan langsung pada data mentah (*textbook RSA*) atau dipecah menjadi karakter individual.
   
2. **Penerapan Padding Kriptografis Terverifikasi (RSA-OAEP):**
   Seluruh implementasi RSA wajib menggunakan skema padding **RSA-OAEP** (*Optimal Asymmetric Encryption Padding*) dengan fungsi hash SHA-256 dan MGF1. RSA-OAEP menambahkan elemen keacakan dinamis (*probabilistic padding*) sehingga mengenkripsi pesan identik berkali-kali menghasilkan ciphertext yang sama sekali berbeda (*IND-CCA2 secure*), mencegah serangan pencocokan kamus (*dictionary lookup*) dan saluran sampingan multiset.
