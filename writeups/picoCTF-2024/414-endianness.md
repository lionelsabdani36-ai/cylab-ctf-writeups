# Writeup: endianness (Challenge ID: 414)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Computer Architecture & Byte Ordering
- **Difficulty:** Easy
- **Author:** Nana Ama Atombo-Sackey
- **Event:** picoCTF 2024
- **Points:** 200
- **Flag:** `academy{3ndi4n_sw4p_su33ess_e14d0ec1}`

---

## Problem Statement & Scope
Disediakan kode sumber C (`flag.c`) dan sebuah layanan interaktif TCP. Peserta diminta menghitung representasi Little-Endian dan Big-Endian dari sebuah kata acak 5 huruf berbasis representasi nilai heksadesimal dari setiap karakter ASCII.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Endianness dalam Arsitektur Komputer:**
   - **Big-Endian:** Urutan byte paling signifikan (*Most Significant Byte / MSB*) disimpan di alamat memori terendah. Untuk representasi string, ini identik dengan urutan baca karakter asli dari kiri ke kanan.
   - **Little-Endian:** Urutan byte paling tidak signifikan (*Least Significant Byte / LSB*) disimpan di alamat memori terendah (arsitektur x86/x86_64). Untuk kata per byte, urutan byte dibalik (*reversed order*).
2. **Kesesuaian dengan Kode Sumber C:**
   Dalam `flag.c`, fungsi `find_little_endian` melakukan iterasi mundur:
   ```c
   for (size_t i = word_len; i-- > 0;) {
       snprintf(&little_endian[(word_len - 1 - i) * 2], 3, "%02X", (unsigned char)word[i]);
   }
   ```
   Sedangkan `find_big_endian` melakukan iterasi maju:
   ```c
   for (size_t i = 0; i < length; i++) {
       snprintf(&big_endian[i * 2], 3, "%02X", (unsigned char)word[i]);
   }
   ```

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Sambungkan ke layanan instance:
   ```bash
   nc chatelaine.cylabacademy.net 12817
   ```
2. Server mengirimkan kata tantangan acak, misalnya `hulzm`:
   - Huruf: `h` (0x68), `u` (0x75), `l` (0x6C), `z` (0x7A), `m` (0x6D).
3. Hitung representasi Little-Endian (urutan byte terbalik):
   $$\text{Reverse}(\text{"hulzm"}) = \text{"mzluh"} \rightarrow \text{6D 7A 6C 75 68} \rightarrow \text{6D7A6C7568}$$
4. Hitung representasi Big-Endian (urutan byte normal):
   $$\text{"hulzm"} \rightarrow \text{68 75 6C 7A 6D} \rightarrow \text{68756C7A6D}$$
5. Masukkan kedua nilai secara berturut-turut pada prompt program.
6. Server memverifikasi kecocokan dan menampilkan flag:
   ```text
   Correct Little Endian representation!
   Correct Big Endian representation!
   Congratulations! You found both endian representations correctly!
   Your Flag is: academy{3ndi4n_sw4p_su33ess_e14d0ec1}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{3ndi4n_sw4p_su33ess_e14d0ec1}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemahaman Tingkat Mesin untuk Binary Exploitation & Reverse Engineering:** Pengetahuan tentang Little-Endian sangat fundamental ketika menganalisis stack frame, memory dump, packing pointer alamat return address (`p32` / `p64`), dan decoding raw packet capture.
- **Standar Protokol Jaringan (Network Byte Order):** Protokol jaringan seperti TCP/IP menggunakan Big-Endian (*Network Byte Order*), sehingga fungsi konversi `htons()`, `htonl()`, `ntohs()`, dan `ntohl()` wajib digunakan saat membangun aplikasi jaringan lintas arsitektur CPU.
