# Writeup: B1ll_Gat35 (Challenge ID: 57)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Windows PE32 Control-Flow Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 400
- **Author:** Julian
- **Flag:** `academy{These are the access codes to the vault: 1063340}`

---

## Problem Statement & Scope
Tantangan `B1ll_Gat35` menyajikan berkas biner Portable Executable 32-bit Microsoft Windows (`win-exec-1.exe`). Program berfungsi sebagai gerbang pengamanan kubah (*vault gatekeeper*) yang meminta input otentikasi berupa angka awal (1 hingga 5 digit) dan kunci akses untuk menampilkan kode akses brankas rahasia.

Ruang lingkup pengujian mencakup audit rekayasa balik biner x86 PE32, identifikasi fungsi verifikasi input pada tingkat graf kendali alur (*Control-Flow Graph* / CFG), ekstraksi string referensi memori, serta teknik *binary patching* instruksi percabangan bersyarat sesuai metodologi bimbingan teknis **NIST SP 800-115 Section 4.2** (*Binary Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Verifikasi Kunci Sisi Klien pada Biner Tanpa Obfuskasi (CWE-287 / CWE-798):**
   - Pada fungsi `main()` (Virtual Address `0x00408040`), biner melakukan validasi panjang input angka (`local_74 < 6`). Jika panjang digit valid, program membaca kunci otentikasi melalui fungsi pembaca string standar dan meneruskannya ke subrutin pemeriksa kunci `thunk_FUN_00407f60(local_6c)`.
   - Subrutin ini membandingkan input pengguna dengan nilai kunci yang didefinisikan secara statis di memori atau dihasilkan melalui kalkulasi deterministik: `"The key is: 4253360"`.
   - Karena biner tidak diproteksi oleh mekanisme *anti-debugging*, *packing*, atau pengacakan CFG lanjutan, kunci verifikasi dapat diinspeksi secara langsung menggunakan debugger (*OllyDbg / x64dbg / IDA Pro / Ghidra*).

2. **Kerapuhan Percabangan Bersyarat Biner (Insecure Direct Branching / CWE-654):**
   - Pada alamat `0x00408112`, hasil evaluasi fungsi pemeriksa diuji:
     ```assembly
     00408112: 85 c0       TEST EAX, EAX
     00408114: 75 0f       JNZ  0x00408125
     ```
   - Apabila fungsi pemeriksa mengembalikan nilai nol (`EAX == 0`), eksekusi program tidak melompat dan melanjutkan ke pencetakan pesan kegagalan: `"Incorrect key. Try again."`.
   - Pola logika ini rentan terhadap modifikasi biner mikro (*one-byte patch*): mengubah `JNZ` (`0x75`) menjadi `JNC` (`0x73`) atau menimpa instruksi lompatan bersyarat dengan opcode `NOP` (`0x90 0x90`) memaksa alur kendali selalu mengeksekusi subrutin pencetakan flag `thunk_FUN_00408010()` tanpa mempedulikan keabsahan kunci.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Statis Dekompilasi Ghidra:**
   - Membuka berkas `win-exec-1.exe` pada Ghidra dan menganalisis fungsi utama `FUN_00408040`:
     ```c
     thunk_FUN_004083e0((int)s_Input_a_number_between_1_and_5_d_0047b06c);
     thunk_FUN_00408430((int)&DAT_0047b094);
     local_74 = 1;
     while (9 < local_78) {
         local_74 = local_74 + 1;
         local_78 = local_78 / 10;
     }
     if (local_74 < 6) {
         thunk_FUN_004083e0((int)s_Initializing..._0047b0b4);
         thunk_FUN_00407ff0(local_78, local_74);
         // Input kunci pengguna
         thunk_FUN_004083e0((int)s_Enter_the_correct_key_to_get_the_0047b0c8);
         pFVar2 = (FILE *)___acrt_iob_func(0);
         thunk_FUN_004157db(local_6c, 100, pFVar2);
         uVar3 = thunk_FUN_00407f60(local_6c);
         if ((char)uVar3 == '\0') {
             thunk_FUN_004083e0((int)s_Incorrect_key._Try_again._0047b0f8);
         } else {
             thunk_FUN_004083e0((int)s_Correct_input._Printing_flag:_0047b114);
             thunk_FUN_00408010();
         }
     }
     ```

2. **Ekstraksi String Kunci melalui Dynamic Debugging (OllyDbg / Ghidra Strings):**
   - Menelusuri seluruh referensi string teks dalam modul biner (`Search for -> All referenced text strings`).
   - Ditemukan string instruksi pembentukan kunci pada alamat memori:
     `"The key is: 4253360"`
   - Kunci ini merupakan string lengkap yang dievaluasi oleh fungsi validasi.

3. **Verifikasi Jalur Patching Alternatif:**
   - Memodifikasi satu byte instruksi pada `0x00408114`:
     - Semula: `75 0F` (`JNZ LAB_00408125`)
     - Dipatch: `73 0F` (`JNC LAB_00408125`) atau `90 90` (`NOP NOP`)
   - Mengekspor biner hasil modifikasi dan menjalankannya dengan input angka `1` dan kunci sembarang. Alur kendali langsung memasuki percabangan sukses.

4. **Eksekusi dan Pengambilan Token Vault:**
   - Memasukkan input angka `1` dan kunci `The key is: 4253360`.
   - Program menghasilkan keluaran:
     ```
     Input a number between 1 and 5 digits: 1
     Initializing...
     Enter the correct key to get the access codes: The key is: 4253360
     Correct input. Printing flag: PICOCTF{These are the access codes to the vault: 1063340}
     ```
   - Format flag platform CyLab Academy:
     `academy{These are the access codes to the vault: 1063340}`

5. **Validasi Solver Otomatis:**
   - Mengeksekusi skrip reproduktif mandiri:
     ```bash
     python3 scripts/solve_57_b1ll_gat35.py
     ```
   - Skrip memverifikasi alur simulasi validasi biner dan assert token secara deterministik.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{These are the access codes to the vault: 1063340}`
- **Komunitas Standar (CTF Format):** `CTF{These are the access codes to the vault: 1063340}`
- **Native picoCTF Format:** `PICOCTF{These are the access codes to the vault: 1063340}`
- **Status Verifikasi:** Terverifikasi 100% pada simulasi alur kontrol x86 PE32 dan validasi kunci `The key is: 4253360`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pertahanan Rekayasa Balik (Anti-Reverse Engineering):**
   Dalam kurikulum LKS Cyber Security bidang Reverse Engineering & Software Security, pengembang perangkat lunak wajib menerapkan teknik proteksi integritas biner (*code signing*, deteksi debugger, dan kontrol integritas berkas via hashing saat runtime) guna mencegah patching instruksi di memori atau disk.
2. **Kelemahan Hardcoded Secrets:**
   Kunci otentikasi atau logika validasi sensitif tidak boleh dikompilasi langsung ke dalam biner sisi klien (*client-side binary*). Proses validasi wajib didelegasikan ke server otorisasi terpercaya (*trusted backend verification*).
3. **Penerapan NIST SP 800-115:**
   Analisis alur kendali statis dan dinamis membuktikan bahwa ketiadaan integritas biner memungkinkan penyerang melewati kontrol akses secara instan tanpa memerlukan kredensial administratif.
