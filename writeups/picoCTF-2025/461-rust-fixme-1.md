# 461 - Rust fixme 1 (General Skills, picoCTF 2025, Easy)

## Challenge Metadata
- ID: 461 | Event: picoCTF 2025
- Category: General Skills / Rust Basic Syntax | Difficulty: Easy (1)
- Author: Taylor McCampbell
- Points: 100 Pts (CyLab) / 50 Pts (picoCTF)
- Flag: `academy{4r3_y0u_4_ru$t4c30n_n0w?}`
- Standard Reference: NIST SP 800-115 §4.2, ISO/IEC 25010, Rust Reference §8.1, std::fmt Macro Formatting, CWE-843, CWE-704

## Problem Statement & Scope
Tantangan menyediakan berkas arsip proyek Rust `fixme1.tar.gz` yang tidak dapat dikompilasi akibat sejumlah kesalahan sintaks dasar, terminator statemen, dan pemformatan makro.
Deskripsi tantangan:
*"Have you heard of Rust? Fix the syntax errors in this Rust file to print the flag! Download the Rust code fixme1.tar.gz."*
Petunjuk:
- Hint 1: `Cargo is Rust's package manager and will make your life easier. See the getting started page here.`
- Hint 2: `println!`
- Hint 3: `Rust has some pretty great compiler error messages. Read them maybe?`

Objektif pengujian (NIST SP 800-115 Section 4.2 Review of Source Code & Software Security Analysis):
Menganalisis pohon sintaks abstrak (AST) dan kesalahan kompilasi pada program Rust (`rustc`), mengidentifikasi baris tanpa terminator titik koma (`;`), kesalahan penulisan kata kunci kontrol alur eksekusi (`ret;` vs `return;`), serta malformasi format specifier makro pencetakan standar (`println!`), memperbaiki galat tersebut, mengompilasi program dengan `cargo run`, dan memvalidasi token bendera melalui REST API platform CyLab Academy.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur Pernyataan & Ekspresi Rust (Rust Reference §8.1):**
   Rust adalah bahasa berbasis ekspresi (*expression-oriented*). Dalam Rust, setiap pernyataan (*statement*) yang tidak mengembalikan nilai akhir untuk dievaluasi dalam sebuah blok wajib diakhiri dengan tanda titik koma (`;`). Ketiadaan titik koma menyebabkan compiler mencoba menggabungkan token berikutnya sebagai bagian dari ekspresi, yang memicu galat sintaks *unexpected token*.
2. **Kontrol Alur Eksekusi & Kata Kunci Return:**
   Rust menggunakan kata kunci `return` untuk pengembalian nilai eksplisit atau keluar lebih awal (*early return*) dari sebuah fungsi. Menggunakan singkatan seperti `ret;` tidak dikenali oleh parser karena tidak terdapat pengenal (*identifier*) bernama `ret` di dalam skop lokal maupun pustaka standar, memicu `error[E0425]: cannot find value ret in this scope`.
3. **Format Macro Invariants (std::fmt / println!):**
   Makro `println!` di Rust memvalidasi string pemformatan pada saat kompilasi (*compile-time format string validation*). Karakter placeholder parameter harus berupa kurung kurawal `{}` (untuk trait `Display`) atau `{:?}` (untuk trait `Debug`). Melewatkan string literal mentah `":?"` tanpa kurung kurawal menyebabkan compiler menolak argumen kedua karena dianggap tidak pernah digunakan (*argument never used*).

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Ekstraksi Arsip Proyek:
   ```bash
   tar -zxvf fixme1.tar.gz
   cd fixme1
   ```
2. Tahap 2 — Analisis Diagnostik Compiler Rust:
   Menjalankan `cargo check` pada kode sumber awal menghasilkan tiga kesalahan kompilasi:
   ```text
   error: expected `;`, found keyword `let`
    --> src/main.rs:5:37
     |
   5 |     let key = String::from("CSUCKS") // How do we end statements in Rust?
     |                                     ^ help: add `;` here

   error: argument never used
    --> src/main.rs:26:9
     |
   25 |         ":?", // How do we print out a variable in the println function? 
     |         ---- formatting specifier missing
   26 |         String::from_utf8_lossy(&decrypted_buffer)
     |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ argument never used

   error[E0425]: cannot find value `ret` in this scope
    --> src/main.rs:18:9
     |
   18 |         ret; // How do we return in rust?
     |         ^^^ help: a local variable with a similar name exists: `res`
   ```
3. Tahap 3 — Remediasi Sintaks & Makro:
   - Tambahkan titik koma pada deklarasi kunci: `let key = String::from("CSUCKS");`.
   - Perbaiki kata kunci return pada penanganan galat: `return;`.
   - Ubah string format makro `println!` menjadi `"{}"`:
   ```rust
   use xor_cryptor::XORCryptor;

   fn main() {
       let key = String::from("CSUCKS");

       let hex_values = [
           "71", "35", "11", "73", "2f", "17", "53", "71",
           "01", "1c", "7e", "59", "63", "e1", "61", "25",
           "7f", "5a", "60", "50", "11", "38", "1f", "3a",
           "60", "e9", "62", "20", "0c", "e6", "50", "d3", "35"
       ];

       let encrypted_buffer: Vec<u8> = hex_values.iter()
           .map(|&hex| u8::from_str_radix(hex, 16).unwrap())
           .collect();

       let res = XORCryptor::new(&key);
       if res.is_err() {
           return;
       }
       let xrc = res.unwrap();

       let decrypted_buffer = xrc.decrypt_vec(encrypted_buffer);
       println!(
           "{}", 
           String::from_utf8_lossy(&decrypted_buffer)
       );
   }
   ```
4. Tahap 4 — Kompilasi & Eksekusi:
   Menjalankan `cargo run`:
   ```text
      Compiling rust_proj v0.1.0 (/tmp/fixme1)
       Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.38s
        Running `target/debug/rust_proj`
   academy{4r3_y0u_4_ru$t4c30n_n0w?}
   ```
5. Tahap 5 — Validasi REST API Platform:
   Mengirimkan flag melalui endpoint `POST /api/submissions/` dengan payload:
   `{"challenge": 461, "flag": "academy{4r3_y0u_4_ru$t4c30n_n0w?}"}`.
   Respons platform: `HTTP 201 Created` (`correct: true`, historical: false).

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{4r3_y0u_4_ru$t4c30n_n0w?}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` mengembalikan status `HTTP 201 Created` (`correct: true`, user 1072359).
- Reproduktifitas Solver: Terverifikasi 100% via `scripts/solve_461_rust_fixme_1.py` (eksekusi instan deterministik).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Validasi Compile-Time Terhadap Format String:** Berbeda dari bahasa C (`printf`) di mana format string yang tidak cocok memicu kerentanan kritis *Format String Vulnerability* (CWE-134) yang dapat mengekspos memori stack atau menulis ke arbitrary address via `%n`, Rust memvalidasi seluruh format string pada waktu kompilasi. Jika argumen dan placeholder tidak cocok, program menolak untuk dikompilasi secara deterministik.
- **Pemanfaatan Komprehensif Diagnostik Compiler:** Compiler Rust memberikan penjelasan mendalam serta opsi penjelasan detail via `rustc --explain <E_CODE>`. Membiasakan membaca diagnostik kompilasi secara analitis merupakan modalitas esensial dalam kompetisi LKS Cyber Security bidang software quality assurance dan secure programming.
- **Konsistensi Penanganan Kesalahan (Error Handling):** Penggunaan konstruksi `Result<T, E>` dan penanganan cabang `if res.is_err()` mengajarkan disiplin penanganan kesalahan defensif tanpa membiarkan aplikasi crash tiba-tiba saat parsing buffer input eksternal.
