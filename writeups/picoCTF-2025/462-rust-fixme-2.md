# 462 - Rust fixme 2 (General Skills, picoCTF 2025, Easy)

## Challenge Metadata
- ID: 462 | Event: picoCTF 2025
- Category: General Skills / Rust Borrowing & Mutability | Difficulty: Easy (1)
- Author: Taylor McCampbell
- Points: 100 Pts (CyLab) / 50 Pts (picoCTF)
- Flag: `academy{4r3_y0u_h4v1n5_fun_y31?}`
- Standard Reference: NIST SP 800-115 §4.2, ISO/IEC 25010, Rust Reference §8.2.2, RFC 2094, CWE-843, CWE-662

## Problem Statement & Scope
Tantangan menyediakan arsip proyek Rust `fixme2.tar.gz` yang mengalami kesalahan peminjaman memori (*borrow checker violation*) dan inkonsistensi tipe referensi mutable.
Deskripsi tantangan:
*"The Rust saga continues? I ask you, can I borrow that, pleeeeeaaaasseeeee? Download the Rust code fixme2.tar.gz."*
Petunjuk:
- Hint 1: `https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html`

Objektif pengujian (NIST SP 800-115 Section 4.2 Review of Source Code & Software Security Analysis):
Menganalisis kegagalan kompilasi Rust (`error[E0596]` dan `error[E0308]`), mengkaji aturan sistem peminjaman (*borrowing*) dan mutabilitas Rust, merekonstruksi deklarasi referensi mutable (`&mut String`) pada parameter fungsi dan pemanggilnya (`&mut party_foul`), mengompilasi program dengan `cargo run`, serta memvalidasi token bendera melalui REST API platform CyLab Academy.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Model Kepemilikan & Sistem Peminjaman Rust (Rust Reference §8.2.2):**
   Rust menjamin keamanan memori dan kebebasan dari kondisi perlombaan data (*data races*) melalui aturan ketat sistem peminjaman:
   - Sebuah variabel secara default bersifat *immutable* (tidak dapat diubah nilainya).
   - Referensi yang dipinjam secara default bertipe referensi immutable (`&T`), yang hanya mengizinkan pembacaan data.
   - Apabila suatu fungsi perlu memodifikasi data yang dimiliki oleh konteks lain tanpa mengambil alih kepemilikannya (*transfer of ownership*), fungsi tersebut harus menerima referensi bertipe mutable (`&mut T`).
   - Aturan invariants Rust menegaskan: dalam satu lingkup cakupan (*scope*), hanya diizinkan satu referensi mutable ATAU sejumlah referensi immutable berapapun, tetapi tidak keduanya secara bersamaan (aturan *aliasing XOR mutability*).
2. **Penyebab Kegagalan Kompilasi (error[E0596] & error[E0308]):**
   Pada berkas `src/main.rs`:
   ```rust
   fn decrypt(encrypted_buffer: Vec<u8>, borrowed_string: &String) {
       // ...
       borrowed_string.push_str("PARTY FOUL! Here is your flag: "); // Mutasi buffer
       // ...
       borrowed_string.push_str(&String::from_utf8_lossy(&decrypted_buffer));
       println!("{}", borrowed_string);
   }

   fn main() {
       // ...
       let party_foul = String::from("Using memory unsafe languages is a: ");
       decrypt(encrypted_buffer, &party_foul);
   }
   ```
   - Parameter `borrowed_string` dideklarasikan sebagai referensi immutable: `&String`. Metode `.push_str()` membutuhkan referensi mutable (`&mut self`). Compiler menolak kode dengan pesan:
     `error[E0596]: cannot borrow *borrowed_string as mutable, as it is behind a & reference`.
   - Di sisi lain, pada fungsi `main()`, variabel `party_foul` dideklarasikan dengan `let party_foul` (immutable binding) dan dilewatkan sebagai `&party_foul` (immutable reference). Memperbaiki tanda tangan fungsi menjadi `&mut String` tanpa mengubah pemanggilnya memicu galat:
     `error[E0308]: mismatched types: expected &mut String, found &String`.

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Ekstraksi Arsip Proyek:
   ```bash
   tar -zxvf fixme2.tar.gz
   cd fixme2
   ```
2. Tahap 2 — Analisis Diagnostik Compiler Rust:
   Menjalankan `cargo check` pada kode awal menghasilkan diagnostik compiler:
   ```text
   error[E0596]: cannot borrow `*borrowed_string` as mutable, as it is behind a `&` reference
    --> src/main.rs:9:5
     |
   9 |     borrowed_string.push_str("PARTY FOUL! Here is your flag: ");
     |     ^^^^^^^^^^^^^^^ `borrowed_string` is a `&` reference, so the data it refers to cannot be borrowed as mutable
   ```
3. Tahap 3 — Remediasi Mutabilitas & Peminjaman:
   - Pada definisi fungsi `decrypt`: ubah `borrowed_string: &String` menjadi `borrowed_string: &mut String`.
   - Pada inisialisasi variabel di `main`: ubah `let party_foul` menjadi `let mut party_foul`.
   - Pada pemanggilan fungsi: ubah `decrypt(encrypted_buffer, &party_foul)` menjadi `decrypt(encrypted_buffer, &mut party_foul)`.
   ```rust
   use xor_cryptor::XORCryptor;

   fn decrypt(encrypted_buffer: Vec<u8>, borrowed_string: &mut String) {
       let key = String::from("CSUCKS");
       borrowed_string.push_str("PARTY FOUL! Here is your flag: ");
       let res = XORCryptor::new(&key);
       if res.is_err() {
           return;
       }
       let xrc = res.unwrap();
       let decrypted_buffer = xrc.decrypt_vec(encrypted_buffer);
       borrowed_string.push_str(&String::from_utf8_lossy(&decrypted_buffer));
       println!("{}", borrowed_string);
   }

   fn main() {
       let hex_values = ["71", "35", "11", "73", "2f", "17", "53", "71", "01", "1c", "7e", "59", "63", "e1", "61", "25", "0d", "c4", "60", "f2", "12", "a0", "18", "03", "51", "03", "36", "05", "0e", "f9", "42", "5b"];
       let encrypted_buffer: Vec<u8> = hex_values.iter()
           .map(|&hex| u8::from_str_radix(hex, 16).unwrap())
           .collect();

       let mut party_foul = String::from("Using memory unsafe languages is a: ");
       decrypt(encrypted_buffer, &mut party_foul);
   }
   ```
4. Tahap 4 — Kompilasi & Eksekusi:
   Menjalankan `cargo run`:
   ```text
      Compiling rust_proj v0.1.0 (/tmp/fixme2)
       Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.35s
        Running `target/debug/rust_proj`
   Using memory unsafe languages is a: PARTY FOUL! Here is your flag: academy{4r3_y0u_h4v1n5_fun_y31?}
   ```
5. Tahap 5 — Validasi REST API Platform:
   Mengirimkan flag melalui endpoint `POST /api/submissions/` dengan payload:
   `{"challenge": 462, "flag": "academy{4r3_y0u_h4v1n5_fun_y31?}"}`.
   Respons platform: `HTTP 201 Created` (`correct: true`, historical: false).

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{4r3_y0u_h4v1n5_fun_y31?}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` mengembalikan status `HTTP 201 Created` (`correct: true`, user 1072359).
- Reproduktifitas Solver: Terverifikasi 100% via `scripts/solve_462_rust_fixme_2.py` (eksekusi instan deterministik).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemberantasan Data Races pada Waktu Kompilasi:** Aturan peminjaman Rust (hanya boleh ada satu peminjam mutable pada satu waktu) menjamin secara formal bahwa pembacaan dan penulisan bersamaan (*concurrent read-write*) pada alamat memori yang sama mustahil terjadi. Ini memitigasi kerentanan konkurensi (CWE-662).
- **Prinsip Immutability by Default:** Menjadikan immutability sebagai nilai baku (*default*) meminimalisir efek samping (*side effects*) yang tidak diinginkan dalam alur kerja rekayasa perangkat lunak, mempermudah pelacakan mutasi status data, dan mencegah korupsi memori.
- **Keterampilan Debugging Compiler Diagnostik pada LKS:** Pesan kesalahan compiler modern memberikan jalur perbaikan langsung (*compiler hints*). Peserta kompetisi LKS Cyber Security dituntut mampu membaca saran compiler secara presisi guna memperbaiki logika kode dalam batas waktu kompetisi yang ketat.
