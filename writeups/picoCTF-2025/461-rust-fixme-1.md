# Writeup: Rust fixme 1 (Challenge ID: 461)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Rust Basic Syntax
- **Difficulty:** Easy
- **Author:** Taylor McCampbell
- **Event:** picoCTF 2025
- **Points:** 100
- **Flag:** `academy{4r3_y0u_4_ru$t4c30n_n0w?}`

---

## Deskripsi Tantangan
> Have you heard of Rust? Fix the syntax errors in this Rust file to print the flag!
> Download the Rust code `fixme1.tar.gz`.
> Hints:
> 1. Cargo is Rust's package manager and will make your life easier. See the getting started page here.
> 2. `println!`
> 3. Rust has some pretty great compiler error messages. Read them maybe?

---

## Analisis Kerentanan & Konsep Teknis
Tantangan pemula ini menguji pemahaman sintaks dasar dan penanganan galat kompilasi pada bahasa Rust:
1. **Penutup Statemen:** Pada baris inisialisasi kunci sandi, statemen tidak diakhiri dengan titik koma (`;`):
   ```rust
   let key = String::from("CSUCKS") // Error: expected `;`
   ```
2. **Kata Kunci Return:** Kesalahan ketik sintaksis pada pengembalian nilai kondisi:
   ```rust
   if res.is_err() {
       ret; // Error: cannot find value `ret` in this scope
   }
   ```
   Harus ditulis `return;`.
3. **Format Macro `println!`:** String format yang keliru:
   ```rust
   println!(
       ":?", // Error: format argument must be a string literal with `{}`
       String::from_utf8_lossy(&decrypted_buffer)
   );
   ```
   Format specifier yang benar adalah `{}` untuk trait `Display` atau `{:?}` untuk trait `Debug`.

---

## Tahapan Eksploitasi & Solusi
1. Perbaiki ketiga galat sintaksis pada berkas `src/main.rs`.
2. Jalankan kompilasi melalui `cargo`:
   ```bash
   cd fixme1
   cargo run
   ```
3. Program berhasil didekripsi dan menghasilkan token flag:
   ```text
   academy{4r3_y0u_4_ru$t4c30n_n0w?}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Pemanfaatan Kompiler Diagnostik:** Kompiler Rust (`rustc`) menyediakan pesan galat paling informatif di industri perangkat lunak dengan petunjuk baris, kode penjelasan (`rustc --explain E0000`), dan saran perbaikan otomatis. Membaca pesan diagnostik kompiler adalah keterampilan fundamental dalam pengujian perangkat lunak dan reverse engineering.
