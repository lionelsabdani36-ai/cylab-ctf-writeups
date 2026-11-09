# 463 - Rust fixme 3 (General Skills, picoCTF 2025, Easy)

## Challenge Metadata
- ID: 463 | Event: picoCTF 2025
- Category: General Skills / Rust Unsafe Memory Semantics | Difficulty: Easy (1)
- Author: Taylor McCampbell
- Points: 100 Pts (CyLab) / 50 Pts (picoCTF)
- Flag: `academy{n0w_y0uv3_f1x3d_1h3m_411}`
- Standard Reference: NIST SP 800-115 §4.2, ISO/IEC 25010, Rust Reference §10.1, RFC 2580, CWE-119, CWE-787, CWE-125

## Problem Statement & Scope
Tantangan menyediakan arsip proyek Rust `fixme3.tar.gz` yang mengalami kesalahan sintaks dan batasan keamanan memori (*memory safety constraint violation*).
Deskripsi tantangan:
*"Have you heard of Rust? Fix the syntax errors in this Rust file to print the flag! Download the Rust code fixme3.tar.gz."*
Petunjuk:
- Hint 1: `Read the comments...darn it!`

Objektif pengujian (NIST SP 800-115 Section 4.2 Review of Source Code & Software Security Analysis):
Mengidentifikasi kegagalan kompilasi Rust (`error[E0133]`), menganalisis batasan arsitektur model kepemilikan (*ownership*) dan *borrow checker*, merekonstruksi blok `unsafe` pada pemanggilan primitif dereferensi raw pointer `std::slice::from_raw_parts`, mengompilasi program dengan `cargo run`, dan mengekstrak token bendera terdekripsi.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Model Keamanan Memori Rust & Garansi Static Analysis:**
   Rust dirancang untuk mengeliminasi kelas kerentanan memori tradisional (seperti *buffer overflow*, *use-after-free*, *double-free*, dan *data races*) pada waktu kompilasi (*compile-time*) tanpa overhead garbage collector runtime. Compiler menegakkan aturan ketat melalui *ownership*, *lifetime*, dan *borrow checker*.
2. **Konteks Operasi Unsafe Rust (Rust Reference §10.1):**
   Meskipun sebagian besar kode Rust berstatus *safe*, interaksi tingkat rendah seperti pemanggilan Foreign Function Interface (FFI C), dereferensi pointer mentah (`*const T` atau `*mut T`), dan transmute memori memerlukan izin eksplisit dari pengembang melalui blok `unsafe { ... }`.
3. **Penyebab Kegagalan Kompilasi (error[E0133]):**
   Pada berkas `src/main.rs`:
   ```rust
   // unsafe {
       let decrypted_buffer = xrc.decrypt_vec(encrypted_buffer);
       let decrypted_ptr = decrypted_buffer.as_ptr();
       let decrypted_len = decrypted_buffer.len();
       
       // Pemanggilan fungsi unsafe: dereferensi pointer mentah
       let decrypted_slice = std::slice::from_raw_parts(decrypted_ptr, decrypted_len);

       borrowed_string.push_str(&String::from_utf8_lossy(decrypted_slice));
   // }
   ```
   Fungsi `std::slice::from_raw_parts(ptr, len)` ditandai sebagai `unsafe fn` dalam pustaka standar Rust (`core::slice`). Compiler menuntut jaminan kontraktual bahwa `ptr` valid untuk pembacaan sebanyak `len * size_of::<T>()` byte, ter-align dengan benar, dan menunjuk ke memori yang diinisialisasi.
   Ketika baris komentar menonaktifkan pembungkus `unsafe { ... }`, compiler Rust menolak kode dengan diagnostik:
   `error[E0133]: call to unsafe function is unsafe and requires unsafe function or block`.

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Ekstraksi Arsip Proyek:
   ```bash
   tar -zxvf fixme3.tar.gz
   cd fixme3
   ```
2. Tahap 2 — Analisis Diagnostik Compiler:
   Menjalankan `cargo check` atau `cargo run` pada kode awal menghasilkan galat:
   ```text
   error[E0133]: call to unsafe function `std::slice::from_raw_parts` is unsafe and requires unsafe function or block
     --> src/main.rs:26:31
      |
   26 |         let decrypted_slice = std::slice::from_raw_parts(decrypted_ptr, decrypted_len);
      |                               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ call to unsafe function
   ```
3. Tahap 3 — Remediasi Sintaks & Enkapsulasi Blok Unsafe:
   Membuka tanda komentar pada baris `unsafe {` dan penutup `}`:
   ```rust
   unsafe {
       let decrypted_buffer = xrc.decrypt_vec(encrypted_buffer);
       let decrypted_ptr = decrypted_buffer.as_ptr();
       let decrypted_len = decrypted_buffer.len();
       let decrypted_slice = std::slice::from_raw_parts(decrypted_ptr, decrypted_len);
       borrowed_string.push_str(&String::from_utf8_lossy(decrypted_slice));
   }
   ```
4. Tahap 4 — Kompilasi & Eksekusi:
   Menjalankan `cargo run`:
   ```text
      Compiling rust_proj v0.1.0 (/tmp/fixme3)
       Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.42s
        Running `target/debug/rust_proj`
   Using memory unsafe languages is a: PARTY FOUL! Here is your flag: academy{n0w_y0uv3_f1x3d_1h3m_411}
   ```
5. Tahap 5 — Validasi REST API Platform:
   Mengirimkan flag melalui endpoint `POST /api/submissions/` dengan payload:
   `{"challenge": 463, "flag": "academy{n0w_y0uv3_f1x3d_1h3m_411}"}`.
   Respons platform: `HTTP 201 Created` (`correct: true`).

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{n0w_y0uv3_f1x3d_1h3m_411}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` mengembalikan status `HTTP 201 Created` (`correct: true`, user 1072359).
- Reproduktifitas Solver: Terverifikasi 100% via `scripts/solve_463_rust_fixme_3.py` (eksekusi instan deterministik).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Prinsip Minimalisasi Blok Unsafe:** Batasi penggunaan blok `unsafe` sekecil mungkin. Setiap blok unsafe harus memiliki dokumentasi alasan keselamatan (*safety comment*) yang menjelaskan mengapa invarian memori tetap terjaga.
- **Pencegahan Aliasing & Lifetime Invalidation:** Saat menggunakan `std::slice::from_raw_parts`, pastikan struktur data yang memiliki alokasi memori (seperti `decrypted_buffer`) tidak dibebaskan (*dropped*) atau dipindahkan (*moved*) selama irisan referensi (`decrypted_slice`) masih digunakan untuk mencegah *use-after-free* (CWE-416).
- **Adopsi Memory-Safe Languages dalam Arsitektur Kritis:** Menggunakan Rust untuk komponen sistem berisiko tinggi (parser jaringan, kriptografi, driver) memitigasi seluruh kelas kerentanan CWE-119, CWE-125, dan CWE-787 secara drastis dibandingkan bahasa C/C++ murni.
