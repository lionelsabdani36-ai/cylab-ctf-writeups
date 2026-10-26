# Writeup: Rust fixme 3 (Challenge ID: 463)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Rust Unsafe Memory Semantics
- **Difficulty:** Easy
- **Author:** Taylor McCampbell
- **Event:** picoCTF 2025
- **Points:** 100
- **Flag:** `academy{n0w_y0uv3_f1x3d_1h3m_411}`

---

## Deskripsi Tantangan
> Have you heard of Rust? Fix the syntax errors in this Rust file to print the flag!
> Download the Rust code `fixme3.tar.gz`.
> Hints:
> 1. Read the comments...darn it!

---

## Analisis Kerentanan & Konsep Teknis
Rust dirancang dengan jaminan keamanan memori tingkat tinggi melalui model *ownership* dan *borrow checker*. Namun, untuk berinteraksi dengan memori perangkat keras tingkat rendah, FFI C, atau manipulasi pointer mentah (*raw pointer*), Rust menyediakan blok `unsafe`.

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
Fungsi `std::slice::from_raw_parts` bertanda `unsafe` karena compiler Rust tidak dapat memvalidasi apakah pointer yang dilewatkan valid, teralokasi, atau bebas dari aliasing yang melanggar aturan. Menghilangkan pembungkus `unsafe { ... }` menyebabkan compiler menolak proses build (`error[E0133]: call to unsafe function is unsafe and requires unsafe function or block`).

---

## Tahapan Eksploitasi & Solusi
1. Buka tanda komentar pada blok `unsafe {` dan tanda penutup `}` di sekitar pemanggilan `std::slice::from_raw_parts`.
2. Kompilasi dan jalankan program menggunakan `cargo`:
   ```bash
   cd fixme3
   cargo run
   ```
3. Program berhasil didekripsi dan mencetak keluaran:
   ```text
   Using memory unsafe languages is a: PARTY FOUL! Here is your flag: academy{n0w_y0uv3_f1x3d_1h3m_411}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Minimalisasi Blok Unsafe:** Blok `unsafe` dalam Rust harus diisolasi ke dalam abstraksi aman terkecil yang teruji dengan cermat (sound abstractions).
- **Integritas Pointer:** Saat memanggil `std::slice::from_raw_parts`, pengembang wajib memverifikasi bahwa pointer tidak null, ter-align dengan benar, dan masa hidup memori penyangga sumber (`decrypted_buffer`) tidak dibebaskan sebelum irisan selesai digunakan.
