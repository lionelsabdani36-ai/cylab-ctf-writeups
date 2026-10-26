# Writeup: Rust fixme 2 (Challenge ID: 462)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Rust Borrowing & Mutability
- **Difficulty:** Easy
- **Author:** Taylor McCampbell
- **Event:** picoCTF 2025
- **Points:** 100
- **Flag:** `academy{4r3_y0u_h4v1n5_fun_y31?}`

---

## Deskripsi Tantangan
> The Rust saga continues? I ask you, can I borrow that, pleeeeeaaaasseeeee?
> Download the Rust code `fixme2.tar.gz`.
> Hints:
> 1. https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html

---

## Analisis Kerentanan & Konsep Teknis
Salah satu pilar keamanan memori Rust adalah sistem peminjaman (*borrowing*):
1. Variabel secara default bersifat *immutable* (tidak dapat diubah).
2. Jika sebuah fungsi bermaksud memodifikasi nilai yang dipinjam, referensi harus bertipe referensi *mutable* (`&mut T`).
3. Variabel sumber yang akan dipinjam secara mutable juga harus dideklarasikan secara eksplisit dengan kata kunci `mut`.

Pada kode awal `src/main.rs`:
```rust
fn decrypt(encrypted_buffer:Vec<u8>, borrowed_string: &String){
    ...
    borrowed_string.push_str("PARTY FOUL! Here is your flag: "); // Error: cannot borrow immutable reference as mutable
}

fn main() {
    ...
    let party_foul = String::from("Using memory unsafe languages is a: ");
    decrypt(encrypted_buffer, &party_foul); // Error: expected `&mut String`, found `&String`
}
```
Kompilasi gagal dengan `error[E0596]: cannot borrow *borrowed_string as mutable` dan `error[E0308]: mismatched types`.

---

## Tahapan Eksploitasi & Solusi
1. Ubah parameter fungsi penerima menjadi `borrowed_string: &mut String`.
2. Ubah deklarasi variabel di fungsi `main` menjadi `let mut party_foul = ...`.
3. Lewatkan referensi mutable saat pemanggilan fungsi: `decrypt(encrypted_buffer, &mut party_foul);`.
4. Kompilasi dan eksekusi dengan `cargo`:
   ```bash
   cd fixme2
   cargo run
   ```
5. Output yang dihasilkan:
   ```text
   Using memory unsafe languages is a: PARTY FOUL! Here is your flag: academy{4r3_y0u_h4v1n5_fun_y31?}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Pencegahan Data Races pada Tingkat Bahasa:** Aturan peminjaman Rust (hanya boleh ada satu referensi mutable ATAU beberapa referensi immutable dalam satu waktu) secara matematis mengeliminasi potensi kondisi perlombaan data (*data race*) pada eksekusi konkurensi multi-threaded.
