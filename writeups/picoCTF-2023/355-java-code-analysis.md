# Writeup: Java Code Analysis!?! (Challenge ID: 355)

- **Platform:** CyLab Security Academy (picoCTF 2023)
- **Category:** Web Exploitation
- **Difficulty:** Medium
- **Event:** picoCTF 2023
- **Flag:** `academy{w34k_jwt_n0t_g00d_d3a1bea8}`

---

## Problem Statement & Scope

Tantangan ini menyajikan aplikasi web Java Spring Boot bernama **BookShelf Pico**. Pengguna diberikan akses ke kode sumber aplikasi (`bookshelf-pico.zip`) dan sebuah instans container aktif. Aplikasi ini mengelola buku dengan kontrol akses berbasis peran (Role-Based Access Control / RBAC): peran *Free*, *Premium*, dan *Admin*. Buku flag hanya dapat diunduh oleh pengguna dengan peran `Admin`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Insecure JWT Secret Generation (CWE-330 / CWE-798):**
   Pada kelas `io.github.nandandesai.pico.security.SecretGenerator`, metode `generateRandomString` diimplementasikan secara statis tanpa entropi:
   ```java
   private String generateRandomString(int len) {
       // not so random
       return "1234";
   }
   ```
   Karena berkas `server_secret.txt` tidak ada secara bawaan di direktori `userdata`, aplikasi selalu menggunakan kunci HMAC statis `"1234"`.

2. **Broken Access Control & Privilege Escalation (CWE-285):**
   Endpoint `PATCH /base/users/role` hanya memeriksa apakah pemanggil memiliki klaim `hasAuthority('Admin')` di JWT dan ID pemanggil tidak sama dengan ID target:
   ```java
   @PreAuthorize("hasAuthority('Admin') and #userRoleRequest.id != authentication.principal.grantedAuthorities[0].userId")
   public void updateRole(UpdateUserRoleRequest userRoleRequest)
   ```
   Penyerang dapat membuat token JWT palsu (*forged token*) dengan `role: "Admin"` dan `userId: 9999`, menandatanganinya dengan kunci rahasia `"1234"`, lalu mengubah peran akun biasa menjadi `Admin`.

3. **Sensitive Data Exposure via Authorized Object Reference:**
   Setelah peran diperbarui di basis data, pengguna dapat mengunduh berkas PDF buku rahasia (`ID: 5`, berjudul `Flag`) via endpoint `GET /base/books/pdf/5`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance Kode Sumber:**
   Ekstraksi `bookshelf-pico.zip` mengungkap penggunaan JWT HMAC256 dan kunci rahasia statis `"1234"` di `SecretGenerator.java`.
2. **Pembuatan Token Admin Palsu:**
   Membuat payload JWT dengan atribut:
   - `iss`: `bookshelf`
   - `role`: `Admin`
   - `userId`: `9999`
   Ditandatangani menggunakan algoritma `HS256` dengan kunci `"1234"`.
3. **Eskalasi Hak Akses (Privilege Escalation):**
   Mengirim HTTP `PATCH /base/users/role` dengan header `Authorization: Bearer <forged_admin_token>` dan body `{"id": 1, "role": "Admin"}`.
4. **Pengunduhan Dokumen Flag:**
   Membuat token baru untuk `userId: 1` dengan `role: "Admin"`, lalu mengirim request `GET /base/books/pdf/5`.
5. **Ekstraksi Teks:**
   Membaca konten PDF menggunakan `pdftotext` untuk mendapatkan string flag resmi.

---

## Flag & Verifikasi

- **Flag:** `academy{w34k_jwt_n0t_g00d_d3a1bea8}`
- **Hasil Submission:**
  ```json
  {"user": 1072359, "challenge": 355, "flag": "academy{w34k_jwt_n0t_g00d_d3a1bea8}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Pembangkitan Kunci Kriptografis Berentropi Tinggi (CSPRNG):**
   Hindari segala bentuk fallback hardcoded pada generator rahasia. Gunakan `java.security.SecureRandom` untuk menghasilkan kunci minimal 256-bit (32 byte) secara kriptografis aman:
   ```java
   byte[] secretBytes = new byte[32];
   new SecureRandom().nextBytes(secretBytes);
   String secret = Base64.getEncoder().encodeToString(secretBytes);
   ```
2. **Penyimpanan Rahasia Terisolasi (Secrets Management):**
   Kunci rahasia penandatanganan token wajib diinjeksikan secara dinamis melalui environment variable atau modul pengelola rahasia (HashiCorp Vault, AWS Secrets Manager), dengan kebijakan rotasi kunci berkala.
3. **Validasi Kontrol Akses Bertingkat (Defense in Depth):**
   Operasi eskalasi peran sistem tidak boleh hanya bergantung pada pembacaan klaim stateless JWT sisi klien. Validasi wajib memverifikasi ulang status pengguna secara langsung pada entitas basis data aktif serta menerapkan otentikasi multifaktor (MFA) untuk operasi pengubahan privilese administratif.
