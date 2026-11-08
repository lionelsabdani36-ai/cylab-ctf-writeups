# Writeup: MY GIT (Challenge ID: 764)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Version Control Security (NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** Darkraicg492
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{1mp3rs0n4t4_g17_345y_f382bd68}`
- **Flag Komunitas:** `CTF{1mp3rs0n4t4_g17_345y_f382bd68}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman peserta terhadap arsitektur metadata sistem kontrol versi terdistribusi (Git) dan model pembuktian identitas (*commit provenance*):
> *"I have built my own Git server with my own rules!"*

Layanan menyajikan peladen Git kustom yang dapat diakses melalui protokol SSH (`ssh://git@HOST:PORT/git/challenge.git`). Repositori berisi instruksi dalam `README.md` yang menetapkan aturan kontrol akses: token flag hanya akan dilepaskan oleh skrip hook peladen apabila terdapat berkas `flag.txt` yang di-push oleh pengguna dengan identitas author `root <root@academy>`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

Eksploitasi berakar pada asumsi keliru mengenai batas kepercayaan (*trust boundary*) antara klien Git dan peladen:

1. **CWE-287 / Otentikasi Metadata Pengarang yang Lemah (Client-Controlled Author Metadata):**
   - Pada spesifikasi arsitektur Git standar, objek commit menyimpan metadata teks pengarang (*Author*) dan pembuat commit (*Committer*), yang mencakup nama, alamat surel, dan stempel waktu (*timestamp*).
   - Seluruh metadata ini dihasilkan secara lokal oleh klien Git berdasarkan konfigurasi lokal (`git config user.name` dan `git config user.email`) atau variabel lingkungan (`GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`).
   - Git sama sekali **tidak melakukan verifikasi kriptografis** terhadap identitas pengarang saat operasi commit dibuat, kecuali jika penandatanganan digital (*GPG/SSH commit signing*) diwajibkan secara eksplisit.

2. **CWE-347 / Kegagalan Verifikasi Tanda Tangan Kriptografis (Unverified Commit Signatures in Server Hooks):**
   - Skrip hook pada sisi peladen (seperti `pre-receive` atau `update`) hanya memeriksa kecocokan string (*string comparison*) dari header objek commit:
     $$\text{Author} \stackrel{?}{=} \text{"root <root@academy>"}$$
   - Karena hook tidak memeriksa keberadaan tanda tangan digital valid dari pasangan kunci publik terpercaya (*trusted keyring*), penyerang yang memiliki akses transportasi SSH generik dapat dengan bebas memalsukan identitas author (*commit impersonation*) tanpa memerlukan kredensial otentik dari pengguna `root`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Kloning Repositori Remote:**
   - Melakukan kloning repositori target melalui jalur SSH:
     ```bash
     git clone ssh://git@xebec.cylabacademy.net:34513/git/challenge.git
     cd challenge
     ```

2. **Pembuatan Artefak yang Diminta:**
   - Membuat berkas `flag.txt` sesuai instruksi README:
     ```bash
     echo "give me the flag" > flag.txt
     git add flag.txt
     ```

3. **Pemalsuan Identitas Pengarang Commit (*Inline Author Spoofing*):**
   - Membuat commit dengan menimpa konfigurasi author langsung pada baris perintah (`-c` flag):
     ```bash
     git -c user.name="root" -c user.email="root@academy" commit -m "Add flag.txt"
     ```
   - Memeriksa integritas metadata commit lokal:
     ```bash
     git log -1 --pretty=format:"Author: %an <%ae>"
     # Output: Author: root <root@academy>
     ```

4. **Pengiriman (*Push*) ke Peladen Remote:**
   - Mendorong commit ke branch utama peladen:
     ```bash
     git push origin master
     ```
   - Skrip hook peladen mendeteksi pengarang `root <root@academy>`, meloloskan validasi string, dan mencetak flag resmi pada keluaran respons push.
   - Skrip reproduktif: `scripts/solve_764_my_git.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{1mp3rs0n4t4_g17_345y_f382bd68}`
- **Format Flag Komunitas:** `CTF{1mp3rs0n4t4_g17_345y_f382bd68}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 764, "flag": "academy{1mp3rs0n4t4_g17_345y_f382bd68}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penegakan Penandatanganan Commit Kriptografis (Commit Signing Enforcement):**
   - Dalam kompetensi LKS Cyber Security bidang *DevSecOps* dan *Supply Chain Security*, integritas kode sumber wajib dijamin dengan penandatanganan digital berbasis GPG atau kunci SSH (`git config commit.gpgsign true`).
   - Pada peladen Git (GitHub, GitLab, Gitea, atau peladen Git internal), wajibkan aturan branch protection yang mewajibkan status *Signed Commits* dan tolak commit tanpa tanda tangan (*reject unsigned commits*).
2. **Validasi Provenance dan Hook Server-Side yang Ketat (CWE-287 / CWE-347 Remediation):**
   - Skrip hook `pre-receive` pada peladen Git harus memverifikasi tanda tangan kriptografis menggunakan utilitas `git verify-commit` terhadap keyring kunci publik pengembang terverifikasi.
   - Jangan pernah mengandalkan string teks `user.name` atau `user.email` sebagai penentu hak akses otorisasi (*authorization boundary*). Kaitkan identitas pengarang dengan identitas otentikasi lapisan transport (seperti sertifikat SSH atau akun OAuth/LDAP terautentikasi).
3. **Audit Jejak Rekam dan Integritas Pipeline CI/CD (NIST SP 800-115 §4.2):**
   - Seluruh pipeline otomatisasi CI/CD harus menginspeksi hash kriptografis dan tanda tangan commit sebelum memicu proses deployment ke lingkungan produksi, mencegah infiltrasi kode berbahaya akibat pemalsuan identitas committer (*supply-chain tampering*).
