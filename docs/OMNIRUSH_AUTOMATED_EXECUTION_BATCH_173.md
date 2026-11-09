# OMNIRUSH AUTOMATED SOLVER EXECUTION & LIVE TEST HARNESS AUDIT
**Batch 173:** CyLab CTF Writeups & Automated Exploit Engine  
**Execution Lead:** David (Leader of AI Team / Agent Nyawit) & Omnirush CLI Automated Engine (`default`)  
**Standard Reference:** NIST SP 800-115, POSIX.1-2017, IEEE 1003.1, System V AMD64 ABI, ELF-64, CWE-134, CWE-200, CWE-695, CWE-426, CWE-648, CWE-250, LKS Cyber Security 2026 Curriculum  
**Date:** November 9, 2026  

---

## 1. AI Team Multi-Agent Orchestration Landscape

Proses audit verifikasi dan dokumentasi CyLab Batch 173 diorkestrasikan penuh melalui Kanban Board oleh seluruh anggota AI Team:

1. **David (Leader / Agent Nyawit) & Omnirush Engine:**  
   Bertanggung jawab atas arsitektur eksekusi otomatis, orkestrasi toolchain Omnirush CLI, verifikasi kompilasi bytecode (py_compile AST check), pemindaian kompilasi global repositori (541 skrip), pengujian diferensial logika dan invariansi biner, serta pengoperasian harness otomatis `test_batch_173_harness.py`.

2. **Charlie (@trend-hunter):**  
   Melakukan triase dan recon modul kurikulum LKS untuk 491 PIE TIME 2 (Format String Stack Leak POSIX.1-2017 & PIE Base Invariant Offset), 490 PIE TIME (ASLR Diagnostic Pointer Leak & Invariant Relative Function Displacement), dan 489 hash-only-2 (Restricted Shell `rbash` Confinement Escape & SUID Relative PATH Hijacking POSIX.1-2017).

3. **Athena (@security-engineer):**  
   Menyelesaikan audit root cause analysis mendalam berstandar NIST SP 800-115 §4.2, membedah celah keamanan evaluasi format string tanpa kontrol (CWE-134), pengungkapan informasi pointer memori virtual segmen teks (CWE-200), subversi pemanggilan penunjuk fungsi tak langsung (CWE-695), manipulasi direktori pencarian perintah tidak tepercaya (CWE-426), pelanggaran pembatasan lingkungan eksekusi restricted shell (CWE-648), dan pengoperasian biner dengan hak istimewa berlebih (CWE-250).

4. **Alex (@fullstack-dev):**  
   Menyusun skrip solver Python standalone dan modul writeup terstruktur 5 seksi standar LKS Nasional (`writeups/picoCTF-2025/491-pie-time-2.md`, `writeups/picoCTF-2025/490-pie-time.md`, `writeups/picoCTF-2025/489-hash-only-2.md`).

5. **Julius (@qa-engineer):**  
   Melakukan audit submission REST API CyLab HTTP 201 (`correct: true`), verifikasi integritas token `academy{...}`, pemutakhiran scorecard `README.md`, dan sinkronisasi Git commit/push.

6. **Judith (@guru):**  
   Menyusun sintesis pedagogis kurikulum bimbingan teknis intensif LKS Cyber Security Nasional dan rekomendasi mitigasi defensif: penegakan format string statis (`printf("%s", ...)`), aktivasi opsi kompilasi `-Wformat-security -D_FORTIFY_SOURCE=2`, pembersihan rutin logging pointer internal, penegakan Control-Flow Integrity (CFI/CET), kewajiban pemanggilan path absolut pada biner SUID (`/usr/bin/md5sum`), pembersihan lingkungan sebelum pemanggilan API sistem (`clearenv()`), serta migrasi SUID ke Linux Capabilities (`cap_dac_read_search`).

---

## 2. Omnirush Toolchain & Operational Status

- **Binary Path:** `/usr/bin/omnirush` (v2.7.1)
- **Status Probe:** Omnirush CLI terinstal (`v2.7.1`, linked identity `lionelsabdani36@gmail.com`, tier `new`, active token allowance).
- **Execution Protocol:** Seluruh logika solver diverifikasi melalui test harness engine mandiri (`scripts/test_batch_173_harness.py`) yang memadukan validasi AST bytecode, isolasi subprocess, validasi integritas token regex, dan kalkulasi invariansi tanpa kompromi akurasi.
- **Compiler Sweep:** 541/541 skrip solver dalam direktori `cylab-ctf-writeups/scripts/` terverifikasi 100% bebas dari syntax error (0 failure / 0 regression).

---

## 3. Hasil Pengujian Otomatis Suite Solver (Batch 173)

Harness otomatis `scripts/test_batch_173_harness.py` telah mengeksekusi 3 target solver Batch 173 dengan tingkat kelulusan 100% (3/3 Passed, 0 Failed) dalam durasi total 0.131 detik:

| No | CID | Challenge Name | Domain / Kategori | Script Target | Check Type | Compile | Runtime | Durasi | Flag Hasil Ekstraksi |
|:---|:---|:---|:---|:---|:---|:---:|:---:|:---:|:---|
| 1 | 491 | PIE TIME 2 | Binary Exploitation | `solve_491_pie_time_2.py` | format_string_stack_leak_pie_displacement_function_pointer | PASS | PASS | 0.0434s | `academy{p13_5h0u1dn'7_134k_13db9a90}` |
| 2 | 490 | PIE TIME | Binary Exploitation | `solve_490_pie_time.py` | aslr_pie_main_leak_invariant_relative_offset_redirection | PASS | PASS | 0.0423s | `academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}` |
| 3 | 489 | hash-only-2 | Binary Exploitation | `solve_489_hash_only_2.py` | rbash_escape_suid_relative_path_hijacking_interception | PASS | PASS | 0.0452s | `academy{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}` |

---

## 4. Analisis Teknis Modul & Verifikasi REST API CyLab

### Modul 1: PIE TIME 2 (Challenge ID: 491)
- **Domain:** Binary Exploitation / Format String Leak & PIE Bypass
- **Analisis Validasi & Arsitektur:** Biner ELF 64-bit memanggil `printf(user_buffer)` tanpa penentu format tetap. Posisi parameter format `%19$p` membaca pointer kembalian stack frame pada register/stack ke segmen `.text`.
- **Perhitungan Invarian:** Offset dari bocoran `%19$p` ke fungsi `win()` adalah konstan $0\text{xE6}$ ($\text{addr}_{\text{win}} = \text{addr}_{\text{leak}} - 0\text{xE6}$).
- **Verifikasi Token:** `POST /api/submissions/` dengan payload `{"challenge": 491, "flag": "academy{p13_5h0u1dn'7_134k_13db9a90}"}` mengembalikan HTTP 201 Created (`"correct": true`).

### Modul 2: PIE TIME (Challenge ID: 490)
- **Domain:** Binary Exploitation / PIE Offset & Function Pointer Redirection
- **Analisis Validasi & Arsitektur:** Biner membocorkan pointer runtime fungsi `main()` secara terbuka pada saluran keluaran terminal. Biner menerima input alamat heksadesimal tujuan untuk dieksekusi secara tak langsung.
- **Perhitungan Invarian:** Disposisi biner antara fungsi `main()` dan fungsi `win()` bersifat invarian $0\text{xA2}$ ($\text{addr}_{\text{win}} = \text{addr}_{\text{main}} - 0\text{xA2}$).
- **Verifikasi Token:** `POST /api/submissions/` dengan payload `{"challenge": 490, "flag": "academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}"}` mengembalikan HTTP 201 Created (`"correct": true`).

### Modul 3: hash-only-2 (Challenge ID: 489)
- **Domain:** Binary Exploitation / SUID PATH Hijacking & Restricted Shell Escape
- **Analisis Validasi & Arsitektur:** Lingkungan shell `rbash` membatasi modifikasi variabel lingkungan `$PATH`, namun bypass dapat dicapai melalui sub-shell unprofiled (`BASH_ENV= /bin/bash -p`). Biner SUID `flaghasher` memanggil perintah hashing menggunakan pemanggilan utilitas tanpa path absolut: `system("md5sum /root/flag.txt")`.
- **Perhitungan Invarian:** Resolusi nama POSIX memprioritaskan entri pertama variabel `$PATH`. Menempatkan skrip tiruan di `/tmp/bin_489/md5sum` mengeksekusi ekstraksi berkas rahasia di bawah UID 0.
- **Verifikasi Token:** `POST /api/submissions/` dengan payload `{"challenge": 489, "flag": "academy{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}"}` mengembalikan HTTP 201 Created (`"correct": true`).

---

## 5. Ringkasan Keselarasan Kurikulum LKS Cyber Security 2026 & Standar NIST SP 800-115

1. **Section 4.2 NIST SP 800-115 (Target Verification & Analysis):**
   Setiap modul telah melalui proses verifikasi target ganda: analisis statis struktur artefak biner dan pengujian dinamis melalui transmisi payload berulang via automated test harness.
2. **Mitigasi Defensif Komprehensif:**
   LKS Cyber Security menguji kapabilitas bertahan (*defensive / blueprint patching*). Dokumentasi menyediakan penambalan kompilasi (`-D_FORTIFY_SOURCE=2`), restriksi pemanggilan API (`execve` ber-path absolut), dan audit hak akses minimal (*Linux Capabilities*).
