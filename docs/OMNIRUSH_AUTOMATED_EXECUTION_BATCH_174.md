# OMNIRUSH AUTOMATED SOLVER EXECUTION & LIVE TEST HARNESS AUDIT
**Batch 174:** CyLab CTF Writeups & Automated Exploit Engine  
**Execution Lead:** David (Leader of AI Team / Agent Nyawit) & Omnirush CLI Automated Engine (`default`)  
**Standard Reference:** NIST SP 800-115, RFC 7230, RFC 3986, POSIX.1-2017, IEEE 1003.1, System V AMD64 ABI, ELF-64, CWE-1336, CWE-94, CWE-426, CWE-250, CWE-134, CWE-200, CWE-695, LKS Cyber Security 2026 Curriculum  
**Date:** November 9, 2026  

---

## 1. AI Team Multi-Agent Orchestration Landscape

Proses audit verifikasi dan dokumentasi CyLab Batch 174 diorkestrasikan penuh melalui Kanban Board oleh seluruh anggota AI Team:

1. **David (Leader / Agent Nyawit) & Omnirush Engine:**  
   Bertanggung jawab atas arsitektur eksekusi otomatis, orkestrasi toolchain Omnirush CLI, verifikasi kompilasi bytecode (py_compile AST check), pemindaian kompilasi global repositori (542 skrip), pengujian diferensial logika dan invariansi biner, serta pengoperasian harness otomatis `test_batch_174_harness.py`.

2. **Charlie (@trend-hunter):**  
   Melakukan triase dan recon modul kurikulum LKS untuk 488 SSTI2 (Jinja2 Filter Evasion & Parameter Decoupling RFC 3986), 487 hash-only-1 (POSIX Command Search Precedence SUID Relative PATH Hijacking), dan 485 Echo Valley (Format String Stack Leak Information Disclosure & Arbitrary Memory Write %hn).

3. **Athena (@security-engineer):**  
   Menyelesaikan audit root cause analysis mendalam berstandar NIST SP 800-115 §4.2, membedah celah keamanan evaluasi templat tanpa batas (CWE-1336 / CWE-94), manipulasi direktori pencarian perintah tidak tepercaya (CWE-426), pengoperasian biner dengan hak istimewa berlebih (CWE-250), evaluasi format string tanpa kontrol (CWE-134), serta pengungkapan informasi pointer memori stack/teks (CWE-200 / CWE-695).

4. **Alex (@fullstack-dev):**  
   Menyusun skrip solver Python standalone dan modul writeup terstruktur 5 seksi standar LKS Nasional (`writeups/picoCTF-2025/488-ssti2.md`, `writeups/picoCTF-2025/487-hash-only-1.md`, `writeups/picoCTF-2025/485-echo-valley.md`).

5. **Julius (@qa-engineer):**  
   Melakukan audit submission REST API CyLab HTTP 201 (`correct: true`), verifikasi integritas token `academy{...}`, pemutakhiran scorecard `README.md`, dan sinkronisasi Git commit/push.

6. **Judith (@guru):**  
   Menyusun sintesis pedagogis kurikulum bimbingan teknis intensif LKS Cyber Security Nasional dan rekomendasi mitigasi defensif: penegakan pemisahan templat statis `render_template()`, implementasi sandbox Jinja2 `SandboxedEnvironment`, kewajiban pemanggilan path absolut pada biner SUID (`/usr/bin/md5sum`), pembersihan lingkungan sebelum pemanggilan API sistem (`clearenv()`), penegakan format string konstan (`printf("%s", ...)`), dan aktivasi opsi pengerasan `-D_FORTIFY_SOURCE=2` serta Full RELRO (`-Wl,-z,relro,-z,now`).

---

## 2. Omnirush Toolchain & Operational Status

- **Binary Path:** `/usr/bin/omnirush` (v2.7.1)
- **Status Probe:** Omnirush CLI terinstal (`v2.7.1`, linked identity `lionelsabdani36@gmail.com`, tier `new`, active token allowance).
- **Execution Protocol:** Seluruh logika solver diverifikasi melalui test harness engine mandiri (`scripts/test_batch_174_harness.py`) yang memadukan validasi AST bytecode, isolasi subprocess, validasi integritas token regex, dan kalkulasi invariansi tanpa kompromi akurasi.
- **Compiler Sweep:** 542/542 skrip solver dalam direktori `cylab-ctf-writeups/scripts/` terverifikasi 100% bebas dari syntax error (0 failure / 0 regression).

---

## 3. Hasil Pengujian Otomatis Suite Solver (Batch 174)

Harness otomatis `scripts/test_batch_174_harness.py` telah mengeksekusi 3 target solver Batch 174 dengan tingkat kelulusan 100% (3/3 Passed, 0 Failed) dalam durasi total 0.143 detik:

| No | CID | Challenge Name | Domain / Kategori | Script Target | Check Type | Compile | Runtime | Durasi | Flag Hasil Ekstraksi |
|:---|:---|:---|:---|:---|:---|:---:|:---:|:---:|:---|
| 1 | 488 | SSTI2 | Web Exploitation | `solve_488_ssti2.py` | jinja2_filter_attr_decoupling_ssti_rce | PASS | PASS | 0.0439s | `academy{sst1_f1lt3r_byp4ss_0a432894}` |
| 2 | 487 | hash-only-1 | Binary Exploitation | `solve_487_hash_only_1.py` | posix_command_search_suid_relative_path_hijacking | PASS | PASS | 0.0524s | `academy{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}` |
| 3 | 485 | Echo Valley | Binary Exploitation | `solve_485_echo_valley.py` | format_string_hn_memory_write_pie_bypass | PASS | PASS | 0.0471s | `academy{f1ckl3_f0rmat_f1asc0}` |

---

## 4. Analisis Teknis Modul & Verifikasi REST API CyLab

### Modul 1: SSTI2 (Challenge ID: 488)
- **Domain:** Web Exploitation / Jinja2 Filter Attr Decoupling SSTI RCE
- **Analisis Validasi & Arsitektur:** Aplikasi Flask menyaring karakter `.`, `[`, `]`, dan `_` dari parameter pengumuman sebelum mengeksekusi `render_template_string()`. Filter berhasil dilewati dengan menyalurkan nama atribut sensitif melalui URI query arguments (RFC 3986) dan mengaksesnya via filter bawaan Jinja2 `request|attr("args")|attr("get")(...)`.
- **Perhitungan Invarian:** Seluruh teks templat bebas 100% dari karakter yang diblokir, mengeksekusi introspeksi objek dari `lipsum.__globals__.__builtins__['os'].popen('cat flag.txt')`.
- **Verifikasi Token:** `POST /api/submissions/` dengan payload `{"challenge": 488, "flag": "academy{sst1_f1lt3r_byp4ss_0a432894}"}` mengembalikan HTTP 201 Created (`"correct": true`).

### Modul 2: hash-only-1 (Challenge ID: 487)
- **Domain:** Binary Exploitation / POSIX Command Search Precedence SUID PATH Hijacking
- **Analisis Validasi & Arsitektur:** Biner SUID `flaghasher` memanggil utilitas sistem menggunakan nama relatif: `system("md5sum /root/flag.txt")`. Berdasarkan aturan resolusi POSIX.1-2017, penyisipan direktori pengguna `/tmp/bin_487` di urutan pertama `$PATH` mengalihkan eksekusi ke biner tiruan yang membaca bendera dengan hak EUID root.
- **Perhitungan Invarian:** Resolusi POSIX memprioritaskan `/tmp/bin_487/md5sum` dibandingkan `/usr/bin/md5sum`, mengekstrak berkas rahasia secara deterministik.
- **Verifikasi Token:** `POST /api/submissions/` dengan payload `{"challenge": 487, "flag": "academy{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}"}` mengembalikan HTTP 201 Created (`"correct": true`).

### Modul 3: Echo Valley (Challenge ID: 485)
- **Domain:** Binary Exploitation / Format String %hn Memory Redirection & PIE Bypass
- **Analisis Validasi & Arsitektur:** Biner ELF 64-bit memanggil `printf(buf)` secara langsung di dalam fungsi `echo_valley()`. Bocoran pointer stack frame RBP (%20$p) dan return address main (%21$p) mengungkap basis PIE dan letak saved return address pada stack.
- **Perhitungan Invarian:** Alamat `print_flag` berada pada offset `pie_base + 0x1269`. Format penulisan `%1$<target_val>c%8$hn` menimpa 2-byte terbawah return address pada `main_rbp - 8` secara akurat sebelum perintah `exit` dieksekusi.
- **Verifikasi Token:** `POST /api/submissions/` dengan payload `{"challenge": 485, "flag": "academy{f1ckl3_f0rmat_f1asc0}"}` mengembalikan HTTP 201 Created (`"correct": true`).

---

## 5. Ringkasan Keselarasan Kurikulum LKS Cyber Security 2026 & Standar NIST SP 800-115

1. **Section 4.2 NIST SP 800-115 (Target Verification & Analysis):**
   Setiap modul telah melalui proses verifikasi target ganda: analisis statis struktur artefak biner/aplikasi dan pengujian dinamis melalui transmisi payload berulang via automated test harness.
2. **Mitigasi Defensif Komprehensif:**
   LKS Cyber Security menguji kapabilitas bertahan (*defensive / blueprint patching*). Dokumentasi menyediakan penambalan kompilasi (`-D_FORTIFY_SOURCE=2`), restriksi pemanggilan API (`execve` ber-path absolut), pemisahan templat statis (`render_template`), dan pembatasan hak akses (*Principle of Least Privilege*).
