# 483 - YaraRules0x100 (General Skills / Malware Analysis, picoCTF 2025, Medium)

## Challenge Metadata
- ID: 483 | Event: picoCTF 2025 | Author: Nandan Desai
- Category: Threat Intelligence / Malware Analysis | Difficulty: Medium (2) | Points: 200
- Flag: `academy{yara_rul35_r0ckzzz_3fd2bd06}`

---

## Problem Statement & Scope
Tim InfoSec mendeteksi berkas biner Windows mencurigakan (`suspicious.exe`) pada salah satu PC karyawan. Berkas tersebut berhasil melewati sistem deteksi intrusi (IDS) karena belum terdaftar dalam basis data signature. Analis ditugaskan untuk melakukan rekayasa balik (reverse engineering) pada berkas tersebut, mengidentifikasi perilaku mencurigakan dan teknik obfusikasi yang digunakan, serta menyusun aturan deteksi YARA yang tangguh.

Aturan YARA yang diajukan diuji secara otomatis oleh sistem evaluasi backend terhadap **64 skenario pengujian** (3 sampel malware positif yang mencakup versi *packed*, *unpacked*, dan mutasi fungsional; serta 61 sampel biner bersih/benign). Kriteria keberhasilan: lolos 100% tanpa adanya *False Negative* maupun *False Positive*.

---

## Teori & Analisis Malware
1. **Analisis Header & Kompresi Biner (UPX Packing):**
   Pemeriksaan awal menggunakan utilitas `file` dan `strings`:
   ```bash
   file suspicious.exe
   # suspicious.exe: PE32 executable for MS Windows 6.00 (GUI), Intel i386, UPX compressed, 3 sections
   ```
   Biner diproteksi menggunakan kompresi UPX versi 4.21. Header seksi menunjukkan seksi `UPX0`, `UPX1`, dan `.rsrc`.
   Proses dekompresi dilakukan menggunakan:
   ```bash
   upx -d -o unpacked.exe suspicious.exe
   # 40960 <- 26624 (65.00%) win32/pe unpacked.exe
   ```

2. **Analisis Perilaku & Anti-Analisis (Anti-Debugging & Process Termination):**
   Melalui analisis string UTF-16LE (*wide strings*) dan impor API Win32 pada berkas `unpacked.exe`, ditemukan beberapa rantai fungsi ofensif/defensif:
   - **Eskalasi Hak Istimewa Token:**
     Malware meminta hak istimewa `SeDebugPrivilege` menggunakan kombinasi API:
     - `OpenProcessToken`
     - `LookupPrivilegeValueW`
     - `AdjustTokenPrivileges`
   - **Pencarian & Enumerasi Proses Host:**
     Malware membuat snapshot proses sistem untuk mengidentifikasi keberadaan debugger atau proses pemantau:
     - `CreateToolhelp32Snapshot`
     - `Process32FirstW` / `Process32NextW`
   - **Pemberantasan Debugger (Anti-Analysis / Process Killing):**
     Jika debugger terdeteksi, malware mencoba melampirkan debugger aktif atau menghentikan proses:
     - `DebugActiveProcess` / `DebugActiveProcessStop`
     - `TerminateProcess`
   - **Pemeriksaan Status Debugging:**
     - `IsDebuggerPresent`
     - `NtQueryInformationProcess`

3. **Tantangan Penyusunan Signature YARA (Trade-off Deteksi):**
   - Jika hanya menggunakan string statis biasa (misal pesan dialog atau nama program), modifikasi biner (*compiler variation* atau penggantian teks) akan menyebabkan *False Negative*. Selain itu, string tertentu dapat memicu *False Positive* pada program sah.
   - Pada berkas terkompresi (UPX), sebagian besar string dan kode fungsi berada dalam bentuk terkompresi dan terenkripsi sederhana, sehingga fungsi `CreateToolhelp32Snapshot` atau `DebugActiveProcess` tidak dapat dibaca langsung dalam bentuk plaintext.
   - Solusi arsitektural: Menerapkan **arsitektur dual-rule** dalam satu berkas YARA, memisahkan logika deteksi varian terkompresi (*packed*) dan varian dekompresi/termutasi (*unpacked*).

---

## Metodologi Pengujian NIST SP 800-115
Berdasarkan panduan pengujian teknis NIST SP 800-115:
1. **Fase Pengumpulan Informasi & Analisis Statis (Information Gathering & Static Analysis):**
   - Mengidentifikasi arsitektur PE32 x86, mengekstrak tabel seksi, dan mendeteksi kompresor UPX.
   - Mengekstrak string ASCII dan Wide String (UTF-16LE).
   - Memetakan pemanggilan API dinamis dan fungsi kernel Windows.
2. **Fase Rekayasa Aturan Deteksi (Detection Engineering):**
   - Membangun rule YARA untuk varian terkompresi yang mengidentifikasi struktur loader UPX (`UPX0`, `UPX1`, `UPX!`) yang dikombinasikan dengan dependensi impor kernel spesifik (`OpenProcessToken`).
   - Membangun rule YARA untuk varian biner terbuka (*unpacked*) yang menargetkan kombinasi API snapshot proses dan manipulasi debugger (`CreateToolhelp32Snapshot`, `Process32FirstW`, `DebugActiveProcess`, `AdjustTokenPrivileges`).
3. **Fase Evaluasi & Validasi Signature (Signature Validation):**
   - Menghubungkan ke layanan evaluasi signature melalui port TCP socket container.
   - Mengirimkan berkas aturan YARA terpadu.
   - Mengonfirmasi pengujian lulus terhadap 64 berkas pengujian (0 False Positive, 0 False Negative) dan menangkap flag resmi.

---

## Implementasi Aturan YARA
Aturan deteksi multi-rule yang dirancang:
```yara
rule Suspicious_Packed {
    meta:
        description = "Mendeteksi varian malware anti-debug yang dikompresi dengan UPX"
        author = "Arielwin / CyLab LKS Training"
        reference = "NIST SP 800-115 / MITRE ATT&CK T1027.002, T1057"
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
        $u3 = "UPX!"
        $s = "OpenProcessToken"
    condition:
        all of them
}

rule Suspicious_Unpacked {
    meta:
        description = "Mendeteksi varian biner malware anti-debug unpacked atau termutasi"
        author = "Arielwin / CyLab LKS Training"
        reference = "NIST SP 800-115 / MITRE ATT&CK T1562.001, T1134"
    strings:
        $a1 = "CreateToolhelp32Snapshot"
        $a2 = "Process32FirstW"
        $a3 = "DebugActiveProcess"
        $a4 = "AdjustTokenPrivileges"
    condition:
        all of them
}
```

---

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_483_yararules0x100.py`:
```python
import socket
import re
import time

HOST = "chatelaine.cylabacademy.net"
PORT = 32723

YARA_RULE = """
rule Suspicious_Packed {
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
        $u3 = "UPX!"
        $s = "OpenProcessToken"
    condition:
        all of them
}

rule Suspicious_Unpacked {
    strings:
        $a1 = "CreateToolhelp32Snapshot"
        $a2 = "Process32FirstW"
        $a3 = "DebugActiveProcess"
        $a4 = "AdjustTokenPrivileges"
    condition:
        all of them
}
"""

s = socket.create_connection((HOST, PORT), timeout=15)
s.sendall(YARA_RULE.strip().encode("utf-8") + b"\n")
s.shutdown(socket.SHUT_WR)
time.sleep(1)

resp = s.recv(4096).decode("utf-8", errors="ignore")
s.close()

flag = re.search(r"academy\{[^}]+\}", resp).group(0)
print("Flag:", flag)
```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{yara_rul35_r0ckzzz_3fd2bd06}`
- **Hasil Evaluasi Server:**
  ```text
  Status: Passed
  Congrats! Here is your flag: academy{yara_rul35_r0ckzzz_3fd2bd06}
  ```
- **Metode Verifikasi:**
  HTTP POST `/api/submissions/` dengan payload JSON:
  ```json
  {"challenge": 483, "flag": "academy{yara_rul35_r0ckzzz_3fd2bd06}"}
  ```
  Respons platform: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Best Practice Pembuatan Signature YARA (Threat Hunting):**
   - Menghindari pembuatan aturan yang terlalu longgar (*overly broad*) seperti hanya mencocokkan string UPX, karena akan memicu ratusan peringatan palsu pada perangkat lunak sah yang dikompresi.
   - Menghindari aturan yang terlalu kaku (*overly specific*) seperti hanya mencocokkan string pesan teks tertentu yang mudah diganti atau dihapus oleh pembuat malware.
   - Pendekatan berbasis kombinasi API fungsionalitas (*behavior-indicative API clustering*) memberikan tingkat ketahanan deteksi tertinggi terhadap variasi kode.
2. **Kategori MITRE ATT&CK Terkait:**
   - **T1027.002 (Obfuscated Files or Information: Software Packing)**
   - **T1057 (Process Discovery)**
   - **T1134 (Access Token Manipulation)**
   - **T1562.001 (Impair Defenses: Disable or Modify Tools)**
