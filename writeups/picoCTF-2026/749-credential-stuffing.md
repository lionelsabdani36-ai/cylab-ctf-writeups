# 749 - Credential Stuffing (Web Exploitation, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 749 | Event: picoCTF 2026
- Category: Web Exploitation | Difficulty: Medium (2)
- Flag: `academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}`

## Problem Statement & Scope
Simulasi serangan credential stuffing: 1500 pasangan username/password
hasil breach department store (`creds-dump.txt`, format `user;pass`).
Satu korban memakai ulang kredensial yang sama di layanan Online Banking
(netcat login: prompt `Username:` lalu `Password:`). Tugas: replay
seluruh dump sampai login berhasil (NIST SP 800-63B: password reuse
adalah vektor account takeover dominan).

## Teori & Akar Kerentanan (Root Cause)
- Password reuse lintas layanan: satu breach membocorkan kredensial yang
  valid di layanan lain. Tidak ada kejahatan di sisi teknik replay —
  kerentanannya adalah tidak adanya deteksi (rate limit, lockout,
  MFA, breach-corpus check).
- Server membedakan respons (`Invalid username or password` vs
  `Welcome ranna!` + flag), memberi oracle biner sempurna untuk stuffing.
- Tanpa throttling, 1500 percobaan selesai dalam hitungan menit.

## Rekonstruksi Eksploitasi Step-by-Step
1. Download `creds-dump.txt` (1500 baris) dari CDN.
2. Launch instance (`PUT /api/challenges/749/instance/`), tunggu RUNNING:
   `nc chatelaine.cylabacademy.net 46610`.
3. Probe manual: banner `Welcome to the Online Banking Service!`,
   kirim `rora` / `winner1` -> `Invalid username or password`.
4. Skrip `solve_749_credential_stuffing.py`: untuk tiap pasangan,
   buka koneksi socket baru, kirim user + `\n`, kirim pass + `\n`,
   cocokkan regex `academy\{[^}]*\}` pada respons.
5. HIT pada index 372: `ranna` / `phoenix` ->
   `Welcome ranna!` + flag.
6. Submit `POST /api/submissions/` -> `correct: true`; `DELETE` instance.

## Flag & Verifikasi
- `academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}` (`correct: true`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Rate limiting + account lockout eksponensial + CAPTCHA setelah N gagal.
- Cek password terhadap breach corpus (HaveIBeenPwned API / k-anonimitas).
- Wajibkan MFA; bedakan respons generik tanpa oracle user-enumeration.
- Kebijakan: larang reuse password, dorong password manager + SSO.
