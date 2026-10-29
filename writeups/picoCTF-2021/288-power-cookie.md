# Writeup: Power Cookie (Challenge ID: 288)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Cookie Tampering
- **Difficulty:** Medium
- **Event:** picoCTF 2021
- **Flag:** `academy{gr4d3_A_c00k13_6cf86b5a}`

---

## Problem Statement & Scope

Online Gradebook dengan tombol "Continue as guest". File `guest.js`
menyetel cookie lalu redirect ke `/check.php`:

```js
window.location.href = '/check.php';
document.cookie = "isAdmin=0";
```

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Authorization via client-controlled cookie:** server (`check.php`)
   memercayai nilai `isAdmin` dari header `Cookie` tanpa session binding
   atau signature (HMAC). Cookie = input user biasa.
2. **Boolean coercion:** perbandingan longgar (`== 1` / truthy) membuat
   string `"1"` lolos sebagai admin.
3. **Fail-open guest path:** guest yang sah pun melewati endpoint yang
   sama dengan admin — satu-satunya pembeda adalah cookie.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. `GET /` → halaman gradebook statis + `guest.js`.
2. `GET /guest.js` → terlihat `document.cookie = "isAdmin=0"`.
3. `GET /check.php` dengan `Cookie: isAdmin=0` →
   `We apologize, but we have no guest services...`.
4. Replay dengan `Cookie: isAdmin=1` →
   `<p>academy{gr4d3_A_c00k13_6cf86b5a}</p>`.
5. Solver `scripts/solve_288_power_cookie.py <base-url>` otomatisasi penuh.
6. Submit via API → `{"correct": true}` (HTTP 201).

---

## Flag & Verifikasi

- **Flag:** `academy{gr4d3_A_c00k13_6cf86b5a}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan
  `{"correct": true}` (HTTP 201);
  `solved_by_user: true` pada `GET /api/challenges/288/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- Otorisasi jangan di cookie mentah — gunakan session ID acak server-side
  atau signed cookie (HMAC-SHA256 + secret server).
- Terapkan `HttpOnly; Secure; SameSite` dan validasi ketat di server
  (`===`, allowlist peran).
- Untuk lomba: hint "modify cookies" = langsung uji `isAdmin/admin/role`
  via DevTools/Cookie-Editor sebelum menyentuh backend.
