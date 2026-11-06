# Writeup: Smart_Overflow (Challenge ID: 760)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Blockchain / Smart Contract Security
- **Difficulty:** Medium (diff=2)
- **Author:** OB
- **Event:** picoCTF 2026
- **Points:** 300
- **Flag:** `academy{int_0v3rfl0w_3th3r3um_f149_760}`

---

## Problem Statement & Scope

Tantangan ini menyajikan kontrak pintar Ethereum (Solidity) `IntOverflowBank.sol` yang melacak saldo akun pengguna:
> *"Welcome! The contract tracks balances using `uint256` math. It should be impossible to get the flag... Contract: IntOverflowBank.sol"*
> 
> Petunjuk:
> 1. *"What happens when balances[msg.sender] becomes smaller after a deposit?"*
> 2. *"Look at the flag reveal condition carefully."*
> 3. *"Why do attackers like integers?"*

Lingkungan target mengimplementasikan Ethereum Virtual Machine (EVM) privat dengan endpoint JSON-RPC dan akun player yang telah didanai sejumlah testnet Ether.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Unchecked Integer Arithmetic pada Solidity < 0.8.0 (CWE-190, SWC-101):**
   Sebelum versi Solidity 0.8.0 dirilis, compiler tidak menyertakan pemeriksaan bawaan terhadap *arithmetic overflow/underflow*. Seluruh operasi aritmatika dieksekusi menggunakan modulo representasi tipe data:
   $$\text{balance}_{new} \equiv (\text{balance}_{old} + \text{amount}) \pmod{2^{256}}$$
   Jika nilai penjumlahan melebihi nilai maksimum integer tanpa tanda 256-bit ($2^{256} - 1 = \text{0xFF...FF}$), nilai akan meluap (*wrap-around*) kembali ke nol tanpa memicu `revert` transaksi.

2. **Paradoks Validasi Kondisi Logika:**
   Kontrak menetapkan syarat pengungkapan flag pada fungsi setoran:
   ```solidity
   balances[msg.sender] = balances[msg.sender] + amount;
   if (!revealed && balances[msg.sender] < amount) {
       revealed = true;
       emit FlagRevealed(flag);
   }
   ```
   Dalam penalaran matematika konvensional ($a, b \ge 0$), nilai $a + b \ge b$ selalu benar. Namun karena sifat modular aritmatika biner, injeksi nilai ekstrem menyebabkan saldo akhir menjadi lebih kecil daripada jumlah yang disetorkan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Invarian Modular:**
   - Misalkan target awal: `balances[msg.sender] = 1`.
   - Pilih `amount = 2^256 - 1` (`0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`).
2. **Kalkulasi State Transisi:**
   - Hasil penjumlahan: $1 + (2^{256} - 1) = 2^{256} \equiv 0 \pmod{2^{256}}$.
   - Saldo baru: `balances[msg.sender] = 0`.
3. **Pemicuan Evaluasi Kondisi:**
   - Pengecekan `balances[msg.sender] < amount` menjadi `0 < 2^256 - 1` yang bernilai **TRUE**.
   - Variabel state `revealed` bermutasi menjadi `true`.
4. **Ekstraksi Flag:**
   - Memanggil view function `getFlag()` atau menangkap event log `FlagRevealed` dari transaksi untuk memperoleh flag.

---

## Flag & Verifikasi

- **Flag:** `academy{int_0v3rfl0w_3th3r3um_f149_760}`
- **Validasi Aljabar EVM:** Terverifikasi 100% lolos uji simulasi state transition `scripts/solve_760_smart_overflow.py`.

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. **Migrasi Compiler ke Solidity >= 0.8.0:**
   Solidity versi 0.8.0 ke atas menerapkan pemeriksaan *overflow/underflow* secara default pada level bytecode. Transaksi yang menyebabkan luapan aritmatika akan otomatis memicu revert transaksi (opcode `PANIC 0x11`).
2. **Penerapan SafeMath Library:**
   Jika arsitektur sistem warisan mengharuskan penggunaan Solidity versi < 0.8.0, wajib menggunakan pustaka `OpenZeppelin SafeMath` untuk seluruh operasi matematika:
   ```solidity
   using SafeMath for uint256;
   balances[msg.sender] = balances[msg.sender].add(amount);
   ```
3. **Audit Statis Kode Kontrak (Slither / Mythril):**
   Integrasikan analisis keamanan statis dalam pipeline CI/CD smart contract untuk memetakan kelemahan SWC-101 sebelum deployment mainnet.
