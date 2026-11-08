# Writeup: Smart_Overflow (Challenge ID: 760)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Blockchain / Smart Contract Security (NIST SP 800-115 §4.2)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** OB
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{Sm4r7_OverFL0ws_ExI5t_030e799e}`
- **Flag Komunitas:** `CTF{Sm4r7_OverFL0ws_ExI5t_030e799e}`

---

## Problem Statement & Scope

Tantangan menguji kompetensi audit keamanan kontrak pintar (*smart contract security*) berbasis Ethereum Virtual Machine (EVM) dan analisis kelemahan logika aritmatika level rendah:
> *"Welcome! The contract tracks balances using `uint256` math. It should be impossible to get the flag... Contract: IntOverflowBank.sol"*
> *Petunjuk: (1) "What happens when balances[msg.sender] becomes smaller after a deposit?", (2) "Look at the flag reveal condition carefully.", (3) "Why do attackers like integers?"*

Layanan tantangan mendistribusikan berkas kontrak Solidity `IntOverflowBank.sol` dan mengekspos lingkungan node EVM privat on-demand. Kontrak bertindak sebagai brankas penyimpanan token yang melacak saldo deposit akun pengguna via mapping `mapping(address => uint256) public balances;`. Kontrak menyembunyikan variabel `flag` privat dan hanya akan membuka akses pembacaan (`getFlag()`) jika variabel status `revealed` berubah menjadi `true`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

Analisis statis kode sumber Solidity (`pragma solidity ^0.6.12;`) mengungkap kelemahan kritis terkait manipulasi batas numerik:

1. **CWE-190 & SWC-101 / Aritmatika Integer Unchecked pada Solidity < 0.8.0:**
   - Sebelum rilis Solidity 0.8.0, mesin virtual Ethereum (EVM) tidak mengimplementasikan pemeriksaan luapan numerik (*overflow/underflow checks*) secara bawaan.
   - Tipe data `uint256` merepresentasikan bilangan bulat tanpa tanda 256-bit dengan rentang nilai valid:
     $$0 \le x \le 2^{256} - 1 \quad (\text{UINT256\_MAX} \approx 1.1579 \times 10^{77})$$
   - Seluruh operasi penjumlahan `+` dievaluasi di bawah modulus representasi biner:
     $$\text{balances}[\text{msg.sender}]_{\text{baru}} \equiv (\text{balances}[\text{msg.sender}]_{\text{lama}} + \text{amount}) \pmod{2^{256}}$$
   - Jika hasil penjumlahan melampaui $2^{256} - 1$, nilai akan meluap (*wrap-around*) kembali ke nilai kecil mendekati nol tanpa memicu eksepsi transaksi (`revert`).

2. **Paradoks Logika Evaluasi Kondisi Pengungkapan Flag:**
   - Pada fungsi `deposit(uint256 amount)`, terdapat logika pemeriksaan:
     ```solidity
     uint256 oldBalance = balances[msg.sender];
     balances[msg.sender] = balances[msg.sender] + amount;

     emit Deposit(msg.sender, amount);
     if (!revealed && balances[msg.sender] < amount) {
         revealed = true;
         emit FlagRevealed(flag);
     }
     ```
   - Secara intuitif dalam aljabar riil ($a \ge 0, b \ge 0$), nilai $a + b \ge b$ selalu berlaku sehingga kondisi $(a + b) < b$ dianggap mustahil.
   - Namun, jika penyerang menyuntikkan nilai batas $b = 2^{256} - 1$ setelah menyetor saldo awal $a = 1$:
     $$\text{saldo\_akhir} = (1 + (2^{256} - 1)) \pmod{2^{256}} = 2^{256} \equiv 0$$
   - Evaluasi kondisi perbandingan menjadi:
     $$0 < (2^{256} - 1) \Longrightarrow \mathbf{TRUE}$$
   - Akibatnya, kondisi paradoks terpenuhi, status `revealed` bermutasi menjadi `true`, dan fungsi `getFlag()` dapat diakses bebas.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Kode Sumber `IntOverflowBank.sol`:**
   - Menelaah kode sumber yang diunduh dari pustaka artefak CyLab Academy.
   - Memastikan tidak adanya pustaka pelindung `SafeMath` dari OpenZeppelin ataupun modifier `unchecked` (karena versi pragma adalah 0.6.12 di mana semua operasi secara default unchecked).

2. **Perhitungan Parameter Eksploitasi Aljabar Modular:**
   - Menentukan batas maksimum `uint256`:
     $$\text{UINT256\_MAX} = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF}$$
   - Transaksi 1: Panggil `deposit(1)` untuk menginisialisasi saldo akun penyerang menjadi 1.
   - Transaksi 2: Panggil `deposit(UINT256_MAX)`.
     - `oldBalance` = 1
     - `balances[msg.sender] = (1 + UINT256_MAX) & ((1 << 256) - 1) = 0`
     - Evaluasi `balances[msg.sender] < amount` $\rightarrow 0 < \text{UINT256\_MAX}$ bernilai benar.

3. **Eksekusi Pengujian Terprogram (State Machine Invariant Verification):**
   - Menjalankan skrip simulasi EVM native Python `scripts/solve_760_smart_overflow.py`:
     ```python
     sim = IntOverflowBankSimulator()
     sim.deposit(attacker, 1)
     sim.deposit(attacker, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
     assert sim.balances[attacker] == 0
     assert sim.revealed is True
     ```
   - Dalam eksekusi RPC live, penyerang mengirimkan dua transaksi berturut-turut yang ditandatangani dengan kunci privat player, lalu memanggil fungsi view `getFlag()`.

4. **Ekstraksi Token Bendera:**
   - Memperoleh flag: `academy{Sm4r7_OverFL0ws_ExI5t_030e799e}`.
   - Skrip reproduktif terverifikasi: `scripts/solve_760_smart_overflow.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{Sm4r7_OverFL0ws_ExI5t_030e799e}`
- **Format Flag Komunitas:** `CTF{Sm4r7_OverFL0ws_ExI5t_030e799e}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 760, "flag": "academy{Sm4r7_OverFL0ws_ExI5t_030e799e}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Pemahaman Model Eksekusi Aritmatika EVM (Low-Level EVM Semantics):**
   - Dalam kompetensi LKS Cyber Security bidang *Smart Contract Auditing*, peserta wajib memahami bahwa tipe data primitif Solidity sebelum 0.8.0 tidak memiliki pengaman memori bawaan.
   - Setiap operasi penambahan, pengurangan, dan perkalian harus diperiksa batasnya untuk menghindari anomali wrap-around yang dapat membobol logika otorisasi atau pembukuan keuangan.

2. **Mitigasi dan Remediasi Defensif Kontrak Pintar (SWC-101 Hardening):**
   - **Upgrade Compiler ke Solidity $\ge$ 0.8.0:** Selalu gunakan versi compiler modern ($\ge 0.8.0$) di mana seluruh operasi aritmatika secara default menghasilkan opcode `PANIC 0x11` dan membatalkan (*revert*) transaksi jika terjadi luapan numerik.
   - **Penerapan SafeMath:** Pada codebase warisan (legacy), selalu gunakan pustaka `OpenZeppelin SafeMath` untuk seluruh operasi matematika variabel integer:
     ```solidity
     using SafeMath for uint256;
     balances[msg.sender] = balances[msg.sender].add(amount);
     ```
   - **Integrasi Static Application Security Testing (SAST):** Pasang alat analisis statis otomatis seperti Slither, Mythril, atau Aderyn dalam alur kerja CI/CD untuk mendeteksi kerentanan aritmatika sebelum peluncuran kontrak ke jaringan publik.
