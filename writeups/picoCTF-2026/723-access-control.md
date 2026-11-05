# Writeup: Access_Control (Challenge ID: 723)

- **Platform:** CyLab Security Academy (picoCTF 2026)
- **Category:** Blockchain
- **Difficulty:** Medium
- **Event:** picoCTF 2026
- **Flag:** `academy{i_c4n_b3_0wn3r_7a45d669}`

---

## Problem Statement & Scope

Tantangan ini menyajikan smart contract Ethereum berbasis Solidity 0.8.0 bernama `AccessControl.sol`. Kontrak menyimpan flag rahasia yang hanya dapat diakses melalui pemanggilan fungsi `solve()` oleh alamat `owner`. Peserta diberikan node RPC privat, alamat kontrak, dan akun pemain beserta private key untuk berinteraksi dengan rantai EVM.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Unprotected Administrative Function (SWC-105 / CWE-284):**
   Fungsi `changeOwner` didefinisikan dengan visibilitas `public` tanpa pengaman modifikator hak akses (seperti `onlyOwner`):
   ```solidity
   function changeOwner(address _newOwner) public {
       address oldOwner = owner;
       owner = _newOwner;
       emit OwnerChanged(oldOwner, _newOwner);
   }
   ```
2. **Broken Access Control pada Logika Validasi:**
   Karena ketiadaan pemeriksaan otorisasi pada `changeOwner`, siapa pun (termasuk alamat pemain) dapat mengalihkan kepemilikan kontrak kepada dirinya sendiri.
3. **Penyelesaian State Kontrak:**
   Setelah menjadi `owner`, fungsi `solve()` dapat dieksekusi dengan sukses (`require(msg.sender == owner)` terpenuhi), mengubah flag `revealed` menjadi `true`. Selanjutnya fungsi `getFlag()` dapat dipanggil untuk membaca string flag.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Mengambil parameter instans (RPC node, alamat kontrak, private key pemain).
2. Menghubungkan client Web3 Python (`web3.py`) ke endpoint RPC tantangan:
   ```python
   w3 = Web3(Web3.HTTPProvider(rpc_url))
   ```
3. Mengirimkan transaksi pertama memanggil `changeOwner(player_address)` yang ditandatangani dengan private key pemain:
   - Hasil: State variabel `owner` beralih ke `player_address`.
4. Mengirimkan transaksi kedua memanggil `solve()`:
   - Hasil: State variabel `revealed` bernilai `true`.
5. Memanggil fungsi `getFlag()` via RPC call atau membaca status di web interface `/status`:
   - Nilai flag terungkap: `academy{i_c4n_b3_0wn3r_7a45d669}`.

---

## Flag & Verifikasi

- **Flag:** `academy{i_c4n_b3_0wn3r_7a45d669}`
- **Hasil Submission:**
  ```json
  {"user": 1072359, "challenge": 723, "flag": "academy{i_c4n_b3_0wn3r_7a45d669}", "correct": true, "historical": false}
  ```

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. Tambahkan modifikator hak akses `onlyOwner` pada seluruh fungsi administratif penting:
   ```solidity
   modifier onlyOwner() {
       require(msg.sender == owner, "Caller is not the owner");
       _;
   }

   function changeOwner(address _newOwner) public onlyOwner {
       owner = _newOwner;
   }
   ```
2. Manfaatkan pustaka standar industri seperti OpenZeppelin `Ownable.sol` atau `AccessControl.sol` yang telah diaudit secara formal.
