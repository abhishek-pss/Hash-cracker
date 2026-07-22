# 🔐 Hash-cracker

A lightweight command-line utility to **identify** hash types and **crack** them using dictionary (wordlist) attacks. Built for authorized penetration testing and security research.

> ⚠️ **Authorized use only.** This tool is intended for penetration testers, security researchers, and CTF players working on systems/hashes they own or have explicit permission to test. Do not use it against data you don't have authorization to access.

---

## ✨ Features

- **Hash Identifier** — Detects likely hash type(s) from a given hash string using regex pattern matching and length-based heuristics.
- **Hash Decoder / Cracker** — Runs a dictionary attack against a hash using a wordlist (e.g. `rockyou.txt`) and reports the matching plaintext if found.
- **Broad hash coverage** — Recognizes 30+ formats, including:
  - MD5, MD4, NTLM
  - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256
  - SHA3-256, SHA3-512
  - RIPEMD-160, Whirlpool, Blake2b-256, GOST, Tiger-160, Haval-160, Snefru-256
  - bcrypt (`$2a$`, `$2b$`, `$2y$`), SHA-256/512 crypt (`$5$`, `$6$`), APR MD5, Django SHA-1
  - MySQL (< 4.1 and 5/6), LM hash, CRC32/CRC64
  - Bitcoin & Ethereum addresses
- **Hashcat mode mapping** — Suggests the corresponding hashcat `-m` mode for each identified hash type, so you can hand off to hashcat/John the Ripper for faster GPU-accelerated cracking.
- **Auto wordlist detection** — Automatically checks common Kali Linux wordlist locations (`rockyou.txt`, SecLists, `dirb`, etc.).
- **Save cracked results** — Optionally saves recovered hash:password pairs to `cracked.txt`.

---

## 📦 Requirements

- Python 3.7+
- Standard library only (`re`, `os`, `hashlib`, `pathlib`)

> **Note:** Some hash algorithms (MD4, NTLM, RIPEMD-160, Whirlpool, GOST) depend on your Python build's OpenSSL support via `hashlib.new()`. If unavailable on your system, those options will return `None` instead of a hash.

No external dependencies are required to run the core tool.

---

## 🛠️ Installation

1. **Clone the repository**

```bash
git clone https://github.com/abhishek-pss/Hash-cracker.git
cd Hash-cracker
```

2. **(Optional) Create a virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

> The core tool relies only on Python's standard library, so `requirements.txt` currently has no third-party packages. It's included for consistency and to make future dependencies easy to track.

4. **Verify it runs**

```bash
python3 App.py
```

---

## 🚀 Usage

1. Save the target hash into a `.txt` file (e.g. `hash.txt`).
2. Run the script:

```bash
python3 App.py
```

3. Enter the path to your hash file when prompted (defaults to `hash.txt`).
4. Choose from the menu:

```
  MENU:
    1. Hash Identifier
    2. Hash Decoder
    3. Exit
```

### Option 1 — Hash Identifier
Analyzes the hash and lists all possible matching hash types along with their hashcat mode numbers.

### Option 2 — Hash Decoder
1. Identifies possible hash types.
2. Lets you select which type to crack against.
3. Choose a wordlist — auto-detected system wordlists or a custom path.
4. Runs the dictionary attack and reports the cracked password if found.
5. Optionally saves the result to `cracked.txt`.

---

## 🖼️ Example

```
🔐 HASH TOOL v1.0 — Identifier & Decoder
Authorized penetration testing use only
============================================================

  Enter path to .txt file containing hash: hash.txt

  [✓] Loaded hash: 5d41402abc4b2a76b9719d911017c592

----------------------------------------
  MENU:
    1. Hash Identifier
    2. Hash Decoder
    3. Exit
----------------------------------------
```

---

## 📁 Project Structure

```
Hash-cracker/
├── App.py        # Main tool: identification + cracking logic
└── README.md      # Project documentation
```

---

## ⚖️ Disclaimer

This project is provided for **educational and authorized security testing purposes only**. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before testing or attempting to crack any hash or credential.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to open a pull request or issue if you'd like to add support for more hash types or improve cracking performance.

---

## 📄 License

This project currently has no license specified. Consider adding one (e.g. MIT) to clarify how others can use, modify, and distribute this code.
- **Broad hash coverage** — Recognizes 30+ formats, including:
  - MD5, MD4, NTLM
  - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256
  - SHA3-256, SHA3-512
  - RIPEMD-160, Whirlpool, Blake2b-256, GOST, Tiger-160, Haval-160, Snefru-256
  - bcrypt (`$2a$`, `$2b$`, `$2y$`), SHA-256/512 crypt (`$5$`, `$6$`), APR MD5, Django SHA-1
  - MySQL (< 4.1 and 5/6), LM hash, CRC32/CRC64
  - Bitcoin & Ethereum addresses
- **Hashcat mode mapping** — Suggests the corresponding hashcat `-m` mode for each identified hash type, so you can hand off to hashcat/John the Ripper for faster GPU-accelerated cracking.
- **Auto wordlist detection** — Automatically checks common Kali Linux wordlist locations (`rockyou.txt`, SecLists, `dirb`, etc.).
- **Save cracked results** — Optionally saves recovered hash:password pairs to `cracked.txt`.

---

## 📦 Requirements

- Python 3.7+
- Standard library only (`re`, `os`, `hashlib`, `pathlib`)

> **Note:** Some hash algorithms (MD4, NTLM, RIPEMD-160, Whirlpool, GOST) depend on your Python build's OpenSSL support via `hashlib.new()`. If unavailable on your system, those options will return `None` instead of a hash.

No external dependencies are required to run the core tool.

---

## 🚀 Usage

1. Save the target hash into a `.txt` file (e.g. `hash.txt`).
2. Run the script:

```bash
python3 App.py
```

3. Enter the path to your hash file when prompted (defaults to `hash.txt`).
4. Choose from the menu:

```
  MENU:
    1. Hash Identifier
    2. Hash Decoder
    3. Exit
```

### Option 1 — Hash Identifier
Analyzes the hash and lists all possible matching hash types along with their hashcat mode numbers.

### Option 2 — Hash Decoder
1. Identifies possible hash types.
2. Lets you select which type to crack against.
3. Choose a wordlist — auto-detected system wordlists or a custom path.
4. Runs the dictionary attack and reports the cracked password if found.
5. Optionally saves the result to `cracked.txt`.

---

## 🖼️ Example

```
🔐 HASH TOOL v1.0 — Identifier & Decoder
Authorized penetration testing use only
============================================================

  Enter path to .txt file containing hash: hash.txt

  [✓] Loaded hash: 5d41402abc4b2a76b9719d911017c592

----------------------------------------
  MENU:
    1. Hash Identifier
    2. Hash Decoder
    3. Exit
----------------------------------------
```

---

## 📁 Project Structure

```
Hash-cracker/
├── App.py        # Main tool: identification + cracking logic
└── README.md      # Project documentation
```

---

## ⚖️ Disclaimer

This project is provided for **educational and authorized security testing purposes only**. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before testing or attempting to crack any hash or credential.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to open a pull request or issue if you'd like to add support for more hash types or improve cracking performance.

---

## 📄 License

This project currently has no license specified. Consider adding one (e.g. MIT) to clarify how others can use, modify, and distribute this code.
