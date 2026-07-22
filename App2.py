#!/usr/bin/env python3
"""
Hash Tool v1.0 — Hash Identifier & Decoder
Authorized penetration testing utility
"""

import re
import os
import hashlib
from pathlib import Path

# ──────────────────────────────────────────────
# HASH IDENTIFICATION DATABASE (regex patterns)
# ──────────────────────────────────────────────
HASH_PATTERNS = [
    # (name, regex, length, hashcat_mode, example)
    ("MD5",             re.compile(r"^[a-f0-9]{32}$"),                 32,   0,  "5d41402abc4b2a76b9719d911017c592"),
    ("MD4",             re.compile(r"^[a-f0-9]{32}$"),                 32,   900, "5d41402abc4b2a76b9719d911017c592"),
    ("NTLM",            re.compile(r"^[a-f0-9]{32}$"),                 32,   1000,"b4b9b02e6f09a9bd760f388b67351e2b"),
    ("SHA-1",           re.compile(r"^[a-f0-9]{40}$"),                 40,   100, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"),
    ("SHA-224",         re.compile(r"^[a-f0-9]{56}$"),                 56,   1300,"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
    ("SHA-256",         re.compile(r"^[a-f0-9]{64}$"),                 64,   1400,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("SHA-384",         re.compile(r"^[a-f0-9]{96}$"),                 96,   10800,"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
    ("SHA-512",         re.compile(r"^[a-f0-9]{128}$"),                128,  1700,"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    ("SHA-512/256",     re.compile(r"^[a-f0-9]{64}$"),                 64,   2150,"c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"),
    ("SHA3-256",        re.compile(r"^[a-f0-9]{64}$"),                 64,   17400,"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    ("SHA3-512",        re.compile(r"^[a-f0-9]{128}$"),                128,  17600,"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
    ("RIPEMD-160",      re.compile(r"^[a-f0-9]{40}$"),                 40,   6000,"9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    ("Whirlpool",       re.compile(r"^[a-f0-9]{128}$"),                128,  6100,"b905ecbb77e7af57e79614e169e1b14d084abed2cb6e8f997a0b211221a25cab1ad0c186a24b107c9a4b1c38cca8341abf6536f67600dd12057e4da239dbed1f"),
    ("MySQL < 4.1",     re.compile(r"^[a-f0-9]{16}$"),                 16,   200,  "5d4102abc4b2a76b"),
    ("MySQL 5 / 6",     re.compile(r"^\*[a-f0-9]{40}$"),              41,   300,  "*A4B64E3560896E4A5F8C8B2F5F5E4D6A5B6C7D8E"),
    ("SHA-1(Django)",   re.compile(r"^sha1\$.+\$.+"),                  None, 131,  "sha1$c6218$161b5f9a7a5c9c0f5b7c3d4e5f6a7b8c9d0e1f2"),
    ("MD5(APR)",        re.compile(r"^\$apr1\$.+\$.+"),                None, 1600, "$apr1$6c3d4e5f$e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),
    ("bcrypt",          re.compile(r"^\$2[ayb]\$\d{2}\$.{53}$"),       None, 3200, "$2y$12$LJ3m4ys3Lk0THwHk8E1KeeEM1O1p7q8s9d0f1g2h3j4k5l6m7n8o9p0q"),
    ("bcrypt($2b$)",    re.compile(r"^\$2b\$\d{2}\$.{53}$"),           None, 3200, "$2b$12$LJ3m4ys3Lk0THwHk8E1KeeEM1O1p7q8s9d0f1g2h3j4k5l6m7n8o9p0q"),
    ("SHA-256(Crypt)",  re.compile(r"^\$5\$.{16}\$.{43}$"),           None, 7400, "$5$rounds=5000$usesomesillystri$kqDD7MmsiS0iFJ4L5a4d8H9X4Wl0JL4a4d8H9X"),
    ("SHA-512(Crypt)",  re.compile(r"^\$6\$.{16}\$.{86}$"),           None, 1800, "$6$salt$IyR68s4Q7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7kQ7k"),
    ("LM Hash",         re.compile(r"^[a-f0-9]{32}$"),                 32,   3000, "aad3b435b51404eeaad3b435b51404ee"),
    ("LM (split)",      re.compile(r"^[a-f0-9]{16}$"),                 16,   3000, "aad3b435b51404ee"),
    ("CRC32",           re.compile(r"^[a-f0-9]{8}$"),                  8,    None, "d202ef8d"),
    ("Adobe PDF 128",   re.compile(r"^[0-9a-f]{32,}$"),                None, None, "00000000000000000000000000000000"),
    ("Blake2b-256",     re.compile(r"^[a-f0-9]{64}$"),                 64,   600,  "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
    ("CRC64",           re.compile(r"^[a-f0-9]{16}$"),                 16,   None, "6c40df5f0b4972fa"),
    ("GOST R 34.11-94", re.compile(r"^[a-f0-9]{64}$"),                 64,   6900, "fc2b6a6e7b3c0d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e"),
    ("Haval-160",       re.compile(r"^[a-f0-9]{40}$"),                 40,   None, "d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9"),
    ("Tiger-160",       re.compile(r"^[a-f0-9]{40}$"),                 40,   None, "a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4"),
    ("Snefru-256",      re.compile(r"^[a-f0-9]{64}$"),                 64,   None, "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"),
    ("Bitcoin Address", re.compile(r"^[13][a-km-zA-HJ-NP-Z0-9]{33}$"), None, None, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    ("Ethereum Address",re.compile(r"^0x[a-fA-F0-9]{40}$"),           None, None, "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"),
]

# For length-based collision resolution, we store a dict: length -> list of possible names
LENGTH_MAP = {}
for name, regex, length, hcmode, example in HASH_PATTERNS:
    if length is not None:
        LENGTH_MAP.setdefault(length, []).append((name, hcmode))


def read_hash_from_file(filepath):
    """Read and clean a hash from a .txt file."""
    path = Path(filepath)
    if not path.exists():
        print(f"[!] File not found: {filepath}")
        return None
    raw = path.read_text().strip()
    # Remove any whitespace, newlines, common prefixes like "hash: "
    if ":" in raw and not raw.startswith("$"):
        raw = raw.split(":", 1)[-1].strip()
    if " " in raw:
        raw = raw.split()[-1]
    return raw


def identify_hash(hash_str):
    """Return list of (name, hashcat_mode) candidates sorted by confidence."""
    candidates = []
    for name, regex, length, hcmode, example in HASH_PATTERNS:
        if regex.match(hash_str):
            candidates.append((name, hcmode))

    # Additional length-based filtering for hex hashes
    if re.match(r"^[a-f0-9]+$", hash_str):
        length = len(hash_str)
        if length in LENGTH_MAP:
            for lname, lmode in LENGTH_MAP[length]:
                if (lname, lmode) not in candidates:
                    candidates.append((lname, lmode))

    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for name, mode in candidates:
        if name not in seen:
            seen.add(name)
            unique.append((name, mode))

    # Sort: prefer exact hex-length matches first
    if re.match(r"^[a-f0-9]+$", hash_str):
        unique.sort(key=lambda x: (len([p for p in HASH_PATTERNS if p[0] == x[0] and p[2] == len(hash_str)]), x[0]), reverse=True)

    return unique


def suggest_possible_types(hash_str):
    """When no match found, suggest based on length and character set."""
    length = len(hash_str)
    charset = "hex" if re.match(r"^[a-f0-9]+$", hash_str) else \
              "base64" if re.match(r"^[A-Za-z0-9+/=]+$", hash_str) else \
              "mixed"

    print(f"\n  📏 Length: {length} characters")
    print(f"  🔤 Character set: {charset}")
    print(f"\n  💡 Suggestions based on length and pattern:")

    if charset == "hex":
        suggestions = {
            8:   ["CRC32", "LM Hash (half)", "Adler32"],
            16:  ["MySQL < 4.1", "CRC64", "LM Hash", "NTLM (half)"],
            32:  ["MD5", "MD4", "NTLM", "LM Hash", "MD2"],
            40:  ["SHA-1", "RIPEMD-160", "Haval-160", "Tiger-160", "MySQL 5 (without *)"],
            56:  ["SHA-224"],
            64:  ["SHA-256", "SHA-512/256", "SHA3-256", "Blake2b-256", "GOST R 34.11-94", "Snefru-256"],
            96:  ["SHA-384"],
            128: ["SHA-512", "SHA3-512", "Whirlpool", "Skein-512"],
        }
        if length in suggestions:
            for s in suggestions[length]:
                print(f"     • {s}")
        else:
            print(f"     No common hex hash known with {length} characters.")
    elif hash_str.startswith("$2") or hash_str.startswith("$6") or hash_str.startswith("$5"):
        print("     • bcrypt ($2y$, $2a$, $2b$)")
        print("     • SHA-512 crypt ($6$)")
        print("     • SHA-256 crypt ($5$)")
    elif hash_str.startswith("$") and "$" in hash_str[1:]:
        print("     • Modular Crypt Format hash (various)")
    elif len(hash_str) == 60 and hash_str.endswith("="):
        print("     • Base64-encoded hash (try decoding and re-identifying)")
    else:
        print("     • Try searching hashcat example hashes for this length/pattern")
        print("     • Could be a salted hash, PBKDF2 output, or custom format")


def get_common_wordlists():
    """Return list of common wordlist paths on Kali/Linux."""
    candidates = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/dict/words",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    ]
    available = [p for p in candidates if os.path.exists(p)]
    return available


def compute_hash(word, algo):
    """Compute a hash of `word` using the given algorithm name."""
    w = word.encode()
    if algo == "MD5":
        return hashlib.md5(w).hexdigest()
    elif algo == "MD4":
        # Python's hashlib may not have MD4 on all platforms, use custom
        try:
            return hashlib.new("md4", w).hexdigest()
        except ValueError:
            return None
    elif algo == "NTLM":
        # NTLM = MD4(UTF-16LE(password))
        try:
            return hashlib.new("md4", w.decode().encode("utf-16-le")).hexdigest()
        except ValueError:
            return None
    elif algo == "SHA-1":
        return hashlib.sha1(w).hexdigest()
    elif algo == "SHA-224":
        return hashlib.sha224(w).hexdigest()
    elif algo == "SHA-256":
        return hashlib.sha256(w).hexdigest()
    elif algo == "SHA-384":
        return hashlib.sha384(w).hexdigest()
    elif algo == "SHA-512":
        return hashlib.sha512(w).hexdigest()
    elif algo == "SHA3-256":
        return hashlib.sha3_256(w).hexdigest()
    elif algo == "SHA3-512":
        return hashlib.sha3_512(w).hexdigest()
    elif algo == "RIPEMD-160":
        try:
            return hashlib.new("ripemd160", w).hexdigest()
        except ValueError:
            return None
    elif algo == "Whirlpool":
        try:
            return hashlib.new("whirlpool", w).hexdigest()
        except ValueError:
            return None
    elif algo == "Blake2b-256":
        return hashlib.blake2b(w, digest_size=32).hexdigest()
    elif algo == "Blake2s-256":
        return hashlib.blake2s(w, digest_size=32).hexdigest()
    elif algo in ("GOST R 34.11-94",):
        try:
            return hashlib.new("gost", w).hexdigest()
        except ValueError:
            return None
    elif algo == "MySQL < 4.1":
        return hashlib.md5(w).hexdigest()[:16]
    elif algo == "MySQL 5 / 6":
        return "*" + hashlib.sha1(w).hexdigest().upper()
    elif algo == "LM Hash":
        # Simplified LM hash (only works for <=7 char uppercase ASCII)
        try:
            from Cryptodome.Hash import LM
            return None  # requires pycryptodome
        except ImportError:
            return None
    else:
        return None


def crack_hash(hash_str, hash_name, wordlist_path):
    """Attempt to crack the hash using a dictionary."""
    if not os.path.exists(wordlist_path):
        print(f"\n  [!] Wordlist not found: {wordlist_path}")
        return None

    print(f"\n  [*] Cracking {hash_name} hash using: {wordlist_path}")
    print(f"  [*] Target hash: {hash_str}")
    print(f"  [*] Searching... (press Ctrl+C to abort)\n")

    total = 0
    try:
        with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
            for line in f:
                word = line.rstrip("\n\r")
                total += 1
                computed = compute_hash(word, hash_name)
                if computed and computed.lower() == hash_str.lower():
                    print(f"  [✓] FOUND! Password: {word}")
                    return word
                # Show progress every 500k
                if total % 500000 == 0:
                    print(f"  [*] {total:,} words checked...")
    except KeyboardInterrupt:
        print(f"\n  [!] Interrupted after {total:,} words.")
        return None
    except Exception as e:
        print(f"\n  [!] Error: {e}")
        return None

    print(f"\n  [✗] Password not found in dictionary ({total:,} words checked)")
    return None


def option_identify(hash_str):
    """Option 1: Identify hash type."""
    print("\n" + "=" * 60)
    print("  🔍 HASH IDENTIFIER")
    print("=" * 60)
    print(f"\n  Hash: {hash_str}")

    results = identify_hash(hash_str)

    if not results:
        print("\n  [✗] Could not identify the hash type.")
        suggest_possible_types(hash_str)
    else:
        print(f"\n  [✓] Possible hash type(s):")
        for i, (name, mode) in enumerate(results, 1):
            mode_str = f" (hashcat mode: {mode})" if mode else ""
            print(f"     {i}. {name}{mode_str}")

    print()
    return results


def option_decode(hash_str):
    """Option 2: Hash decoder / cracker."""
    print("\n" + "=" * 60)
    print("  🔓 HASH DECODER")
    print("=" * 60)

    # First, identify possible types
    results = identify_hash(hash_str)
    if not results:
        print("\n  [✗] Cannot decode — hash type unknown.")
        suggest_possible_types(hash_str)
        return

    print(f"\n  [*] Possible hash types for: {hash_str}")
    for i, (name, mode) in enumerate(results, 1):
        mode_str = f" [hashcat mode {mode}]" if mode else ""
        print(f"     {i}. {name}{mode_str}")

    # Let user select
    print()
    while True:
        try:
            choice = input("  Select number (or 0 to cancel): ").strip()
            if choice == "0":
                return
            idx = int(choice) - 1
            if 0 <= idx < len(results):
                selected_name = results[idx][0]
                break
            print("  [!] Invalid selection.")
        except ValueError:
            print("  [!] Enter a number.")

    # Choose dictionary
    print(f"\n  [*] Selected: {selected_name}")
    print("\n  Dictionary options:")
    print("     1. Default wordlist (auto-detect rockyou.txt)")
    print("     2. Custom wordlist path")

    dict_choice = input("\n  Select (1 or 2): ").strip()

    wordlist = None
    if dict_choice == "1":
        defaults = get_common_wordlists()
        if not defaults:
            print("\n  [!] No default wordlists found.")
            custom = input("  Enter custom wordlist path: ").strip()
            if custom and os.path.exists(custom):
                wordlist = custom
            else:
                print("  [!] Invalid path.")
                return
        else:
            wordlist = defaults[0]
            if len(defaults) > 1:
                print(f"\n  [*] Multiple wordlists found:")
                for i, p in enumerate(defaults, 1):
                    size = os.path.getsize(p) if os.path.exists(p) else 0
                    size_mb = size / (1024 * 1024)
                    print(f"     {i}. {p} ({size_mb:.1f} MB)")
                wc = input(f"\n  Select (1-{len(defaults)}, Enter for 1): ").strip()
                if wc:
                    try:
                        idx2 = int(wc) - 1
                        if 0 <= idx2 < len(defaults):
                            wordlist = defaults[idx2]
                    except:
                        pass
            print(f"  [*] Using: {wordlist}")
    else:
        custom = input("  Enter path to wordlist: ").strip()
        if os.path.exists(custom):
            wordlist = custom
        else:
            print("  [!] File not found.")
            return

    # Crack
    result = crack_hash(hash_str, selected_name, wordlist)

    if result:
        # Save result
        save = input("\n  Save decoded password? (y/n): ").strip().lower()
        if save == "y":
            outfile = "cracked.txt"
            with open(outfile, "a") as f:
                f.write(f"{hash_str}:{result}\n")
            print(f"  [✓] Saved to {outfile}")

    print()


def main():
    print("=" * 60)
    print("  🔐 HASH TOOL v1.0 — Identifier & Decoder")
    print("  Authorized penetration testing use only")
    print("=" * 60)

    # Get hash from .txt file
    filepath = input("\n  Enter path to .txt file containing hash: ").strip()
    if not filepath:
        filepath = "hash.txt"

    hash_str = read_hash_from_file(filepath)
    if not hash_str:
        print("\n  [!] Could not read hash. Make sure the file exists and contains a hash.")
        return

    print(f"\n  [✓] Loaded hash: {hash_str}")

    while True:
        print("\n" + "-" * 40)
        print("  MENU:")
        print("    1. Hash Identifier")
        print("    2. Hash Decoder")
        print("    3. Exit")
        print("-" * 40)

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            option_identify(hash_str)
        elif choice == "2":
            option_decode(hash_str)
        elif choice == "3":
            print("\n  [*] Exiting. Good luck with the assessment!\n")
            break
        else:
            print("  [!] Invalid option. Enter 1, 2, or 3.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted. Exiting.\n")
