"""
Crypto Tools Module for CTF-MCP
Classical ciphers, modern cryptography, and cryptanalysis tools
"""

import base64
import hashlib
import string
from collections import Counter
from typing import Union

# Try to import optional crypto libraries
try:
    from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
    from Crypto.PublicKey import RSA
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False

try:
    import gmpy2
    GMPY2_AVAILABLE = True
except ImportError:
    GMPY2_AVAILABLE = False

try:
    from sympy import factorint, isprime, sqrt
    SYMPY_AVAILABLE = True
except ImportError:
    SYMPY_AVAILABLE = False


class CryptoTools:
    """Cryptography tools for CTF challenges"""

    # English letter frequency (for frequency analysis)
    ENGLISH_FREQ = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
        'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
        'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
        'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
    }

    def get_tools(self) -> dict:
        """Return available tools and their descriptions"""
        return {
            "base64_encode": "Base64 encode data",
            "base64_decode": "Base64 decode data",
            "rot_n": "ROT-N cipher",
            "caesar": "Caesar cipher",
            "caesar_bruteforce": "Bruteforce Caesar cipher",
            "vigenere": "Vigenere cipher",
            "xor": "XOR cipher",
            "hash_data": "Calculate hash",
            "rsa_factor": "Factor RSA modulus",
            "rsa_decrypt": "Decrypt RSA ciphertext",
            "freq_analysis": "Frequency analysis",
        }

    # === Encoding ===

    def base64_encode(self, data: str) -> str:
        """Base64 encode"""
        return base64.b64encode(data.encode()).decode()

    def base64_decode(self, data: str) -> str:
        """Base64 decode"""
        try:
            # Handle URL-safe base64
            data = data.replace('-', '+').replace('_', '/')
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.b64decode(data).decode('utf-8', errors='replace')
        except Exception as e:
            return f"Decode error: {e}"

    def base32_encode(self, data: str) -> str:
        """Base32 encode"""
        return base64.b32encode(data.encode()).decode()

    def base32_decode(self, data: str) -> str:
        """Base32 decode"""
        try:
            return base64.b32decode(data).decode('utf-8', errors='replace')
        except Exception as e:
            return f"Decode error: {e}"

    # === Classical Ciphers ===

    def rot_n(self, text: str, n: int = 13) -> str:
        """ROT-N cipher (default ROT13)"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + n) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)

    def caesar(self, text: str, shift: int = 3) -> str:
        """Caesar cipher with custom shift"""
        return self.rot_n(text, shift)

    def caesar_bruteforce(self, text: str) -> str:
        """Bruteforce all Caesar cipher shifts"""
        results = []
        for shift in range(26):
            decrypted = self.rot_n(text, shift)
            results.append(f"Shift {shift:2d}: {decrypted}")
        return '\n'.join(results)

    def vigenere(self, text: str, key: str, decrypt: bool = False) -> str:
        """Vigenere cipher encrypt/decrypt"""
        result = []
        key = key.upper()
        key_index = 0

        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                if decrypt:
                    shift = -shift
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
                key_index += 1
            else:
                result.append(char)

        return ''.join(result)

    def atbash(self, text: str) -> str:
        """Atbash cipher (A=Z, B=Y, ...)"""
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(chr(ord('Z') - (ord(char) - ord('A'))))
                else:
                    result.append(chr(ord('z') - (ord(char) - ord('a'))))
            else:
                result.append(char)
        return ''.join(result)

    def affine(self, text: str, a: int, b: int, decrypt: bool = False) -> str:
        """Affine cipher: E(x) = (ax + b) mod 26"""
        result = []

        if decrypt:
            # Find modular inverse of a
            a_inv = pow(a, -1, 26)
            for char in text:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    x = ord(char) - base
                    decrypted = (a_inv * (x - b)) % 26
                    result.append(chr(decrypted + base))
                else:
                    result.append(char)
        else:
            for char in text:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    x = ord(char) - base
                    encrypted = (a * x + b) % 26
                    result.append(chr(encrypted + base))
                else:
                    result.append(char)

        return ''.join(result)

    # === XOR ===

    def xor(self, data: str, key: str, input_hex: bool = False) -> str:
        """XOR data with key"""
        if input_hex:
            data_bytes = bytes.fromhex(data.replace(' ', '').replace('0x', ''))
        else:
            data_bytes = data.encode()

        key_bytes = key.encode() if not input_hex else bytes.fromhex(key.replace(' ', ''))
        result = bytes(a ^ b for a, b in zip(data_bytes, key_bytes * (len(data_bytes) // len(key_bytes) + 1)))

        # Try to decode as string, otherwise return hex
        try:
            return f"String: {result.decode()}\nHex: {result.hex()}"
        except:
            return f"Hex: {result.hex()}"

    def xor_single_byte_bruteforce(self, data: str, input_hex: bool = True) -> str:
        """Bruteforce single-byte XOR"""
        if input_hex:
            data_bytes = bytes.fromhex(data.replace(' ', ''))
        else:
            data_bytes = data.encode()

        results = []
        for key in range(256):
            decrypted = bytes(b ^ key for b in data_bytes)
            try:
                decoded = decrypted.decode('ascii')
                if decoded.isprintable():
                    score = sum(1 for c in decoded.lower() if c in 'etaoinshrdlu ')
                    results.append((score, key, decoded))
            except:
                pass

        results.sort(reverse=True)
        output = []
        for score, key, text in results[:10]:
            output.append(f"Key 0x{key:02x} ({key:3d}): {text[:50]}...")
        return '\n'.join(output)

    # === Hashing ===

    def hash_data(self, data: str, algorithm: str = "sha256") -> str:
        """Calculate hash of data"""
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }

        if algorithm not in algorithms:
            return f"Unknown algorithm. Available: {', '.join(algorithms.keys())}"

        hash_obj = algorithms[algorithm](data.encode())
        return f"{algorithm.upper()}: {hash_obj.hexdigest()}"

    def hash_all(self, data: str) -> str:
        """Calculate all common hashes"""
        results = []
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            results.append(self.hash_data(data, algo))
        return '\n'.join(results)

    # === RSA ===

    def rsa_factor(self, n: str, e: str = "65537") -> str:
        """Try to factor RSA modulus n"""
        n = int(n)
        e = int(e)

        results = [f"N = {n}", f"E = {e}", f"Bits: {n.bit_length()}", ""]

        # Try small factors first
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        for p in small_primes:
            if n % p == 0:
                q = n // p
                results.append(f"[!] Found small factor!")
                results.append(f"p = {p}")
                results.append(f"q = {q}")
                return '\n'.join(results)

        # Check if n is a perfect square (p = q)
        if GMPY2_AVAILABLE:
            sqrt_n = gmpy2.isqrt(n)
            if sqrt_n * sqrt_n == n:
                results.append("[!] N is a perfect square!")
                results.append(f"p = q = {sqrt_n}")
                return '\n'.join(results)

        # Try Fermat factorization for close primes
        results.append("Trying Fermat factorization...")
        p, q = self._fermat_factor(n)
        if p and q:
            results.append(f"[!] Fermat factorization successful!")
            results.append(f"p = {p}")
            results.append(f"q = {q}")
            return '\n'.join(results)

        # Use sympy for factorization (might be slow for large n)
        if SYMPY_AVAILABLE and n.bit_length() < 80:
            results.append("Trying sympy factorization...")
            factors = factorint(n)
            if len(factors) == 2:
                primes = list(factors.keys())
                results.append(f"[!] Factorization successful!")
                results.append(f"p = {primes[0]}")
                results.append(f"q = {primes[1]}")
                return '\n'.join(results)

        results.append("[-] Could not factor N automatically")
        results.append("Try: factordb.com, RsaCtfTool, or Cado-NFS")
        return '\n'.join(results)

    def _fermat_factor(self, n: int, max_iterations: int = 100000) -> tuple:
        """Fermat factorization for close primes"""
        if GMPY2_AVAILABLE:
            a = gmpy2.isqrt(n) + 1
            b2 = a * a - n

            for _ in range(max_iterations):
                if gmpy2.is_square(b2):
                    b = gmpy2.isqrt(b2)
                    p = int(a + b)
                    q = int(a - b)
                    if p * q == n:
                        return (p, q)
                a += 1
                b2 = a * a - n

        return (None, None)

    def rsa_decrypt(self, p: str, q: str, e: str, c: str) -> str:
        """Decrypt RSA ciphertext given p, q, e, c"""
        p, q, e, c = int(p), int(q), int(e), int(c)
        n = p * q
        phi = (p - 1) * (q - 1)

        try:
            if PYCRYPTODOME_AVAILABLE:
                d = inverse(e, phi)
            else:
                d = pow(e, -1, phi)

            m = pow(c, d, n)

            results = [
                f"n = {n}",
                f"phi = {phi}",
                f"d = {d}",
                f"m (decimal) = {m}",
            ]

            # Try to convert to bytes/string
            if PYCRYPTODOME_AVAILABLE:
                try:
                    plaintext = long_to_bytes(m)
                    results.append(f"m (bytes) = {plaintext}")
                    results.append(f"m (string) = {plaintext.decode('utf-8', errors='replace')}")
                except:
                    pass
            else:
                try:
                    hex_str = hex(m)[2:]
                    if len(hex_str) % 2:
                        hex_str = '0' + hex_str
                    plaintext = bytes.fromhex(hex_str)
                    results.append(f"m (bytes) = {plaintext}")
                    results.append(f"m (string) = {plaintext.decode('utf-8', errors='replace')}")
                except:
                    pass

            return '\n'.join(results)

        except Exception as ex:
            return f"Decryption error: {ex}"

    def rsa_common_modulus(self, n: str, e1: str, c1: str, e2: str, c2: str) -> str:
        """RSA Common modulus attack when gcd(e1, e2) = 1"""
        from math import gcd

        n, e1, c1, e2, c2 = int(n), int(e1), int(c1), int(e2), int(c2)

        if gcd(e1, e2) != 1:
            return "Error: gcd(e1, e2) must be 1 for this attack"

        # Extended Euclidean Algorithm
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd_val, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd_val, x, y

        _, s1, s2 = extended_gcd(e1, e2)

        # m = c1^s1 * c2^s2 mod n
        if s1 < 0:
            c1 = pow(c1, -1, n)
            s1 = -s1
        if s2 < 0:
            c2 = pow(c2, -1, n)
            s2 = -s2

        m = (pow(c1, s1, n) * pow(c2, s2, n)) % n

        results = [f"m (decimal) = {m}"]

        try:
            hex_str = hex(m)[2:]
            if len(hex_str) % 2:
                hex_str = '0' + hex_str
            plaintext = bytes.fromhex(hex_str)
            results.append(f"m (string) = {plaintext.decode('utf-8', errors='replace')}")
        except:
            pass

        return '\n'.join(results)

    # === Frequency Analysis ===

    def freq_analysis(self, text: str) -> str:
        """Perform frequency analysis on ciphertext"""
        # Count letters only
        letters = [c.lower() for c in text if c.isalpha()]
        total = len(letters)

        if total == 0:
            return "No alphabetic characters found"

        freq = Counter(letters)
        results = ["Letter Frequency Analysis:", "-" * 40]

        # Sort by frequency
        sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)

        for letter, count in sorted_freq:
            percentage = (count / total) * 100
            bar = '█' * int(percentage / 2)
            results.append(f"{letter.upper()}: {count:4d} ({percentage:5.2f}%) {bar}")

        results.append("")
        results.append("Most common letters in English: E T A O I N S H R D L U")
        results.append("Most common in ciphertext: " + ' '.join(l.upper() for l, _ in sorted_freq[:12]))

        # Suggest possible Caesar shift
        if sorted_freq:
            most_common = sorted_freq[0][0]
            suggested_shift = (ord(most_common) - ord('e')) % 26
            results.append(f"\nIf Caesar cipher with 'E' -> '{most_common.upper()}', shift = {suggested_shift}")

        return '\n'.join(results)

    def index_of_coincidence(self, text: str) -> str:
        """Calculate Index of Coincidence"""
        letters = [c.lower() for c in text if c.isalpha()]
        n = len(letters)

        if n < 2:
            return "Text too short"

        freq = Counter(letters)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

        results = [
            f"Index of Coincidence: {ic:.4f}",
            "",
            "Reference values:",
            "  English text: ~0.0667",
            "  Random text:  ~0.0385",
            "",
        ]

        if ic > 0.06:
            results.append("=> Likely monoalphabetic substitution or transposition")
        else:
            results.append("=> Likely polyalphabetic cipher (Vigenere, etc.)")

        return '\n'.join(results)
