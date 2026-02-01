"""
Crypto Tools Module for CTF-MCP
Classical ciphers, modern cryptography, and cryptanalysis tools
"""

import base64
import hashlib
import string
import struct
import itertools
from collections import Counter
from typing import Union, List, Tuple, Optional
from math import gcd, isqrt, log2

from ..utils.security import dangerous_operation, RiskLevel
from ..utils.helpers import rot_n as _rot_n, hex_to_bytes as _hex_to_bytes, clean_hex

# Try to import optional crypto libraries
try:
    from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, DES, DES3, ARC4
    from Crypto.Util.Padding import pad, unpad
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False

try:
    import gmpy2
    GMPY2_AVAILABLE = True
except ImportError:
    GMPY2_AVAILABLE = False

try:
    from sympy import factorint, isprime, sqrt, continued_fraction_periodic, Integer
    from sympy import Rational
    SYMPY_AVAILABLE = True
except ImportError:
    SYMPY_AVAILABLE = False


# Module-level constants
ALPHABET_SIZE = 26
FERMAT_MAX_ITERATIONS = 100_000


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

    def get_tools(self) -> dict[str, str]:
        """Return available tools and their descriptions"""
        return {
            # Encoding
            "base64_encode": "Base64 encode data",
            "base64_decode": "Base64 decode data",
            "base32_encode": "Base32 encode data",
            "base32_decode": "Base32 decode data",
            "base58_encode": "Base58 encode (Bitcoin style)",
            "base58_decode": "Base58 decode",
            "base85_encode": "Base85/ASCII85 encode",
            "base85_decode": "Base85/ASCII85 decode",
            # Classical Ciphers
            "rot_n": "ROT-N cipher (default ROT13)",
            "caesar": "Caesar cipher with custom shift",
            "caesar_bruteforce": "Bruteforce all Caesar cipher shifts",
            "vigenere": "Vigenere cipher encrypt/decrypt",
            "vigenere_key_length": "Detect Vigenere key length using Kasiski/IC",
            "atbash": "Atbash cipher (A=Z, B=Y, ...)",
            "affine": "Affine cipher: E(x) = (ax + b) mod 26",
            "rail_fence": "Rail fence cipher encrypt/decrypt",
            "rail_fence_bruteforce": "Bruteforce rail fence cipher",
            "bacon": "Bacon cipher encode/decode",
            "playfair": "Playfair cipher encrypt/decrypt",
            "hill_cipher": "Hill cipher (2x2 matrix)",
            "polybius": "Polybius square cipher",
            "morse": "Morse code encode/decode",
            "tap_code": "Tap code (prison cipher) encode/decode",
            "substitution_analyze": "Analyze substitution cipher",
            # XOR
            "xor": "XOR data with key",
            "xor_single_byte_bruteforce": "Bruteforce single-byte XOR",
            "xor_repeating_key": "XOR with repeating key analysis",
            # Modern Crypto
            "aes_encrypt": "AES encrypt (ECB/CBC)",
            "aes_decrypt": "AES decrypt (ECB/CBC)",
            "des_encrypt": "DES encrypt",
            "des_decrypt": "DES decrypt",
            "rc4": "RC4 stream cipher",
            # Hashing
            "hash_data": "Calculate hash (MD5/SHA1/SHA256/SHA512)",
            "hash_all": "Calculate all common hashes",
            "hash_identify": "Identify hash type by format",
            "hash_crack": "Attempt hash crack with wordlist",
            # RSA
            "rsa_factor": "Factor RSA modulus n",
            "rsa_decrypt": "Decrypt RSA ciphertext given p,q,e,c",
            "rsa_common_modulus": "RSA common modulus attack",
            "rsa_wiener": "RSA Wiener attack for small d",
            "rsa_hastad": "RSA Hastad broadcast attack",
            "rsa_low_exponent": "RSA low public exponent attack",
            "rsa_franklin_reiter": "RSA Franklin-Reiter related message attack",
            "rsa_parity_oracle": "RSA parity oracle attack helper",
            "rsa_bleichenbacher": "RSA Bleichenbacher signature attack",
            # Analysis
            "freq_analysis": "Frequency analysis on ciphertext",
            "index_of_coincidence": "Calculate Index of Coincidence",
            "entropy": "Calculate entropy of data",
            # Math helpers
            "mod_inverse": "Calculate modular inverse",
            "crt": "Chinese Remainder Theorem solver",
            "discrete_log": "Discrete logarithm (baby-step giant-step)",
            "euler_phi": "Calculate Euler's totient function",
            "primitive_root": "Find primitive root modulo n",
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
        return _rot_n(text, n)

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
            data_bytes = _hex_to_bytes(data)
        else:
            data_bytes = data.encode()

        key_bytes = key.encode() if not input_hex else _hex_to_bytes(key)
        result = bytes(a ^ b for a, b in zip(data_bytes, key_bytes * (len(data_bytes) // len(key_bytes) + 1)))

        # Try to decode as string, otherwise return hex
        try:
            return f"String: {result.decode()}\nHex: {result.hex()}"
        except UnicodeDecodeError:
            return f"Hex: {result.hex()}"

    @dangerous_operation(
        risk_level=RiskLevel.MEDIUM,
        description="XOR bruteforce can be used to break weak encryption"
    )
    def xor_single_byte_bruteforce(self, data: str, input_hex: bool = True) -> str:
        """Bruteforce single-byte XOR"""
        if input_hex:
            data_bytes = _hex_to_bytes(data)
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
            except UnicodeDecodeError:
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

    def _fermat_factor(self, n: int, max_iterations: int = FERMAT_MAX_ITERATIONS) -> tuple:
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
                except (ValueError, OverflowError):
                    pass
            else:
                try:
                    hex_str = hex(m)[2:]
                    if len(hex_str) % 2:
                        hex_str = '0' + hex_str
                    plaintext = bytes.fromhex(hex_str)
                    results.append(f"m (bytes) = {plaintext}")
                    results.append(f"m (string) = {plaintext.decode('utf-8', errors='replace')}")
                except (ValueError, OverflowError):
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
        except (ValueError, OverflowError):
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

    # === Additional Encoding Methods ===

    def base58_encode(self, data: str) -> str:
        """Base58 encode (Bitcoin alphabet)"""
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        data_bytes = data.encode()

        # Count leading zeros
        leading_zeros = 0
        for byte in data_bytes:
            if byte == 0:
                leading_zeros += 1
            else:
                break

        # Convert to integer
        num = int.from_bytes(data_bytes, 'big')

        # Convert to base58
        result = ''
        while num > 0:
            num, remainder = divmod(num, 58)
            result = alphabet[remainder] + result

        return '1' * leading_zeros + result

    def base58_decode(self, data: str) -> str:
        """Base58 decode"""
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

        # Count leading '1's
        leading_ones = 0
        for char in data:
            if char == '1':
                leading_ones += 1
            else:
                break

        # Convert from base58
        num = 0
        for char in data:
            num = num * 58 + alphabet.index(char)

        # Convert to bytes
        result = num.to_bytes((num.bit_length() + 7) // 8, 'big')
        result = b'\x00' * leading_ones + result

        try:
            return result.decode('utf-8', errors='replace')
        except (UnicodeDecodeError, ValueError):
            return result.hex()

    def base85_encode(self, data: str) -> str:
        """Base85/ASCII85 encode"""
        return base64.b85encode(data.encode()).decode()

    def base85_decode(self, data: str) -> str:
        """Base85/ASCII85 decode"""
        try:
            return base64.b85decode(data).decode('utf-8', errors='replace')
        except Exception as e:
            # Try a85 format
            try:
                return base64.a85decode(data).decode('utf-8', errors='replace')
            except Exception:
                return f"Decode error: {e}"

    # === Additional Classical Ciphers ===

    def rail_fence(self, text: str, rails: int = 3, decrypt: bool = False) -> str:
        """Rail fence cipher"""
        if decrypt:
            # Decrypt
            result = [''] * len(text)
            rail_lengths = [0] * rails

            # Calculate length of each rail
            idx = 0
            direction = 1
            for i in range(len(text)):
                rail_lengths[idx] += 1
                idx += direction
                if idx == rails - 1 or idx == 0:
                    direction = -direction

            # Fill the rails
            pos = 0
            rails_data = []
            for length in rail_lengths:
                rails_data.append(text[pos:pos + length])
                pos += length

            # Read in zigzag
            rail_pos = [0] * rails
            idx = 0
            direction = 1
            for i in range(len(text)):
                result[i] = rails_data[idx][rail_pos[idx]]
                rail_pos[idx] += 1
                idx += direction
                if idx == rails - 1 or idx == 0:
                    direction = -direction

            return ''.join(result)
        else:
            # Encrypt
            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1

            for char in text:
                fence[rail].append(char)
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction = -direction

            return ''.join([''.join(rail) for rail in fence])

    def rail_fence_bruteforce(self, text: str, max_rails: int = 10) -> str:
        """Bruteforce rail fence cipher"""
        results = ["Rail Fence Cipher Bruteforce:", "-" * 40]
        for rails in range(2, min(max_rails + 1, len(text))):
            decrypted = self.rail_fence(text, rails, decrypt=True)
            results.append(f"Rails {rails:2d}: {decrypted}")
        return '\n'.join(results)

    def bacon(self, text: str, decrypt: bool = False) -> str:
        """Bacon cipher (5-bit binary)"""
        bacon_dict = {
            'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB',
            'E': 'AABAA', 'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB',
            'I': 'ABAAA', 'J': 'ABAAB', 'K': 'ABABA', 'L': 'ABABB',
            'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA', 'P': 'ABBBB',
            'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
            'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB',
            'Y': 'BBAAA', 'Z': 'BBAAB'
        }

        if decrypt:
            # Normalize input
            text = text.upper().replace('0', 'A').replace('1', 'B')
            text = ''.join(c for c in text if c in 'AB')

            reverse_dict = {v: k for k, v in bacon_dict.items()}
            result = []
            for i in range(0, len(text) - 4, 5):
                chunk = text[i:i+5]
                if chunk in reverse_dict:
                    result.append(reverse_dict[chunk])
                else:
                    result.append('?')
            return ''.join(result)
        else:
            result = []
            for char in text.upper():
                if char in bacon_dict:
                    result.append(bacon_dict[char])
            return ' '.join(result)

    def playfair(self, text: str, key: str, decrypt: bool = False) -> str:
        """Playfair cipher"""
        # Create the 5x5 key square
        key = key.upper().replace('J', 'I')
        key = ''.join(dict.fromkeys(key + string.ascii_uppercase.replace('J', '')))

        matrix = [list(key[i:i+5]) for i in range(0, 25, 5)]

        def find_position(char):
            for i, row in enumerate(matrix):
                if char in row:
                    return i, row.index(char)
            return None

        # Prepare text
        text = text.upper().replace('J', 'I')
        text = ''.join(c for c in text if c.isalpha())

        # Split into digraphs
        digraphs = []
        i = 0
        while i < len(text):
            a = text[i]
            if i + 1 < len(text):
                b = text[i + 1]
                if a == b:
                    digraphs.append(a + 'X')
                    i += 1
                else:
                    digraphs.append(a + b)
                    i += 2
            else:
                digraphs.append(a + 'X')
                i += 1

        result = []
        for digraph in digraphs:
            r1, c1 = find_position(digraph[0])
            r2, c2 = find_position(digraph[1])

            if r1 == r2:  # Same row
                if decrypt:
                    result.append(matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5])
                else:
                    result.append(matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5])
            elif c1 == c2:  # Same column
                if decrypt:
                    result.append(matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2])
                else:
                    result.append(matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2])
            else:  # Rectangle
                result.append(matrix[r1][c2] + matrix[r2][c1])

        return ''.join(result)

    def hill_cipher(self, text: str, key: str, decrypt: bool = False) -> str:
        """Hill cipher with 2x2 matrix (key = 4 letters like 'GYBN')"""
        text = text.upper()
        text = ''.join(c for c in text if c.isalpha())
        if len(text) % 2:
            text += 'X'

        key = key.upper()
        if len(key) != 4:
            return "Key must be 4 letters for 2x2 matrix"

        # Convert key to matrix
        k = [ord(c) - ord('A') for c in key]
        km = [[k[0], k[1]], [k[2], k[3]]]

        det = (km[0][0] * km[1][1] - km[0][1] * km[1][0]) % 26

        if decrypt:
            # Find modular inverse of determinant
            try:
                det_inv = pow(det, -1, 26)
            except (ValueError, ArithmeticError):
                return "Matrix is not invertible mod 26"

            # Adjugate matrix
            adj = [[km[1][1], -km[0][1]], [-km[1][0], km[0][0]]]
            inv_m = [[(det_inv * adj[i][j]) % 26 for j in range(2)] for i in range(2)]
            matrix = inv_m
        else:
            matrix = km

        result = []
        for i in range(0, len(text), 2):
            p = [ord(text[i]) - ord('A'), ord(text[i+1]) - ord('A')]
            c = [(matrix[0][0] * p[0] + matrix[0][1] * p[1]) % 26,
                 (matrix[1][0] * p[0] + matrix[1][1] * p[1]) % 26]
            result.append(chr(c[0] + ord('A')) + chr(c[1] + ord('A')))

        return ''.join(result)

    def polybius(self, text: str, decrypt: bool = False) -> str:
        """Polybius square cipher (5x5, I=J)"""
        square = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # No J

        if decrypt:
            # Input should be pairs of digits 11-55
            text = ''.join(c for c in text if c.isdigit())
            result = []
            for i in range(0, len(text) - 1, 2):
                row = int(text[i]) - 1
                col = int(text[i+1]) - 1
                if 0 <= row < 5 and 0 <= col < 5:
                    result.append(square[row * 5 + col])
            return ''.join(result)
        else:
            result = []
            text = text.upper().replace('J', 'I')
            for char in text:
                if char in square:
                    idx = square.index(char)
                    result.append(f"{idx // 5 + 1}{idx % 5 + 1}")
            return ' '.join(result)

    def morse(self, text: str, decrypt: bool = False) -> str:
        """Morse code"""
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....',
            '7': '--...', '8': '---..', '9': '----.', ' ': '/'
        }

        if decrypt:
            reverse_dict = {v: k for k, v in morse_dict.items()}
            words = text.split('/')
            result = []
            for word in words:
                letters = word.strip().split()
                for code in letters:
                    result.append(reverse_dict.get(code, '?'))
                result.append(' ')
            return ''.join(result).strip()
        else:
            result = []
            for char in text.upper():
                if char in morse_dict:
                    result.append(morse_dict[char])
            return ' '.join(result)

    def tap_code(self, text: str, decrypt: bool = False) -> str:
        """Tap code (Polybius-based, K=C)"""
        grid = "ABCDEFGHIJLMNOPQRSTUVWXYZ"  # No K (K=C)

        if decrypt:
            # Input like ".. ... / ... .." or "2,3 3,2"
            text = text.replace(',', ' ').replace('/', ' / ')
            pairs = []
            current = []
            for part in text.split():
                if part == '/':
                    if current:
                        pairs.append(current)
                        current = []
                    pairs.append(' ')
                else:
                    taps = len(part) if '.' in part else int(part)
                    current.append(taps)
                    if len(current) == 2:
                        pairs.append(current)
                        current = []
            if current:
                pairs.append(current)

            result = []
            for pair in pairs:
                if pair == ' ':
                    result.append(' ')
                elif isinstance(pair, list) and len(pair) == 2:
                    idx = (pair[0] - 1) * 5 + (pair[1] - 1)
                    if 0 <= idx < 25:
                        result.append(grid[idx])
            return ''.join(result)
        else:
            result = []
            for char in text.upper():
                if char == 'K':
                    char = 'C'
                if char in grid:
                    idx = grid.index(char)
                    row = idx // 5 + 1
                    col = idx % 5 + 1
                    result.append(f"{'.' * row} {'.' * col}")
                elif char == ' ':
                    result.append('/')
            return ' / '.join(result)

    def vigenere_key_length(self, text: str, max_length: int = 20) -> str:
        """Detect Vigenere key length using Kasiski examination and IC"""
        text = ''.join(c.lower() for c in text if c.isalpha())

        results = ["Vigenere Key Length Analysis:", "-" * 40, ""]

        # Method 1: Index of Coincidence for each key length
        results.append("Index of Coincidence method:")
        ic_scores = []

        for key_len in range(1, min(max_length + 1, len(text) // 2)):
            avg_ic = 0
            for i in range(key_len):
                substring = text[i::key_len]
                if len(substring) > 1:
                    freq = Counter(substring)
                    n = len(substring)
                    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
                    avg_ic += ic
            avg_ic /= key_len
            ic_scores.append((key_len, avg_ic))
            results.append(f"  Key length {key_len:2d}: IC = {avg_ic:.4f}")

        # Find best candidates
        sorted_scores = sorted(ic_scores, key=lambda x: abs(x[1] - 0.0667))
        results.append(f"\nMost likely key lengths (closest to 0.0667):")
        for kl, ic in sorted_scores[:5]:
            results.append(f"  Length {kl}: IC = {ic:.4f}")

        return '\n'.join(results)

    def substitution_analyze(self, text: str) -> str:
        """Analyze substitution cipher"""
        text_letters = ''.join(c.lower() for c in text if c.isalpha())

        results = ["Substitution Cipher Analysis:", "-" * 40, ""]

        # Frequency analysis
        freq = Counter(text_letters)
        total = len(text_letters)
        sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)

        results.append("Letter frequency:")
        for letter, count in sorted_freq:
            pct = count / total * 100
            results.append(f"  {letter.upper()}: {pct:5.2f}% ({count})")

        # Common patterns
        english_freq = 'etaoinshrdlcumwfgypbvkjxqz'
        cipher_freq = ''.join(l for l, _ in sorted_freq)

        results.append(f"\nEnglish frequency: {english_freq.upper()}")
        results.append(f"Cipher frequency:  {cipher_freq.upper()}")

        # Suggest mapping
        results.append("\nSuggested initial mapping:")
        for i, (c_letter, e_letter) in enumerate(zip(cipher_freq[:10], english_freq[:10])):
            results.append(f"  {c_letter.upper()} -> {e_letter.upper()}")

        # Bigram analysis
        results.append("\nCommon bigrams in ciphertext:")
        bigrams = Counter(text_letters[i:i+2] for i in range(len(text_letters)-1))
        for bg, count in bigrams.most_common(10):
            results.append(f"  {bg.upper()}: {count}")

        results.append("\nCommon English bigrams: TH HE IN ER AN RE")

        return '\n'.join(results)

    # === Modern Cryptography ===

    def aes_encrypt(self, plaintext: str, key: str, mode: str = "ECB",
                    iv: str = None, output_hex: bool = True) -> str:
        """AES encryption"""
        if not PYCRYPTODOME_AVAILABLE:
            return "PyCryptodome not available. Install with: pip install pycryptodome"

        # Prepare key (pad or truncate to 16/24/32 bytes)
        key_bytes = key.encode()
        if len(key_bytes) <= 16:
            key_bytes = key_bytes.ljust(16, b'\x00')
        elif len(key_bytes) <= 24:
            key_bytes = key_bytes.ljust(24, b'\x00')
        else:
            key_bytes = key_bytes[:32].ljust(32, b'\x00')

        plaintext_bytes = plaintext.encode()

        try:
            if mode.upper() == "ECB":
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                ct = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
            elif mode.upper() == "CBC":
                if iv:
                    iv_bytes = iv.encode()[:16].ljust(16, b'\x00')
                else:
                    iv_bytes = b'\x00' * 16
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
                ct = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
            else:
                return f"Unsupported mode: {mode}. Use ECB or CBC."

            if output_hex:
                return f"Ciphertext (hex): {ct.hex()}"
            else:
                return f"Ciphertext (base64): {base64.b64encode(ct).decode()}"
        except Exception as e:
            return f"Encryption error: {e}"

    def aes_decrypt(self, ciphertext: str, key: str, mode: str = "ECB",
                    iv: str = None, input_hex: bool = True) -> str:
        """AES decryption"""
        if not PYCRYPTODOME_AVAILABLE:
            return "PyCryptodome not available"

        # Prepare key
        key_bytes = key.encode()
        if len(key_bytes) <= 16:
            key_bytes = key_bytes.ljust(16, b'\x00')
        elif len(key_bytes) <= 24:
            key_bytes = key_bytes.ljust(24, b'\x00')
        else:
            key_bytes = key_bytes[:32].ljust(32, b'\x00')

        try:
            if input_hex:
                ct_bytes = _hex_to_bytes(ciphertext)
            else:
                ct_bytes = base64.b64decode(ciphertext)

            if mode.upper() == "ECB":
                cipher = AES.new(key_bytes, AES.MODE_ECB)
            elif mode.upper() == "CBC":
                if iv:
                    iv_bytes = iv.encode()[:16].ljust(16, b'\x00')
                else:
                    iv_bytes = b'\x00' * 16
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            else:
                return f"Unsupported mode: {mode}"

            pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
            return f"Plaintext: {pt.decode('utf-8', errors='replace')}"
        except Exception as e:
            return f"Decryption error: {e}"

    @dangerous_operation(
        risk_level=RiskLevel.MEDIUM,
        description="DES is deprecated and insecure (56-bit key, vulnerable to brute force)"
    )
    def des_encrypt(self, plaintext: str, key: str, output_hex: bool = True) -> str:
        """DES encryption (ECB mode)"""
        if not PYCRYPTODOME_AVAILABLE:
            return "PyCryptodome not available"

        key_bytes = key.encode()[:8].ljust(8, b'\x00')
        plaintext_bytes = plaintext.encode()

        try:
            cipher = DES.new(key_bytes, DES.MODE_ECB)
            ct = cipher.encrypt(pad(plaintext_bytes, DES.block_size))

            if output_hex:
                return f"Ciphertext (hex): {ct.hex()}"
            else:
                return f"Ciphertext (base64): {base64.b64encode(ct).decode()}"
        except Exception as e:
            return f"Encryption error: {e}"

    @dangerous_operation(
        risk_level=RiskLevel.MEDIUM,
        description="DES is deprecated and insecure (56-bit key, vulnerable to brute force)"
    )
    def des_decrypt(self, ciphertext: str, key: str, input_hex: bool = True) -> str:
        """DES decryption (ECB mode)"""
        if not PYCRYPTODOME_AVAILABLE:
            return "PyCryptodome not available"

        key_bytes = key.encode()[:8].ljust(8, b'\x00')

        try:
            if input_hex:
                ct_bytes = _hex_to_bytes(ciphertext)
            else:
                ct_bytes = base64.b64decode(ciphertext)

            cipher = DES.new(key_bytes, DES.MODE_ECB)
            pt = unpad(cipher.decrypt(ct_bytes), DES.block_size)
            return f"Plaintext: {pt.decode('utf-8', errors='replace')}"
        except Exception as e:
            return f"Decryption error: {e}"

    @dangerous_operation(
        risk_level=RiskLevel.MEDIUM,
        description="RC4 is deprecated and has known vulnerabilities (biased keystream, related-key attacks)"
    )
    def rc4(self, data: str, key: str, input_hex: bool = False) -> str:
        """RC4 stream cipher"""
        if not PYCRYPTODOME_AVAILABLE:
            return "PyCryptodome not available"

        try:
            if input_hex:
                data_bytes = _hex_to_bytes(data)
            else:
                data_bytes = data.encode()

            cipher = ARC4.new(key.encode())
            result = cipher.encrypt(data_bytes)

            try:
                return f"Result (string): {result.decode()}\nResult (hex): {result.hex()}"
            except (UnicodeDecodeError, ValueError):
                return f"Result (hex): {result.hex()}"
        except Exception as e:
            return f"RC4 error: {e}"

    # === Additional RSA Attacks ===

    def rsa_wiener(self, n: str, e: str) -> str:
        """Wiener's attack for small private exponent d"""
        n, e = int(n), int(e)

        results = ["RSA Wiener Attack:", "-" * 40, f"n = {n}", f"e = {e}", ""]

        if not SYMPY_AVAILABLE:
            results.append("Note: SymPy not available, using basic implementation")

        def convergents(cf):
            """Generate convergents from continued fraction"""
            n0, n1 = 0, 1
            d0, d1 = 1, 0
            for a in cf:
                n2 = a * n1 + n0
                d2 = a * d1 + d0
                yield n2, d2
                n0, n1 = n1, n2
                d0, d1 = d1, d2

        def continued_fraction(num, den):
            """Generate continued fraction expansion"""
            while den:
                q = num // den
                yield q
                num, den = den, num - q * den

        # Generate convergents of e/n
        cf = list(continued_fraction(e, n))

        for k, d in convergents(cf):
            if k == 0:
                continue

            # Check if phi = (ed - 1) / k is valid
            if (e * d - 1) % k != 0:
                continue

            phi = (e * d - 1) // k

            # Check if n = pq where phi = (p-1)(q-1)
            # p + q = n - phi + 1
            # p * q = n
            s = n - phi + 1
            discriminant = s * s - 4 * n

            if discriminant >= 0:
                sqrt_disc = isqrt(discriminant)
                if sqrt_disc * sqrt_disc == discriminant:
                    p = (s + sqrt_disc) // 2
                    q = (s - sqrt_disc) // 2

                    if p * q == n and p > 1 and q > 1:
                        results.append("[!] Attack successful!")
                        results.append(f"d = {d}")
                        results.append(f"p = {p}")
                        results.append(f"q = {q}")
                        results.append(f"phi = {phi}")
                        return '\n'.join(results)

        results.append("[-] Wiener attack failed (d might not be small enough)")
        results.append("Condition: d < (1/3) * n^(1/4)")
        return '\n'.join(results)

    def rsa_hastad(self, moduli: str, ciphertexts: str, e: int = 3) -> str:
        """Hastad's broadcast attack (same message, different moduli, small e)"""
        results = ["RSA Hastad Broadcast Attack:", "-" * 40, f"e = {e}", ""]

        # Parse input
        n_list = [int(x.strip()) for x in moduli.split(',')]
        c_list = [int(x.strip()) for x in ciphertexts.split(',')]

        if len(n_list) < e or len(c_list) < e:
            return f"Need at least {e} (n, c) pairs for e = {e}"

        n_list = n_list[:e]
        c_list = c_list[:e]

        results.append(f"Using {e} (n, c) pairs")

        # Chinese Remainder Theorem
        def crt_solve(remainders, moduli):
            """Chinese Remainder Theorem"""
            N = 1
            for n in moduli:
                N *= n

            result = 0
            for c_i, n_i in zip(remainders, moduli):
                N_i = N // n_i
                try:
                    if PYCRYPTODOME_AVAILABLE:
                        y_i = inverse(N_i, n_i)
                    else:
                        y_i = pow(N_i, -1, n_i)
                    result += c_i * N_i * y_i
                except (ValueError, ArithmeticError):
                    return None, None
            return result % N, N

        m_e, _ = crt_solve(c_list, n_list)

        if m_e is None:
            return "CRT failed - moduli might not be coprime"

        # Take e-th root
        if GMPY2_AVAILABLE:
            m, exact = gmpy2.iroot(m_e, e)
            if exact:
                results.append("[!] Attack successful!")
                results.append(f"m^{e} = {m_e}")
                results.append(f"m = {m}")

                # Convert to string
                try:
                    if PYCRYPTODOME_AVAILABLE:
                        plaintext = long_to_bytes(int(m))
                    else:
                        hex_str = hex(int(m))[2:]
                        if len(hex_str) % 2:
                            hex_str = '0' + hex_str
                        plaintext = bytes.fromhex(hex_str)
                    results.append(f"Plaintext: {plaintext.decode('utf-8', errors='replace')}")
                except (ValueError, UnicodeDecodeError):
                    pass
                return '\n'.join(results)
        else:
            # Basic integer root
            m = int(m_e ** (1/e))
            for delta in range(-2, 3):
                if (m + delta) ** e == m_e:
                    results.append("[!] Attack successful!")
                    results.append(f"m = {m + delta}")
                    return '\n'.join(results)

        results.append("[-] Could not find exact e-th root")
        return '\n'.join(results)

    def rsa_low_exponent(self, n: str, e: str, c: str) -> str:
        """Attack when e is small and m^e < n"""
        n, e, c = int(n), int(e), int(c)

        results = ["RSA Low Exponent Attack:", "-" * 40]
        results.append(f"n = {n}")
        results.append(f"e = {e}")
        results.append(f"c = {c}")
        results.append("")

        # If m^e < n, then c = m^e (no mod)
        if GMPY2_AVAILABLE:
            m, exact = gmpy2.iroot(c, e)
            if exact:
                results.append("[!] Attack successful! (m^e < n)")
                results.append(f"m = {m}")

                try:
                    if PYCRYPTODOME_AVAILABLE:
                        plaintext = long_to_bytes(int(m))
                    else:
                        hex_str = hex(int(m))[2:]
                        if len(hex_str) % 2:
                            hex_str = '0' + hex_str
                        plaintext = bytes.fromhex(hex_str)
                    results.append(f"Plaintext: {plaintext.decode('utf-8', errors='replace')}")
                except (ValueError, UnicodeDecodeError):
                    pass
                return '\n'.join(results)

        results.append("[-] Simple root extraction failed")
        results.append("The message might be padded or m^e > n")
        return '\n'.join(results)

    def rsa_franklin_reiter(self, n: str, e: str, c1: str, c2: str,
                            a: str = "1", b: str = None) -> str:
        """Franklin-Reiter related message attack: m2 = a*m1 + b"""
        results = ["RSA Franklin-Reiter Attack:", "-" * 40]
        results.append("Condition: m2 = a*m1 + b (linear relation)")
        results.append("")

        n, e = int(n), int(e)
        c1, c2, a = int(c1), int(c2), int(a)

        if b is None:
            results.append("Need parameter b (m2 = a*m1 + b)")
            results.append("Common case: a=1, b=1 (m2 = m1 + 1)")
            return '\n'.join(results)

        b = int(b)

        if e != 3:
            results.append("Note: This implementation works best with e=3")

        # For e=3: gcd(x^3 - c1, (ax + b)^3 - c2) mod n
        # This gives us m1

        results.append("This attack requires polynomial GCD computation.")
        results.append("Use SageMath or the following approach:")
        results.append("")
        results.append("```python")
        results.append("from Crypto.Util.number import *")
        results.append(f"n = {n}")
        results.append(f"e = {e}")
        results.append(f"c1 = {c1}")
        results.append(f"c2 = {c2}")
        results.append(f"a = {a}")
        results.append(f"b = {b}")
        results.append("")
        results.append("# In SageMath:")
        results.append("# R.<x> = PolynomialRing(Zmod(n))")
        results.append("# f1 = x^e - c1")
        results.append(f"# f2 = (a*x + b)^e - c2")
        results.append("# m1 = -gcd(f1, f2).monic().coefficients()[0]")
        results.append("```")

        return '\n'.join(results)

    def rsa_parity_oracle(self, n: str, e: str, c: str) -> str:
        """RSA parity oracle attack template"""
        n, e, c = int(n), int(e), int(c)

        results = ["RSA Parity Oracle Attack Template:", "-" * 40]
        results.append("")
        results.append("This attack exploits an oracle that reveals if m is odd/even.")
        results.append("We can recover m bit by bit using binary search.")
        results.append("")
        results.append("```python")
        results.append("from Crypto.Util.number import *")
        results.append(f"n = {n}")
        results.append(f"e = {e}")
        results.append(f"c = {c}")
        results.append("")
        results.append("def oracle(ct):")
        results.append("    # Returns True if decryption is even")
        results.append("    # Implement based on challenge")
        results.append("    pass")
        results.append("")
        results.append("# Attack")
        results.append("multiplier = pow(2, e, n)")
        results.append("lo, hi = 0, n")
        results.append("ct = c")
        results.append("")
        results.append("for _ in range(n.bit_length()):")
        results.append("    ct = (ct * multiplier) % n")
        results.append("    if oracle(ct):  # Even -> m < n/2")
        results.append("        hi = (lo + hi) // 2")
        results.append("    else:  # Odd -> m >= n/2")
        results.append("        lo = (lo + hi) // 2")
        results.append("")
        results.append("m = hi")
        results.append("print(long_to_bytes(m))")
        results.append("```")

        return '\n'.join(results)

    def rsa_bleichenbacher(self, n: str, e: str, signature: str = None) -> str:
        """RSA Bleichenbacher's e=3 signature forgery attack"""
        n, e = int(n), int(e)

        results = ["RSA Bleichenbacher Signature Attack:", "-" * 40]
        results.append("Attack on PKCS#1 v1.5 signature with e=3")
        results.append("")

        if e != 3:
            results.append(f"Warning: e={e}, attack works best with e=3")

        results.append("Vulnerable signature verification:")
        results.append("  s^e = 0001ff...ff00<hash_prefix><hash> (mod n)")
        results.append("")
        results.append("If verification only checks prefix (not trailing garbage):")
        results.append("  We can forge: s = cube_root(0001ff...ff00<prefix><hash><garbage>)")
        results.append("")
        results.append("```python")
        results.append("import hashlib")
        results.append("from Crypto.Util.number import *")
        results.append("")
        results.append("# SHA-256 ASN.1 prefix")
        results.append("sha256_prefix = bytes.fromhex('3031300d060960864801650304020105000420')")
        results.append("")
        results.append("message = b'message to sign'")
        results.append("h = hashlib.sha256(message).digest()")
        results.append("")
        results.append("# Craft block: 0001ff00<prefix><hash><garbage>")
        results.append("block = b'\\x00\\x01\\xff\\x00' + sha256_prefix + h")
        results.append("block = block + b'\\x00' * (256 - len(block))  # pad to key size")
        results.append("")
        results.append("# Find cube root")
        results.append("block_int = bytes_to_long(block)")
        results.append("sig = gmpy2.iroot(block_int, 3)[0] + 1  # round up")
        results.append("")
        results.append("# Verify: sig^3 should start with our prefix")
        results.append("print(long_to_bytes(pow(sig, 3))[:50].hex())")
        results.append("```")

        return '\n'.join(results)

    # === Hash utilities ===

    def hash_identify(self, hash_str: str) -> str:
        """Identify hash type by format"""
        hash_str = hash_str.strip().lower()
        length = len(hash_str)

        results = ["Hash Type Identification:", "-" * 40, f"Input: {hash_str}", f"Length: {length} characters", ""]

        hash_types = []

        if length == 32:
            hash_types.append("MD5")
            hash_types.append("NTLM")
            hash_types.append("MD4")
        elif length == 40:
            hash_types.append("SHA-1")
            hash_types.append("MySQL5")
        elif length == 56:
            hash_types.append("SHA-224")
        elif length == 64:
            hash_types.append("SHA-256")
            hash_types.append("SHA3-256")
            hash_types.append("RIPEMD-256")
        elif length == 96:
            hash_types.append("SHA-384")
            hash_types.append("SHA3-384")
        elif length == 128:
            hash_types.append("SHA-512")
            hash_types.append("SHA3-512")
            hash_types.append("Whirlpool")

        # Check for specific formats
        if hash_str.startswith('$1$'):
            hash_types.insert(0, "MD5crypt (Unix)")
        elif hash_str.startswith('$2a$') or hash_str.startswith('$2b$'):
            hash_types.insert(0, "bcrypt")
        elif hash_str.startswith('$5$'):
            hash_types.insert(0, "SHA-256crypt (Unix)")
        elif hash_str.startswith('$6$'):
            hash_types.insert(0, "SHA-512crypt (Unix)")
        elif hash_str.startswith('$apr1$'):
            hash_types.insert(0, "Apache MD5")
        elif ':' in hash_str:
            parts = hash_str.split(':')
            if len(parts) == 2 and len(parts[0]) == 32:
                hash_types.insert(0, "MD5 with salt (hash:salt)")

        if hash_types:
            results.append("Possible hash types:")
            for ht in hash_types:
                results.append(f"  - {ht}")
        else:
            results.append("Unknown hash type")

        results.append("")
        results.append("Tools to crack:")
        results.append("  - hashcat")
        results.append("  - john the ripper")
        results.append("  - crackstation.net")

        return '\n'.join(results)

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="Hash cracking can be used to compromise passwords and authentication"
    )
    def hash_crack(self, hash_str: str, wordlist: str = None) -> str:
        """Attempt to crack hash with common passwords"""
        hash_str = hash_str.strip().lower()

        # Default wordlist
        common_passwords = [
            "password", "123456", "password1", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "qwerty",
            "login", "passw0rd", "hello", "shadow", "sunshine",
            "princess", "football", "superman", "iloveyou", "trustno1",
            "abc123", "123456789", "12345678", "password123", "1234567890",
            "flag", "ctf", "flag{", "CTF{", "test", "root", "toor"
        ]

        if wordlist:
            common_passwords = wordlist.split(',')

        results = ["Hash Cracking Attempt:", "-" * 40, f"Hash: {hash_str}", ""]

        # Detect hash type
        length = len(hash_str)
        hash_funcs = []

        if length == 32:
            hash_funcs.append(("MD5", hashlib.md5))
        if length == 40:
            hash_funcs.append(("SHA1", hashlib.sha1))
        if length == 64:
            hash_funcs.append(("SHA256", hashlib.sha256))
        if length == 128:
            hash_funcs.append(("SHA512", hashlib.sha512))

        for name, func in hash_funcs:
            for password in common_passwords:
                if func(password.encode()).hexdigest() == hash_str:
                    results.append(f"[!] CRACKED!")
                    results.append(f"Hash type: {name}")
                    results.append(f"Password: {password}")
                    return '\n'.join(results)

        results.append("[-] No match found in wordlist")
        results.append(f"Tried {len(common_passwords)} passwords")
        results.append("")
        results.append("Try online services:")
        results.append("  - crackstation.net")
        results.append("  - hashes.com")
        results.append("  - cmd5.com")

        return '\n'.join(results)

    # === Additional Analysis ===

    def entropy(self, data: str) -> str:
        """Calculate Shannon entropy"""
        if not data:
            return "Empty input"

        freq = Counter(data)
        length = len(data)

        entropy_val = -sum((count / length) * log2(count / length)
                       for count in freq.values())

        max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1

        results = [
            "Entropy Analysis:",
            "-" * 40,
            f"Length: {length} characters",
            f"Unique characters: {len(freq)}",
            f"Entropy: {entropy_val:.4f} bits/symbol",
            f"Max possible entropy: {max_entropy:.4f} bits/symbol",
            f"Randomness: {entropy_val / max_entropy * 100:.1f}%" if max_entropy > 0 else "",
            "",
            "Reference:",
            "  English text: ~4.0-5.0 bits/char",
            "  Random data:  ~7.5-8.0 bits/byte",
            "  Compressed:   ~7.5+ bits/byte",
        ]

        if entropy_val < 4:
            results.append("\n=> Low entropy, likely natural language or simple encoding")
        elif entropy_val < 6:
            results.append("\n=> Medium entropy, possibly encoded or simple encryption")
        else:
            results.append("\n=> High entropy, likely encrypted or compressed")

        return '\n'.join(results)

    # === Math Helpers ===

    def mod_inverse(self, a: str, m: str) -> str:
        """Calculate modular inverse of a mod m"""
        a, m = int(a), int(m)

        try:
            if PYCRYPTODOME_AVAILABLE:
                inv = inverse(a, m)
            else:
                inv = pow(a, -1, m)
            return f"Modular inverse of {a} mod {m} = {inv}"
        except (ValueError, ArithmeticError):
            return f"No modular inverse exists (gcd({a}, {m}) != 1)"

    def crt(self, remainders: str, moduli: str) -> str:
        """Chinese Remainder Theorem solver"""
        rem_list = [int(x.strip()) for x in remainders.split(',')]
        mod_list = [int(x.strip()) for x in moduli.split(',')]

        if len(rem_list) != len(mod_list):
            return "Number of remainders must equal number of moduli"

        results = ["Chinese Remainder Theorem:", "-" * 40]
        for r, m in zip(rem_list, mod_list):
            results.append(f"  x = {r} (mod {m})")
        results.append("")

        # Check pairwise coprimality
        for i in range(len(mod_list)):
            for j in range(i + 1, len(mod_list)):
                if gcd(mod_list[i], mod_list[j]) != 1:
                    results.append(f"Warning: gcd({mod_list[i]}, {mod_list[j]}) != 1")

        # Solve
        N = 1
        for m in mod_list:
            N *= m

        result = 0
        for r_i, m_i in zip(rem_list, mod_list):
            N_i = N // m_i
            try:
                if PYCRYPTODOME_AVAILABLE:
                    y_i = inverse(N_i, m_i)
                else:
                    y_i = pow(N_i, -1, m_i)
                result += r_i * N_i * y_i
            except (ValueError, ArithmeticError):
                results.append("CRT failed - moduli not coprime")
                return '\n'.join(results)

        result = result % N
        results.append(f"x = {result} (mod {N})")
        results.append(f"\nSmallest positive solution: x = {result}")

        return '\n'.join(results)

    def discrete_log(self, g: str, h: str, p: str) -> str:
        """Discrete logarithm using baby-step giant-step"""
        g, h, p = int(g), int(h), int(p)

        results = ["Discrete Logarithm (Baby-step Giant-step):", "-" * 40]
        results.append(f"Find x such that {g}^x = {h} (mod {p})")
        results.append("")

        m = isqrt(p) + 1

        # Baby step: compute g^j mod p for j = 0, 1, ..., m-1
        baby_steps = {}
        val = 1
        for j in range(m):
            baby_steps[val] = j
            val = (val * g) % p

        # Giant step: compute h * (g^(-m))^i mod p
        try:
            if PYCRYPTODOME_AVAILABLE:
                factor = inverse(pow(g, m, p), p)
            else:
                factor = pow(pow(g, m, p), -1, p)
        except (ValueError, ArithmeticError):
            results.append("Cannot compute inverse")
            return '\n'.join(results)

        gamma = h
        for i in range(m):
            if gamma in baby_steps:
                x = i * m + baby_steps[gamma]
                results.append(f"[!] Found: x = {x}")
                results.append(f"Verification: {g}^{x} mod {p} = {pow(g, x, p)}")
                return '\n'.join(results)
            gamma = (gamma * factor) % p

        results.append("[-] No solution found in range")
        results.append(f"Searched up to x = {m * m}")

        return '\n'.join(results)

    def euler_phi(self, n: str) -> str:
        """Calculate Euler's totient function"""
        n = int(n)

        if n <= 0:
            return "n must be positive"

        results = [f"Euler's Totient phi({n}):", "-" * 40]

        if n == 1:
            results.append("phi(1) = 1")
            return '\n'.join(results)

        # Factor n
        result = n
        temp = n
        factors = []

        p = 2
        while p * p <= temp:
            if temp % p == 0:
                factors.append(p)
                result -= result // p
                while temp % p == 0:
                    temp //= p
            p += 1
        if temp > 1:
            factors.append(temp)
            result -= result // temp

        results.append(f"Prime factors: {factors}")
        results.append(f"phi({n}) = {result}")

        return '\n'.join(results)

    def primitive_root(self, n: str) -> str:
        """Find a primitive root modulo n"""
        n = int(n)

        results = [f"Primitive Root modulo {n}:", "-" * 40]

        # Calculate phi(n)
        phi = n - 1  # Assuming n is prime for simplicity

        # Factor phi
        temp = phi
        factors = set()
        p = 2
        while p * p <= temp:
            if temp % p == 0:
                factors.add(p)
                while temp % p == 0:
                    temp //= p
            p += 1
        if temp > 1:
            factors.add(temp)

        results.append(f"phi({n}) = {phi}")
        results.append(f"Factors of phi: {sorted(factors)}")
        results.append("")

        # Find primitive root
        for g in range(2, n):
            is_primitive = True
            for f in factors:
                if pow(g, phi // f, n) == 1:
                    is_primitive = False
                    break
            if is_primitive:
                results.append(f"Primitive root: {g}")
                return '\n'.join(results)

        results.append("No primitive root found (n might not be prime)")
        return '\n'.join(results)

    @dangerous_operation(
        risk_level=RiskLevel.MEDIUM,
        description="XOR repeating-key analysis can be used to break weak encryption"
    )
    def xor_repeating_key(self, ciphertext: str, key_length: int = None,
                          input_hex: bool = True) -> str:
        """Analyze XOR with repeating key"""
        if input_hex:
            ct = _hex_to_bytes(ciphertext)
        else:
            ct = ciphertext.encode()

        results = ["XOR Repeating Key Analysis:", "-" * 40]

        if key_length is None:
            # Try to detect key length using Hamming distance
            results.append("Detecting key length using Hamming distance...")
            results.append("")

            def hamming_distance(b1, b2):
                return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))

            scores = []
            for kl in range(2, min(40, len(ct) // 2)):
                blocks = [ct[i:i+kl] for i in range(0, len(ct) - kl, kl)]
                if len(blocks) < 2:
                    continue

                total_dist = 0
                comparisons = 0
                for i in range(min(4, len(blocks) - 1)):
                    total_dist += hamming_distance(blocks[i], blocks[i+1])
                    comparisons += 1

                avg_dist = (total_dist / comparisons) / kl
                scores.append((kl, avg_dist))

            scores.sort(key=lambda x: x[1])
            results.append("Most likely key lengths:")
            for kl, score in scores[:5]:
                results.append(f"  Length {kl}: normalized Hamming distance = {score:.4f}")

            if scores:
                key_length = scores[0][0]

        if key_length:
            results.append(f"\nAnalyzing with key length = {key_length}")
            results.append("")

            # Break into key_length groups
            key = []
            for i in range(key_length):
                group = bytes(ct[j] for j in range(i, len(ct), key_length))

                # Find best single-byte XOR for this group
                best_score = 0
                best_key = 0
                for k in range(256):
                    decrypted = bytes(b ^ k for b in group)
                    try:
                        decoded = decrypted.decode('ascii')
                        score = sum(1 for c in decoded.lower() if c in 'etaoinshrdlu ')
                        if score > best_score:
                            best_score = score
                            best_key = k
                    except (ValueError, UnicodeDecodeError):
                        pass
                key.append(best_key)

            results.append(f"Recovered key bytes: {bytes(key)}")
            results.append(f"Key (hex): {bytes(key).hex()}")

            try:
                key_str = bytes(key).decode('ascii')
                results.append(f"Key (ASCII): {key_str}")
            except (ValueError, UnicodeDecodeError):
                pass

            # Decrypt
            decrypted = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
            try:
                results.append(f"\nDecrypted: {decrypted.decode('utf-8', errors='replace')[:200]}...")
            except (UnicodeDecodeError, ValueError):
                results.append(f"\nDecrypted (hex): {decrypted.hex()[:100]}...")

        return '\n'.join(results)
