# CTF-MCP

A Model Context Protocol (MCP) server providing comprehensive tools for CTF (Capture The Flag) challenges.

## Features

### Crypto (53 tools)
- Base encoding (Base64, Base32, Base58, Base85)
- Classical ciphers (Caesar, Vigenere, Atbash, Affine, Rail Fence, Playfair, Hill)
- XOR operations and analysis
- Modern crypto (AES, DES, RC4)
- Hash functions and cracking
- RSA attacks (Wiener, Hastad, Common Modulus, Franklin-Reiter)
- Frequency analysis

### Web (46 tools)
- SQL Injection (Union, Error, Blind, Time-based)
- XSS payloads and filter bypass
- SSTI (Server-Side Template Injection)
- SSRF, XXE, Command Injection
- JWT attacks (None algorithm, Key confusion)
- Deserialization (PHP, Python Pickle, Java, Node.js)
- HTTP Smuggling, GraphQL, WebSocket
- OAuth, CORS, Cache Poisoning

### Pwn (27 tools)
- Shellcode generation (x64/x86)
- Cyclic pattern creation and offset finding
- ROP gadgets and chain building
- Format string exploits
- Heap exploitation (Tcache, Fastbin, House of Force/Spirit)
- Stack pivot techniques
- SROP (Sigreturn-oriented programming)
- Libc database and one_gadget

### Reverse
- Disassembly helpers
- String extraction
- Binary analysis

### Forensics
- File carving
- Memory analysis
- Network forensics

### Misc
- Encoding/decoding utilities
- Steganography helpers

## Installation

```bash
pip install -e .
```

## Usage

### As MCP Server
```bash
ctf-mcp
```

### In Python
```python
from ctf_mcp.tools.crypto import CryptoTools
from ctf_mcp.tools.web import WebTools
from ctf_mcp.tools.pwn import PwnTools

crypto = CryptoTools()
web = WebTools()
pwn = PwnTools()

# Example: Generate SQL injection payloads
print(web.sql_payloads("mysql", "union"))

# Example: Base64 encode
print(crypto.base64_encode("Hello CTF"))

# Example: Create cyclic pattern
print(pwn.pattern_create(100))
```

## MCP Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "ctf-mcp": {
      "command": "ctf-mcp"
    }
  }
}
```

## Requirements

- Python 3.10+
- mcp >= 1.0.0

## Author

**Coff0xc**

## License

MIT
