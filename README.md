# CTF-MCP

[English](#english) | [中文](#中文)

---

## English

A Model Context Protocol (MCP) server providing comprehensive tools for CTF (Capture The Flag) challenges.

## ⚠️ Security Warning

**IMPORTANT: This tool is designed for authorized security testing only.**

- ✅ **Authorized Use**: CTF competitions, penetration testing with written permission, security research, educational purposes
- ❌ **Prohibited Use**: Unauthorized access, malicious attacks, illegal activities

**Before using this tool:**
1. Ensure you have proper authorization
2. Read [SECURITY.md](SECURITY.md) for detailed security guidelines
3. Review [BEST_PRACTICES.md](BEST_PRACTICES.md) for usage recommendations
4. Understand the risk levels of tools you plan to use

**Risk Levels:**
- 🟢 LOW: Information gathering (safe)
- 🟡 MEDIUM: Vulnerability detection (requires authorization)
- 🟠 HIGH: Exploitation tools (explicit authorization required)
- 🔴 CRITICAL: RCE/Deserialization payloads (written authorization required)

**Security Audit Results:**
- 🔒 **Total Security Decorators**: 33 dangerous operations protected
- 🔴 **CRITICAL**: 14 tools (RCE, deserialization)
- 🟠 **HIGH**: 13 tools (exploitation, injection)
- 🟡 **MEDIUM**: 6 tools (weak crypto, code generation)
- See [SECURITY.md](SECURITY.md) for complete tool lists and descriptions

**By using CTF-MCP, you agree to use it responsibly and legally.**

### Features

#### Crypto (53 tools)
- Base encoding (Base64, Base32, Base58, Base85)
- Classical ciphers (Caesar, Vigenere, Atbash, Affine, Rail Fence, Playfair, Hill)
- XOR operations and analysis
- Modern crypto (AES, DES, RC4)
- Hash functions and cracking
- RSA attacks (Wiener, Hastad, Common Modulus, Franklin-Reiter)
- Frequency analysis

#### Web (46 tools)
- SQL Injection (Union, Error, Blind, Time-based)
- XSS payloads and filter bypass
- SSTI (Server-Side Template Injection)
- SSRF, XXE, Command Injection
- JWT attacks (None algorithm, Key confusion)
- Deserialization (PHP, Python Pickle, Java, Node.js)
- HTTP Smuggling, GraphQL, WebSocket
- OAuth, CORS, Cache Poisoning

#### Pwn (27 tools)
- Shellcode generation (x64/x86)
- Cyclic pattern creation and offset finding
- ROP gadgets and chain building
- Format string exploits
- Heap exploitation (Tcache, Fastbin, House of Force/Spirit)
- Stack pivot techniques
- SROP (Sigreturn-oriented programming)
- Libc database and one_gadget

#### Reverse
- Disassembly helpers
- String extraction
- Binary analysis

#### Forensics
- File carving
- Memory analysis
- Network forensics

#### Misc
- Encoding/decoding utilities
- Steganography helpers

### Installation

```bash
pip install -e .
```

### Usage

#### As MCP Server
```bash
ctf-mcp
```

#### In Python
```python
from ctf_mcp.tools.crypto import CryptoTools
from ctf_mcp.tools.web import WebTools
from ctf_mcp.tools.pwn import PwnTools

crypto = CryptoTools()
web = WebTools()
pwn = PwnTools()

# Generate SQL injection payloads
print(web.sql_payloads("mysql", "union"))

# Base64 encode
print(crypto.base64_encode("Hello CTF"))

# Create cyclic pattern
print(pwn.pattern_create(100))
```

### MCP Configuration

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

### Requirements

- Python 3.10+
- mcp >= 1.0.0

---

## 中文

一个为 CTF（夺旗赛）挑战提供全面工具的 MCP（模型上下文协议）服务器。

## ⚠️ 安全警告

**重要提示：本工具仅用于授权的安全测试。**

- ✅ **授权使用**：CTF 竞赛、获得书面许可的渗透测试、安全研究、教育目的
- ❌ **禁止使用**：未经授权的访问、恶意攻击、非法活动

**使用本工具前：**
1. 确保您已获得适当的授权
2. 阅读 [SECURITY.md](SECURITY.md) 了解详细的安全指南
3. 查看 [BEST_PRACTICES.md](BEST_PRACTICES.md) 了解使用建议
4. 了解您计划使用的工具的风险级别

**风险级别：**
- 🟢 低风险：信息收集（安全）
- 🟡 中风险：漏洞检测（需要授权）
- 🟠 高风险：漏洞利用工具（需要明确授权）
- 🔴 严重风险：RCE/反序列化 payload（需要书面授权）

**安全审计结果：**
- 🔒 **安全装饰器总数**: 33个危险操作受保护
- 🔴 **高危**: 14个工具（远程代码执行、反序列化）
- 🟠 **高风险**: 13个工具（漏洞利用、注入）
- 🟡 **中风险**: 6个工具（弱加密、代码生成）
- 查看 [SECURITY.md](SECURITY.md) 获取完整工具列表和说明

**使用 CTF-MCP 即表示您同意负责任且合法地使用它。**

### 功能特性

#### 密码学工具 (53个)
- Base 编码 (Base64, Base32, Base58, Base85)
- 古典密码 (凯撒、维吉尼亚、Atbash、仿射、栅栏、Playfair、Hill)
- XOR 运算与分析
- 现代加密 (AES, DES, RC4)
- 哈希函数与破解
- RSA 攻击 (Wiener、Hastad、共模攻击、Franklin-Reiter)
- 频率分析

#### Web 安全工具 (46个)
- SQL 注入 (联合查询、报错注入、布尔盲注、时间盲注)
- XSS 载荷与过滤器绕过
- SSTI (服务端模板注入)
- SSRF、XXE、命令注入
- JWT 攻击 (None 算法、密钥混淆)
- 反序列化 (PHP, Python Pickle, Java, Node.js)
- HTTP 走私、GraphQL、WebSocket
- OAuth、CORS、缓存投毒

#### 二进制利用工具 (27个)
- Shellcode 生成 (x64/x86)
- 循环模式创建与偏移查找
- ROP gadgets 与链构建
- 格式化字符串漏洞利用
- 堆利用 (Tcache, Fastbin, House of Force/Spirit)
- 栈迁移技术
- SROP (Sigreturn 导向编程)
- Libc 数据库与 one_gadget

#### 逆向工程
- 反汇编辅助
- 字符串提取
- 二进制分析

#### 取证分析
- 文件雕复
- 内存分析
- 网络取证

#### 杂项工具
- 编码/解码工具
- 隐写术辅助

### 安装

```bash
pip install -e .
```

### 使用方法

#### 作为 MCP 服务器
```bash
ctf-mcp
```

#### 在 Python 中使用
```python
from ctf_mcp.tools.crypto import CryptoTools
from ctf_mcp.tools.web import WebTools
from ctf_mcp.tools.pwn import PwnTools

crypto = CryptoTools()
web = WebTools()
pwn = PwnTools()

# 生成 SQL 注入载荷
print(web.sql_payloads("mysql", "union"))

# Base64 编码
print(crypto.base64_encode("Hello CTF"))

# 创建循环模式
print(pwn.pattern_create(100))
```

### MCP 配置

添加到你的 MCP 客户端配置：

```json
{
  "mcpServers": {
    "ctf-mcp": {
      "command": "ctf-mcp"
    }
  }
}
```

### 环境要求

- Python 3.10+
- mcp >= 1.0.0

---

## Author / 作者

**Coff0xc**

## License / 许可证

MIT License - see [LICENSE](LICENSE)
