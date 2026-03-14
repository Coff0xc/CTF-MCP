# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CTF-MCP is an MCP (Model Context Protocol) server that provides 140+ tools for CTF (Capture The Flag) challenges across Crypto, Web, Pwn, Reverse, Forensics, and Misc categories. It also includes an autonomous solving orchestrator and LLM agent integration.

## Commands

```bash
# Install (editable mode)
pip install -e .
# Install with dev tools
pip install -e ".[dev]"
# Install with crypto/web deps
pip install -e ".[standard]"
# Install everything (Linux-only deps like pwntools excluded on Windows)
pip install -e ".[full]"
# Install LLM agent support
pip install -e ".[llm]"

# Run MCP server
ctf-mcp

# Run all tests
pytest

# Run a single test file
pytest tests/test_crypto.py

# Run a specific test
pytest tests/test_crypto.py::TestCryptoBase64::test_base64_encode -v

# Run with coverage
pytest --cov=ctf_mcp --cov-report=term-missing

# Lint
ruff check ctf_mcp/
black --check ctf_mcp/

# Format
black ctf_mcp/
ruff check --fix ctf_mcp/

# Security scan
bandit -r ctf_mcp/ -c pyproject.toml

# Pre-commit hooks
pre-commit install
pre-commit run --all-files
```

## Architecture

### Layer Overview

```
server.py (MCP entry point — dynamic tool registration via introspection)
  ├── tools/          6 tool classes exposed as MCP tools (prefix_method naming)
  ├── core/           Autonomous solving pipeline
  ├── engines/        Category-specific solving engines
  ├── adapters/       External binary tool wrappers
  ├── llm/            LLM-powered agent (ReAct pattern)
  ├── mcp/            MCP protocol extensions (streaming, tasks, registry)
  ├── network/        HTTP client, remote connections, exploit runner
  └── utils/          Security decorators, input validation, helpers
```

### Tool Registration System

`server.py` dynamically discovers and registers all tools at startup:
1. Each `tools/*.py` module has a class (e.g., `CryptoTools`) with a `get_tools()` method returning `{method_name: description}`
2. `register_tools()` iterates modules, introspects method signatures via `inspect`, and generates JSON Schema for MCP
3. Tools are registered as `{prefix}_{method_name}` (e.g., `crypto_base64_encode`, `web_sql_payloads`)
4. The `TOOL_REGISTRY` dict maps tool names to `(module_instance, method_name)` tuples for dispatch

To add a new tool: add a method to the appropriate tools class, add it to `get_tools()` return dict. It auto-registers.

### Autonomous Solving Pipeline (`core/`)

The orchestrator runs a 4-phase pipeline: **Classify → Plan → Execute → Validate**

- `classifier.py` — Identifies challenge type (crypto/web/pwn/etc.) from description, files, and remote info
- `planner.py` — Generates ranked `SolvingStrategy` objects based on classification
- `executor.py` — Runs strategies using engines, with timeout control
- `session.py` — Tracks solve state through `SessionState` enum transitions
- `orchestrator.py` — Coordinates the full pipeline, exposed as `auto_solve` MCP tool

### Engines vs Tools vs Adapters

- **Tools** (`tools/`): Stateless utility classes — encode, decode, generate payloads, analyze. Each method is one MCP tool.
- **Engines** (`engines/`): Extend `SolvingEngine` ABC — have `analyze()` and `solve()` methods, use tools internally, understand challenge context.
- **Adapters** (`adapters/`): Extend `ToolAdapter` ABC — wrap external binaries (nmap, sqlmap, hashcat, etc.) with availability checking and version validation.

### LLM Agent (`llm/`)

- `agent/react.py` — ReAct agent: Think → Act (call CTF tool) → Observe loop
- `providers/` — Multi-provider support: OpenAI, Anthropic, Ollama
- `config.py` — Environment-based config (`CTF_LLM_PROVIDER`, `CTF_LLM_MODEL`, etc.)
- `rag/retriever.py` — CTF knowledge retrieval
- `integration/enhanced_orchestrator.py` — LLM-enhanced orchestrator

### Security Model

- `utils/security.py` provides `@dangerous_operation(risk_level, description)` decorator for high-risk tools
- 4 risk levels: LOW (info gathering) → MEDIUM (vuln detection) → HIGH (exploitation) → CRITICAL (RCE/deser)
- `InputValidator` class validates hostnames, ports, URLs, file paths, shell args
- Bandit runs in CI with skips for B101 (assert) and B311 (random)

## Key Conventions

- **Python 3.10+**, line length 100 (Black + Ruff)
- Optional heavy deps use try/import pattern with `*_AVAILABLE` flags (e.g., `PYCRYPTODOME_AVAILABLE`, `GMPY2_AVAILABLE`)
- Dependency tiers: `minimal` → `standard` → `advanced` → `expert` → `full`
- Test fixtures in `tests/conftest.py` provide pre-instantiated tool classes
- `pytest-asyncio` with `asyncio_mode = "auto"` — async tests run without `@pytest.mark.asyncio`
- Dataclasses with `to_dict()` methods are the standard serialization pattern

### Computation vs Payload Tools

Tools in `tools/` fall into two categories:
- **Computation tools** (preferred): Accept data, perform real analysis, return results. Examples: `jwt_decode`, `jwt_crack` (brute-force), `checksec`, `entropy_analysis`, `png_chunks`, `ssti_identify` (with response text), `graphql_parse_schema`, `http_header_analyze`
- **Payload generators**: Return static payloads/cheat sheets. Examples: `sql_payloads`, `xss_payloads`, `cmd_injection`

When adding new tools, prefer computation tools that process real input over static payload lists. Many existing payload generators accept parameters to filter by context (e.g., `xss_filter_bypass(context="js")`).

### Pure-Python Binary Parsing

`reverse.py` and `forensics.py` use `struct`-based pure-Python parsers for ELF/PNG/ZIP formats with no external deps. External tools (binwalk, etc.) are tried first via `shutil.which()` with pure-Python fallback.
