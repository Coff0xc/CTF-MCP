"""
Angr Adapter
Interface for angr symbolic execution framework
"""

import re
from typing import Any, Optional

from .base import PythonLibraryAdapter, AdapterResult


class AngrAdapter(PythonLibraryAdapter):
    """
    Adapter for angr symbolic execution framework.

    Provides:
    - Symbolic execution
    - Constraint solving
    - Path exploration
    - Vulnerability detection
    - Binary analysis
    """

    def __init__(self):
        super().__init__()
        self._angr = None
        self._claripy = None

    @property
    def name(self) -> str:
        return "angr"

    @property
    def tool_name(self) -> str:
        return "angr"

    @property
    def description(self) -> str:
        return "Binary analysis and symbolic execution framework"

    @property
    def min_version(self) -> Optional[str]:
        return "9.0.0"

    def _get_version(self) -> Optional[str]:
        try:
            import angr
            return angr.__version__
        except Exception:
            return None

    def _get_angr(self):
        """Lazy load angr"""
        if self._angr is None:
            try:
                import angr
                import claripy
                self._angr = angr
                self._claripy = claripy
            except ImportError:
                pass
        return self._angr

    def analyze_binary(self, binary_path: str) -> AdapterResult:
        """
        Perform basic binary analysis.

        Args:
            binary_path: Path to binary

        Returns:
            AdapterResult with analysis info
        """
        result = AdapterResult()
        angr = self._get_angr()

        if not angr:
            result.error = "angr not available"
            return result

        try:
            project = angr.Project(binary_path, auto_load_libs=False)

            result.success = True
            result.data = {
                "arch": project.arch.name,
                "bits": project.arch.bits,
                "entry": hex(project.entry),
                "filename": project.filename,
                "loader": {
                    "main_object": str(project.loader.main_object),
                    "min_addr": hex(project.loader.min_addr),
                    "max_addr": hex(project.loader.max_addr),
                },
            }

            # Get symbols
            symbols = {}
            for sym in project.loader.symbols:
                if sym.is_function and sym.name:
                    symbols[sym.name] = hex(sym.rebased_addr)
            result.data["symbols"] = dict(list(symbols.items())[:30])

            result.output = f"Binary: {project.arch.name} {project.arch.bits}-bit, entry: {hex(project.entry)}"

        except Exception as e:
            result.error = str(e)

        return result

    def find_path_to_address(
        self,
        binary_path: str,
        target_addr: int,
        avoid_addrs: Optional[list[int]] = None,
        timeout: int = 300
    ) -> AdapterResult:
        """
        Find execution path to target address.

        Args:
            binary_path: Path to binary
            target_addr: Address to reach
            avoid_addrs: Addresses to avoid
            timeout: Exploration timeout in seconds

        Returns:
            AdapterResult with path info and input
        """
        result = AdapterResult()
        angr = self._get_angr()

        if not angr:
            result.error = "angr not available"
            return result

        try:
            project = angr.Project(binary_path, auto_load_libs=False)
            state = project.factory.entry_state()
            simgr = project.factory.simulation_manager(state)

            avoid = avoid_addrs or []

            # Explore to find path
            simgr.explore(
                find=target_addr,
                avoid=avoid,
                timeout=timeout
            )

            if simgr.found:
                found_state = simgr.found[0]

                # Try to get stdin input
                stdin_input = None
                try:
                    stdin_input = found_state.posix.dumps(0)
                    if stdin_input:
                        stdin_input = stdin_input.hex()
                except Exception:
                    pass

                result.success = True
                result.data = {
                    "found": True,
                    "target": hex(target_addr),
                    "stdin_input": stdin_input,
                    "path_length": len(found_state.history.bbl_addrs),
                }
                result.output = f"Path found to {hex(target_addr)}"
                if stdin_input:
                    result.output += f"\nInput (hex): {stdin_input}"

            else:
                result.success = False
                result.error = f"No path found to {hex(target_addr)}"
                result.data = {
                    "found": False,
                    "target": hex(target_addr),
                    "deadended": len(simgr.deadended),
                    "active": len(simgr.active),
                }

        except Exception as e:
            result.error = str(e)

        return result

    def solve_constraints(
        self,
        binary_path: str,
        find_output: bytes,
        stdin_length: int = 100
    ) -> AdapterResult:
        """
        Solve for input that produces specific output.

        Args:
            binary_path: Path to binary
            find_output: Expected output bytes
            stdin_length: Maximum stdin length

        Returns:
            AdapterResult with solved input
        """
        result = AdapterResult()
        angr = self._get_angr()
        claripy = self._claripy

        if not angr or not claripy:
            result.error = "angr not available"
            return result

        try:
            project = angr.Project(binary_path, auto_load_libs=False)

            # Create symbolic stdin
            stdin_sym = claripy.BVS('stdin', stdin_length * 8)

            state = project.factory.entry_state(
                stdin=angr.SimFileStream(name='stdin', content=stdin_sym)
            )

            simgr = project.factory.simulation_manager(state)

            def check_output(state):
                try:
                    stdout = state.posix.dumps(1)
                    return find_output in stdout
                except Exception:
                    return False

            # Explore
            simgr.explore(find=check_output, timeout=300)

            if simgr.found:
                found_state = simgr.found[0]

                # Solve for concrete input
                solution = found_state.solver.eval(stdin_sym, cast_to=bytes)

                result.success = True
                result.data = {
                    "found": True,
                    "input_hex": solution.hex(),
                    "input_ascii": solution.decode('utf-8', errors='replace'),
                }
                result.output = f"Solution found:\nHex: {solution.hex()}\nASCII: {solution.decode('utf-8', errors='replace')}"

            else:
                result.success = False
                result.error = "No solution found"

        except Exception as e:
            result.error = str(e)

        return result

    def find_vulnerability(
        self,
        binary_path: str,
        vuln_type: str = "overflow"
    ) -> AdapterResult:
        """
        Search for vulnerabilities using symbolic execution.

        Args:
            binary_path: Path to binary
            vuln_type: Type to search (overflow, format, null_deref)

        Returns:
            AdapterResult with vulnerability info
        """
        result = AdapterResult()
        angr = self._get_angr()

        if not angr:
            result.error = "angr not available"
            return result

        try:
            project = angr.Project(binary_path, auto_load_libs=False)
            state = project.factory.entry_state()
            simgr = project.factory.simulation_manager(state)

            vulnerabilities = []

            if vuln_type == "overflow":
                # Look for unconstrained instruction pointer
                def is_unconstrained(state):
                    return state.regs.pc.symbolic

                simgr.explore(find=is_unconstrained, timeout=120)

                if simgr.found:
                    for s in simgr.found:
                        vulnerabilities.append({
                            "type": "buffer_overflow",
                            "description": "Unconstrained instruction pointer",
                            "state_addr": hex(s.addr) if hasattr(s, 'addr') else "unknown",
                        })

            result.success = True
            result.data = {
                "vuln_type": vuln_type,
                "vulnerabilities": vulnerabilities,
                "count": len(vulnerabilities),
            }

            if vulnerabilities:
                result.output = f"Found {len(vulnerabilities)} potential vulnerabilities"
            else:
                result.output = "No vulnerabilities found"

        except Exception as e:
            result.error = str(e)

        return result

    def get_cfg(self, binary_path: str) -> AdapterResult:
        """
        Generate Control Flow Graph.

        Args:
            binary_path: Path to binary

        Returns:
            AdapterResult with CFG info
        """
        result = AdapterResult()
        angr = self._get_angr()

        if not angr:
            result.error = "angr not available"
            return result

        try:
            project = angr.Project(binary_path, auto_load_libs=False)
            cfg = project.analyses.CFGFast()

            # Get function info
            functions = {}
            for func_addr, func in cfg.functions.items():
                if func.name and not func.name.startswith('_'):
                    functions[func.name] = {
                        "addr": hex(func_addr),
                        "size": func.size,
                        "blocks": len(list(func.blocks)),
                    }

            result.success = True
            result.data = {
                "functions": dict(list(functions.items())[:50]),
                "total_functions": len(cfg.functions),
                "total_nodes": cfg.graph.number_of_nodes(),
                "total_edges": cfg.graph.number_of_edges(),
            }
            result.output = f"CFG: {len(cfg.functions)} functions, {cfg.graph.number_of_nodes()} nodes"

        except Exception as e:
            result.error = str(e)

        return result
