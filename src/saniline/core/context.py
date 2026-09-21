"""
Streaming Execution Context for SaniLine.

Tracks lexical state across streaming chunks and lines (e.g. multi-line comments,
docstrings, import registries, and brace nesting) to enable sub-millisecond,
context-aware line-by-line inspection for AI agents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class StreamContext:
    """Maintains stateful parsing context across streaming lines."""
    language: str = "generic"
    current_line_number: int = 0
    in_multiline_docstring: bool = False
    docstring_delimiter: str | None = None
    in_block_comment: bool = False
    open_paren_count: int = 0
    open_bracket_count: int = 0
    open_brace_count: int = 0
    imported_modules: set[str] = field(default_factory=set)
    imported_symbols: dict[str, str] = field(default_factory=dict)  # symbol -> module
    tainted_variables: set[str] = field(default_factory=set)
    line_history: list[str] = field(default_factory=list)

    @classmethod
    def detect_language_from_path_or_content(cls, path_or_hint: str) -> str:
        lower = path_or_hint.lower()
        if lower.endswith((".py", ".pyw", ".pyi")):
            return "python"
        if lower.endswith((".js", ".jsx", ".mjs", ".cjs")):
            return "javascript"
        if lower.endswith((".ts", ".tsx", ".mts")):
            return "typescript"
        if lower.endswith((".sh", ".bash", ".zsh")):
            return "bash"
        if lower.endswith((".go",)):
            return "go"
        if lower.endswith((".rs",)):
            return "rust"
        if lower.endswith((".c", ".h", ".cpp", ".hpp", ".cc")):
            return "c"
        if lower.endswith((".sql",)):
            return "sql"
        return "generic"

    def advance(self, raw_line: str) -> None:
        """Updates internal lexical state when consuming a new line."""
        self.current_line_number += 1
        self.line_history.append(raw_line)
        if len(self.line_history) > 50:
            self.line_history.pop(0)

        stripped = raw_line.strip()

        # Update Python docstring state
        if self.language in ("python", "generic"):
            for delim in ('"""', "'''"):
                count = raw_line.count(delim)
                if count % 2 != 0:
                    if self.in_multiline_docstring and self.docstring_delimiter == delim:
                        self.in_multiline_docstring = False
                        self.docstring_delimiter = None
                    elif not self.in_multiline_docstring:
                        self.in_multiline_docstring = True
                        self.docstring_delimiter = delim

        # Update C-style block comment state
        if self.language in ("javascript", "typescript", "c", "go", "rust", "generic"):
            if "/*" in raw_line and "*/" not in raw_line:
                self.in_block_comment = True
            elif "*/" in raw_line:
                self.in_block_comment = False

        # Register Python imports
        if self.language == "python" and not self.in_multiline_docstring:
            if stripped.startswith("import "):
                parts = stripped[7:].split(",")
                for p in parts:
                    mod = p.strip().split(" as ")[0].strip()
                    if mod:
                        self.imported_modules.add(mod)
            elif stripped.startswith("from "):
                match = re.match(r"^from\s+([a-zA-Z0-9_\.]+)\s+import\s+(.+)$", stripped)
                if match:
                    mod = match.group(1).strip()
                    self.imported_modules.add(mod)
                    symbols = match.group(2).split(",")
                    for sym in symbols:
                        sym_name = sym.strip().split(" as ")[0].strip()
                        if sym_name:
                            self.imported_symbols[sym_name] = mod

        # Count bracket depths (sample up to first 2048 chars for pathological lines)
        sample = raw_line if len(raw_line) <= 2048 else raw_line[:2048]
        for ch in sample:
            if ch == "(":
                self.open_paren_count += 1
            elif ch == ")" and self.open_paren_count > 0:
                self.open_paren_count -= 1
            elif ch == "[":
                self.open_bracket_count += 1
            elif ch == "]" and self.open_bracket_count > 0:
                self.open_bracket_count -= 1
            elif ch == "{":
                self.open_brace_count += 1
            elif ch == "}" and self.open_brace_count > 0:
                self.open_brace_count -= 1

    def is_inside_comment_or_docstring(self) -> bool:
        return self.in_multiline_docstring or self.in_block_comment

    def is_module_imported(self, module_prefix: str) -> bool:
        for mod in self.imported_modules:
            if mod == module_prefix or mod.startswith(module_prefix + "."):
                return True
        for sym, mod in self.imported_symbols.items():
            if mod == module_prefix or mod.startswith(module_prefix + "."):
                return True
        return False
