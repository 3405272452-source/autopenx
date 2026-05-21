"""CTF Reverse engineering tools package.

Provides tools for reverse engineering CTF challenges:
- decompile: Decompile/disassemble binaries (Ghidra/objdump)
- strings_extract: Extract and filter strings from binaries
- dynamic_analyze: Dynamic analysis via ltrace/strace
- constraint_solve: Solve constraints using z3 theorem prover
"""
from autopnex.tools.base import ToolRegistry

from .decompile import DecompileTool, decompile
from .strings_extract import StringsExtractTool, strings_extract
from .dynamic_analyze import DynamicAnalyzeTool, dynamic_analyze
from .constraint_solve import ConstraintSolveTool, constraint_solve

# Register all tools
ToolRegistry.register(DecompileTool)
ToolRegistry.register(StringsExtractTool)
ToolRegistry.register(DynamicAnalyzeTool)
ToolRegistry.register(ConstraintSolveTool)

# Registry dict for programmatic access to all reverse tool functions
CTF_REVERSE_TOOLS = {
    "decompile": decompile,
    "strings_extract": strings_extract,
    "dynamic_analyze": dynamic_analyze,
    "constraint_solve": constraint_solve,
}

__all__ = [
    "DecompileTool",
    "StringsExtractTool",
    "DynamicAnalyzeTool",
    "ConstraintSolveTool",
    "decompile",
    "strings_extract",
    "dynamic_analyze",
    "constraint_solve",
    "CTF_REVERSE_TOOLS",
]
