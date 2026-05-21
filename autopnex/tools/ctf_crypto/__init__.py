"""CTF crypto tools package.

Provides tools for solving cryptography-related CTF challenges:
- RSA attacks (small e, common modulus, Wiener, Fermat)
- Classical cipher analysis (Caesar, Vigenere, frequency analysis)
- Encoding detection and decoding (Base64, Hex, Morse, etc.)
- Python script execution in sandboxed subprocess
"""
from autopnex.tools.base import ToolRegistry

from .rsa_attack import RSAAttackTool, rsa_attack
from .classical_cipher import ClassicalCipherTool, classical_cipher
from .encoding_decode import EncodingDecodeTool, encoding_decode
from .script_execute import ScriptExecuteTool, script_execute

# Ensure all tools are registered
ToolRegistry.register(RSAAttackTool)
ToolRegistry.register(ClassicalCipherTool)
ToolRegistry.register(EncodingDecodeTool)
ToolRegistry.register(ScriptExecuteTool)

# Registry dict mapping tool names to their standalone functions
CTF_CRYPTO_TOOLS: dict = {
    "rsa_attack": rsa_attack,
    "classical_cipher": classical_cipher,
    "encoding_decode": encoding_decode,
    "script_execute": script_execute,
}

__all__ = [
    "RSAAttackTool",
    "ClassicalCipherTool",
    "EncodingDecodeTool",
    "ScriptExecuteTool",
    "rsa_attack",
    "classical_cipher",
    "encoding_decode",
    "script_execute",
    "CTF_CRYPTO_TOOLS",
]
