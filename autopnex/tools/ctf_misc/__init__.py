"""CTF Misc analysis tools package.

Provides tools for miscellaneous CTF challenges:
- file_analyze: Detect file types, embedded files, and extract strings
- stego_analyze: Steganography analysis (exiftool, steghide, zsteg)
- traffic_analyze: Network traffic (pcap) analysis
- archive_analyze: ZIP archive analysis with pseudo-encryption detection
"""
from autopnex.tools.base import ToolRegistry
from .file_analyze import FileAnalyzeTool, file_analyze
from .stego_analyze import StegoAnalyzeTool, stego_analyze
from .traffic_analyze import TrafficAnalyzeTool, traffic_analyze
from .archive_analyze import ArchiveAnalyzeTool, archive_analyze

ToolRegistry.register(FileAnalyzeTool)
ToolRegistry.register(StegoAnalyzeTool)
ToolRegistry.register(TrafficAnalyzeTool)
ToolRegistry.register(ArchiveAnalyzeTool)

# Registry dict for programmatic access to all misc tool functions
CTF_MISC_TOOLS = {
    "file_analyze": file_analyze,
    "stego_analyze": stego_analyze,
    "traffic_analyze": traffic_analyze,
    "archive_analyze": archive_analyze,
}

__all__ = [
    "FileAnalyzeTool",
    "StegoAnalyzeTool",
    "TrafficAnalyzeTool",
    "ArchiveAnalyzeTool",
    "file_analyze",
    "stego_analyze",
    "traffic_analyze",
    "archive_analyze",
    "CTF_MISC_TOOLS",
]
