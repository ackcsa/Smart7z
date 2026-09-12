"""Earliest application-owned marker, after PyInstaller's Python bootstrap."""
from startup_trace import mark

mark("frozen:runtime_hook")
