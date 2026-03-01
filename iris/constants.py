"""Global constants for IRIS."""

from __future__ import annotations

import importlib

PLUGIN_NAME = "IRIS"
PLUGIN_VERSION = "0.1.0"
PLUGIN_HOTKEY = "Ctrl+Shift+I"
PLUGIN_COMMENT = "Intelligent Reverse-engineering Integrated System"

CONFIG_DIR_NAME = "iris"
CONFIG_FILE_NAME = "config.json"
CHECKPOINTS_DIR_NAME = "checkpoints"

DEFAULT_MAX_TOKENS = 16384
DEFAULT_TEMPERATURE = 0.2
DEFAULT_CONTEXT_WINDOW = 200000

TOOL_RESULT_TRUNCATE_LEN = 8000

SYSTEM_PROMPT_VERSION = 1

SKILLS_DIR_NAME = "skills"
MCP_CONFIG_FILE = "mcp.json"
MCP_TOOL_PREFIX = "mcp_"
MCP_DEFAULT_TIMEOUT = 30.0

# Whether the IDA SDK is importable. Set once at import time.
# Uses importlib.import_module() to bypass Shiboken's __import__ hook.
try:
    importlib.import_module("ida_kernwin")
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

# Whether the Hex-Rays decompiler SDK is importable.
try:
    importlib.import_module("ida_hexrays")
    HAS_HEXRAYS = True
except ImportError:
    HAS_HEXRAYS = False
