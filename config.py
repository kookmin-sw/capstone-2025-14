import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
LLM4MODULE_PATH = os.path.join(CURRENT_DIR, "LLM4Module")

###CodeQL
CODEQL_PATH = os.path.join(CURRENT_DIR, "codeql/codeql/codeql")
QUERY_SUITE = os.path.join(CURRENT_DIR, "codeql-repo/cpp/ql/src/codeql-suites")
TAINT_QUERY = os.path.join(CURRENT_DIR, "codeql-repo/cpp/ql/src/Security/CWE/custom")

###Server
SERVER_PATH = os.path.join(CURRENT_DIR, "project")
MEDIA_PATH = os.path.join(CURRENT_DIR, "media")
TEMPLATES_DIR = os.path.join(CURRENT_DIR,"project/capstone/templates")
STATIC_DIR = os.path.join(CURRENT_DIR,"project/capstone/static")
STYLE_DIR = os.path.join(STATIC_DIR, "css")
SCRIPT_DIR = os.path.join(STATIC_DIR, "js")

####taint_view
TAINT_OUTPUT_DIR = os.path.join(MEDIA_PATH, "taint_result")
####settings

####downloadFile

####decompile
GHIDRA_PATH = os.path.join(CURRENT_DIR, "ghidra_11.0.3_PUBLIC/support/analyzeHeadless")
DECOMPILE_SCRIPT_PATH = os.path.join(LLM4MODULE_PATH, "decompile.py")
PARSE_SCRIPT_PATH = os.path.join(LLM4MODULE_PATH, "parse_global.py")
MODEL_PATH = os.path.join(CURRENT_DIR, "llm4decompile-22b-v2")

####codeql_view
INPUT_ROOT = os.path.join(MEDIA_PATH, "downloads")
CODEQL_OUTPUT_DIR = os.path.join(MEDIA_PATH, "codeql_result")
