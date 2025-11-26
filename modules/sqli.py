#!/usr/bin/env python3
"""
Hacker-style Defensive SQLi Scanner (single-file)

- Reads target.md to find a query-builder function.
- Uses embedded payloads (no external payload file).
- Runs 11 defensive test analyzers per payload.
- Prints color-coded, detailed logs and a final summary.
- DOES NOT execute SQL or contact external systems.

Expected `target.md` format (very simple key: value per line):
--------------------------------------------------------------
target_name: Login Endpoint
path: app/query_builders/login_query.py    # or module.path.to.module
function: build_login_query
# optional:
# type: function
--------------------------------------------------------------
"""

import re
import time
import importlib
import importlib.util
from dataclasses import dataclass, asdict
from typing import Callable, List, Dict, Tuple, Any
from pathlib import Path
import sys
import traceback

# -------------------------
# ANSI colors
# -------------------------
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"

# -------------------------
# Compact ASCII banner
# -------------------------
BANNER = r"""
███████╗██╗     ██╗     ██╗     ██╗███╗   ██╗ █████╗ ███████╗
██╔════╝██║     ██║     ██║     ██║████╗  ██║██╔══██╗██╔════╝
█████╗  ██║     ██║     ██║     ██║██╔██╗ ██║███████║█████╗  
██╔══╝  ██║     ██║     ██║     ██║██║╚██╗██║██╔══██║██╔══╝  
██║     ███████╗███████╗███████╗██║██║ ╚████║██║  ██║███████╗
╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
           SQL INJECTION SAFETY SCANNER (DEFENSIVE)
"""

# -------------------------
# Embedded payloads (no files)
# -------------------------
FUZZ_INPUTS = [
    "'", "\"", "''", "\"\"",
    "1 OR 1=1", "' OR '1'='1", "\" OR \"1\"=\"1",
    "admin'--", "admin\"--",
    "abc');--", 'abc");--',
    "%%", "%27", "%22",
    "); DROP TABLE test; --",
    "OR 1=1", "OR 'a'='a'", "OR \"a\"=\"a\"",
    "') OR ('1'='1", '") OR ("1"="1',
    "test')#", 'test")#',
    "UNION ALL SELECT NULL", "UNION SELECT username, password",
    "SLEEP(5)", "BENCHMARK(1000000,MD5(1))",
    "/* injected */", "' OR 'x'='x' /*", "\" OR \"x\"=\"x\" --",
    "1; DROP TABLE users;", "'; EXEC xp_cmdshell('whoami') --"
]

# -------------------------
# Unsafe pattern regexes
# -------------------------
UNSAFE_SQL_PATTERNS = {
    "nested_single_quotes": re.compile(r"'.*'.*'.*", re.DOTALL),
    "nested_double_quotes": re.compile(r"\".*\".*\".*", re.DOTALL),
    "sql_comment": re.compile(r"--|/\*", re.DOTALL),
    "or_boolean": re.compile(r"\bOR\b\s+\S+?=\S+", re.IGNORECASE),
    "stacked_statements": re.compile(r";"),
    "union_select": re.compile(r"\bUNION\b\s+\bSELECT\b", re.IGNORECASE),
    "time_functions": re.compile(r"\bSLEEP\b|\bBENCHMARK\b|\bWAITFOR\b", re.IGNORECASE),
}

PLACEHOLDER_PATTERNS = [r"\?", r"%s", r":\w+"]

# -------------------------
# Dataclass for results
# -------------------------
@dataclass
class SQLiTestResult:
    payload: str
    generated_query: str
    method_results: Dict[str, Tuple[bool, str]]  # method_name -> (flag, message)
    severity_score: int
    verdict: str
    exception: str  # exception message when calling builder (if any)
    duration_ms: float

# -------------------------
# Helper utilities
# -------------------------
def color_text(s: str, color: str) -> str:
    return f"{color}{s}{RESET}"

def has_placeholders(query: str) -> bool:
    return any(re.search(p, query) for p in PLACEHOLDER_PATTERNS)

def reflect_input(query: str, payload: str) -> bool:
    # Check if payload (or a normalized form) appears in generated query
    return payload in query

def pattern_detects(query: str, pattern_re: re.Pattern) -> bool:
    return bool(pattern_re.search(query))

# -------------------------
# 11 Defensive Test Methods
# Each returns (flag: bool, message: str)
# flag True => finds suspicious pattern / indicates risk for that method
# -------------------------

def test_quote_breaks(query: str, payload: str) -> Tuple[bool, str]:
    if pattern_detects(query, UNSAFE_SQL_PATTERNS["nested_single_quotes"]) or pattern_detects(query, UNSAFE_SQL_PATTERNS["nested_double_quotes"]):
        return True, "Quote nesting or breaks detected"
    return False, "No quote structure issues detected"

def test_comment_injection(query: str, payload: str) -> Tuple[bool, str]:
    if pattern_detects(query, UNSAFE_SQL_PATTERNS["sql_comment"]):
        return True, "SQL comment tokens found (possible comment injection)"
    return False, "No comment tokens found"

def test_boolean_logic_injection(query: str, payload: str) -> Tuple[bool, str]:
    if pattern_detects(query, UNSAFE_SQL_PATTERNS["or_boolean"]):
        return True, "Boolean logic patterns (OR ... = ...) detected"
    return False, "No boolean logic bypass patterns detected"

def test_union_select_patterns(query: str, payload: str) -> Tuple[bool, str]:
    if pattern_detects(query, UNSAFE_SQL_PATTERNS["union_select"]):
        return True, "UNION SELECT pattern found (possible data retrieval injection)"
    return False, "No UNION SELECT patterns"

def test_stack_semicolon_usage(query: str, payload: str) -> Tuple[bool, str]:
    if pattern_detects(query, UNSAFE_SQL_PATTERNS["stacked_statements"]):
        return True, "Semicolon/stacked statements detected"
    return False, "No stacked statements"

def test_tautology_detection(query: str, payload: str) -> Tuple[bool, str]:
    # heuristic: look for tautology-like payload reflections
    if re.search(r"\b1\s*=\s*1\b|\b'a'\s*=\s*'a'\b", query, re.IGNORECASE):
        return True, "Tautology-like expression detected"
    return False, "No tautology patterns"

def test_concat_leakage(query: str, payload: str) -> Tuple[bool, str]:
    if reflect_input(query, payload):
        return True, "User input reflected verbatim in query (likely concatenation)"
    return False, "No direct reflection of input"

def test_placeholder_presence(query: str, payload: str) -> Tuple[bool, str]:
    if not has_placeholders(query):
        return True, "No parameter placeholders found"
    return False, "Placeholders present (good sign)"

def test_keyword_injection(query: str, payload: str) -> Tuple[bool, str]:
    # look for keywords commonly weaponized
    if re.search(r"\bDROP\b|\bEXEC\b|\bALTER\b|\bINSERT\b|\bUPDATE\b", query, re.IGNORECASE):
        return True, "Dangerous SQL keyword observed in generated query"
    return False, "No dangerous keywords"

def test_malformed_query_patterns(query: str, payload: str) -> Tuple[bool, str]:
    # Unbalanced quotes or parentheses simple check
    single_quotes = query.count("'")
    double_quotes = query.count('"')
    open_paren = query.count("(")
    close_paren = query.count(")")
    if single_quotes % 2 != 0 or double_quotes % 2 != 0 or open_paren != close_paren:
        return True, "Unbalanced quotes/parentheses detected"
    return False, "Query structure balanced"

def test_input_reflection(query: str, payload: str) -> Tuple[bool, str]:
    # more flexible reflection detection: normalized tokens of payload in query
    token = re.sub(r"\s+", "", payload)
    if token and token in re.sub(r"\s+", "", query):
        return True, "Normalized payload token reflected in query"
    return False, "No normalized input reflection"

# Map of test methods for ordered output
TEST_METHODS = [
    ("Quote Breaks", test_quote_breaks),
    ("Comment Injection", test_comment_injection),
    ("Boolean Logic Injection", test_boolean_logic_injection),
    ("Union Select Patterns", test_union_select_patterns),
    ("Stacked Semicolons", test_stack_semicolon_usage),
    ("Tautology Detection", test_tautology_detection),
    ("Concatenation Leakage", test_concat_leakage),
    ("Placeholder Presence", test_placeholder_presence),
    ("Keyword Injection", test_keyword_injection),
    ("Malformed Query Patterns", test_malformed_query_patterns),
    ("Input Reflection", test_input_reflection),
]

# -------------------------
# Severity calculation
# -------------------------
def calculate_severity(method_results: Dict[str, Tuple[bool, str]]) -> int:
    # Weighted heuristic: different tests have different weights
    weights = {
        "Quote Breaks": 2,
        "Comment Injection": 2,
        "Boolean Logic Injection": 2,
        "Union Select Patterns": 3,
        "Stacked Semicolons": 3,
        "Tautology Detection": 2,
        "Concatenation Leakage": 4,
        "Placeholder Presence": 4,
        "Keyword Injection": 3,
        "Malformed Query Patterns": 2,
        "Input Reflection": 3,
    }
    score = 0
    for name, (flag, _) in method_results.items():
        if flag:
            score += weights.get(name, 1)
    # Normalize to 0-10
    max_score = sum(weights.values())
    normalized = round((score / max_score) * 10)
    return max(0, min(normalized, 10))

# -------------------------
# Target loader (reads target.md)
# -------------------------
def parse_target_md(md_path: str = "target.md") -> Dict[str, str]:
    p = Path(md_path)
    if not p.exists():
        raise FileNotFoundError(f"target.md not found at {md_path}")
    data = {}
    for line in p.read_text().splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        data[key.strip()] = val.strip()
    # minimal validation
    if "path" not in data or "function" not in data:
        raise ValueError("target.md must include at least 'path:' and 'function:' entries")
    return data

def import_target_function(path: str, function_name: str) -> Callable[[str], str]:
    """
    Accepts either a module file path (e.g. app/query_builders/login_query.py)
    or a dot module path (package.module).
    Returns the function object.
    """
    # Try as file path first
    p = Path(path)
    if p.exists():
        # load module from file
        module_name = f"target_module_{abs(hash(str(p)))}"
        spec = importlib.util.spec_from_file_location(module_name, str(p))
        module = importlib.util.module_from_spec(spec)
        loader = spec.loader
        assert loader is not None
        loader.exec_module(module)
    else:
        # try dot path import
        module = importlib.import_module(path)
    if not hasattr(module, function_name):
        raise AttributeError(f"Function '{function_name}' not found in module '{path}'")
    fn = getattr(module, function_name)
    if not callable(fn):
        raise TypeError(f"Attribute '{function_name}' in '{path}' is not callable")
    return fn

# -------------------------
# Runner: main scan logic
# -------------------------
def run_sql_injection_tests(
    payloads: List[str],
    query_builder: Callable[[str], str],
    target_name: str = "Unknown Target",
    verbose: bool = True,
) -> List[Dict[str, Any]]:

    print(BANNER)
    print(f"{BOLD}[+] Target:{RESET} {target_name}")
    print(f"{BOLD}[+] Mode:{RESET} Defensive SQL construction analysis")
    print(f"{BOLD}[+] Payloads to test:{RESET} {len(payloads)}")
    print("-" * 64 + "\n")

    results: List[SQLiTestResult] = []
    start_all = time.time()

    for idx, payload in enumerate(payloads, start=1):
        t0 = time.time()
        header = f"[{idx}/{len(payloads)}] Payload: {repr(payload)}"
        print(color_text(header, CYAN))

        # call builder safely (catch exceptions)
        gen_query = ""
        ex_msg = ""
        try:
            gen_query = query_builder(payload)
            exec_status = "OK"
        except Exception as e:
            gen_query = "<EXCEPTION RAISED - query not produced>"
            ex_msg = "".join(traceback.format_exception_only(e.__class__, e)).strip()
            exec_status = "ERROR"

        # run all tests
        method_results: Dict[str, Tuple[bool, str]] = {}
        for name, fn in TEST_METHODS:
            try:
                flag, msg = fn(gen_query, payload)
            except Exception as e:
                flag, msg = True, f"Test error: {e}"
            method_results[name] = (flag, msg)

        severity = calculate_severity(method_results)
        duration_ms = round((time.time() - t0) * 1000, 2)

        # decide verdict heuristically
        if severity >= 7:
            verdict = "VULNERABLE"
            verdict_color = RED
        elif severity >= 4:
            verdict = "SUSPICIOUS"
            verdict_color = YELLOW
        else:
            verdict = "CLEAN"
            verdict_color = GREEN

        # Print detailed log for this payload
        print(f"   ├─ Exec Status: {exec_status}")
        if ex_msg:
            print(f"   ├─ Builder Exception: {color_text(ex_msg, MAGENTA)}")
        print(f"   ├─ Generated Query: {color_text(gen_query, BOLD)}")
        print(f"   ├─ Duration: {duration_ms} ms")
        print(f"   ├─ Tests:")
        for name, (flag, msg) in method_results.items():
            mark = color_text("RISK", RED) if flag else color_text("OK", GREEN)
            print(f"   │   ├─ {name:<24} : {mark} - {msg}")
        print(f"   ├─ Severity Score: {severity}/10")
        print(f"   └─ Verdict: {color_text(verdict, verdict_color)}\n")

        results.append(SQLiTestResult(
            payload=payload,
            generated_query=gen_query,
            method_results=method_results,
            severity_score=severity,
            verdict=verdict,
            exception=ex_msg,
            duration_ms=duration_ms
        ))

    total_elapsed = round((time.time() - start_all), 2)

    # Summary
    print("-" * 64)
    print(f"{BOLD}[+] Scan complete{RESET} — time: {total_elapsed}s, payloads: {len(payloads)}")
    # aggregate counts
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "CLEAN": 0}
    highest = None
    for r in results:
        counts[r.verdict] += 1
        if highest is None or r.severity_score > highest.severity_score:
            highest = r

    print(f"   ├─ {color_text('VULNERABLE', RED)} : {counts['VULNERABLE']}")
    print(f"   ├─ {color_text('SUSPICIOUS', YELLOW)}  : {counts['SUSPICIOUS']}")
    print(f"   ├─ {color_text('CLEAN', GREEN)}       : {counts['CLEAN']}")
    if highest:
        print(f"   ├─ Highest severity payload: {repr(highest.payload)} -> {highest.severity_score}/10 ({highest.verdict})")
        print(f"   └─ Example generated query: {color_text(highest.generated_query, BOLD)}")
    else:
        print("   └─ No payloads processed")

    # Final overall verdict heuristic
    overall = "CLEAN"
    if counts["VULNERABLE"] > 0:
        overall = "VULNERABLE"
        col = RED
    elif counts["SUSPICIOUS"] > 0:
        overall = "SUSPICIOUS"
        col = YELLOW
    else:
        overall = "CLEAN"
        col = GREEN

    print("\n" + color_text(f"[+] OVERALL VERDICT: {overall}", col))
    print("-" * 64 + "\n")

    # Return as list of dicts (for potential programmatic consumption in-memory)
    return [asdict(r) for r in results]

# -------------------------
# Main executable
# -------------------------
def main():
    try:
        target_info = parse_target_md("target.md")
        target_name = target_info.get("target_name", target_info.get("name", "Unknown Target"))
        path = target_info["path"]
        function = target_info["function"]

        print(color_text(f"[i] Loading target function '{function}' from '{path}'", CYAN))

        qb = import_target_function(path, function)
    except Exception as e:
        print(color_text(f"[!] Failed to load target: {e}", RED))
        print(color_text("Make sure target.md exists and contains 'path:' and 'function:' keys.", YELLOW))
        sys.exit(1)

    # Run tests using embedded payloads
    run_sql_injection_tests(FUZZ_INPUTS, qb, target_name=target_name, verbose=True)

if __name__ == "__main__":
    main()
