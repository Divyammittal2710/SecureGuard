# backend/preprocessor.py
"""
Preprocessing module for SecureGuard v2.
Runs before any AI call to:
1. Extract imports and dependencies
2. Detect and strip suspicious comments (prompt injection attempts)
3. Normalize whitespace
4. Return cleaned code + metadata
"""

import re
from typing import List, Tuple


# ── Suspicious comment patterns ───────────────────────────────────────────────
# These are patterns commonly used in prompt injection via code comments

INJECTION_PATTERNS = [
    # Direct instruction overrides
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"override\s+(all\s+)?instructions?",

    # Role/persona changes
    r"you\s+are\s+now\s+a?\s+\w+",
    r"act\s+as\s+(a|an)?\s+\w+",
    r"pretend\s+(you\s+are|to\s+be)",
    r"your\s+new\s+(role|job|task|instruction)",

    # Security bypass attempts
    r"report\s+(this\s+)?(as\s+)?(secure|safe|clean|approved)",
    r"risk[_\s]?score\s*=?\s*0",
    r"risk[_\s]?level\s*=?\s*(low|none|zero)",
    r"no\s+(vulnerabilit|issue|finding|problem)",
    r"mark\s+(this\s+)?(as\s+)?(safe|secure|clean)",
    r"approve\s+(this\s+)?(code|submission|request)",

    # System prompt manipulation
    r"system\s*:\s*",
    r"\[system\]",
    r"\[inst\]",
    r"<\s*system\s*>",
    r"###\s*instruction",
    r"###\s*system",

    # Jailbreak patterns
    r"jailbreak",
    r"dan\s*mode",
    r"developer\s*mode",
    r"do\s+anything\s+now",

    # Output manipulation
    r"print\s+(only|just)\s+",
    r"respond\s+(only|just)\s+with",
    r"output\s+(only|just)\s+",
    r"return\s+(only|just)\s+",

    # Confidence/finding manipulation
    r"confidence\s*=?\s*(low|zero|none|0)",
    r"no\s+findings?",
    r"zero\s+findings?",
    r"this\s+(code\s+)?(has\s+been\s+)?(audited|reviewed|approved|verified)",
]


def extract_imports(code: str, language: str) -> List[str]:
    """
    Extract import statements from code.
    Used by dependency_analyzer node.
    """
    imports = []

    if language == "python":
        # Match: import x, from x import y
        pattern = r"^(?:import|from)\s+[\w\.]+"
        imports = re.findall(pattern, code, re.MULTILINE)

    elif language in ("javascript", "typescript"):
        imports = []
        # Match: require('express'), require("express")
        require_pattern = r"require\s*\(\s*['\"][\w\.\-\/@]+"
        imports += re.findall(require_pattern, code)
        # Match: import axios from 'axios', import { x } from 'y'
        import_pattern = r"from\s+['\"][\w\.\-\/@]+"
        imports += re.findall(import_pattern, code)
        # Match: import 'module' (side effect imports)
        side_effect_pattern = r"^import\s+['\"][\w\.\-\/@]+"
        imports += re.findall(side_effect_pattern, code, re.MULTILINE)

    elif language == "java":
        # Match: import com.example.Class
        pattern = r"^import\s+[\w\.]+"
        imports = re.findall(pattern, code, re.MULTILINE)

    elif language == "go":
        # Match: import "package" or import ( "package" )
        pattern = r"\"[\w\.\/\-]+"
        imports = re.findall(pattern, code)

    elif language == "rust":
        # Match: use std::io, extern crate x
        pattern = r"^(?:use|extern\s+crate)\s+[\w\:]+"
        imports = re.findall(pattern, code, re.MULTILINE)

    elif language == "php":
        # Match: require_once, include, use
        pattern = r"(?:require|include|use)\s+[\w\\\'\"]+"
        imports = re.findall(pattern, code)

    elif language == "ruby":
        # Match: require 'gem', require_relative
        pattern = r"require(?:_relative)?\s+['\"][\w\/\.]+"
        imports = re.findall(pattern, code)

    elif language in ("cpp", "c"):
        # Match: #include <lib> or #include "file"
        pattern = r"#include\s*[<\"][\w\.\/]+"
        imports = re.findall(pattern, code)

    return [imp.strip() for imp in imports]


def extract_comments(code: str, language: str) -> List[str]:
    """
    Extract all comments from code based on language syntax.
    """
    comments = []

    if language in ("python", "ruby"):
        # Single line: # comment
        pattern = r"#.*$"
        comments = re.findall(pattern, code, re.MULTILINE)

    elif language in ("javascript", "typescript", "java", "go", "cpp", "c", "rust", "php"):
        # Single line: // comment
        single = re.findall(r"//.*$", code, re.MULTILINE)
        # Multi line: /* comment */
        multi = re.findall(r"/\*.*?\*/", code, re.DOTALL)
        comments = single + multi

    return [c.strip() for c in comments]


def is_suspicious_comment(comment: str) -> bool:
    """
    Check if a comment contains prompt injection patterns.
    Case insensitive matching.
    """
    comment_lower = comment.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, comment_lower):
            return True
    return False


def strip_comments(code: str, language: str) -> Tuple[str, List[str]]:
    """
    Remove all comments from code.
    Returns: (cleaned_code, list_of_removed_comments)
    """
    removed = []

    if language in ("python", "ruby"):
        def replacer(match):
            removed.append(match.group(0))
            return ""
        cleaned = re.sub(r"#.*$", replacer, code, flags=re.MULTILINE)

    elif language in ("javascript", "typescript", "java", "go", "cpp", "c", "rust", "php"):
        def replacer_single(match):
            removed.append(match.group(0))
            return ""
        def replacer_multi(match):
            removed.append(match.group(0))
            return ""
        cleaned = re.sub(r"//.*$", replacer_single, code, flags=re.MULTILINE)
        cleaned = re.sub(r"/\*.*?\*/", replacer_multi, cleaned, flags=re.DOTALL)

    else:
        cleaned = code

    return cleaned.strip(), removed


def normalize_whitespace(code: str) -> str:
    """
    Normalize excessive whitespace while preserving code structure.
    - Collapse 3+ blank lines into 2
    - Strip trailing whitespace from each line
    """
    # Strip trailing whitespace per line
    lines = [line.rstrip() for line in code.split("\n")]

    # Collapse 3+ consecutive blank lines into 2
    result = []
    blank_count = 0
    for line in lines:
        if line == "":
            blank_count += 1
            if blank_count <= 2:
                result.append(line)
        else:
            blank_count = 0
            result.append(line)

    return "\n".join(result)


def preprocess(code: str, language: str) -> dict:
    """
    Main preprocessing function.
    Returns a PreprocessResult dict.
    """
    original_code = code

    # Step 1 — Extract imports BEFORE stripping
    imports = extract_imports(code, language)

    # Step 2 — Extract all comments to check for injection
    all_comments = extract_comments(code, language)

    # Step 3 — Find suspicious comments
    flagged_comments = [
        c for c in all_comments
        if is_suspicious_comment(c)
    ]
    has_suspicious_comments = len(flagged_comments) > 0

    # Step 4 — Strip ALL comments from code sent to AI
    # This prevents ANY comment from being used for injection
    cleaned_code, stripped_comments = strip_comments(code, language)

    # Step 5 — Normalize whitespace
    cleaned_code = normalize_whitespace(cleaned_code)

    return {
        "cleaned_code": cleaned_code,
        "original_code": original_code,
        "imports": imports,
        "has_suspicious_comments": has_suspicious_comments,
        "flagged_comments": flagged_comments,
        "stripped_comments": stripped_comments,
        "language": language,
    }