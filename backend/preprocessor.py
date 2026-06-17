# backend/preprocessor.py
"""
Preprocessing module for SecureGuard v2.
Runs before any AI call to:
1. Extract imports and dependencies
2. Detect and strip suspicious comments (prompt injection attempts)
3. Detect injection in string literals and docstrings
4. Normalize whitespace
5. Return cleaned code + metadata
"""

import re
from typing import List, Tuple


# ── Suspicious patterns ───────────────────────────────────────────────────────

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
    Extract import statements from code based on language.
    Used by dependency_analyzer node.
    """
    imports = []

    if language == "python":
        pattern = r"^(?:import|from)\s+[\w\.]+"
        imports = re.findall(pattern, code, re.MULTILINE)

    elif language in ("javascript", "typescript"):
        imports = []
        require_pattern = r"require\s*\(\s*['\"][\w\.\-\/@]+"
        imports += re.findall(require_pattern, code)
        import_pattern = r"from\s+['\"][\w\.\-\/@]+"
        imports += re.findall(import_pattern, code)
        side_effect_pattern = r"^import\s+['\"][\w\.\-\/@]+"
        imports += re.findall(side_effect_pattern, code, re.MULTILINE)

    elif language == "java":
        pattern = r"^import\s+[\w\.]+"
        imports = re.findall(pattern, code, re.MULTILINE)

    elif language == "go":
        pattern = r"\"[\w\.\/\-]+"
        imports = re.findall(pattern, code)

    elif language == "rust":
        pattern = r"^(?:use|extern\s+crate)\s+[\w\:]+"
        imports = re.findall(pattern, code, re.MULTILINE)

    elif language == "php":
        pattern = r"(?:require|include|use)\s+[\w\\\'\"]+"
        imports = re.findall(pattern, code)

    elif language == "ruby":
        pattern = r"require(?:_relative)?\s+['\"][\w\/\.]+"
        imports = re.findall(pattern, code)

    elif language in ("cpp", "c"):
        pattern = r"#include\s*[<\"][\w\.\/]+"
        imports = re.findall(pattern, code)

    return [imp.strip() for imp in imports]


def extract_comments(code: str, language: str) -> List[str]:
    """
    Extract all comments from code based on language syntax.
    """
    comments = []

    if language in ("python", "ruby"):
        pattern = r"#.*$"
        comments = re.findall(pattern, code, re.MULTILINE)

    elif language in ("javascript", "typescript", "java", "go", "cpp", "c", "rust", "php"):
        single = re.findall(r"//.*$", code, re.MULTILINE)
        multi = re.findall(r"/\*.*?\*/", code, re.DOTALL)
        comments = single + multi

    return [c.strip() for c in comments]


def extract_string_literals(code: str) -> List[str]:
    """
    Extract string literals and docstrings from code.
    These can contain injection attempts that bypass comment stripping.
    Only extracts strings longer than 20 chars to avoid noise.
    """
    literals = []

    # Triple quoted strings (docstrings)
    triple_double = re.findall(r'"""(.*?)"""', code, re.DOTALL)
    triple_single = re.findall(r"'''(.*?)'''", code, re.DOTALL)
    literals += triple_double + triple_single

    # Single line strings — only if long enough to be suspicious
    single_double = re.findall(r'"([^"]{20,})"', code)
    single_single = re.findall(r"'([^']{20,})'", code)
    literals += single_double + single_single

    return [l.strip() for l in literals if l.strip()]


def is_suspicious_comment(comment: str) -> bool:
    """
    Check if a comment or string contains prompt injection patterns.
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


def strip_docstrings(code: str) -> Tuple[str, List[str]]:
    """
    Remove docstrings from code sent to AI.
    Replaces with a safe placeholder so code structure is preserved.
    Returns: (cleaned_code, list_of_removed_docstrings)
    """
    removed = []

    def replacer_double(match):
        removed.append(match.group(0))
        return '""" [docstring removed] """'

    def replacer_single(match):
        removed.append(match.group(0))
        return "''' [docstring removed] '''"

    cleaned = re.sub(r'""".*?"""', replacer_double, code, flags=re.DOTALL)
    cleaned = re.sub(r"'''.*?'''", replacer_single, cleaned, flags=re.DOTALL)

    return cleaned, removed


def normalize_whitespace(code: str) -> str:
    """
    Normalize excessive whitespace while preserving code structure.
    - Strip trailing whitespace from each line
    - Collapse 3+ blank lines into 2
    """
    lines = [line.rstrip() for line in code.split("\n")]

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

    # Step 2 — Extract all comments
    all_comments = extract_comments(code, language)

    # Step 3 — Find suspicious comments
    flagged_comments = [
        c for c in all_comments
        if is_suspicious_comment(c)
    ]

    # Step 4 — Extract string literals and docstrings
    string_literals = extract_string_literals(code)

    # Step 5 — Find suspicious string literals
    flagged_strings = [
        s for s in string_literals
        if is_suspicious_comment(s)
    ]

    # Step 6 — Strip ALL comments
    cleaned_code, stripped_comments = strip_comments(code, language)

    # Step 7 — Strip docstrings (can contain injection)
    cleaned_code, stripped_docstrings = strip_docstrings(cleaned_code)

    # Step 8 — Normalize whitespace
    cleaned_code = normalize_whitespace(cleaned_code)

    has_suspicious = len(flagged_comments) > 0 or len(flagged_strings) > 0

    return {
        "cleaned_code": cleaned_code,
        "original_code": original_code,
        "imports": imports,
        "has_suspicious_comments": has_suspicious,
        "flagged_comments": flagged_comments,
        "flagged_strings": flagged_strings,
        "stripped_comments": stripped_comments,
        "stripped_docstrings": stripped_docstrings,
        "language": language,
    }