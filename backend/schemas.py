# backend/schemas.py
from enum import Enum
from pydantic import BaseModel, Field, field_validator

MAX_CODE_LENGTH = 20_000


class Language(str, Enum):
    python = "python"
    javascript = "javascript"
    java = "java"
    typescript = "typescript"
    go = "go"
    rust = "rust"
    cpp = "cpp"
    c = "c"
    ruby = "ruby"
    php = "php"


def detect_language(code: str) -> str:
    """
    Simple heuristic language detector based on keyword patterns.
    Not perfect — but good enough to catch obvious mismatches.
    Returns detected language string or 'unknown' if unsure.
    """
    code_lower = code.lower()

    scores = {
        "python": 0,
        "javascript": 0,
        "java": 0,
        "typescript": 0,
        "go": 0,
        "rust": 0,
        "cpp": 0,
        "c": 0,
        "ruby": 0,
        "php": 0,
    }

    # Python signals
    if "def " in code: scores["python"] += 2
    if "import " in code and "from " in code: scores["python"] += 2
    if "print(" in code: scores["python"] += 1
    if "elif " in code: scores["python"] += 3
    if "self." in code: scores["python"] += 2
    if "None" in code: scores["python"] += 1
    if "True" in code or "False" in code: scores["python"] += 1
    if "pip" in code_lower: scores["python"] += 1

    # JavaScript signals
    if "function " in code: scores["javascript"] += 2
    if "const " in code: scores["javascript"] += 2
    if "let " in code: scores["javascript"] += 2
    if "var " in code: scores["javascript"] += 1
    if "=>" in code: scores["javascript"] += 2
    if "console.log" in code: scores["javascript"] += 3
    if "document." in code: scores["javascript"] += 3
    if "require(" in code: scores["javascript"] += 2
    if "undefined" in code: scores["javascript"] += 1

    # TypeScript signals (on top of JS)
    if ": string" in code: scores["typescript"] += 3
    if ": number" in code: scores["typescript"] += 3
    if ": boolean" in code: scores["typescript"] += 3
    if "interface " in code: scores["typescript"] += 3
    if "type " in code and "=" in code: scores["typescript"] += 2
    if "<T>" in code or "Array<" in code: scores["typescript"] += 2

    # Java signals
    if "public class " in code: scores["java"] += 3
    if "public static void main" in code: scores["java"] += 3
    if "System.out.println" in code: scores["java"] += 3
    if "private " in code or "protected " in code: scores["java"] += 1
    if "new " in code and "();" in code: scores["java"] += 1
    if "import java." in code: scores["java"] += 3

    # Go signals
    if "func " in code: scores["go"] += 2
    if "package main" in code: scores["go"] += 3
    if "fmt.Println" in code: scores["go"] += 3
    if ":=" in code: scores["go"] += 2
    if "import (" in code: scores["go"] += 2

    # Rust signals
    if "fn " in code: scores["rust"] += 2
    if "let mut " in code: scores["rust"] += 3
    if "println!(" in code: scores["rust"] += 3
    if "use std::" in code: scores["rust"] += 3
    if "impl " in code: scores["rust"] += 2
    if "-> Result<" in code: scores["rust"] += 2

    # C++ signals
    if "#include <iostream>" in code: scores["cpp"] += 3
    if "std::" in code: scores["cpp"] += 2
    if "cout <<" in code: scores["cpp"] += 3
    if "endl" in code: scores["cpp"] += 2
    if "nullptr" in code: scores["cpp"] += 2

    # C signals
    if "#include <stdio.h>" in code: scores["c"] += 3
    if "printf(" in code: scores["c"] += 2
    if "malloc(" in code: scores["c"] += 2
    if "int main(" in code: scores["c"] += 2

    # Ruby signals
    if "def " in code and "end" in code: scores["ruby"] += 2
    if "puts " in code: scores["ruby"] += 3
    if "require '" in code: scores["ruby"] += 2
    if "attr_accessor" in code: scores["ruby"] += 3
    if ".each do" in code: scores["ruby"] += 3

    # PHP signals
    if "<?php" in code: scores["php"] += 5
    if "echo " in code: scores["php"] += 2
    if "$" in code: scores["php"] += 1
    if "->" in code and "$" in code: scores["php"] += 2

    # Get highest score
    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        return "unknown"
    return best


class CodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=MAX_CODE_LENGTH)
    language: Language

    @field_validator("code")
    @classmethod
    def reject_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            v = v.replace("\x00", "")
        return v

    @field_validator("code")
    @classmethod
    def reject_binary(cls, v: str) -> str:
        non_printable = sum(
            1 for c in v
            if ord(c) < 32 and c not in ("\n", "\r", "\t")
        )
        if len(v) > 0 and (non_printable / len(v)) > 0.1:
            raise ValueError(
                "Binary content detected — please submit source code only"
            )
        return v