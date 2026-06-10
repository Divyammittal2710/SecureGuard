# backend/schemas.py
from enum import Enum
from pydantic import BaseModel, Field, field_validator

MAX_CODE_LENGTH = 20_000


class Language(str, Enum):
    python     = "python"
    javascript = "javascript"
    java       = "java"
    typescript = "typescript"
    go         = "go"
    rust       = "rust"
    cpp        = "cpp"
    c          = "c"
    ruby       = "ruby"
    php        = "php"


def detect_language(code: str) -> str:
    """
    Heuristic language detector based on keyword patterns.
    Scores each language and returns the highest scoring one.
    Returns 'unknown' if no language scores above 0.
    """
    scores = {
        "python": 0, "javascript": 0, "java": 0,
        "typescript": 0, "go": 0, "rust": 0,
        "cpp": 0, "c": 0, "ruby": 0, "php": 0,
    }

    # ── PYTHON ──────────────────────────────────────────
    if "def "          in code: scores["python"] += 2
    if "elif "         in code: scores["python"] += 3  # unique to python
    if "self."         in code: scores["python"] += 2
    if "import "       in code: scores["python"] += 1
    if "from "         in code and "import " in code: scores["python"] += 2
    if "print("        in code: scores["python"] += 2
    if "None"          in code: scores["python"] += 2  # not null, not nil
    if "True"          in code or "False" in code: scores["python"] += 2
    if "__init__"      in code: scores["python"] += 3
    if "__name__"      in code: scores["python"] += 3
    if "lambda "       in code: scores["python"] += 2
    if "list("         in code: scores["python"] += 1
    if "dict("         in code: scores["python"] += 1
    if "len("          in code: scores["python"] += 1
    if "range("        in code: scores["python"] += 2
    if "for "          in code and " in " in code: scores["python"] += 2  # for x in y
    if "pass"          in code: scores["python"] += 2
    if "raise "        in code: scores["python"] += 1
    if "except "       in code: scores["python"] += 1
    if "with open("    in code: scores["python"] += 3
    if "f\""           in code or "f'"  in code: scores["python"] += 2  # f-strings
    if "pip"           in code: scores["python"] += 1
    if "requirements"  in code: scores["python"] += 1
    if "virtualenv"    in code: scores["python"] += 2
    if "@app.route"    in code: scores["python"] += 3  # Flask
    if "@app.get"      in code: scores["python"] += 3  # FastAPI
    if "async def "    in code: scores["python"] += 2
    if "await "        in code: scores["python"] += 1

    # ── JAVASCRIPT ──────────────────────────────────────
    if "function "     in code: scores["javascript"] += 2
    if "const "        in code: scores["javascript"] += 2
    if "let "          in code: scores["javascript"] += 2
    if "var "          in code: scores["javascript"] += 1
    if "=>"            in code: scores["javascript"] += 2  # arrow functions
    if "console.log"   in code: scores["javascript"] += 3
    if "console.error" in code: scores["javascript"] += 3
    if "document."     in code: scores["javascript"] += 3  # DOM
    if "window."       in code: scores["javascript"] += 3  # browser
    if "require("      in code: scores["javascript"] += 2  # CommonJS
    if "module.exports"in code: scores["javascript"] += 3
    if "undefined"     in code: scores["javascript"] += 2
    if "null"          in code: scores["javascript"] += 1
    if "==="           in code: scores["javascript"] += 2  # strict equality
    if "!=="           in code: scores["javascript"] += 2
    if "async "        in code: scores["javascript"] += 1
    if "await "        in code: scores["javascript"] += 1
    if "Promise"       in code: scores["javascript"] += 2
    if ".then("        in code: scores["javascript"] += 2
    if ".catch("       in code: scores["javascript"] += 2
    if "JSON.parse"    in code: scores["javascript"] += 3
    if "JSON.stringify"in code: scores["javascript"] += 3
    if "addEventListener" in code: scores["javascript"] += 3
    if "getElementById"in code: scores["javascript"] += 3
    if "typeof "       in code: scores["javascript"] += 2
    if "npm"           in code: scores["javascript"] += 1
    if "node_modules"  in code: scores["javascript"] += 2
    if "express"       in code: scores["javascript"] += 2

    # ── TYPESCRIPT ─────────────────────────────────────
    # TypeScript includes all JS signals + these specific ones
    if ": string"      in code: scores["typescript"] += 3
    if ": number"      in code: scores["typescript"] += 3
    if ": boolean"     in code: scores["typescript"] += 3
    if ": void"        in code: scores["typescript"] += 3
    if ": any"         in code: scores["typescript"] += 2
    if "interface "    in code: scores["typescript"] += 3
    if "type "         in code and " = " in code: scores["typescript"] += 2
    if "<T>"           in code: scores["typescript"] += 3  # generics
    if "Array<"        in code: scores["typescript"] += 3
    if "Promise<"      in code: scores["typescript"] += 3
    if "enum "         in code: scores["typescript"] += 2
    if "readonly "     in code: scores["typescript"] += 2
    if "private "      in code and ":" in code: scores["typescript"] += 2
    if "public "       in code and ":" in code: scores["typescript"] += 1
    if "implements "   in code: scores["typescript"] += 3
    if "extends "      in code: scores["typescript"] += 1
    if "as "           in code: scores["typescript"] += 1  # type casting
    if "import type"   in code: scores["typescript"] += 3
    if ".ts\""         in code: scores["typescript"] += 2
    if "tsconfig"      in code: scores["typescript"] += 3

    # boost JS signals for TS too since TS is a superset
    if "const "        in code: scores["typescript"] += 1
    if "=>"            in code: scores["typescript"] += 1

    # ── JAVA ────────────────────────────────────────────
    if "public class " in code: scores["java"] += 4
    if "public static void main" in code: scores["java"] += 4
    if "System.out.println" in code: scores["java"] += 4
    if "import java."  in code: scores["java"] += 4
    if "private "      in code: scores["java"] += 1
    if "protected "    in code: scores["java"] += 2
    if "throws "       in code: scores["java"] += 3  # throws Exception
    if "void "         in code: scores["java"] += 1
    if "String "       in code: scores["java"] += 2  # String username (capital S)
    if "int "          in code: scores["java"] += 1
    if "boolean "      in code: scores["java"] += 1
    if "new "          in code and "(" in code: scores["java"] += 1
    if "null"          in code: scores["java"] += 1
    if "this."         in code: scores["java"] += 2
    if "super."        in code: scores["java"] += 2
    if "extends "      in code: scores["java"] += 1
    if "implements "   in code: scores["java"] += 2
    if "interface "    in code: scores["java"] += 2
    if "abstract "     in code: scores["java"] += 2
    if "final "        in code: scores["java"] += 1
    if "static "       in code: scores["java"] += 1
    if "try {"         in code: scores["java"] += 1
    if "catch ("       in code: scores["java"] += 2
    if "ResultSet"     in code: scores["java"] += 4  # very java-specific
    if "DriverManager" in code: scores["java"] += 4
    if "SQLException"  in code: scores["java"] += 4
    if "ArrayList"     in code: scores["java"] += 3
    if "HashMap"       in code: scores["java"] += 3
    if "Iterator"      in code: scores["java"] += 3
    if "override"      in code.lower(): scores["java"] += 2
    if ".equals("      in code: scores["java"] += 3  # java string comparison
    if ".length()"     in code: scores["java"] += 2
    if ".toString()"   in code: scores["java"] += 2
    if "stmt."         in code: scores["java"] += 3  # JDBC statement
    if "conn."         in code: scores["java"] += 2  # JDBC connection
    if "prepareStatement" in code: scores["java"] += 4

    # ── GO ──────────────────────────────────────────────
    if "package main"  in code: scores["go"] += 4
    if "func "         in code: scores["go"] += 3
    if "fmt.Println"   in code: scores["go"] += 4
    if "fmt.Printf"    in code: scores["go"] += 4
    if ":="            in code: scores["go"] += 3  # short variable declaration
    if "import ("      in code: scores["go"] += 3  # Go multi-import
    if "var "          in code and ":=" in code: scores["go"] += 1
    if "go func"       in code: scores["go"] += 4  # goroutine
    if "chan "          in code: scores["go"] += 4  # channels
    if "defer "        in code: scores["go"] += 4  # very Go-specific
    if "goroutine"     in code: scores["go"] += 3
    if "interface{"    in code: scores["go"] += 3
    if "struct {"      in code: scores["go"] += 2
    if "make("         in code: scores["go"] += 2
    if "append("       in code: scores["go"] += 1
    if "len("          in code: scores["go"] += 1
    if "nil"           in code: scores["go"] += 2
    if "error"         in code: scores["go"] += 1
    if "if err != nil" in code: scores["go"] += 4  # extremely Go-specific
    if "return nil"    in code: scores["go"] += 2
    if "map["          in code: scores["go"] += 2
    if "range "        in code: scores["go"] += 2
    if "select {"      in code: scores["go"] += 3

    # ── RUST ────────────────────────────────────────────
    if "fn "           in code: scores["rust"] += 2
    if "let mut "      in code: scores["rust"] += 4  # mutable binding
    if "let "          in code: scores["rust"] += 1
    if "println!("     in code: scores["rust"] += 4
    if "eprintln!("    in code: scores["rust"] += 4
    if "use std::"     in code: scores["rust"] += 4
    if "impl "         in code: scores["rust"] += 3
    if "pub fn"        in code: scores["rust"] += 3
    if "-> Result<"    in code: scores["rust"] += 4
    if "-> Option<"    in code: scores["rust"] += 4
    if "match "        in code: scores["rust"] += 3
    if "Some("         in code: scores["rust"] += 3
    if "None"          in code and "fn " in code: scores["rust"] += 2
    if "unwrap()"      in code: scores["rust"] += 4  # very Rust-specific
    if "expect("       in code: scores["rust"] += 2
    if "Vec<"          in code: scores["rust"] += 3
    if "HashMap<"      in code: scores["rust"] += 3
    if "String::from"  in code: scores["rust"] += 4
    if "to_string()"   in code: scores["rust"] += 2
    if "&str"          in code: scores["rust"] += 4
    if "&mut "         in code: scores["rust"] += 4  # mutable reference
    if "lifetime"      in code: scores["rust"] += 3
    if "cargo"         in code.lower(): scores["rust"] += 2
    if "Cargo.toml"    in code: scores["rust"] += 4
    if "#[derive("     in code: scores["rust"] += 4  # derive macros
    if "#[test]"       in code: scores["rust"] += 4
    if "mod "          in code: scores["rust"] += 2
    if "crate::"       in code: scores["rust"] += 3

    # ── C++ ─────────────────────────────────────────────
    if "#include <iostream>" in code: scores["cpp"] += 4
    if "#include <vector>"   in code: scores["cpp"] += 4
    if "#include <string>"   in code: scores["cpp"] += 3
    if "#include <map>"      in code: scores["cpp"] += 3
    if "std::"         in code: scores["cpp"] += 3
    if "cout <<"       in code: scores["cpp"] += 4
    if "cin >>"        in code: scores["cpp"] += 4
    if "endl"          in code: scores["cpp"] += 3
    if "nullptr"       in code: scores["cpp"] += 4  # modern C++
    if "auto "         in code: scores["cpp"] += 2
    if "vector<"       in code: scores["cpp"] += 3
    if "string "       in code and "std" in code: scores["cpp"] += 2
    if "class "        in code and "::" in code: scores["cpp"] += 2
    if "public:"       in code: scores["cpp"] += 3
    if "private:"      in code: scores["cpp"] += 3
    if "protected:"    in code: scores["cpp"] += 3
    if "new "          in code and "delete" in code: scores["cpp"] += 4
    if "delete "       in code: scores["cpp"] += 3
    if "->"            in code and "::" in code: scores["cpp"] += 2
    if "template<"     in code: scores["cpp"] += 4  # templates
    if "namespace "    in code: scores["cpp"] += 3
    if "using namespace" in code: scores["cpp"] += 4
    if "virtual "      in code: scores["cpp"] += 3
    if "override"      in code: scores["cpp"] += 2
    if "const_cast"    in code: scores["cpp"] += 4
    if "static_cast"   in code: scores["cpp"] += 4

    # ── C ───────────────────────────────────────────────
    if "#include <stdio.h>"  in code: scores["c"] += 4
    if "#include <stdlib.h>" in code: scores["c"] += 4
    if "#include <string.h>" in code: scores["c"] += 3
    if "#include <math.h>"   in code: scores["c"] += 3
    if "printf("       in code: scores["c"] += 3
    if "scanf("        in code: scores["c"] += 4
    if "malloc("       in code: scores["c"] += 4
    if "calloc("       in code: scores["c"] += 4
    if "realloc("      in code: scores["c"] += 4
    if "free("         in code: scores["c"] += 3
    if "int main("     in code: scores["c"] += 4
    if "void main("    in code: scores["c"] += 3
    if "return 0;"     in code: scores["c"] += 2
    if "NULL"          in code: scores["c"] += 2
    if "sizeof("       in code: scores["c"] += 3
    if "struct "       in code and "typedef" not in code: scores["c"] += 2
    if "typedef "      in code: scores["c"] += 3
    if "char "         in code: scores["c"] += 2
    if "int "          in code and "float" in code: scores["c"] += 1
    if "pointer"       in code.lower(): scores["c"] += 1
    if "*"             in code and "&" in code: scores["c"] += 1
    if "fopen("        in code: scores["c"] += 4
    if "fclose("       in code: scores["c"] += 4
    if "fprintf("      in code: scores["c"] += 3
    if "fscanf("       in code: scores["c"] += 3
    if "strcpy("       in code: scores["c"] += 4
    if "strcat("       in code: scores["c"] += 4
    if "strlen("       in code: scores["c"] += 3

    # ── RUBY ────────────────────────────────────────────
    if "def "          in code and "end" in code: scores["ruby"] += 3
    if "puts "         in code: scores["ruby"] += 4
    if "print "        in code and "end" in code: scores["ruby"] += 2
    if "require '"     in code: scores["ruby"] += 3
    if "require \""    in code: scores["ruby"] += 3
    if "attr_accessor" in code: scores["ruby"] += 4  # very Ruby-specific
    if "attr_reader"   in code: scores["ruby"] += 4
    if "attr_writer"   in code: scores["ruby"] += 4
    if ".each do"      in code: scores["ruby"] += 4
    if ".each {"       in code: scores["ruby"] += 3
    if "do |"          in code: scores["ruby"] += 3  # block with variable
    if "end"           in code: scores["ruby"] += 1
    if "nil"           in code: scores["ruby"] += 1
    if "elsif"         in code: scores["ruby"] += 4  # unique to ruby
    if "unless "       in code: scores["ruby"] += 4  # unique to ruby
    if "until "        in code: scores["ruby"] += 3
    if "yield"         in code: scores["ruby"] += 3
    if "class "        in code and "end" in code: scores["ruby"] += 2
    if "module "       in code and "end" in code: scores["ruby"] += 3
    if "initialize"    in code: scores["ruby"] += 3  # Ruby constructor
    if "raise "        in code and "end" in code: scores["ruby"] += 1
    if "rescue "       in code: scores["ruby"] += 3  # Ruby's except
    if "begin"         in code and "rescue" in code: scores["ruby"] += 3
    if "p "            in code: scores["ruby"] += 1
    if "pp "           in code: scores["ruby"] += 2
    if "gem "          in code: scores["ruby"] += 3
    if "Gemfile"       in code: scores["ruby"] += 4
    if "@"             in code: scores["ruby"] += 1  # instance variables
    if "@@"            in code: scores["ruby"] += 3  # class variables
    if "symbol"        in code.lower(): scores["ruby"] += 1
    if ":"             in code and "=>" in code: scores["ruby"] += 2  # hash syntax

    # ── PHP ─────────────────────────────────────────────
    if "<?php"         in code: scores["php"] += 5  # definitive
    if "?>"            in code: scores["php"] += 3
    if "echo "         in code: scores["php"] += 3
    if "$"             in code: scores["php"] += 2  # variables start with $
    if "->"            in code and "$" in code: scores["php"] += 3  # $obj->method
    if "::"            in code and "$" in code: scores["php"] += 2  # static method
    if "function "     in code and "$" in code: scores["php"] += 2
    if "array("        in code: scores["php"] += 3
    if "foreach("      in code: scores["php"] += 3
    if "foreach ("     in code: scores["php"] += 3
    if "isset("        in code: scores["php"] += 4  # very PHP-specific
    if "empty("        in code: scores["php"] += 3
    if "unset("        in code: scores["php"] += 3
    if "die("          in code: scores["php"] += 3
    if "exit("         in code: scores["php"] += 2
    if "include "      in code: scores["php"] += 2
    if "require_once"  in code: scores["php"] += 4
    if "include_once"  in code: scores["php"] += 4
    if "namespace "    in code and "$" in code: scores["php"] += 3
    if "use "          in code and "$" in code: scores["php"] += 2
    if "public function" in code: scores["php"] += 3
    if "private function" in code: scores["php"] += 3
    if "protected function" in code: scores["php"] += 3
    if "mysqli_"       in code: scores["php"] += 4  # PHP MySQL extension
    if "PDO"           in code: scores["php"] += 4  # PHP database
    if "$_GET"         in code: scores["php"] += 5
    if "$_POST"        in code: scores["php"] += 5
    if "$_SESSION"     in code: scores["php"] += 5
    if "$_SERVER"      in code: scores["php"] += 5
    if "htmlspecialchars" in code: scores["php"] += 4
    if "strlen("       in code and "$" in code: scores["php"] += 2
    if "str_replace("  in code: scores["php"] += 2
    if "explode("      in code: scores["php"] += 3
    if "implode("      in code: scores["php"] += 3

    # ── RESOLVE ─────────────────────────────────────────
    # TypeScript vs JavaScript disambiguation:
    # If code has strong TS signals (: string, interface, generics)
    # reduce JS score to avoid false JS detection
    if scores["typescript"] >= 6:
        scores["javascript"] = max(0, scores["javascript"] - 4)

    # C vs C++ disambiguation:
    # If code has strong C++ signals (std::, cout, class with ::)
    # reduce C score
    if scores["cpp"] >= 6:
        scores["c"] = max(0, scores["c"] - 3)

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