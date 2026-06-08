# backend/schemas.py

from pydantic import BaseModel, Field, field_validator

# 20,000 characters ~ 500 lines of code — enough for real use,
# prevents memory exhaustion and expensive Azure OpenAI calls.
MAX_CODE_LENGTH = 20_000


class CodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=MAX_CODE_LENGTH)

    @field_validator("code")
    @classmethod
    def reject_null_bytes(cls, v: str) -> str:
        """
        Null bytes (\x00) can bypass pattern matchers — some scanners
        stop reading at null bytes, so 'password\x00malicious' would
        only be scanned as 'password'. Strip them outright.
        """
        if "\x00" in v:
            v = v.replace("\x00", "")
        return v

    @field_validator("code")
    @classmethod
    def reject_binary(cls, v: str) -> str:
        """
        Reject binary content — compiled bytecode or executables
        submitted as 'code' would confuse the rule engine and waste
        Azure OpenAI tokens. Check for high density of non-printable
        characters as a signal of binary content.
        """
        non_printable = sum(
            1 for c in v
            if ord(c) < 32 and c not in ("\n", "\r", "\t")
        )
        if len(v) > 0 and (non_printable / len(v)) > 0.1:
            raise ValueError(
                "Binary content detected — please submit source code only"
            )
        return v