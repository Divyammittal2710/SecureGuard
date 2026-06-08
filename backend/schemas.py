# backend/schemas.py

from pydantic import BaseModel, Field

# 20,000 characters ~ 500 lines of code — enough for real use,
# prevents memory exhaustion from massive payloads.
MAX_CODE_LENGTH = 20_000

class CodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=MAX_CODE_LENGTH)