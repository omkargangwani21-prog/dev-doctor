import re
from typing import Any

_PATTERNS = [
    (re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*'), 'Bearer [REDACTED]'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b'), '[JWT REDACTED]'),
    (re.compile(r'\bAIza[0-9A-Za-z_-]{20,}\b'), '[API KEY REDACTED]'),
]
_SECRET = re.compile(r'(?i)(token|secret|password|passwd|authorization|api[_-]?key|\bkey\b)\s*[=:]\s*([^,;\s]+)')

def redact(value: Any):
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if re.search(r'(?i)token|secret|password|passwd|authorization|api[_-]?key|^key$', str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    text = str(value)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return _SECRET.sub(lambda m: m.group(1) + '=[REDACTED]', text)[:500]
