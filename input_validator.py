"""
OWASP LLM Top 10 Guardrails for Hancock
- Prompt Injection (LLM01)
- Improper Output Handling (LLM05)
- Excessive Agency (LLM06)
"""
import re
import json
from typing import Dict, Any

def sanitize_prompt(prompt: str) -> str:
    """Block common injection patterns."""
    # Block system prompt overrides
    prompt = re.sub(r"(?i)(system|ignore|override|jailbreak|developer mode)", "[REDACTED]", prompt)
    return prompt.strip()

def validate_output(output: Dict[str, Any]) -> Dict[str, Any]:
    """Enforce structured output + PII redaction."""
    if not isinstance(output, dict):
        output = {"result": str(output)}
    # Redact potential secrets
    for key in list(output.keys()):
        if any(secret in str(output[key]).lower() for secret in ["password", "key", "token", "secret"]):
            output[key] = "[REDACTED]"
    return output

def check_authorization(state: Dict) -> bool:
    """Human-in-the-loop for high-risk modes."""
    high_risk_modes = {"pentest", "exploit", "google"}
    if state.get("mode") in high_risk_modes and not state.get("authorized"):
        raise PermissionError("High-risk action requires explicit authorization.")
    return True
