"""
Hancock Advanced OWASP LLM01 Prompt Injection Guard (2026 edition)
Blocks multi-layer encoding, role-play hijacks, delimiter attacks, token smuggling, and multi-turn poisoning.
"""
import re
import json
from typing import Dict, Any

# Advanced pattern database (high-confidence only — no false positives on legitimate pentest commands)
ADVANCED_INJECTION_PATTERNS = [
    r"(?i)(developer mode|jailbreak|ignore all rules|override system|new instructions|act as)",
    r"(?i)(base64|rot13|hex|unicode|utf-?7|html entity).*?prompt|system|instruction",
    r"(?i)(\{\{|\}\}|\[\[|\]\]|<system>|<\/system>|<prompt>|<\/prompt>)",
    r"(?i)(zero-width|homoglyph|invisible|control character|U\+200B|U\+FEFF)",
    r"(?i)(you are now|pretend you are|roleplay as).*?(developer|unrestricted|root)",
]

def detect_encoding_layer(prompt: str) -> bool:
    """Detect nested encoding attempts."""
    encodings = ["base64", "rot13", "hex", "unicode"]
    lower = prompt.lower()
    return any(enc in lower and any(other in lower for other in encodings if other != enc) for enc in encodings)

def sanitize_prompt(prompt: str, mode: str = "auto") -> str:
    """Advanced LLM01 sanitization — layered, fail-closed."""
    original = prompt
    max_len = 4000 if mode in {"pentest", "exploit"} else 2000
    if len(prompt) > max_len:
        prompt = prompt[:max_len] + " [TRUNCATED — LLM01]"

    # 1. Block advanced patterns
    for pattern in ADVANCED_INJECTION_PATTERNS:
        prompt = re.sub(pattern, "[LLM01_BLOCKED]", prompt, flags=re.IGNORECASE)

    # 2. Encoding detection
    if detect_encoding_layer(prompt):
        prompt = "[LLM01_ENCODING_DETECTED]"

    # 3. Delimiter / hierarchy escaping
    prompt = re.sub(r"(\{\{|\}\}|\[\[|\]\]|<|>|&lt;|&gt;)", r"\\\1", prompt)

    # 4. Token smuggling / invisible chars
    prompt = re.sub(r"[\u200B-\u200F\uFEFF]", "[INVISIBLE_BLOCKED]", prompt)

    if prompt != original:
        print(f"🛡️ Advanced LLM01 injection sanitized: {len(original)} → {len(prompt)} chars")
    return prompt.strip()

def validate_output(output: Dict[str, Any]) -> Dict[str, Any]:
    """LLM02 tie-in: sensitive info redaction."""
    if not isinstance(output, dict):
        output = {"result": str(output)}
    for k, v in list(output.items()):
        if any(secret in str(v).lower() for secret in ["password", "key", "token", "secret", "api_key", "credentials"]):
            output[k] = "[REDACTED_SENSITIVE]"
    return output

def check_authorization(state: Dict) -> bool:
    """LLM06 tie-in."""
    high_risk = {"pentest", "exploit", "google"}
    if state.get("mode") in high_risk and (state.get("confidence", 0) < 0.9 or not state.get("authorized")):
        raise PermissionError("High-risk action requires explicit authorization (confidence < 0.9)")
    return True
