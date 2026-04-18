"""
Hancock OWASP LLM01 Encoding Bypass Guard (multi-layer + recursive detection)
"""
import re
import base64
from collections import deque
from typing import Dict, Any

CONV_HISTORY: deque = deque(maxlen=10)

ENCODING_PATTERNS = [
    r"(?i)(base64|rot13|hex|unicode|utf-?7|html entity|%[0-9a-f]{2})",
    r"(?i)(decode|unescape|from base64|rot13)",
]

def recursive_decode(text: str, depth: int = 3) -> str:
    """Attempt up to 3 layers of common encodings and re-scan."""
    if depth == 0:
        return text
    decoded = text
    try:
        # Base64
        if len(decoded) % 4 == 0 and re.search(r"^[A-Za-z0-9+/=]+$", decoded):
            decoded = base64.b64decode(decoded).decode("utf-8", errors="ignore")
    except:
        pass
    try:
        # Rot13
        decoded = decoded.translate(str.maketrans("NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"))
    except:
        pass
    # Re-check for injection after decode
    if re.search(r"(?i)(system|ignore|jailbreak|developer mode)", decoded):
        return "[LLM01_ENCODING_BYPASS_DETECTED]"
    return recursive_decode(decoded, depth - 1)

def sanitize_prompt(prompt: str, mode: str = "auto") -> str:
    """LLM01 Encoding + Role-Play + Multi-Turn sanitization."""
    global CONV_HISTORY
    original = prompt
    max_len = 4000 if mode in {"pentest", "exploit"} else 2000
    if len(prompt) > max_len:
        prompt = prompt[:max_len] + " [TRUNCATED — LLM01]"

    CONV_HISTORY.append(prompt.lower())

    # 1. Recursive encoding detection
    prompt = recursive_decode(prompt)

    # 2. Role-play + multi-turn patterns
    history_text = " ".join(CONV_HISTORY)
    if re.search(r"(?i)(you are now|role-play as|pretend you are|act as).*?(unrestricted|developer mode|jailbreak)", history_text):
        prompt = "[LLM01_ROLE_PLAY_BYPASS_DETECTED]"

    # 3. Standard injection + delimiter hardening
    prompt = re.sub(r"(?i)(developer mode|jailbreak|ignore all rules|override system)", "[LLM01_BLOCKED]", prompt)
    prompt = re.sub(r"(\{\{|\}\}|\[\[|\]\]|<|>|&lt;|&gt;)", r"\\\1", prompt)
    prompt = re.sub(r"[\u200B-\u200F\uFEFF]", "[INVISIBLE_BLOCKED]", prompt)

    if prompt != original:
        print(f"🛡️ LLM01 Encoding Bypass sanitized: {len(original)} → {len(prompt)} chars")
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
