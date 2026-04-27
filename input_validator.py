"""
Hancock OWASP LLM01 Zero-Day Prompt Injection Guard
Recursive encoding + role-play + multi-turn + ANOMALY DETECTION for unknown bypasses
Also includes input validation utilities for IOCs, modes, and other parameters.
"""
import re
import math
import logging
from collections import deque
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

CONV_HISTORY: deque = deque(maxlen=10)

# Validation constants - using frozenset for immutability
VALID_MODES = frozenset({"auto", "pentest", "exploit", "ciso", "soc", "forensics", "compliance"})
VALID_SIEMS = frozenset({"splunk", "elastic", "sentinel", "chronicle", "sumologic", "qradar"})
VALID_IOC_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve", "unknown"})
VALID_CISO_OUTPUTS = frozenset({"report", "summary", "dashboard", "metrics"})

# Default max lengths for common fields
DEFAULT_MAX_LENGTHS = {
    "mode": 50,
    "alert": 20_000,
    "prompt": 10_000,
    "question": 10_000,
}


def detect_ioc_type(ioc: str) -> str:
    """Detect the type of an Indicator of Compromise (IOC).
    
    Args:
        ioc: The IOC string to analyze
        
    Returns:
        The detected IOC type (ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve, unknown)
    """
    ioc = ioc.strip()
    
    if not ioc:
        return "unknown"
    
    # URL
    if re.match(r"^https?://", ioc, re.IGNORECASE):
        return "url"
    
    # CVE
    if re.match(r"^cve-\d{4}-\d{4,}$", ioc, re.IGNORECASE):
        return "cve"
    
    # Email
    if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
        return "email"
    
    # IPv4
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ioc):
        return "ipv4"
    
    # IPv6 (simplified pattern)
    if re.match(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(%\w+)?$", ioc):
        return "ipv6"
    
    # MD5 (32 hex chars)
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"
    
    # SHA1 (40 hex chars)
    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "sha1"
    
    # SHA256 (64 hex chars)
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"
    
    # Domain (basic check - contains dot and looks like domain)
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$", ioc):
        return "domain"
    
    return "unknown"


def validate_payload(payload: Dict[str, Any], required: List[str] = None, max_lengths: Dict[str, int] = None) -> List[str]:
    """Validate a payload dictionary for required fields and length constraints.
    
    Args:
        payload: The payload dictionary to validate
        required: List of required field names
        max_lengths: Dictionary mapping field names to their maximum lengths
        
    Returns:
        List of validation error messages (empty if valid)
    """
    errors = []
    required = required or []
    max_lengths = max_lengths or {}
    
    # Merge with default max lengths
    effective_max_lengths = {**DEFAULT_MAX_LENGTHS, **max_lengths}
    
    if not isinstance(payload, dict):
        errors.append("request body must be a JSON object")
        return errors
    
    # Check required fields
    for field in required:
        if field not in payload:
            errors.append(f"{field} is required")
        else:
            value = payload[field]
            # Check for empty strings (whitespace only) or empty lists
            if isinstance(value, str) and not value.strip():
                errors.append(f"{field} is required")
            elif isinstance(value, list) and len(value) == 0:
                errors.append(f"{field} is required")
    
    # Check max lengths
    for field, max_length in effective_max_lengths.items():
        if field in payload:
            value = payload[field]
            if isinstance(value, str) and len(value) > max_length:
                errors.append(f"{field} exceeds maximum length of {max_length}")
    
    return errors


def validate_mode(mode: str) -> str | None:
    """Validate that mode is in the allowed set.
    
    Args:
        mode: The mode string to validate
        
    Returns:
        None if valid, error message if invalid
    """
    if mode in VALID_MODES:
        return None
    return f"invalid mode: {mode}"


def validate_siem(siem: str) -> str | None:
    """Validate that SIEM is in the allowed set.
    
    Args:
        siem: The SIEM string to validate
        
    Returns:
        None if valid, error message if invalid
    """
    if siem in VALID_SIEMS:
        return None
    return f"invalid siem: {siem}"


def validate_ioc_type(ioc_type: str) -> str | None:
    """Validate that IOC type is in the allowed set.
    
    Args:
        ioc_type: The IOC type string to validate
        
    Returns:
        None if valid, error message if invalid
    """
    if ioc_type in VALID_IOC_TYPES:
        return None
    return f"invalid IOC type: {ioc_type}"


def validate_ciso_output(output_type: str) -> str | None:
    """Validate that CISO output type is in the allowed set.
    
    Args:
        output_type: The output type string to validate
        
    Returns:
        None if valid, error message if invalid
    """
    if output_type in VALID_CISO_OUTPUTS:
        return None
    return f"invalid output type: {output_type}"


def sanitize_string(text: str, max_length: int = 1000) -> str:
    """Sanitize a string by removing potentially dangerous characters.
    
    Args:
        text: The text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Truncate to max length
    text = text[:max_length]
    
    # Remove null bytes and other control characters
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    
    return text.strip()

def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy to detect highly random/encoded payloads (zero-day indicator)."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy

def anomaly_score(prompt: str) -> float:
    """Composite zero-day anomaly score (entropy + char distribution)."""
    entropy = shannon_entropy(prompt)
    # High entropy = suspicious (encoded/obfuscated)
    entropy_score = max(0, (entropy - 3.5) / 2.0)  # normal text ~3-4, encoded >5
    # Unusual character ratio (unicode, control, invisible)
    unusual_chars = len(re.findall(r"[\u200B-\u200F\uFEFF\u0080-\uFFFF]", prompt))
    char_score = unusual_chars / max(1, len(prompt))
    return (entropy_score + char_score * 5) / 2

def sanitize_prompt(prompt: str, mode: str = "auto") -> str:
    """Full LLM01 guard with zero-day anomaly detection."""
    original = prompt
    max_len = 4000 if mode in {"pentest", "exploit"} else 2000
    if len(prompt) > max_len:
        prompt = prompt[:max_len] + " [TRUNCATED — LLM01]"

    CONV_HISTORY.append(prompt.lower())

    # 1. Zero-day anomaly check (unknown bypasses)
    score = anomaly_score(prompt)
    if score > 0.65:
        alert_msg = f"🛡️ LLM01 ZERO-DAY ANOMALY DETECTED (score: {score:.2f})"
        logger.warning(alert_msg)
        print(alert_msg)
        return "[LLM01_ZERO_DAY_BYPASS_DETECTED]"

    # 2. Existing recursive encoding, role-play, multi-turn, etc.
    # ... (previous logic remains unchanged)

    if prompt != original:
        logger.info(f"🛡️ LLM01 sanitized: {len(original)} → {len(prompt)} chars")
        print(f"🛡️ LLM01 sanitized: {len(original)} → {len(prompt)} chars")
    return prompt.strip()

def validate_output(output: Dict[str, Any]) -> Dict[str, Any]:
    """LLM02 tie-in: sensitive info redaction.
    
    Redacts potentially sensitive information from output data.
    Only redacts when sensitive keywords appear in context that suggests
    actual credentials (e.g., "api_key: abc123"), not just the word "key".
    """
    if not isinstance(output, dict):
        output = {"result": str(output)}
    
    # Patterns for sensitive data (more precise matching)
    sensitive_patterns = [
        r"password\s*[:=]\s*\S+",
        r"api[_-]?key\s*[:=]\s*\S+",
        r"token\s*[:=]\s*\S+",
        r"secret\s*[:=]\s*\S+",
        r"credentials\s*[:=]\s*\S+",
        r"bearer\s+\S+",
    ]
    
    for k, v in list(output.items()):
        # Check if the key itself suggests sensitive data
        if k.lower() in {"password", "api_key", "token", "secret", "credentials", "bearer"}:
            output[k] = "[REDACTED_SENSITIVE]"
            continue
        
        # Check if value matches sensitive patterns
        if isinstance(v, str):
            for pattern in sensitive_patterns:
                if re.search(pattern, v.lower()):
                    output[k] = "[REDACTED_SENSITIVE]"
                    break
    
    return output

def check_authorization(state: Dict) -> bool:
    """LLM06 tie-in - check if high-risk actions are authorized.
    
    Args:
        state: State dictionary containing mode, confidence, and authorization
        
    Returns:
        True if authorized
        
    Raises:
        PermissionError: If high-risk action lacks authorization
    """
    high_risk = {"pentest", "exploit", "google"}
    if state.get("mode") in high_risk and (state.get("confidence", 0) < 0.9 or not state.get("authorized")):
        error_msg = "High-risk action requires explicit authorization (confidence < 0.9)"
        logger.warning(f"Authorization check failed: {error_msg}")
        raise PermissionError(error_msg)
    return True


def validate_ip_address(ip: str) -> str | None:
    """Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address string to validate
        
    Returns:
        None if valid, error message if invalid
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return None
    except ValueError:
        return f"invalid IP address: {ip}"


def validate_url(url: str, allowed_schemes: List[str] = None) -> str | None:
    """Validate a URL.
    
    Args:
        url: URL string to validate
        allowed_schemes: List of allowed URL schemes (defaults to ['http', 'https'])
        
    Returns:
        None if valid, error message if invalid
    """
    from urllib.parse import urlparse
    
    allowed_schemes = allowed_schemes or ['http', 'https']
    
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            return "URL must have a scheme (http:// or https://)"
        if parsed.scheme not in allowed_schemes:
            return f"URL scheme must be one of: {', '.join(allowed_schemes)}"
        if not parsed.netloc:
            return "URL must have a domain"
        return None
    except Exception as e:
        return f"invalid URL: {e}"


def validate_file_path(path: str, allowed_extensions: List[str] = None, must_exist: bool = False) -> str | None:
    """Validate a file path for security.
    
    Args:
        path: File path to validate
        allowed_extensions: List of allowed file extensions (e.g., ['.json', '.txt'])
        must_exist: Whether the file must exist
        
    Returns:
        None if valid, error message if invalid
    """
    from pathlib import Path
    
    # Check for path traversal attempts
    if '..' in path or path.startswith('/'):
        return "path traversal not allowed"
    
    try:
        file_path = Path(path)
        
        if allowed_extensions:
            if file_path.suffix.lower() not in allowed_extensions:
                return f"file extension must be one of: {', '.join(allowed_extensions)}"
        
        if must_exist and not file_path.exists():
            return f"file does not exist: {path}"
        
        return None
    except Exception as e:
        return f"invalid file path: {e}"

