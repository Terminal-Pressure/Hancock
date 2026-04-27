"""
Hancock LLM04 Data & Model Poisoning Protection
SHA256 manifest + runtime verification for all datasets
Enhanced with caching and comprehensive error handling
"""
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Dict, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

MANIFEST_PATH = Path("data/manifest.json")

# Cache for hash computations (useful for repeated verifications)
_hash_cache: Dict[str, tuple[str, float]] = {}
CACHE_TTL = 300  # 5 minutes


def compute_sha256(file_path: str, use_cache: bool = True) -> str:
    """Compute SHA256 of a dataset file with optional caching.

    Args:
        file_path: Path to the file to hash
        use_cache: Whether to use cached hash values

    Returns:
        Hex digest of SHA256 hash

    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If there's an error reading the file
    """
    file_path_obj = Path(file_path)

    if not file_path_obj.exists():
        logger.error(f"File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")

    # Check cache
    if use_cache and file_path in _hash_cache:
        cached_hash, cached_time = _hash_cache[file_path]
        if time.time() - cached_time < CACHE_TTL:
            # Verify file hasn't been modified
            if file_path_obj.stat().st_mtime <= cached_time:
                logger.debug(f"Using cached hash for {file_path}")
                return cached_hash

    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                sha256.update(block)

        hash_value = sha256.hexdigest()

        # Update cache
        if use_cache:
            _hash_cache[file_path] = (hash_value, time.time())

        logger.debug(f"Computed SHA256 for {file_path}: {hash_value[:16]}...")
        return hash_value

    except IOError as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise


def generate_manifest(data_dir: Optional[Path] = None) -> Dict[str, str]:
    """Generate signed manifest for all datasets.

    Args:
        data_dir: Directory containing datasets (defaults to 'data/')

    Returns:
        Dictionary mapping filenames to their SHA256 hashes

    Raises:
        RuntimeError: If the data directory doesn't exist or is empty
    """
    data_dir = data_dir or Path("data")

    if not data_dir.exists():
        logger.error(f"Data directory not found: {data_dir}")
        raise RuntimeError(f"LLM04: Data directory not found: {data_dir}")

    manifest = {}
    jsonl_files = list(data_dir.glob("*.jsonl"))

    if not jsonl_files:
        logger.warning(f"No .jsonl files found in {data_dir}")

    for jsonl in jsonl_files:
        try:
            manifest[jsonl.name] = compute_sha256(str(jsonl))
            logger.info(f"Added {jsonl.name} to manifest")
        except Exception as e:
            logger.error(f"Failed to hash {jsonl.name}: {e}")
            raise

    try:
        MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
        logger.info(f"✅ LLM04 manifest generated: {MANIFEST_PATH} ({len(manifest)} datasets)")
        print(f"✅ LLM04 manifest generated: {MANIFEST_PATH} ({len(manifest)} datasets)")
    except IOError as e:
        logger.error(f"Failed to write manifest: {e}")
        raise RuntimeError(f"LLM04: Failed to write manifest: {e}")

    return manifest


def verify_dataset(dataset_path: str) -> bool:
    """LLM04 runtime check — fail fast if poisoned.

    Args:
        dataset_path: Path to the dataset file to verify

    Returns:
        True if verification passes

    Raises:
        RuntimeError: If manifest is missing, dataset not in manifest,
                     or hash mismatch detected
        FileNotFoundError: If the dataset file doesn't exist
    """
    if not MANIFEST_PATH.exists():
        logger.error("LLM04: No dataset manifest found")
        raise RuntimeError("LLM04: No dataset manifest found — run generate_manifest() first")

    try:
        manifest = json.loads(MANIFEST_PATH.read_text())
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"LLM04: Failed to read manifest: {e}")
        raise RuntimeError(f"LLM04: Failed to read manifest: {e}")

    filename = Path(dataset_path).name

    if filename not in manifest:
        logger.error(f"LLM04: Dataset {filename} not in signed manifest")
        raise RuntimeError(f"LLM04: Dataset {filename} not in signed manifest")

    try:
        current_hash = compute_sha256(dataset_path)
    except FileNotFoundError:
        logger.error(f"LLM04: Dataset file not found: {dataset_path}")
        raise

    if current_hash != manifest[filename]:
        logger.critical(f"🚨 LLM04 DATA POISONING DETECTED: {filename}")
        logger.critical(f"   Expected: {manifest[filename]}")
        logger.critical(f"   Got:      {current_hash}")
        raise RuntimeError(f"LLM04 DATA POISONING DETECTED: {filename} hash mismatch")

    logger.info(f"✅ LLM04 verification passed: {filename}")
    print(f"✅ LLM04 verification passed: {filename}")
    return True


def clear_hash_cache() -> None:
    """Clear the hash computation cache.

    Useful when you know files have been modified and want to force recomputation.
    """
    _hash_cache.clear()
    logger.info("Hash cache cleared")
