import hashlib
import logging

logger = logging.getLogger(__name__)

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError:
        logger.error(f"Unable to read file: {file_path}")
        return None

def check_file_integrity(file_path):
    known_good_hashes = {
        "6.02": "e33a16be6b60496721f01deb9562e9d2ad76f03feebf8d0144f9da92dc2839e1",
        "6.10": "7df5f0bf7f3c29c1511f3353e7d49c5c7cde8887759f1765625f30aad8db625b",
    }

    calculated_hash = calculate_file_hash(file_path)
    if calculated_hash is None:
        return "integrity", False

    logger.info(f"Calculated hash for {file_path}: {calculated_hash}")

    for version, known_hash in known_good_hashes.items():
        if calculated_hash == known_hash:
            logger.info(f"File integrity check passed for version {version}")
            return "integrity", True

    logger.warning("File integrity check failed")
    return "integrity", False
