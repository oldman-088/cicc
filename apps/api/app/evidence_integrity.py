"""Bounded stream digest comparison, not an evidence storage or custody system.

The caller owns the stream, its trusted origin, lifetime, access control and
storage. Matching a supplied hash only compares the bytes read; it does not
validate authenticity, safety, provenance, media type or subsequent bytes.
"""
from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import BinaryIO

MAX_EVIDENCE_BYTES = 100 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
_SHA256 = re.compile(r'[0-9a-f]{64}')


class EvidenceTooLarge(ValueError):
    """The observed stream exceeds the caller's explicit byte limit."""


@dataclass(frozen=True)
class DigestComparison:
    sha256: str
    byte_count: int
    matches: bool


def compare_sha256(stream: BinaryIO, expected_sha256: str, *, max_bytes: int) -> DigestComparison:
    """Consume at most max_bytes + 1 bytes from a blocking binary stream.

    Read failures propagate; the function never closes or rewinds the stream.
    The extra byte is necessary to distinguish exact-limit from oversized input.
    A byte limit is not a deadline: callers must bound blocking I/O separately.
    """
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise ValueError('Invalid expected SHA-256')
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_EVIDENCE_BYTES:
        raise ValueError('Invalid byte limit')
    digest = hashlib.sha256()
    total = 0
    while True:
        requested = min(CHUNK_BYTES, max_bytes - total + 1)
        chunk = stream.read(requested)
        if not isinstance(chunk, bytes) or len(chunk) > requested:
            raise ValueError('Invalid binary stream')
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise EvidenceTooLarge('Evidence exceeds byte limit')
        digest.update(chunk)
    actual = digest.hexdigest()
    return DigestComparison(sha256=actual, byte_count=total, matches=hmac.compare_digest(actual, expected_sha256))
