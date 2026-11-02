import hashlib
import io
import pytest
from app.evidence_integrity import CHUNK_BYTES, MAX_EVIDENCE_BYTES, EvidenceTooLarge, compare_sha256


def digest(data): return hashlib.sha256(data).hexdigest()


def test_stream_digest_matches_and_mismatch_without_claiming_authenticity():
    data = b'synthetic evidence only' * 5000
    stream = io.BytesIO(data)
    result = compare_sha256(stream, digest(data), max_bytes=len(data))
    assert result.matches and result.sha256 == digest(data) and result.byte_count == len(data)
    assert not stream.closed and stream.tell() == len(data)
    result = compare_sha256(io.BytesIO(data), '0'*64, max_bytes=len(data))
    assert not result.matches and result.sha256 == digest(data)


def test_empty_exact_and_oversize_bounds():
    assert compare_sha256(io.BytesIO(b''), digest(b''), max_bytes=0).matches
    assert compare_sha256(io.BytesIO(b'x'), digest(b'x'), max_bytes=1).matches
    stream = io.BytesIO(b'xyzzzz')
    with pytest.raises(EvidenceTooLarge): compare_sha256(stream, digest(b'x'), max_bytes=1)
    assert stream.tell() == 2
    with pytest.raises(EvidenceTooLarge): compare_sha256(io.BytesIO(b'x'), digest(b''), max_bytes=0)


@pytest.mark.parametrize('value', ['', 'F'*64, '0'*63, '0'*65, '../', None])
def test_invalid_digest_fails_before_read(value):
    class NoRead:
        def read(self, n): raise AssertionError('must not read')
    with pytest.raises(ValueError): compare_sha256(NoRead(), value, max_bytes=1)


@pytest.mark.parametrize('value', [-1, MAX_EVIDENCE_BYTES+1, True, 1.5, None])
def test_invalid_limits_fail_before_read(value):
    class NoRead:
        def read(self, n): raise AssertionError('must not read')
    with pytest.raises(ValueError): compare_sha256(NoRead(), '0'*64, max_bytes=value)


def test_bad_stream_and_io_error_are_not_silently_accepted():
    class Bad:
        def read(self, n): return b'x'*(n+1)
    with pytest.raises(ValueError): compare_sha256(Bad(), '0'*64, max_bytes=1)
    with pytest.raises(ValueError): compare_sha256(io.StringIO('x'), '0'*64, max_bytes=1)
    class Broken:
        def read(self, n): raise OSError('read failed')
    with pytest.raises(OSError): compare_sha256(Broken(), '0'*64, max_bytes=1)


def test_short_reads_and_chunk_size_are_supported():
    data = b'x'*(CHUNK_BYTES+5)
    class Short(io.BytesIO):
        def read(self, n):
            assert n <= CHUNK_BYTES
            return super().read(min(n, 1000))
    result = compare_sha256(Short(data), digest(data), max_bytes=len(data))
    assert result.matches and result.byte_count == len(data)
