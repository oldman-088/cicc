"""Synthetic bytes only; this is not a production storage validation."""
import hashlib
import io
import os
import stat
import pytest
from app.evidence_integrity import EvidenceTooLarge
from app.evidence_quarantine import stage_stream


def private_dir(tmp_path):
    path = tmp_path / 'private'
    path.mkdir(mode=0o700)
    return path


def test_stages_private_bounded_bytes_with_generated_name(tmp_path):
    path = private_dir(tmp_path)
    data = b'synthetic fixture' * 10000
    stream = io.BytesIO(data)
    result = stage_stream(str(path), stream, max_bytes=len(data))
    assert result.byte_count == len(data) and result.sha256 == hashlib.sha256(data).hexdigest()
    assert len(result.object_id) == 64 and result.object_id.isascii()
    stored = path / ('q-' + result.object_id)
    assert list(path.iterdir()) == [stored] and stored.read_bytes() == data
    assert stat.S_IMODE(stored.stat().st_mode) & 0o077 == 0
    assert not stream.closed


def test_failures_cleanup_staging_and_never_publish(tmp_path, monkeypatch):
    path = private_dir(tmp_path)
    with pytest.raises(EvidenceTooLarge): stage_stream(str(path), io.BytesIO(b'1234'), max_bytes=3)
    assert list(path.iterdir()) == []
    class Failing:
        def read(self, n): raise OSError('failure')
    with pytest.raises(OSError): stage_stream(str(path), Failing(), max_bytes=20)
    assert list(path.iterdir()) == []
    def fail_link(*args, **kwargs): raise OSError('link failed')
    monkeypatch.setattr(os, 'link', fail_link)
    with pytest.raises(OSError): stage_stream(str(path), io.BytesIO(b'fixture'), max_bytes=20)
    assert list(path.iterdir()) == []


def test_private_directory_required_and_symlink_rejected(tmp_path):
    path = private_dir(tmp_path)
    link = tmp_path / 'link'
    link.symlink_to(path, target_is_directory=True)
    with pytest.raises(OSError): stage_stream(str(link), io.BytesIO(b''), max_bytes=0)
    path.chmod(0o755)
    with pytest.raises(ValueError, match='private'): stage_stream(str(path), io.BytesIO(b''), max_bytes=0)
    assert list(path.iterdir()) == []


def test_no_clobber_existing_destination(tmp_path, monkeypatch):
    path = private_dir(tmp_path)
    monkeypatch.setattr('app.evidence_quarantine.secrets.token_hex', lambda _: 'a'*64)
    existing = path / ('q-'+'a'*64)
    existing.write_bytes(b'existing fixture')
    with pytest.raises(FileExistsError): stage_stream(str(path), io.BytesIO(b'other fixture'), max_bytes=20)
    assert existing.read_bytes() == b'existing fixture'
    assert list(path.iterdir()) == [existing]


def test_empty_and_invalid_stream_and_limits(tmp_path):
    path = private_dir(tmp_path)
    result = stage_stream(str(path), io.BytesIO(b''), max_bytes=0)
    assert result.byte_count == 0 and result.sha256 == hashlib.sha256(b'').hexdigest()
    with pytest.raises(ValueError): stage_stream(str(path), io.StringIO('x'), max_bytes=1)
    with pytest.raises(ValueError): stage_stream(str(path), io.BytesIO(b''), max_bytes=True)
    assert len(list(path.iterdir())) == 1


def test_existing_temporary_file_is_not_deleted(tmp_path, monkeypatch):
    path = private_dir(tmp_path)
    monkeypatch.setattr('app.evidence_quarantine.secrets.token_hex', lambda _: 'b'*64)
    existing = path / ('tmp-'+'b'*64)
    existing.write_bytes(b'existing fixture')
    with pytest.raises(FileExistsError): stage_stream(str(path), io.BytesIO(b'other fixture'), max_bytes=20)
    assert existing.read_bytes() == b'existing fixture'
    assert list(path.iterdir()) == [existing]


@pytest.mark.parametrize('failure_call', [1, 2])
def test_sync_failure_removes_only_created_objects(tmp_path, monkeypatch, failure_call):
    path = private_dir(tmp_path)
    real_fsync, calls = os.fsync, []
    def failing(fd):
        calls.append(fd)
        if len(calls) == failure_call: raise OSError('sync failure')
        return real_fsync(fd)
    monkeypatch.setattr(os, 'fsync', failing)
    with pytest.raises(OSError, match='sync failure'):
        stage_stream(str(path), io.BytesIO(b'synthetic'), max_bytes=100)
    assert list(path.iterdir()) == []


def test_short_os_writes_are_completed(tmp_path, monkeypatch):
    path = private_dir(tmp_path)
    real_write = os.write
    def short(fd, data): return real_write(fd, data[:3])
    monkeypatch.setattr(os, 'write', short)
    result = stage_stream(str(path), io.BytesIO(b'synthetic payload'), max_bytes=100)
    assert (path / ('q-' + result.object_id)).read_bytes() == b'synthetic payload'


def test_inspect_detects_mismatch_and_reads_only_generated_name(tmp_path):
    from app.evidence_quarantine import inspect_object
    path = private_dir(tmp_path)
    result = stage_stream(str(path), io.BytesIO(b'fixture'), max_bytes=20)
    check = inspect_object(str(path), result.object_id, result.sha256, max_bytes=20)
    assert check.matches and check.byte_count == 7
    obj = path / ('q-' + result.object_id)
    obj.write_bytes(b'tampered')
    assert not inspect_object(str(path), result.object_id, result.sha256, max_bytes=20).matches
    for name in ('../escape', 'q-'+result.object_id, 'A'*64, '', None):
        with pytest.raises(ValueError): inspect_object(str(path), name, result.sha256, max_bytes=20)
    with pytest.raises(EvidenceTooLarge): inspect_object(str(path), result.object_id, result.sha256, max_bytes=2)


def test_inspect_rejects_symlinks_hardlinks_directories_and_permissions(tmp_path):
    from app.evidence_quarantine import inspect_object
    path = private_dir(tmp_path)
    obj_id='a'*64
    item=path / ('q-' + obj_id)
    outside=tmp_path / 'outside'; outside.write_bytes(b'outside')
    item.symlink_to(outside)
    with pytest.raises(OSError): inspect_object(str(path), obj_id, '0'*64, max_bytes=10)
    item.unlink(); os.link(outside, item)
    with pytest.raises(ValueError, match='Unsafe'): inspect_object(str(path), obj_id, '0'*64, max_bytes=10)
    item.unlink(); item.mkdir()
    with pytest.raises(ValueError, match='Unsafe'): inspect_object(str(path), obj_id, '0'*64, max_bytes=10)
    item.rmdir(); item.write_bytes(b'data'); item.chmod(0o644)
    with pytest.raises(ValueError, match='Unsafe'): inspect_object(str(path), obj_id, '0'*64, max_bytes=10)


def test_inspect_detects_selected_concurrent_modification(tmp_path, monkeypatch):
    from app import evidence_quarantine
    path = private_dir(tmp_path)
    result = stage_stream(str(path), io.BytesIO(b'fixture'), max_bytes=20)
    original = evidence_quarantine.compare_sha256
    def mutate(stream, expected, **kwargs):
        answer = original(stream, expected, **kwargs)
        (path / ('q-' + result.object_id)).write_bytes(b'changed content')
        return answer
    monkeypatch.setattr(evidence_quarantine, 'compare_sha256', mutate)
    with pytest.raises(ValueError, match='changed'):
        evidence_quarantine.inspect_object(str(path), result.object_id, result.sha256, max_bytes=20)


def test_inspect_rejects_fifo_without_blocking(tmp_path):
    from app.evidence_quarantine import inspect_object
    path = private_dir(tmp_path)
    os.mkfifo(path / ('q-' + 'c'*64), 0o600)
    with pytest.raises(ValueError, match='Unsafe'):
        inspect_object(str(path), 'c'*64, '0'*64, max_bytes=10)
