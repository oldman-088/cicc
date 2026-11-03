"""Experimental local quarantine staging primitive; not an upload service.

Requires a pre-existing private directory owned by the current process user.
Only generated names are used. This provides bounded staging and no-clobber
publication, not tenant isolation, malware scanning, immutable storage, durable
custody, crash cleanup or protection from processes running under the same UID.
Never use it for sensitive or production evidence.
"""
from dataclasses import dataclass
import hashlib
import os
import secrets
import stat
from typing import BinaryIO

from .evidence_integrity import CHUNK_BYTES, MAX_EVIDENCE_BYTES, EvidenceTooLarge


@dataclass(frozen=True)
class QuarantinedObject:
    object_id: str
    byte_count: int
    sha256: str


def stage_stream(directory: str, stream: BinaryIO, *, max_bytes: int) -> QuarantinedObject:
    """Store a bounded stream under an opaque name in a private directory.

    Reads at most max_bytes + 1 bytes. Caller must supply a trusted configured
    directory path and own authorization, retention and reconciliation. A match
    of the returned hash to a reference does not establish authenticity. I/O is
    blocking and has no deadline. Caller owns the stream; it is not closed.
    """
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_EVIDENCE_BYTES:
        raise ValueError('Invalid byte limit')
    if not all(hasattr(os, flag) for flag in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'geteuid')):
        raise RuntimeError('Required filesystem protections unavailable')
    dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    tmp_name = final_name = None
    published = False
    created = False
    try:
        info = os.fstat(dirfd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Quarantine directory must be private and owned by process user')
        object_id = secrets.token_hex(32)
        tmp_name, final_name = 'tmp-' + object_id, 'q-' + object_id
        fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=dirfd)
        created = True
        try:
            digest, total = hashlib.sha256(), 0
            while True:
                request = min(CHUNK_BYTES, max_bytes - total + 1)
                chunk = stream.read(request)
                if not isinstance(chunk, bytes) or len(chunk) > request:
                    raise ValueError('Invalid binary stream')
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise EvidenceTooLarge('Evidence exceeds byte limit')
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError('Unable to stage evidence')
                    view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        # Hard-link creation fails if the destination exists; no overwrite.
        os.link(tmp_name, final_name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
        published = True
        os.unlink(tmp_name, dir_fd=dirfd)
        tmp_name = None
        created = False
        os.fsync(dirfd)
        return QuarantinedObject(object_id=object_id, byte_count=total, sha256=digest.hexdigest())
    except BaseException:
        # Best effort only; process death or filesystem errors can leave orphans.
        for name in (tmp_name if created else None, final_name if published else None):
            if name is not None:
                try:
                    os.unlink(name, dir_fd=dirfd)
                except OSError:
                    pass
        raise
    finally:
        os.close(dirfd)
