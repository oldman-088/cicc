"""Experimental local quarantine staging primitive; not an upload service.

Requires a pre-existing private directory owned by the current process user.
Only generated names are used. This provides bounded staging and no-clobber
publication, not tenant isolation, malware scanning, immutable storage, durable
custody, crash cleanup or protection from processes running under the same UID.
Never use it for sensitive or production evidence.
"""
from dataclasses import dataclass
try:
    import fcntl
except ImportError:  # The primitive requires POSIX locking.
    fcntl = None
import hashlib
import os
import re
import secrets
import stat
from typing import BinaryIO

from .evidence_integrity import CHUNK_BYTES, MAX_EVIDENCE_BYTES, EvidenceTooLarge, DigestComparison, compare_sha256


@dataclass(frozen=True)
class QuarantinedObject:
    object_id: str
    byte_count: int
    sha256: str


def _open_private_dir(directory: str) -> int:
    if not all(hasattr(os, flag) for flag in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK', 'geteuid')):
        raise RuntimeError('Required filesystem protections unavailable')
    dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(dirfd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Quarantine directory must be private and owned by process user')
        return dirfd
    except BaseException:
        os.close(dirfd)
        raise


def stage_stream(directory: str, stream: BinaryIO, *, max_bytes: int) -> QuarantinedObject:
    """Store a bounded stream under an opaque name in a private directory.

    Reads at most max_bytes + 1 bytes. Caller must supply a trusted configured
    directory path and own authorization, retention and reconciliation. A match
    of the returned hash to a reference does not establish authenticity. I/O is
    blocking and has no deadline. A nonblocking shared directory flock coordinates
    only with cooperating maintenance; caller owns the stream and it is not closed.
    """
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_EVIDENCE_BYTES:
        raise ValueError('Invalid byte limit')
    dirfd = _open_private_dir(directory)
    # Cooperating maintenance must take an exclusive directory flock. Keep the
    # shared lock from before name creation until publication/cleanup completes.
    try:
        if fcntl is None:
            raise RuntimeError('Required filesystem locking unavailable')
        fcntl.flock(dirfd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BaseException:
        os.close(dirfd)
        raise
    tmp_name = final_name = None
    published = False
    created = False
    try:
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


def inspect_object(directory: str, object_id: str, expected_sha256: str, *, max_bytes: int) -> DigestComparison:
    """Recheck one generated object; equality is not authenticity or custody.

    The configured directory and same-UID processes remain trusted. Metadata
    comparisons detect some concurrent mutations, not all possible changes.
    Neither ACLs nor a hard I/O deadline are checked.
    """
    if not isinstance(object_id, str) or re.fullmatch(r'[0-9a-f]{64}', object_id) is None:
        raise ValueError('Invalid quarantine object identifier')
    dirfd = _open_private_dir(directory)
    try:
        fd = os.open('q-' + object_id, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dirfd)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_mode & 0o077 or before.st_nlink != 1):
                raise ValueError('Unsafe quarantine object')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                result = compare_sha256(stream, expected_sha256, max_bytes=max_bytes)
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if any(getattr(before, field) != getattr(after, field) for field in fields):
                raise ValueError('Quarantine object changed during inspection')
            return result
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)


@dataclass(frozen=True)
class QuarantineEntry:
    object_id: str
    kind: str
    size: int
    modified_ns: int
    safe_metadata: bool
    link_count: int


@dataclass(frozen=True)
class QuarantineInventory:
    items: tuple[QuarantineEntry, ...]
    examined: int
    truncated: bool


def inventory(directory: str, *, max_entries: int) -> QuarantineInventory:
    """Inspect a bounded directory prefix without deleting or opening objects.

    Requires an exclusive nonblocking directory flock; only staging processes
    using the same advisory protocol are coordinated. Enumeration order is not
    stable and no cursor is provided, so repeated calls may examine the same
    entries. Metadata is an observation, not proof of ownership, custody, safety,
    content integrity or orphan status. Caller must authorize and protect output.
    """
    if type(max_entries) is not int or not 1 <= max_entries <= 1000:
        raise ValueError('Invalid inventory limit')
    dirfd = _open_private_dir(directory)
    try:
        if fcntl is None:
            raise RuntimeError('Required filesystem locking unavailable')
        fcntl.flock(dirfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        items = []
        examined = 0
        truncated = False
        with os.scandir(dirfd) as entries:
            for entry in entries:
                if examined == max_entries:
                    truncated = True
                    break
                examined += 1
                match = re.fullmatch(r'(tmp|q)-([0-9a-f]{64})', entry.name)
                if match is None:
                    continue
                try:
                    info = os.stat(entry.name, dir_fd=dirfd, follow_symlinks=False)
                except FileNotFoundError:
                    # A non-cooperating process can still change the directory.
                    continue
                safe = (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                        and not info.st_mode & 0o077 and info.st_nlink == 1)
                items.append(QuarantineEntry(object_id=match.group(2), kind='temporary' if match.group(1) == 'tmp' else 'published',
                    size=info.st_size, modified_ns=info.st_mtime_ns, safe_metadata=bool(safe), link_count=info.st_nlink))
        return QuarantineInventory(items=tuple(items), examined=examined, truncated=truncated)
    finally:
        os.close(dirfd)
