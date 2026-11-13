"""Bounded user-owned configuration edits with no-follow paths and private backups."""
from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import stat

LIMIT = 1024 * 1024


@dataclass(frozen=True)
class Snapshot:
    raw: bytes | None
    identity: tuple | None


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private_owner(info):
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("configuration must be user-owned and not writable by other users")


def open_parent(path: Path, *, create=False) -> int | None:
    """Pin the configuration directory; caller closes the returned descriptor."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("configuration path must be absolute without parent traversal")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None
                os.mkdir(part, mode=0o700, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        _private_owner(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(fd: int | None, name: str) -> Snapshot:
    if fd is None:
        return Snapshot(None, None)
    try:
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return Snapshot(None, None)
    try:
        before = os.fstat(source)
        _private_owner(before)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > LIMIT:
            raise ValueError("configuration must be a bounded regular file with one link")
        with os.fdopen(source, "rb", closefd=False) as stream:
            raw = stream.read(LIMIT + 1)
        after = os.fstat(source)
        if len(raw) > LIMIT or _identity(before) != _identity(after):
            raise ValueError("configuration changed while reading or exceeded its budget")
        return Snapshot(raw, _identity(after))
    finally:
        os.close(source)


def _write_new(fd: int, name: str, raw: bytes):
    target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchmod(target, 0o600)
        with os.fdopen(target, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(target)
    except BaseException:
        os.unlink(name, dir_fd=fd)
        raise
    finally:
        os.close(target)


def replace(path: Path, expected: Snapshot, raw: bytes) -> dict:
    """Compare before replacing; advisory locks coordinate this tool's writers.

    Other editors need not honor the lock, so a final check/rename race remains.
    A failed post-rename directory sync is reported as applied with a warning.
    """
    import fcntl
    if len(raw) > LIMIT:
        raise ValueError("new configuration exceeds the read budget")
    fd = open_parent(path.parent, create=True)
    lock = None
    temporary = None
    backup = None
    try:
        lock = os.open("." + path.name + ".protection-agency.lock",
                       os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
        lock_info = os.fstat(lock)
        _private_owner(lock_info)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or lock_info.st_size:
            raise ValueError("unsafe configuration lock")
        os.fchmod(lock, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "conflict", "changed": False, "reason": "Another setup operation holds the configuration lock"}
        if read(fd, path.name) != expected:
            return {"status": "conflict", "changed": False, "reason": "Configuration changed; inspect it and retry"}
        if expected.raw is not None:
            backup = path.name + ".protection-agency." + secrets.token_hex(8) + ".bak"
            _write_new(fd, backup, expected.raw)
        temporary = "." + path.name + ".protection-agency." + secrets.token_hex(8) + ".tmp"
        _write_new(fd, temporary, raw)
        # Verify both the pathname and the file just before the atomic replacement.
        current_parent = open_parent(path.parent)
        try:
            same_parent = current_parent is not None and (
                os.fstat(current_parent).st_dev, os.fstat(current_parent).st_ino
            ) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        finally:
            if current_parent is not None:
                os.close(current_parent)
        if not same_parent or read(fd, path.name) != expected:
            return {"status": "conflict", "changed": False, "backup": backup,
                    "reason": "Configuration or its directory changed before replacement"}
        os.replace(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        temporary = None
        try:
            os.fsync(fd)
        except OSError:
            return {"status": "applied_with_warning", "changed": True, "backup": backup,
                    "reason": "Configuration replaced; directory durability sync failed. Verify the file"}
        return {"status": "applied", "changed": True, "backup": backup}
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=fd)
            except FileNotFoundError:
                pass
        if lock is not None:
            os.close(lock)
        os.close(fd)
