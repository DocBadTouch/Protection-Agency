"""Bounded POSIX reads that refuse symlinks at every path component."""
import os
from pathlib import Path
import stat


def read_project_file(root: Path, relative: str, limit: int) -> bytes:
    parts = Path(relative).parts
    if not parts or any(part in {"..", "/", ""} for part in parts) or Path(relative).is_absolute():
        raise OSError("invalid project-relative path")
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("secure reads require POSIX O_NOFOLLOW")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        target = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(target)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("not a regular file")
            if info.st_size > limit:
                raise OSError("file exceeds read budget")
            chunks = []
            total = 0
            while True:
                chunk = os.read(target, min(65536, limit + 1 - total))
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise OSError("file grew beyond read budget")
        finally:
            os.close(target)
    finally:
        os.close(fd)
