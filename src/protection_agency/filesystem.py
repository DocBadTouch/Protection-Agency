"""Bounded POSIX reads that refuse symlinks at every path component."""
import os
from pathlib import Path
import stat
from contextlib import contextmanager


def normalize_root(root: Path) -> Path:
    if os.name == "nt":
        from .windows_files import pin_directory
        with pin_directory(root) as directory:
            return directory.path
    return Path(root).resolve(strict=True)


@contextmanager
def directory_entries(root: Path, relative: str = ""):
    if os.name == "nt":
        from .windows_files import pin_directory, entries
        parts = Path(relative).parts
        if Path(relative).anchor or ".." in parts:
            raise OSError("invalid project-relative directory")
        with pin_directory(root / relative) as directory:
            yield entries(directory)
        return
    fd = open_project_directory(root, relative)
    try:
        with os.scandir(fd) as children:
            # scandir(fd) entries have relative paths; supply names to the caller.
            yield children
    finally:
        os.close(fd)


def open_project_directory(root: Path, relative: str) -> int:
    """Return a caller-owned directory descriptor, refusing symlink components."""
    parts = Path(relative).parts
    if Path(relative).is_absolute() or any(part in {"..", "/", ""} for part in parts):
        raise OSError("invalid project-relative directory")
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("secure reads require POSIX O_NOFOLLOW")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_project_file(root: Path, relative: str, limit: int) -> bytes:
    parts = Path(relative).parts
    if not parts or any(part in {"..", "/", "\\", ""} for part in parts) or Path(relative).anchor:
        raise OSError("invalid project-relative path")
    if os.name == "nt":
        from .windows_files import pin_directory, read_at
        if Path(relative).drive:
            raise OSError("invalid project-relative path")
        with pin_directory(root.joinpath(*parts[:-1])) as directory:
            return read_at(directory, parts[-1], limit)[0]
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
