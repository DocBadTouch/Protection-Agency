"""Private Windows settings edits using the native filesystem backend."""
import ctypes as C
from pathlib import Path
import secrets

from .config_io import LIMIT, Snapshot
from . import windows_files as win


def read_at(parent, name):
    try:
        raw, identity = win.read_at(parent, name, LIMIT, secure=True)
        return Snapshot(raw, identity)
    except FileNotFoundError:
        return Snapshot(None, None)


def snapshot(path):
    path = win.local_path(path)
    try:
        with win.pin_directory(path.parent, secure=True) as parent:
            return read_at(parent, path.name)
    except FileNotFoundError:
        return Snapshot(None, None)


def replace(path: Path, expected: Snapshot, raw: bytes):
    if len(raw) > LIMIT:
        raise ValueError("new configuration exceeds the read budget")
    path = win.local_path(path)
    backup = temporary = None
    with win.pin_directory(path.parent, create=True, secure=True, writable=True) as parent:
        with win.private_attributes() as attributes:
            lock = win.open_relative(parent, "." + path.name + ".protection-agency.lock", 0xC0000000,
                                     share=3, open_if=True, attributes=attributes)
        overlap = win.Overlapped()
        locked = False
        try:
            record = win.info(lock)
            win.owner_and_acl(lock)
            if record.links != 1 or record.size_high or record.size_low:
                raise ValueError("unsafe configuration lock")
            if not win.lock_file(lock, 3, 0, 1, 0, C.byref(overlap)):
                if C.get_last_error() == 33:
                    return {"status": "conflict", "changed": False, "reason": "Another setup operation holds the configuration lock"}
                raise C.WinError(C.get_last_error())
            locked = True
            if read_at(parent, path.name) != expected:
                return {"status": "conflict", "changed": False, "reason": "Settings changed; inspect them and retry"}
            if expected.raw is not None:
                backup = path.name + ".protection-agency." + secrets.token_hex(8) + ".bak"
                win.write_new(parent, backup, expected.raw)
            temporary = "." + path.name + ".protection-agency." + secrets.token_hex(8) + ".tmp"
            win.write_new(parent, temporary, raw)
            if read_at(parent, path.name) != expected:
                return {"status": "conflict", "changed": False, "backup": backup, "reason": "Settings changed before replacement"}
            flushed = win.rename_at(parent, temporary, path.name)
            temporary = None
            return {"status": "applied" if flushed else "applied_with_warning", "changed": True, "backup": backup,
                    "directory_durability": "not_attested", "access_control": "private_windows_dacl"}
        finally:
            if temporary is not None:
                try:
                    win.delete_at(parent, temporary)
                except FileNotFoundError:
                    pass
            if locked:
                win.unlock_file(lock, 0, 1, 0, C.byref(overlap))
            win.close(lock)
