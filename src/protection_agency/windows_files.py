"""Native local-NTFS access. Hold no-write/no-delete directory handles while
using paths, reject every reparse component, and bound ordinary file reads.

Loaded only on Windows. No shell command or privilege adjustment is used.
"""
from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes as W
from functools import lru_cache
import hashlib
import os
from pathlib import Path, PureWindowsPath
from dataclasses import dataclass
from types import SimpleNamespace

K = C.WinDLL("kernel32", use_last_error=True)
A = C.WinDLL("advapi32", use_last_error=True)
N = C.WinDLL("ntdll", use_last_error=True)


def bind(library, name, result, args):
    function = getattr(library, name)
    function.restype, function.argtypes = result, args
    return function


class Info(C.Structure):
    _fields_ = [("attributes", W.DWORD), ("created", W.FILETIME), ("accessed", W.FILETIME),
                ("written", W.FILETIME), ("volume", W.DWORD), ("size_high", W.DWORD),
                ("size_low", W.DWORD), ("links", W.DWORD), ("index_high", W.DWORD), ("index_low", W.DWORD)]


class SecurityAttributes(C.Structure):
    _fields_ = [("length", W.DWORD), ("descriptor", C.c_void_p), ("inherit", W.BOOL)]


class Overlapped(C.Structure):
    _fields_ = [("internal", C.c_size_t), ("internal_high", C.c_size_t),
                ("offset", W.DWORD), ("offset_high", W.DWORD), ("event", W.HANDLE)]


class UnicodeString(C.Structure):
    _fields_ = [("length", W.USHORT), ("maximum", W.USHORT), ("buffer", W.LPWSTR)]


class ObjectAttributes(C.Structure):
    _fields_ = [("length", W.ULONG), ("root", W.HANDLE), ("name", C.POINTER(UnicodeString)),
                ("attributes", W.ULONG), ("security", C.c_void_p), ("quality", C.c_void_p)]


class IOStatus(C.Structure):
    _fields_ = [("status", C.c_void_p), ("information", C.c_size_t)]


class RenameInfo(C.Structure):
    _fields_ = [("replace", W.BOOLEAN), ("root", W.HANDLE), ("length", W.ULONG), ("name", W.WCHAR * 1)]


class DirectoryInfo(C.Structure):
    _fields_ = [("next", W.DWORD), ("index", W.DWORD), ("created", C.c_longlong),
                ("accessed", C.c_longlong), ("written", C.c_longlong), ("changed", C.c_longlong),
                ("size", C.c_longlong), ("allocated", C.c_longlong), ("attributes", W.DWORD),
                ("name_length", W.DWORD), ("ea_size", W.DWORD), ("short_length", C.c_byte),
                ("short_name", W.WCHAR * 12), ("file_id", C.c_longlong), ("name", W.WCHAR * 1)]


@dataclass
class Directory:
    path: Path
    handle: int


create_file = bind(K, "CreateFileW", W.HANDLE, [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE])
close = bind(K, "CloseHandle", W.BOOL, [W.HANDLE])
get_info = bind(K, "GetFileInformationByHandle", W.BOOL, [W.HANDLE, C.POINTER(Info)])
get_type = bind(K, "GetFileType", W.DWORD, [W.HANDLE])
read = bind(K, "ReadFile", W.BOOL, [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p])
write = bind(K, "WriteFile", W.BOOL, [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p])
flush = bind(K, "FlushFileBuffers", W.BOOL, [W.HANDLE])
mkdir = bind(K, "CreateDirectoryW", W.BOOL, [W.LPCWSTR, C.c_void_p])
move = bind(K, "MoveFileExW", W.BOOL, [W.LPCWSTR, W.LPCWSTR, W.DWORD])
drive_type = bind(K, "GetDriveTypeW", W.UINT, [W.LPCWSTR])
volume_info = bind(K, "GetVolumeInformationW", W.BOOL, [W.LPCWSTR, W.LPWSTR, W.DWORD, C.c_void_p, C.c_void_p, C.c_void_p, W.LPWSTR, W.DWORD])
local_free = bind(K, "LocalFree", C.c_void_p, [C.c_void_p])
get_process = bind(K, "GetCurrentProcess", W.HANDLE, [])
open_token = bind(A, "OpenProcessToken", W.BOOL, [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)])
token_info = bind(A, "GetTokenInformation", W.BOOL, [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)])
sid_string = bind(A, "ConvertSidToStringSidW", W.BOOL, [C.c_void_p, C.POINTER(C.c_void_p)])
convert_sd = bind(A, "ConvertStringSecurityDescriptorToSecurityDescriptorW", W.BOOL, [W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.c_void_p])
security_info = bind(A, "GetSecurityInfo", W.DWORD, [W.HANDLE, C.c_int, W.DWORD, C.POINTER(C.c_void_p), C.c_void_p, C.POINTER(C.c_void_p), C.c_void_p, C.POINTER(C.c_void_p)])
get_ace = bind(A, "GetAce", W.BOOL, [C.c_void_p, W.DWORD, C.POINTER(C.c_void_p)])
lock_file = bind(K, "LockFileEx", W.BOOL, [W.HANDLE, W.DWORD, W.DWORD, W.DWORD, W.DWORD, C.POINTER(Overlapped)])
unlock_file = bind(K, "UnlockFileEx", W.BOOL, [W.HANDLE, W.DWORD, W.DWORD, W.DWORD, C.POINTER(Overlapped)])
query_file = bind(K, "GetFileInformationByHandleEx", W.BOOL, [W.HANDLE, C.c_int, C.c_void_p, W.DWORD])
nt_create = bind(N, "NtCreateFile", W.LONG, [C.POINTER(W.HANDLE), W.DWORD, C.POINTER(ObjectAttributes),
    C.POINTER(IOStatus), C.c_void_p, W.DWORD, W.DWORD, W.DWORD, W.DWORD, C.c_void_p, W.DWORD])
nt_set = bind(N, "NtSetInformationFile", W.LONG, [W.HANDLE, C.POINTER(IOStatus), C.c_void_p, W.ULONG, C.c_int])
dos_error = bind(N, "RtlNtStatusToDosError", W.ULONG, [W.LONG])
INVALID = C.c_void_p(-1).value
REPARSE, DIRECTORY = 0x400, 0x10
FLAGS = 0x02000000 | 0x00200000  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT


def checked(ok):
    if not ok:
        raise C.WinError(C.get_last_error())


def extended(path):
    return "\\\\?\\" + str(path)


def component(name):
    if (not name or name in {".", ".."} or name[-1:] in {".", " "}
            or any(ord(c) < 32 or c in '<>:"/\\|?*' for c in name)
            or name.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}):
        raise OSError("unsupported Windows path component")


@lru_cache(maxsize=32)
def check_drive(anchor):
    if drive_type(anchor) != 3:
        raise OSError("Windows secure access requires a local fixed drive")
    filesystem = C.create_unicode_buffer(32)
    checked(volume_info(anchor, None, 0, None, None, None, filesystem, len(filesystem)))
    if filesystem.value != "NTFS":
        raise OSError("Windows secure access currently supports NTFS only")


def local_path(path):
    raw = PureWindowsPath(os.fspath(path))
    if raw.drive.startswith("\\") or (raw.drive and not raw.is_absolute()) or ".." in raw.parts:
        raise OSError("unsupported Windows namespace or relative drive")
    path = Path(path).absolute()
    if len(path.drive) != 2 or path.drive[1] != ":" or not path.is_absolute():
        raise OSError("an absolute local drive path is required")
    for part in path.parts[1:]:
        component(part)
    check_drive(path.anchor)
    return path


def info(handle, *, directory=False):
    result = Info()
    checked(get_info(handle, C.byref(result)))
    if get_type(handle) != 1 or result.attributes & REPARSE or bool(result.attributes & DIRECTORY) != directory:
        raise OSError("reparse points and non-ordinary filesystem objects are refused")
    return result


def identity(record, mode=0o100600):
    return (record.volume, record.index_high << 32 | record.index_low, mode,
            record.size_high << 32 | record.size_low,
            record.written.dwHighDateTime << 32 | record.written.dwLowDateTime,
            record.created.dwHighDateTime << 32 | record.created.dwLowDateTime,
            record.attributes, record.links)


def open_handle(path, access, *, share=1, disposition=3, attributes=None):
    handle = create_file(extended(path), access, share, C.byref(attributes) if attributes is not None else None,
                         disposition, FLAGS, None)
    if handle == INVALID:
        raise C.WinError(C.get_last_error())
    return handle


def nt_checked(status):
    if status < 0:
        raise C.WinError(dos_error(status))


def open_relative(parent, name, access, *, share=1, create=False, open_if=False, directory=False, attributes=None):
    component(name)
    encoded = name.encode("utf-16-le")
    text = C.create_string_buffer(encoded + b"\0\0")
    string = UnicodeString(len(encoded), len(encoded) + 2, C.cast(text, W.LPWSTR))
    descriptor = ObjectAttributes(C.sizeof(ObjectAttributes), parent.handle, C.pointer(string),
                                  0x1040, attributes.descriptor if attributes else None, None)
    handle, status = W.HANDLE(), IOStatus()
    options = 0x20 | (1 if create and directory else 0x200000)
    disposition = 2 if create else 3 if open_if else 1
    nt_checked(nt_create(C.byref(handle), access | 0x100000, C.byref(descriptor), C.byref(status), None,
                         0x10 if directory else 0x80, share, disposition, options, None, 0))
    return handle.value


def sid_text(pointer):
    text = C.c_void_p()
    checked(sid_string(pointer, C.byref(text)))
    try:
        return C.wstring_at(text)
    finally:
        local_free(text)


@lru_cache(maxsize=1)
def user_sid():
    token = W.HANDLE()
    checked(open_token(get_process(), 8, C.byref(token)))
    try:
        size = W.DWORD()
        token_info(token, 1, None, 0, C.byref(size))
        if not size.value or size.value > 65536:
            raise OSError("current user identity could not be established")
        data = C.create_string_buffer(size.value)
        checked(token_info(token, 1, data, size.value, C.byref(size)))
        return sid_text(C.c_void_p.from_buffer(data).value)
    finally:
        close(token)


@contextmanager
def private_attributes():
    descriptor = C.c_void_p()
    sddl = f"O:{user_sid()}D:P(A;;FA;;;{user_sid()})(A;;FA;;;SY)(A;;FA;;;BA)"
    checked(convert_sd(sddl, 1, C.byref(descriptor), None))
    try:
        yield SecurityAttributes(C.sizeof(SecurityAttributes), descriptor, False)
    finally:
        local_free(descriptor)


def owner_and_acl(handle):
    """Conservatively refuse foreign write grants; return private-read state/hash."""
    owner, dacl, descriptor = C.c_void_p(), C.c_void_p(), C.c_void_p()
    error = security_info(handle, 1, 5, C.byref(owner), None, C.byref(dacl), None, C.byref(descriptor))
    if error:
        raise C.WinError(error)
    try:
        trusted = {user_sid(), "S-1-5-18", "S-1-5-32-544"}
        if not owner.value or sid_text(owner) not in trusted or not dacl.value:
            raise ValueError("configuration must have a current-user or trusted system owner and an explicit DACL")
        header = C.string_at(dacl, 8)
        size, count = int.from_bytes(header[2:4], "little"), int.from_bytes(header[4:6], "little")
        if size < 8 or size > 65535:
            raise ValueError("unsupported configuration DACL")
        private = True
        for index in range(count):
            ace = C.c_void_p()
            checked(get_ace(dacl, index, C.byref(ace)))
            fields = C.string_at(ace, 8)
            kind, flags = fields[0], fields[1]
            if kind not in {0, 1}:
                raise ValueError("unsupported configuration DACL entry")
            if kind == 1 or flags & 8:  # Deny ACE / inherit-only ACE
                continue
            mask = int.from_bytes(fields[4:8], "little")
            principal = sid_text(ace.value + 8)
            if principal not in trusted:
                if mask & (0x50000000 | 0xD0156):
                    raise ValueError("configuration grants write access to another principal")
                if mask:
                    private = False
        return private, hashlib.sha256(C.string_at(dacl, size) + user_sid().encode()).hexdigest()
    finally:
        local_free(descriptor)


@contextmanager
def pin_directory(path, *, create=False, secure=False, writable=False):
    path = local_path(path)
    handles = []
    current = Path(path.anchor)
    try:
        for part in (None, *path.parts[1:]):
            if part is not None:
                current /= part
            share = 3 if writable and current == path else 1
            try:
                handle = (open_handle(current, 0x120081, share=share) if part is None else
                          open_relative(Directory(current.parent, handles[-1]), part, 0x120081, share=share))
            except FileNotFoundError:
                if not create or part is None:
                    raise
                with private_attributes() as attributes:
                    try:
                        handle = open_relative(Directory(current.parent, handles[-1]), part, 0x120081,
                                               create=True, directory=True, attributes=attributes, share=share)
                    except FileExistsError:
                        handle = open_relative(Directory(current.parent, handles[-1]), part, 0x120081, share=share)
            handles.append(handle)
            info(handle, directory=True)
        if secure:
            owner_and_acl(handles[-1])
        yield Directory(path, handles[-1])
    finally:
        for handle in reversed(handles):
            close(handle)


def read_at(parent, name, limit, *, secure=False):
    component(name)
    handle = open_relative(parent, name, 0x80000000)
    try:
        before = info(handle)
        permissions = owner_and_acl(handle) if secure else (True, "")
        if secure and before.links != 1:
            raise ValueError("configuration must have one hard link")
        before_id = identity(before, 0o100600 if permissions[0] else 0o100644) + (permissions[1],)
        if before_id[3] > limit:
            raise OSError("file exceeds read budget")
        chunks, total = [], 0
        while True:
            buffer = C.create_string_buffer(min(65536, limit + 1 - total))
            received = W.DWORD()
            checked(read(handle, buffer, len(buffer), C.byref(received), None))
            if not received.value:
                break
            chunks.append(buffer.raw[:received.value])
            total += received.value
            if total > limit:
                raise OSError("file grew beyond read budget")
        after = info(handle)
        if identity(before) != identity(after) or (secure and owner_and_acl(handle) != permissions):
            raise OSError("file changed while reading")
        return b"".join(chunks), before_id
    finally:
        close(handle)


def write_new(parent, name, raw):
    component(name)
    with private_attributes() as attributes:
        handle = open_relative(parent, name, 0xC0010000, share=0, create=True, attributes=attributes)
    try:
        info(handle)
        offset = 0
        while offset < len(raw):
            buffer = C.create_string_buffer(raw[offset:offset + 65536])
            sent = W.DWORD()
            checked(write(handle, buffer, len(buffer) - 1, C.byref(sent), None))
            if not sent.value:
                raise OSError("configuration write did not progress")
            offset += sent.value
        checked(flush(handle))
    except BaseException:
        disposition = W.BOOLEAN(True)
        status = IOStatus()
        nt_set(handle, C.byref(status), C.byref(disposition), C.sizeof(disposition), 13)
        close(handle)
        raise
    else:
        close(handle)


def rename_at(parent, source, target):
    component(target)
    handle = open_relative(parent, source, 0xC0010000, share=0)
    try:
        info(handle)
        raw = target.encode("utf-16-le")
        buffer = C.create_string_buffer(max(C.sizeof(RenameInfo), RenameInfo.name.offset + len(raw)))
        record = RenameInfo.from_buffer(buffer)
        record.replace, record.root, record.length = True, parent.handle, len(raw)
        C.memmove(C.addressof(buffer) + RenameInfo.name.offset, raw, len(raw))
        status = IOStatus()
        nt_checked(nt_set(handle, C.byref(status), buffer, len(buffer), 10))
        return bool(flush(handle))
    finally:
        close(handle)


def delete_at(parent, name):
    handle = open_relative(parent, name, 0x10000 | 0x100000)
    try:
        disposition, status = W.BOOLEAN(True), IOStatus()
        nt_checked(nt_set(handle, C.byref(status), C.byref(disposition), C.sizeof(disposition), 13))
    finally:
        close(handle)


def entries(parent):
    """Enumerate the pinned handle in bounded packets, not a mutable path."""
    first = True
    while True:
        buffer = C.create_string_buffer(65536)
        if not query_file(parent.handle, 11 if first else 10, buffer, len(buffer)):
            error = C.get_last_error()
            if error == 18:
                return
            raise C.WinError(error)
        first, offset = False, 0
        while True:
            if offset + C.sizeof(DirectoryInfo) > len(buffer):
                raise OSError("invalid directory enumeration record")
            record = DirectoryInfo.from_buffer(buffer, offset)
            start = offset + DirectoryInfo.name.offset
            if record.name_length % 2 or start + record.name_length > len(buffer):
                raise OSError("invalid directory entry name")
            try:
                name = buffer.raw[start:start + record.name_length].decode("utf-16-le")
            except UnicodeError as error:
                raise OSError("directory entry name cannot be decoded") from error
            if name not in {".", ".."}:
                yield Entry(parent.path, name, record.attributes)
            if not record.next:
                break
            if record.next < DirectoryInfo.name.offset:
                raise OSError("invalid directory enumeration offset")
            offset += record.next


class Entry:
    def __init__(self, parent, name, attributes):
        self.name, self.path, self.attributes = name, str(parent / name), attributes

    def is_symlink(self):
        return bool(self.attributes & REPARSE)

    def is_dir(self, *, follow_symlinks=True):
        return bool(self.attributes & DIRECTORY)

    def stat(self, *, follow_symlinks=True):
        return SimpleNamespace(st_mode=0o040777 if self.is_dir() else 0o100666,
                               st_file_attributes=self.attributes)
