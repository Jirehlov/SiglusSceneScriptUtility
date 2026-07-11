import base64
import os
import struct
import zlib
from pathlib import Path


class FilenameCaseCollisionError(OSError):
    pass


_WINDOWS_LOWER_EXCEPTIONS_DATA = "PCOC3Q2JJZJQCAAA2AJOHXWEVUYTCMOEEBIY5ZARHSA2YXMYEAVNJCVVSTJJMTTUAJFILASIFFMFBHAQCHTVTRFBYLPMK7ZPPF6V3IKQL5LSRVDU2W3B364PAQHTY7JU3DWRS67M6WOK2Y6BBVR4PA5DYYOTHYNYJFJ2NHJQMPLJY6ILJZNLIZGZRJK2PHDWY2NLHVV55OOPGNS4ODIXWLTZ35SZXLWYOLKTKH6YO3OQ2H72ZBGR766EU47PHOK3XZYNXF7O7DFF2X73Y2335455D76OQJZ77PC267XTXM75Z45H7P7PFN377RV4O7Y6PDUOKE6BAGXTV2BVV554GIMHBV55HCFXDTY3MUPPDBZ5JODDEYODO2OKWQJWNTE2GNX4CSMLSYWFXMPKSTJ44WDT225PGNS4GB5DFWD5FLMOGWOP64DC66WJP335ZN7DQVSDA3GEFOU6BAEDBYMTNYUIKFR4MTMYGRW4NLBZ6MLCYWVSNTC2VU6WVQ5WPQ2FS5OLN2MKFXLWZO7OUZNW5O7DV2D74B473R3CI==="
_WINDOWS_LOWER_EXCEPTIONS = dict(
    struct.iter_unpack(
        "<II", zlib.decompress(base64.b32decode(_WINDOWS_LOWER_EXCEPTIONS_DATA))
    )
)


def windows_filename_key(value):
    out = []
    for char in str(value or ""):
        codepoint = ord(char)
        if codepoint > 0xFFFF:
            out.append(char)
            continue
        mapped = _WINDOWS_LOWER_EXCEPTIONS.get(codepoint)
        out.append(chr(mapped) if mapped is not None else char.lower())
    return "".join(out)


def _collision_details(directory, entries):
    names = ", ".join(repr(entry.name) for entry in entries)
    return f"filenames differ only by case in the same directory: {directory}: {names}"


def _entry_groups(entries):
    groups = {}
    for entry in entries:
        groups.setdefault(windows_filename_key(entry.name), []).append(entry)
    return groups


def _read_entries(directory):
    entries = list(os.scandir(directory))
    for group in _entry_groups(entries).values():
        if len(group) > 1:
            raise FilenameCaseCollisionError(
                _collision_details(
                    directory, sorted(group, key=lambda entry: entry.name)
                )
            )
    return entries


def resolve_read_path(path, kind=None):
    original = os.fspath(path)
    if not original:
        raise FileNotFoundError(original)
    absolute = os.path.abspath(original)
    parts = Path(absolute).parts
    if not parts:
        raise FileNotFoundError(original)
    current = parts[0]
    for part in parts[1:]:
        entries = list(os.scandir(current))
        matches = [
            entry
            for entry in entries
            if windows_filename_key(entry.name) == windows_filename_key(part)
        ]
        if len(matches) > 1:
            raise FilenameCaseCollisionError(
                _collision_details(
                    current, sorted(matches, key=lambda entry: entry.name)
                )
            )
        if not matches:
            candidate = os.path.join(current, part)
            if os.name == "nt" and os.path.lexists(candidate):
                current = candidate
                continue
            raise FileNotFoundError(original)
        current = matches[0].path
    if kind == "file" and not os.path.isfile(current):
        raise FileNotFoundError(original)
    if kind == "dir" and not os.path.isdir(current):
        raise NotADirectoryError(original)
    return current


def read_path_exists(path, kind=None):
    try:
        resolve_read_path(path, kind=kind)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def open_read(path, mode="rb", **kwargs):
    if "r" not in mode or any(flag in mode for flag in "wax+"):
        raise ValueError(f"not a read-only mode: {mode}")
    return open(resolve_read_path(path, kind="file"), mode, **kwargs)


def read_file_stat(path):
    return os.stat(resolve_read_path(path, kind="file"))


def read_directory(path):
    directory = resolve_read_path(path, kind="dir")
    return directory, _read_entries(directory)


def walk_read_directory(path):
    root = resolve_read_path(path, kind="dir")
    pending = [root]
    while pending:
        directory = pending.pop()
        entries = _read_entries(directory)
        dirs = []
        files = []
        for entry in entries:
            if entry.is_dir():
                dirs.append(entry.name)
            else:
                files.append(entry.name)
        yield directory, dirs, files
        children = [
            os.path.join(directory, name)
            for name in dirs
            if not os.path.islink(os.path.join(directory, name))
        ]
        pending.extend(reversed(children))
