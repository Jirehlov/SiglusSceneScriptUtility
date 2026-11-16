import os
import stat
import sys
from functools import lru_cache


class FilenameCaseCollisionError(OSError):
    pass


_WINDOWS_11_26300_9974_LOWER = {
    codepoint: codepoint + offset
    for first, last, step, offset in (
        (0x0041, 0x005A, 1, 0x0020),
        (0x00C0, 0x00D6, 1, 0x0020),
        (0x00D8, 0x00DE, 1, 0x0020),
        (0x0100, 0x012E, 2, 0x0001),
        (0x0132, 0x0136, 2, 0x0001),
        (0x0139, 0x0147, 2, 0x0001),
        (0x014A, 0x0176, 2, 0x0001),
        (0x0178, 0x0178, 1, -0x0079),
        (0x0179, 0x017D, 2, 0x0001),
        (0x0181, 0x0181, 1, 0x00D2),
        (0x0182, 0x0184, 2, 0x0001),
        (0x0186, 0x0186, 1, 0x00CE),
        (0x0187, 0x0187, 1, 0x0001),
        (0x0189, 0x018A, 1, 0x00CD),
        (0x018B, 0x018B, 1, 0x0001),
        (0x018E, 0x018E, 1, 0x004F),
        (0x018F, 0x018F, 1, 0x00CA),
        (0x0190, 0x0190, 1, 0x00CB),
        (0x0191, 0x0191, 1, 0x0001),
        (0x0193, 0x0193, 1, 0x00CD),
        (0x0194, 0x0194, 1, 0x00CF),
        (0x0196, 0x0196, 1, 0x00D3),
        (0x0197, 0x0197, 1, 0x00D1),
        (0x0198, 0x0198, 1, 0x0001),
        (0x019C, 0x019C, 1, 0x00D3),
        (0x019D, 0x019D, 1, 0x00D5),
        (0x019F, 0x019F, 1, 0x00D6),
        (0x01A0, 0x01A4, 2, 0x0001),
        (0x01A6, 0x01A6, 1, 0x00DA),
        (0x01A7, 0x01A7, 1, 0x0001),
        (0x01A9, 0x01A9, 1, 0x00DA),
        (0x01AC, 0x01AC, 1, 0x0001),
        (0x01AE, 0x01AE, 1, 0x00DA),
        (0x01AF, 0x01AF, 1, 0x0001),
        (0x01B1, 0x01B2, 1, 0x00D9),
        (0x01B3, 0x01B5, 2, 0x0001),
        (0x01B7, 0x01B7, 1, 0x00DB),
        (0x01B8, 0x01B8, 1, 0x0001),
        (0x01BC, 0x01BC, 1, 0x0001),
        (0x01C4, 0x01C4, 1, 0x0002),
        (0x01C7, 0x01C7, 1, 0x0002),
        (0x01CA, 0x01CA, 1, 0x0002),
        (0x01CD, 0x01DB, 2, 0x0001),
        (0x01DE, 0x01EE, 2, 0x0001),
        (0x01F1, 0x01F1, 1, 0x0002),
        (0x01F4, 0x01F4, 1, 0x0001),
        (0x01F6, 0x01F6, 1, -0x0061),
        (0x01F7, 0x01F7, 1, -0x0038),
        (0x01F8, 0x021E, 2, 0x0001),
        (0x0220, 0x0220, 1, -0x0082),
        (0x0222, 0x0232, 2, 0x0001),
        (0x023A, 0x023A, 1, 0x2A2B),
        (0x023B, 0x023B, 1, 0x0001),
        (0x023D, 0x023D, 1, -0x00A3),
        (0x023E, 0x023E, 1, 0x2A28),
        (0x0241, 0x0241, 1, 0x0001),
        (0x0243, 0x0243, 1, -0x00C3),
        (0x0244, 0x0244, 1, 0x0045),
        (0x0245, 0x0245, 1, 0x0047),
        (0x0246, 0x024E, 2, 0x0001),
        (0x0370, 0x0372, 2, 0x0001),
        (0x0376, 0x0376, 1, 0x0001),
        (0x0386, 0x0386, 1, 0x0026),
        (0x0388, 0x038A, 1, 0x0025),
        (0x038C, 0x038C, 1, 0x0040),
        (0x038E, 0x038F, 1, 0x003F),
        (0x0391, 0x03A1, 1, 0x0020),
        (0x03A3, 0x03AB, 1, 0x0020),
        (0x03CF, 0x03CF, 1, 0x0008),
        (0x03D8, 0x03EE, 2, 0x0001),
        (0x03F7, 0x03F7, 1, 0x0001),
        (0x03F9, 0x03F9, 1, -0x0007),
        (0x03FA, 0x03FA, 1, 0x0001),
        (0x03FD, 0x03FF, 1, -0x0082),
        (0x0400, 0x040F, 1, 0x0050),
        (0x0410, 0x042F, 1, 0x0020),
        (0x0460, 0x0480, 2, 0x0001),
        (0x048A, 0x04BE, 2, 0x0001),
        (0x04C0, 0x04C0, 1, 0x000F),
        (0x04C1, 0x04CD, 2, 0x0001),
        (0x04D0, 0x0522, 2, 0x0001),
        (0x0531, 0x0556, 1, 0x0030),
        (0x10A0, 0x10C5, 1, 0x1C60),
        (0x1E00, 0x1E94, 2, 0x0001),
        (0x1EA0, 0x1EFE, 2, 0x0001),
        (0x1F08, 0x1F0F, 1, -0x0008),
        (0x1F18, 0x1F1D, 1, -0x0008),
        (0x1F28, 0x1F2F, 1, -0x0008),
        (0x1F38, 0x1F3F, 1, -0x0008),
        (0x1F48, 0x1F4D, 1, -0x0008),
        (0x1F59, 0x1F5F, 2, -0x0008),
        (0x1F68, 0x1F6F, 1, -0x0008),
        (0x1F88, 0x1F8F, 1, -0x0008),
        (0x1F98, 0x1F9F, 1, -0x0008),
        (0x1FA8, 0x1FAF, 1, -0x0008),
        (0x1FB8, 0x1FB9, 1, -0x0008),
        (0x1FBA, 0x1FBB, 1, -0x004A),
        (0x1FBC, 0x1FBC, 1, -0x0009),
        (0x1FC8, 0x1FCB, 1, -0x0056),
        (0x1FCC, 0x1FCC, 1, -0x0009),
        (0x1FD8, 0x1FD9, 1, -0x0008),
        (0x1FDA, 0x1FDB, 1, -0x0064),
        (0x1FE8, 0x1FE9, 1, -0x0008),
        (0x1FEA, 0x1FEB, 1, -0x0070),
        (0x1FEC, 0x1FEC, 1, -0x0007),
        (0x1FF8, 0x1FF9, 1, -0x0080),
        (0x1FFA, 0x1FFB, 1, -0x007E),
        (0x1FFC, 0x1FFC, 1, -0x0009),
        (0x2132, 0x2132, 1, 0x001C),
        (0x2160, 0x216F, 1, 0x0010),
        (0x2183, 0x2183, 1, 0x0001),
        (0x24B6, 0x24CF, 1, 0x001A),
        (0x2C00, 0x2C2E, 1, 0x0030),
        (0x2C60, 0x2C60, 1, 0x0001),
        (0x2C62, 0x2C62, 1, -0x29F7),
        (0x2C63, 0x2C63, 1, -0x0EE6),
        (0x2C64, 0x2C64, 1, -0x29E7),
        (0x2C67, 0x2C6B, 2, 0x0001),
        (0x2C6D, 0x2C6D, 1, -0x2A1C),
        (0x2C6E, 0x2C6E, 1, -0x29FD),
        (0x2C6F, 0x2C6F, 1, -0x2A1F),
        (0x2C72, 0x2C72, 1, 0x0001),
        (0x2C75, 0x2C75, 1, 0x0001),
        (0x2C80, 0x2CE2, 2, 0x0001),
        (0xA640, 0xA65E, 2, 0x0001),
        (0xA662, 0xA66C, 2, 0x0001),
        (0xA680, 0xA696, 2, 0x0001),
        (0xA722, 0xA72E, 2, 0x0001),
        (0xA732, 0xA76E, 2, 0x0001),
        (0xA779, 0xA77B, 2, 0x0001),
        (0xA77D, 0xA77D, 1, -0x8A04),
        (0xA77E, 0xA786, 2, 0x0001),
        (0xA78B, 0xA78B, 1, 0x0001),
        (0xFF21, 0xFF3A, 1, 0x0020),
    )
    for codepoint in range(first, last + 1, step)
}


@lru_cache(maxsize=4096)
def windows_filename_key(value):
    return str(value or "").translate(_WINDOWS_11_26300_9974_LOWER)


def same_read_path(first, second):
    first = os.path.abspath(os.fspath(first))
    second = os.path.abspath(os.fspath(second))
    if first == second:
        return True
    if windows_filename_key(first) != windows_filename_key(second):
        return False
    return same_file_path(first, second)


def same_file_path(first, second):
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def validate_input_paths(paths, *, seen=None, warn_only=False, allow_same_file=False):
    paths = list(paths)
    if seen is None:
        if len(paths) < 2:
            return paths
        seen = {}
    for path in paths:
        absolute = os.path.abspath(os.fspath(path))
        key = windows_filename_key(absolute)
        previous = seen.get(key)
        if previous is not None:
            if allow_same_file and same_read_path(previous, absolute):
                continue
            message = f"input paths collide under Windows case matching: {previous!r} and {absolute!r}"
            if not warn_only:
                raise FilenameCaseCollisionError(message)
            print(f"warning: {message}", file=sys.stderr)
        else:
            seen[key] = absolute
    return paths


def resolve_read_path(path, kind=None):
    original = os.fspath(path)
    if not original:
        raise FileNotFoundError(original)
    absolute = os.path.abspath(original)
    path_stat = os.stat(absolute)
    if kind == "file" and not stat.S_ISREG(path_stat.st_mode):
        raise FileNotFoundError(original)
    if kind == "dir" and not stat.S_ISDIR(path_stat.st_mode):
        raise NotADirectoryError(original)
    return absolute


def read_file_exists(path):
    try:
        resolve_read_path(path, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def open_read(path, mode="rb", **kwargs):
    if "r" not in mode or any(flag in mode for flag in "wax+"):
        raise ValueError(f"not a read-only mode: {mode}")
    return open(path, mode, **kwargs)


def read_file_stat(path):
    original = os.fspath(path)
    if not original:
        raise FileNotFoundError(original)
    path_stat = os.stat(original)
    if not stat.S_ISREG(path_stat.st_mode):
        raise FileNotFoundError(original)
    return path_stat


def read_directory(path):
    original = os.fspath(path)
    if not original:
        raise FileNotFoundError(original)
    directory = os.path.abspath(original)
    with os.scandir(directory) as entries:
        return directory, list(entries)


def walk_read_directory(path):
    root, entries = read_directory(path)
    pending = [(root, entries)]
    while pending:
        directory, entries = pending.pop()
        if entries is None:
            _, entries = read_directory(directory)
        dirs = []
        files = []
        for entry in entries:
            if entry.is_dir():
                dirs.append(entry)
            else:
                files.append(entry.name)
        yield directory, [entry.name for entry in dirs], files
        children = [
            entry.path
            for entry in dirs
            if not entry.is_symlink() and not entry.is_junction()
        ]
        pending.extend((child, None) for child in reversed(children))
