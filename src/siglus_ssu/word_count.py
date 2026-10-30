import re
import unicodedata
from bisect import bisect_right

_CJK_RANGES = (
    (0x3040, 0x309F),
    (0x30A0, 0x30FF),
    (0x3100, 0x312F),
    (0x31A0, 0x31BF),
    (0x31F0, 0x31FF),
    (0x32D0, 0x32FE),
    (0x3300, 0x3357),
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xF900, 0xFAFF),
    (0xFF66, 0xFF9D),
    (0xFF9E, 0xFF9F),
    (0x1B000, 0x1B000),
    (0x1B001, 0x1B11F),
    (0x1B120, 0x1B12F),
    (0x1B132, 0x1B132),
    (0x1B150, 0x1B167),
    (0x20000, 0x2A6DF),
    (0x2A700, 0x2B73F),
    (0x2B740, 0x2B81F),
    (0x2B820, 0x2CEAF),
    (0x2CEB0, 0x2EBEF),
    (0x2EBF0, 0x2EE5F),
    (0x30000, 0x323AF),
)
_CJK_RANGE_STARTS = tuple(start for start, _end in _CJK_RANGES)
_HANGUL_RANGES = (
    (0x1100, 0x11FF),
    (0x3130, 0x318F),
    (0xA960, 0xA97F),
    (0xAC00, 0xD7A3),
    (0xD7B0, 0xD7FF),
)
_WORD_CONNECTORS = frozenset(
    {"'", "\u2019", "-", "_", "\u2010", "\u2011", "\ufe63", "\uff0d"}
)
_NUMBER_CONNECTORS = frozenset(
    {".", ",", "/", ":", "\uff0e", "\uff0c", "\uff0f", "\uff1a"}
)
_KEYCAP_RE = re.compile(r"[0-9#*]\ufe0f?\u20e3")


def _is_hangul(ch: str) -> bool:
    cp = ord(ch)
    for start, end in _HANGUL_RANGES:
        if start <= cp <= end:
            return True
    return False


def _is_cjk_unit(ch: str) -> bool:
    cp = ord(ch)
    index = bisect_right(_CJK_RANGE_STARTS, cp) - 1
    return index >= 0 and cp <= _CJK_RANGES[index][1]


def _is_halfwidth_katakana_base(ch: str) -> bool:
    cp = ord(ch)
    return 0xFF66 <= cp <= 0xFF9D


def _is_halfwidth_katakana_mark(ch: str) -> bool:
    cp = ord(ch)
    return 0xFF9E <= cp <= 0xFF9F


def _is_mark(ch: str) -> bool:
    return unicodedata.category(ch).startswith("M")


def _is_decimal_digit(ch: str) -> bool:
    return unicodedata.category(ch) == "Nd"


def _is_non_asian_core(ch: str) -> bool:
    return _is_hangul(ch) or (
        unicodedata.category(ch)[0] in ("L", "N") and not _is_cjk_unit(ch)
    )


def _prev_non_mark(text: str, idx: int, lower: int) -> int:
    while idx >= lower and _is_mark(text[idx]):
        idx -= 1
    return idx


def _next_non_mark(text: str, idx: int) -> int:
    while idx < len(text) and _is_mark(text[idx]):
        idx += 1
    return idx


def _is_run_connector(text: str, idx: int, start: int) -> bool:
    prev_idx = _prev_non_mark(text, idx - 1, start)
    next_idx = _next_non_mark(text, idx + 1)
    if prev_idx < start or next_idx >= len(text):
        return False
    prev_ch = text[prev_idx]
    next_ch = text[next_idx]
    ch = text[idx]
    if ch in _WORD_CONNECTORS:
        return _is_non_asian_core(prev_ch) and _is_non_asian_core(next_ch)
    if ch in _NUMBER_CONNECTORS:
        return _is_decimal_digit(prev_ch) and _is_decimal_digit(next_ch)
    return False


def _consume_non_asian_run(text: str, start: int) -> int:
    i = start + 1
    while i < len(text):
        ch = text[i]
        if _is_non_asian_core(ch) or _is_mark(ch):
            i += 1
            continue
        if _is_run_connector(text, i, start):
            i += 1
            continue
        break
    return i


def count_text_units(text: str) -> int:
    text = _KEYCAP_RE.sub(" ", unicodedata.normalize("NFC", str(text or "")))
    total = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if unicodedata.category(ch)[0] in ("P", "S", "M"):
            i += 1
            continue
        if _is_halfwidth_katakana_base(ch):
            if (i + 1) < len(text) and _is_halfwidth_katakana_mark(text[i + 1]):
                total += 1
                i += 2
                continue
            total += 1
            i += 1
            continue
        if _is_cjk_unit(ch):
            total += 1
            i += 1
            continue
        if _is_non_asian_core(ch):
            i = _consume_non_asian_run(text, i)
            total += 1
            continue
        i += 1
    return total
