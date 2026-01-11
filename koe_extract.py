import argparse
import os
import re
import struct
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple, Union


@dataclass(frozen=True)
class KOECoord:
    koe_no: int
    chara_no: int = -1


def parse_koe_coord(value: str) -> KOECoord:
    s = value.strip()
    m = re.fullmatch(r"KOE\(\s*(\d+)\s*(?:,\s*(\d+)\s*)?\)", s, flags=re.IGNORECASE)
    if m:
        koe = int(m.group(1))
        ch = int(m.group(2)) if m.group(2) is not None else -1
        return KOECoord(koe, ch)
    s2 = re.sub(r"\s+", "", s)
    if "," in s2:
        a, b = s2.split(",", 1)
        return KOECoord(int(a), int(b))
    if ":" in s2:
        a, b = s2.split(":", 1)
        return KOECoord(int(a), int(b))
    if re.fullmatch(r"\d+", s2):
        return KOECoord(int(s2), -1)
    raise ValueError(f"Invalid KOE coordinate: {value!r}")


def format_koe_coord(coord: Union[KOECoord, Tuple[int, int]]) -> str:
    if isinstance(coord, tuple):
        coord = KOECoord(coord[0], coord[1])
    if coord.chara_no >= 0:
        return f"KOE({coord.koe_no:09d},{coord.chara_no:03d})"
    return f"KOE({coord.koe_no:09d})"


def koe_no_to_scene_line(koe_no: int) -> Tuple[int, int]:
    if koe_no < 0:
        raise ValueError("koe_no must be non-negative")
    scn_no = koe_no // 100000
    line_no = koe_no % 100000
    return scn_no, line_no


def sanitize_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\\\|?*]+', "_", name)


def _candidate_ovk_paths(voice_dir: str, scn_no: int, chara_no: int) -> List[str]:
    zname = f"z{scn_no:04d}.ovk"
    cands = []
    cands.append(os.path.join(voice_dir, "koe", zname))
    cands.append(os.path.join(voice_dir, zname))
    if chara_no >= 0:
        cands.append(os.path.join(voice_dir, "koe", f"{chara_no:03d}", zname))
        cands.append(os.path.join(voice_dir, f"{chara_no:03d}", zname))
    return cands


def find_ovk_path(voice_dir: str, koe_no: int, chara_no: int = -1) -> str:
    scn_no, _ = koe_no_to_scene_line(koe_no)
    for p in _candidate_ovk_paths(voice_dir, scn_no, chara_no):
        if os.path.isfile(p):
            return p
    target = f"z{scn_no:04d}.ovk".lower()
    for root, _, files in os.walk(voice_dir):
        for fn in files:
            if fn.lower() == target:
                return os.path.join(root, fn)
    raise FileNotFoundError(f"OVK not found for scene {scn_no:04d} under {voice_dir!r}")


def _read_u32_le(f) -> int:
    b = f.read(4)
    if len(b) != 4:
        raise EOFError("Unexpected EOF while reading u32")
    return struct.unpack("<I", b)[0]


def _xor_decrypt_if_needed(data: bytes) -> bytes:
    if len(data) >= 4 and data[:4] == b"OggS":
        return data
    if len(data) >= 4:
        key = data[0] ^ ord("O")
        if (
            (data[1] ^ key) == ord("g")
            and (data[2] ^ key) == ord("g")
            and (data[3] ^ key) == ord("S")
        ):
            return bytes((b ^ key) for b in data)
    return data


def extract_ogg_bytes_from_ovk(ovk_path: str, koe_no: int) -> bytes:
    _, line_no = koe_no_to_scene_line(koe_no)
    entry_struct = struct.Struct("<IIii")
    with open(ovk_path, "rb") as f:
        koe_cnt = _read_u32_le(f)
        if koe_cnt == 0:
            raise KeyError(f"No entries in ovk: {ovk_path!r}")
        table = f.read(entry_struct.size * koe_cnt)
        if len(table) != entry_struct.size * koe_cnt:
            raise EOFError("Unexpected EOF while reading ovk table")
        offset = None
        size = None
        for i in range(koe_cnt):
            e_size, e_offset, e_no, _ = entry_struct.unpack_from(
                table, i * entry_struct.size
            )
            if e_no == line_no:
                offset = e_offset
                size = e_size
                break
        if offset is None or size is None:
            raise KeyError(f"Entry not found for line_no={line_no} in {ovk_path!r}")
        f.seek(offset)
        chunk = f.read(size)
        if len(chunk) != size:
            raise EOFError("Unexpected EOF while reading ovk chunk")
    chunk = _xor_decrypt_if_needed(chunk)
    if len(chunk) < 4 or chunk[:4] != b"OggS":
        raise ValueError("Extracted data is not OggS after decryption attempt")
    return chunk


def extract_koe_to_ogg(
    coord: Union[KOECoord, Tuple[int, int], str],
    voice_dir: str,
    out_dir: Optional[str] = None,
    export: bool = False,
) -> Tuple[bytes, str, str]:
    if isinstance(coord, str):
        coord_obj = parse_koe_coord(coord)
    elif isinstance(coord, tuple):
        coord_obj = KOECoord(coord[0], coord[1])
    else:
        coord_obj = coord
    ovk_path = find_ovk_path(voice_dir, coord_obj.koe_no, coord_obj.chara_no)
    ogg_bytes = extract_ogg_bytes_from_ovk(ovk_path, coord_obj.koe_no)
    out_path = ""
    if export:
        if out_dir is None:
            raise ValueError("out_dir is required when export=True")
        os.makedirs(out_dir, exist_ok=True)
        name = sanitize_filename(format_koe_coord(coord_obj)) + ".ogg"
        out_path = os.path.join(out_dir, name)
        with open(out_path, "wb") as w:
            w.write(ogg_bytes)
    return ogg_bytes, ovk_path, out_path


def extract_many(
    coords: Sequence[Union[KOECoord, Tuple[int, int], str]],
    voice_dir: str,
    out_dir: Optional[str] = None,
    export: bool = False,
) -> List[Tuple[str, str, str]]:
    results = []
    for c in coords:
        if isinstance(c, str):
            cc = parse_koe_coord(c)
        elif isinstance(c, tuple):
            cc = KOECoord(c[0], c[1])
        else:
            cc = c
        _, ovk_path, out_path = extract_koe_to_ogg(
            cc, voice_dir, out_dir=out_dir, export=export
        )
        results.append((format_koe_coord(cc), ovk_path, out_path))
    return results


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="koe_extract")
    p.add_argument("--voice-dir", required=True)
    p.add_argument("--out-dir", default="")
    p.add_argument("--export", action="store_true")
    p.add_argument("--coord", action="append", default=[])
    p.add_argument("--koe-no", action="append", default=[])
    p.add_argument("--chara-no", action="append", default=[])
    return p


def _coords_from_args(args: argparse.Namespace) -> List[KOECoord]:
    coords = []
    for s in args.coord:
        coords.append(parse_koe_coord(s))
    if args.koe_no:
        if args.chara_no and len(args.chara_no) not in (1, len(args.koe_no)):
            raise SystemExit(
                "When using --koe-no with --chara-no, provide either 1 chara_no or one per koe_no"
            )
        for i, ks in enumerate(args.koe_no):
            ch = -1
            if args.chara_no:
                ch = (
                    int(args.chara_no[i])
                    if len(args.chara_no) == len(args.koe_no)
                    else int(args.chara_no[0])
                )
            coords.append(KOECoord(int(ks), ch))
    if not coords:
        raise SystemExit(
            "Provide at least one coordinate via --coord or --koe-no/--chara-no"
        )
    return coords


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    coords = _coords_from_args(args)
    out_dir = args.out_dir if args.out_dir else None
    results = extract_many(coords, args.voice_dir, out_dir=out_dir, export=args.export)
    for coord_str, ovk_path, out_path in results:
        if args.export:
            print(f"{coord_str}\t{ovk_path}\t{out_path}")
        else:
            print(f"{coord_str}\t{ovk_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
