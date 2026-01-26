import os
import sys
import shutil
import re
import subprocess
import tempfile

from .common import eprint, hint_help as _hint_help, fmt_kv as _fmt_kv

try:
    # Package import (preferred)
    from . import sound
    from . import extract
except Exception:  # pragma: no cover
    # Direct script import fallback
    import sound  # type: ignore
    import extract  # type: ignore


def _cleanup_tmp_dir(tmp_dir: str, out_root: str) -> None:
    """Remove the dedicated ffmpeg temp directory under output root."""
    if not tmp_dir:
        return
    try:
        if os.path.isdir(tmp_dir) and os.path.basename(tmp_dir) == ".tmp_ffmpeg":
            out_abs = os.path.abspath(out_root)
            tmp_abs = os.path.abspath(tmp_dir)
            # Safety: only delete if it is inside out_root
            if tmp_abs == os.path.join(out_abs, ".tmp_ffmpeg") or tmp_abs.startswith(
                out_abs + os.sep
            ):
                shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass


def _iter_audio_files(inp: str):
    if os.path.isfile(inp):
        yield inp
        return
    for base_dir, _dirs, files in os.walk(inp):
        for fn in files:
            low = fn.lower()
            if low.endswith(".owp") or low.endswith(".nwa") or low.endswith(".ovk"):
                yield os.path.join(base_dir, fn)


def _write_file(path: str, data: bytes) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _analyze_one(path: str) -> int:
    """Analyze one .nwa/.ovk/.owp and print basic metadata to stdout."""
    ext = os.path.splitext(path)[1].lower()
    try:
        st = os.stat(path)
        size = st.st_size
    except Exception:
        size = "?"
    print(_fmt_kv("path", path))
    print(_fmt_kv("type", ext.lstrip(".") or "unknown"))
    print(_fmt_kv("size_bytes", size))

    if ext == ".nwa":
        import struct

        header_struct = struct.Struct("<HHIiiIIIIIII")
        with open(path, "rb") as f:
            data = f.read(header_struct.size)
        if len(data) < header_struct.size:
            eprint("error: NWA header truncated")
            return 1
        fields = header_struct.unpack_from(data, 0)
        channels = int(fields[0])
        bits_per_sample = int(fields[1])
        samples_per_sec = int(fields[2])
        pack_mod = int(fields[3])
        zero_mod = int(fields[4])
        unit_cnt = int(fields[5])
        original_size = int(fields[6])
        pack_size = int(fields[7])
        sample_cnt = int(fields[8])
        unit_sample_cnt = int(fields[9])
        last_sample_cnt = int(fields[10])
        last_sample_pack_size = int(fields[11])

        dur = None
        try:
            dur = sample_cnt / float(samples_per_sec) if samples_per_sec else None
        except Exception:
            dur = None

        print(_fmt_kv("channels", channels))
        print(_fmt_kv("bits_per_sample", bits_per_sample))
        print(_fmt_kv("samples_per_sec", samples_per_sec))
        if dur is not None:
            print(_fmt_kv("duration_sec", f"{dur:.6f}"))
        print(_fmt_kv("sample_cnt", sample_cnt))
        print(_fmt_kv("pack_mod", pack_mod))
        print(_fmt_kv("zero_mod", zero_mod))
        print(_fmt_kv("unit_cnt", unit_cnt))
        print(_fmt_kv("unit_sample_cnt", unit_sample_cnt))
        print(_fmt_kv("last_sample_cnt", last_sample_cnt))
        print(_fmt_kv("original_size", original_size))
        print(_fmt_kv("pack_size", pack_size))
        print(_fmt_kv("last_sample_pack_size", last_sample_pack_size))
        return 0

    if ext == ".ovk":
        import struct

        entry_struct = struct.Struct("<IIii")  # size, offset, no, smp_cnt
        with open(path, "rb") as f:
            cnt_b = f.read(4)
            if len(cnt_b) != 4:
                eprint("error: OVK header truncated")
                return 1
            cnt = struct.unpack("<I", cnt_b)[0]
            print(_fmt_kv("entry_count", cnt))
            if cnt == 0:
                return 0
            table = f.read(entry_struct.size * cnt)
            if len(table) != entry_struct.size * cnt:
                eprint("error: OVK table truncated")
                return 1
        for i in range(cnt):
            size_, offset_, no_, smp_cnt_ = entry_struct.unpack_from(
                table, i * entry_struct.size
            )
            print(_fmt_kv(f"entry[{i}].no", int(no_)))
            print(_fmt_kv(f"entry[{i}].offset", int(offset_)))
            print(_fmt_kv(f"entry[{i}].size", int(size_)))
            print(_fmt_kv(f"entry[{i}].sample_cnt", int(smp_cnt_)))
        return 0

    if ext == ".owp":
        # Report whether it looks like plain OGG or XOR-obfuscated, and output decoded size.
        try:
            with open(path, "rb") as f:
                head = f.read(4)
            is_ogg = head == b"OggS"
            xor_key = None
            if not is_ogg and len(head) == 4:
                # Common OWP key (0x39) check
                if bytes((b ^ 0x39) for b in head) == b"OggS":
                    xor_key = "0x39"
                else:
                    # heuristic: key = first_byte ^ 'O'
                    key = head[0] ^ ord("O")
                    if bytes((head[j] ^ key) for j in range(4)) == b"OggS":
                        xor_key = hex(key)
            print(_fmt_kv("looks_like_ogg", bool(is_ogg)))
            if xor_key is not None:
                print(_fmt_kv("xor_key_candidate", xor_key))
            # Validate by decoding header (full decode) only if not too large? Keep simple.
            ogg = sound.decode_owp_to_ogg_bytes(path)
            print(
                _fmt_kv("decoded_magic", ogg[:4].decode("latin1", "backslashreplace"))
            )
            print(_fmt_kv("decoded_size_bytes", len(ogg)))
        except Exception as e:
            eprint(f"error: OWP decode failed: {e}")
            return 1
        return 0

    eprint("error: unsupported file type (expected .nwa/.ovk/.owp)")
    return 1


_BGM_RE = re.compile(
    r'^\s*#BGM\.\d+\s*=\s*"(?:[^"]*)"\s*,\s*"(?P<fn>[^"]+)"\s*,\s*(?P<start>-?\d+)\s*,\s*(?P<end>-?\d+)\s*,\s*(?P<rep>-?\d+)\s*$',
    re.IGNORECASE,
)


def _parse_bgm_table(gameexe_ini_text: str):
    """
    Parse lines like:
      #BGM.000 = "BGM01A", "M01A", 60000, 6792000, 132000
    Returns: dict[lower(file_name)] -> (start, end, repeat)
    """
    table = {}
    for raw_line in (gameexe_ini_text or "").splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("#"):
            continue
        m = _BGM_RE.match(line)
        if not m:
            continue
        fn = (m.group("fn") or "").strip()
        if not fn:
            continue
        try:
            start = int(m.group("start"))
            end = int(m.group("end"))
            rep = int(m.group("rep"))
        except Exception:
            continue
        table[fn.lower()] = (start, end, rep)
    return table


def _load_gameexe_ini_text(gameexe_dat_path: str) -> str:
    # Reuse extract.py --gei logic (equivalent to: siglus-tool -x --gei ...).
    # This avoids duplicating the exe_el candidate search in sound_tool.py.
    tmp_dir = tempfile.mkdtemp(prefix="siglus_gei_")
    try:
        rc = extract.main(["--gei", gameexe_dat_path, tmp_dir])
        if rc != 0:
            raise RuntimeError("Failed to decode Gameexe.dat payload")
        ini_path = os.path.join(tmp_dir, "Gameexe.ini")
        if not os.path.isfile(ini_path):
            # Fallback: case-insensitive search
            try:
                for fn in os.listdir(tmp_dir):
                    if fn.lower() == "gameexe.ini":
                        ini_path = os.path.join(tmp_dir, fn)
                        break
            except Exception:
                pass
        if not os.path.isfile(ini_path):
            raise RuntimeError("Failed to decode Gameexe.dat payload")
        with open(ini_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _ffmpeg_trim_ogg_bytes(
    ogg_bytes: bytes,
    start_sample: int,
    end_sample: int,
    ffmpeg_path: str,
    tmp_dir: str,
) -> bytes:
    if not ffmpeg_path:
        raise RuntimeError("ffmpeg not found in PATH")
    if start_sample < 0:
        raise RuntimeError("invalid repeat position (start_sample < 0)")
    if end_sample != -1 and end_sample <= start_sample:
        raise RuntimeError("invalid trim range (end_sample <= start_sample)")

    os.makedirs(tmp_dir, exist_ok=True)
    in_fd, in_path = tempfile.mkstemp(prefix="siglus_in_", suffix=".ogg", dir=tmp_dir)
    out_fd, out_path = tempfile.mkstemp(
        prefix="siglus_out_", suffix=".ogg", dir=tmp_dir
    )
    os.close(in_fd)
    os.close(out_fd)
    try:
        with open(in_path, "wb") as f:
            f.write(ogg_bytes)

        if end_sample == -1:
            af = f"atrim=start_sample={start_sample},asetpts=PTS-STARTPTS"
        else:
            af = f"atrim=start_sample={start_sample}:end_sample={end_sample},asetpts=PTS-STARTPTS"

        cmd = [
            ffmpeg_path,
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-i",
            in_path,
            "-vn",
            "-af",
            af,
            "-c:a",
            "libvorbis",
            "-q:a",
            "6",
            out_path,
        ]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode != 0:
            err = (p.stderr or b"").decode("utf-8", "backslashreplace").strip()
            raise RuntimeError("ffmpeg trim failed: " + (err or "unknown error"))

        with open(out_path, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(in_path)
        except Exception:
            pass
        try:
            os.remove(out_path)
        except Exception:
            pass


def _extract_one(
    src_path: str,
    out_root: str,
    rel_dir: str,
    trim_table=None,
    ffmpeg_path: str = "",
    tmp_dir: str = "",
) -> int:
    bn = os.path.basename(src_path)
    base_name, ext = os.path.splitext(bn)
    ext = ext.lower()

    out_dir = os.path.join(out_root, rel_dir) if rel_dir else out_root
    os.makedirs(out_dir, exist_ok=True)

    if ext == ".owp":
        ogg = sound.decode_owp_to_ogg_bytes(src_path)

        if trim_table is not None:
            key = base_name.lower()
            if key not in trim_table:
                raise RuntimeError(f"no #BGM.* entry for file name: {base_name}")
            start_pos, end_pos, rep_pos = trim_table[key]
            # "only export one loop": [repeat_pos, end_pos] (or EOF when end_pos == -1)
            eprint(
                f"trim {base_name}: samples {rep_pos}..{end_pos if end_pos != -1 else 'EOF'}"
            )
            ogg = _ffmpeg_trim_ogg_bytes(
                ogg,
                start_sample=rep_pos,
                end_sample=end_pos,
                ffmpeg_path=ffmpeg_path,
                tmp_dir=tmp_dir,
            )

        _write_file(os.path.join(out_dir, base_name + ".ogg"), ogg)
        return 1

    if ext == ".nwa":
        wav = sound.decode_nwa_to_wav_bytes(src_path)
        _write_file(os.path.join(out_dir, base_name + ".wav"), wav)
        return 1

    if ext == ".ovk":
        entries = sound.read_ovk_table(src_path)
        if not entries:
            return 0
        multi = len(entries) > 1
        wrote = 0
        for entry_no, ogg in sound.iter_ovk_entries(src_path):
            if multi:
                out_name = f"{base_name}_{entry_no}.ogg"
            else:
                out_name = f"{base_name}.ogg"
            _write_file(os.path.join(out_dir, out_name), ogg)
            wrote += 1
        return wrote

    return 0


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help", "help"):
        _hint_help()
        return 0

    do_x = False
    do_a = False
    if "--x" in argv:
        do_x = True
        argv = [a for a in argv if a != "--x"]
    if "--a" in argv:
        do_a = True
        argv = [a for a in argv if a != "--a"]

    if do_x and do_a:
        eprint("error: choose only one of --x or --a")
        _hint_help()
        return 2

    if not do_x and not do_a:
        eprint("error: missing flag: specify --x (extract) or --a (analyze)")
        _hint_help()
        return 2

    if do_a:
        if "--trim" in argv:
            eprint("error: --trim is only valid with --x")
            return 2
        if len(argv) != 1:
            eprint("error: expected 1 input file for --a")
            _hint_help()
            return 2
        inp = argv[0]
        if not os.path.isfile(inp):
            eprint(f"input not found: {inp}")
            return 1
        return _analyze_one(inp)

    # --x (extract/decode)
    trim_path = ""
    if "--trim" in argv:
        i = argv.index("--trim")
        if i + 1 >= len(argv):
            eprint("error: --trim expects a path")
            _hint_help()
            return 2
        trim_path = argv[i + 1]
        del argv[i : i + 2]

    if len(argv) != 2:
        eprint("error: expected <input> <output_dir> for --x")
        _hint_help()
        return 2

    inp, out_root = argv[0], argv[1]

    src_is_dir = os.path.isdir(inp)
    if not src_is_dir and not os.path.isfile(inp):
        eprint(f"input not found: {inp}")
        return 1

    trim_table = None
    ffmpeg_path = ""
    tmp_dir = ""

    if trim_path:
        ffmpeg_path = shutil.which("ffmpeg") or ""
        if not ffmpeg_path:
            eprint("ffmpeg not found in PATH")
            return 1
        if not os.path.isfile(trim_path):
            eprint(f"Gameexe.dat not found: {trim_path}")
            return 1

        gei_txt = _load_gameexe_ini_text(trim_path)
        trim_table = _parse_bgm_table(gei_txt)
        if not trim_table:
            eprint("error: no #BGM.* entries found in Gameexe.dat")
            return 1

        tmp_dir = os.path.join(out_root, ".tmp_ffmpeg")
        try:
            os.makedirs(tmp_dir, exist_ok=True)
        except Exception:
            tmp_dir = tempfile.mkdtemp(prefix="siglus_ffmpeg_")

    os.makedirs(out_root, exist_ok=True)

    files = list(_iter_audio_files(inp)) if src_is_dir else [inp]
    total = len(files)
    wrote = 0
    failed = 0

    if total == 0:
        eprint("no supported audio files found")
        _cleanup_tmp_dir(tmp_dir, out_root)
        return 0

    for idx, src_path in enumerate(files, 1):
        eprint(f"[{idx}/{total}] processing: {src_path}")
        try:
            if src_is_dir:
                rel = os.path.relpath(src_path, inp)
                rel_dir = os.path.dirname(rel)
            else:
                rel_dir = ""
            n = _extract_one(
                src_path,
                out_root,
                rel_dir,
                trim_table=trim_table,
                ffmpeg_path=ffmpeg_path,
                tmp_dir=tmp_dir,
            )
            wrote += n
            eprint(f"[{idx}/{total}] done: wrote {n}")
        except Exception as e:
            failed += 1
            eprint(f"[{idx}/{total}] failed: {src_path}\t{e}")

    eprint(f"done total={total} wrote={wrote} failed={failed}")
    exit_code = 0 if failed == 0 else 1
    _cleanup_tmp_dir(tmp_dir, out_root)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
