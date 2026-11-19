import os
import shutil
import re
import subprocess
import sys
import tempfile
import time
import unicodedata
from contextlib import suppress
from dataclasses import dataclass

try:
    import psutil
except Exception:
    psutil = None
from .common import (
    collect_batch_files,
    eprint,
    hint_help as _hint_help,
    fmt_kv as _fmt_kv,
    hx,
    parse_main_argv,
    prepare_batch_paths,
    content_digest,
    read_bytes,
    open_atomic_output,
    write_bytes,
    missing_input_file,
    decode_text_auto,
    run_batch,
    consume_angou_option,
    split_end_of_options,
    first_option_token,
    is_option_token,
)
from . import sound
from . import GEI
from .path_policy import (
    check_output_inputs,
    open_read,
    read_file_stat,
    read_directory,
    resolve_read_path,
    windows_filename_key,
    validate_input_paths,
)


def _analyze_one(path: str) -> int:
    ext = os.path.splitext(path)[1].lower()
    try:
        st = read_file_stat(path)
        size = st.st_size
    except OSError:
        size = "?"
    print(_fmt_kv("path", path))
    print(_fmt_kv("type", ext.lstrip(".") or "unknown"))
    print(_fmt_kv("size_bytes", size))
    if ext == ".nwa":
        with open_read(path) as f:
            data = f.read(sound.NWA_HEADER_STRUCT.size)
        try:
            header = sound.parse_nwa_header(data)
        except EOFError:
            eprint("error: NWA header truncated")
            return 1
        channels = header.channels
        bits_per_sample = header.bits_per_sample
        samples_per_sec = header.samples_per_sec
        pack_mod = header.pack_mod
        zero_mod = header.zero_mod
        unit_cnt = header.unit_cnt
        original_size = header.original_size
        pack_size = header.pack_size
        sample_cnt = header.sample_cnt
        unit_sample_cnt = header.unit_sample_cnt
        last_sample_cnt = header.last_sample_cnt
        last_sample_pack_size = header.last_sample_pack_size
        dur = (
            sample_cnt / float(samples_per_sec * channels)
            if samples_per_sec and channels
            else None
        )
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

        entry_struct = struct.Struct("<IIii")
        with open_read(path) as f:
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
            print(_fmt_kv(f"entry[{i}].smp_cnt", int(smp_cnt_)))
        return 0
    if ext == ".owp":
        try:
            with open_read(path) as f:
                head = f.read(4)
            is_ogg = head == b"OggS"
            xor_key = None
            if not is_ogg and len(head) == 4:
                if bytes((b ^ 0x39) for b in head) == b"OggS":
                    xor_key = "0x39"
                else:
                    key = head[0] ^ ord("O")
                    if bytes((head[j] ^ key) for j in range(4)) == b"OggS":
                        xor_key = hex(key)
            print(_fmt_kv("looks_like_ogg", bool(is_ogg)))
            if xor_key is not None:
                print(_fmt_kv("xor_key_candidate", xor_key))
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


@dataclass(frozen=True)
class _OvkCompareEntry:
    entry_no: int
    occurrence: int
    size: int
    sample_count: int
    payload_sha256: str
    error: str = ""


def _ovk_scene_no(path: str) -> int | None:
    m = re.fullmatch(r"z(\d{4})\.ovk", os.path.basename(path), flags=re.IGNORECASE)
    if not m:
        return None
    return int(m.group(1))


def _ovk_koe_no_label(key, scene_no: int | None) -> str:
    entry_no, _occurrence = key
    if scene_no is None:
        return "-"
    return str(int(scene_no) * 100000 + int(entry_no))


def _ovk_compare_entries(path: str) -> list[_OvkCompareEntry]:
    entries = sound.read_ovk_table(path)
    seen = {}
    out = []
    with open_read(path) as f:
        for entry in entries:
            occurrence = int(seen.get(entry.entry_no, 0))
            seen[entry.entry_no] = occurrence + 1
            payload_sha256 = ""
            error = ""
            try:
                ogg = sound.extract_ogg_bytes_from_ovk_stream(f, entry)
                payload_sha256 = content_digest(ogg)
            except Exception as exc:
                error = str(exc)
            out.append(
                _OvkCompareEntry(
                    entry_no=int(entry.entry_no),
                    occurrence=occurrence,
                    size=int(entry.size),
                    sample_count=int(entry.sample_count),
                    payload_sha256=payload_sha256,
                    error=error,
                )
            )
    return out


def _compare_ovk(p1: str, p2: str) -> int:
    ext1 = os.path.splitext(p1)[1].lower()
    ext2 = os.path.splitext(p2)[1].lower()
    if ext1 != ".ovk" or ext2 != ".ovk":
        eprint("error: OVK compare expects two .ovk files")
        return 2
    try:
        st1 = read_file_stat(p1)
        st2 = read_file_stat(p2)
        e1 = _ovk_compare_entries(p1)
        e2 = _ovk_compare_entries(p2)
    except Exception as exc:
        eprint(f"error: OVK compare failed: {exc}")
        return 1

    print("==== Compare OVK ====")
    print(f"file1: {p1}")
    print(f"file2: {p2}")
    print(f"type1: ovk  size1={st1.st_size:d} ({hx(st1.st_size)})")
    print(f"type2: ovk  size2={st2.st_size:d} ({hx(st2.st_size)})")
    print()
    print(_fmt_kv("koe_count_1", len(e1)))
    print(_fmt_kv("koe_count_2", len(e2)))
    scene_no1 = _ovk_scene_no(p1)
    scene_no2 = _ovk_scene_no(p2)
    if scene_no1 is not None:
        print(_fmt_kv("scene_no_1", scene_no1))
    if scene_no2 is not None:
        print(_fmt_kv("scene_no_2", scene_no2))

    m1 = {(e.entry_no, e.occurrence): e for e in e1}
    m2 = {(e.entry_no, e.occurrence): e for e in e2}
    keys1 = set(m1.keys())
    keys2 = set(m2.keys())
    common = keys1 & keys2
    only1 = keys1 - keys2
    only2 = keys2 - keys1
    print(
        "koe_set: common=%d only1=%d only2=%d" % (len(common), len(only1), len(only2))
    )
    order1 = [(e.entry_no, e.occurrence) for e in e1]
    order2 = [(e.entry_no, e.occurrence) for e in e2]
    print("koe_order: " + ("identical" if order1 == order2 else "different"))

    rows = []
    payload_diff = 0
    size_diff = 0
    sample_diff = 0
    read_errors = 0
    for key in sorted(keys1 | keys2, key=lambda x: (int(x[0]), int(x[1]))):
        a = m1.get(key)
        b = m2.get(key)
        if a is None or b is None:
            status = "only1" if b is None else "only2"
            if (a or b).error:
                read_errors += 1
                status += "+read_error"
            rows.append((key, a, b, status))
            continue
        status = []
        if a.size != b.size:
            size_diff += 1
            status.append("size")
        if a.sample_count != b.sample_count:
            sample_diff += 1
            status.append("smp_cnt")
        if a.error or b.error:
            read_errors += 1
            status.append("read_error")
        elif a.payload_sha256 != b.payload_sha256:
            payload_diff += 1
            status.append("payload")
        if status:
            rows.append((key, a, b, "+".join(status)))

    if not rows:
        print("koe: identical by (koe_no, size, smp_cnt, decoded payload)")
        return 0

    print()
    print("KOE differences:")
    same_scene = scene_no1 is not None and scene_no1 == scene_no2
    if same_scene:
        print("KOE_NO          SIZE1       SMP1       SIZE2       SMP2  STATUS")
        print("---------  ----------  ---------  ----------  ---------  ----------")
    else:
        print(
            "KOE_NO1    KOE_NO2         SIZE1       SMP1       SIZE2       SMP2  STATUS"
        )
        print(
            "---------  ---------  ----------  ---------  ----------  ---------  ----------"
        )

    def _cell_entry(e: _OvkCompareEntry | None):
        if e is None:
            return "-", "-"
        return str(e.size), str(e.sample_count)

    for key, a, b, status in rows[:5000]:
        size1, smp1 = _cell_entry(a)
        size2, smp2 = _cell_entry(b)
        if same_scene:
            print(
                "%-9s  %10s  %9s  %10s  %9s  %s"
                % (
                    _ovk_koe_no_label(key, scene_no1),
                    size1,
                    smp1,
                    size2,
                    smp2,
                    status,
                )
            )
        else:
            print(
                "%-9s  %-9s  %10s  %9s  %10s  %9s  %s"
                % (
                    _ovk_koe_no_label(key, scene_no1 if a is not None else None),
                    _ovk_koe_no_label(key, scene_no2 if b is not None else None),
                    size1,
                    smp1,
                    size2,
                    smp2,
                    status,
                )
            )
    if len(rows) > 5000:
        print(f"... ({len(rows) - 5000:d} rows omitted)")
    print()
    print(
        "summary: rows=%d size_diff=%d smp_cnt_diff=%d payload_diff=%d read_error=%d only1=%d only2=%d"
        % (
            len(rows),
            size_diff,
            sample_diff,
            payload_diff,
            read_errors,
            len(only1),
            len(only2),
        )
    )
    return 1 if read_errors else 0


_BGM_RE = re.compile(
    r'^\s*#BGM\.\d+\s*=\s*"(?P<name>[^"]*)"\s*,\s*"(?P<fn>[^"]+)"\s*,\s*(?P<start>-?\d+)\s*,\s*(?P<end>-?\d+)\s*,\s*(?P<rep>-?\d+)\s*$',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _BgmLoopEntry:
    name: str
    start_sample: int
    end_sample: int
    repeat_sample: int


def _parse_bgm_table(gameexe_ini_text: str):
    table = {}
    for raw_line in (gameexe_ini_text or "").splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("#"):
            continue
        m = _BGM_RE.match(line)
        if not m:
            continue
        name = (m.group("name") or "").strip()
        fn = (m.group("fn") or "").strip()
        if not name or not fn:
            continue
        try:
            start = int(m.group("start"))
            end = int(m.group("end"))
            rep = int(m.group("rep"))
        except (TypeError, ValueError):
            continue
        table.setdefault(windows_filename_key(fn), []).append(
            _BgmLoopEntry(
                name=name,
                start_sample=start,
                end_sample=end,
                repeat_sample=rep,
            )
        )
    return table


def _load_gameexe_ini_text(gameexe_path: str, explicit_angou: str, read_paths) -> str:
    blob = read_bytes(gameexe_path)
    if not blob.startswith(b"\0\0\0\0"):
        txt = decode_text_auto(blob, stop_at_dos_eof=True)[0]
        analyzer = GEI.IniFileAnalizer()
        ok, txt = analyzer.analize(txt)
        if not ok:
            raise RuntimeError(
                f"GEI parse error line({analyzer.get_error_line()}): {analyzer.get_error_str()}"
            )
        return txt
    _, text = GEI.read_gameexe_dat(
        gameexe_path, blob, explicit_angou=explicit_angou, read_paths=read_paths
    )
    return text


def _load_bgm_table(gameexe_path: str, explicit_angou: str = "", *, read_paths=None):
    try:
        text = _load_gameexe_ini_text(gameexe_path, explicit_angou, read_paths)
    except ValueError as exc:
        eprint(f"error: {exc}")
        return None, 2
    except Exception as exc:
        eprint(f"error: {exc}")
        return None, 1
    table = _parse_bgm_table(text)
    if not table:
        eprint("error: no #BGM.* entries found")
        return None, 1
    return table, None


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
        trimmed = read_bytes(out_path)
        if sound.ogg_calc_smp_cnt(trimmed) <= 0:
            raise RuntimeError("ffmpeg trim produced no audio samples")
        return trimmed
    finally:
        with suppress(OSError):
            os.remove(in_path)
        with suppress(OSError):
            os.remove(out_path)


def _trim_nwa_to_wav_bytes(
    nwa_bytes: bytes,
    start_sample: int,
    end_sample: int,
) -> bytes:
    if start_sample < 0:
        raise RuntimeError("invalid repeat position (start_sample < 0)")
    pcm, header = sound.decode_nwa_to_pcm_bytes(nwa_bytes)
    bytes_per_frame = header.channels * (header.bits_per_sample // 8)
    if header.samples_per_sec <= 0:
        raise RuntimeError("invalid NWA sample rate")
    total_sample_cnt = len(pcm) // bytes_per_frame
    if total_sample_cnt <= 0:
        raise RuntimeError("failed to determine audio sample count")
    if end_sample == -1 or end_sample > total_sample_cnt:
        end_sample = total_sample_cnt
    if end_sample <= start_sample:
        raise RuntimeError("invalid trim range (end_sample <= start_sample)")
    start_byte = start_sample * bytes_per_frame
    end_byte = end_sample * bytes_per_frame
    return sound._build_wav(
        memoryview(pcm)[start_byte:end_byte],
        header.channels,
        header.bits_per_sample,
        header.samples_per_sec,
    )


def _resolve_bgm_entry(trim_table, base_name: str):
    key = windows_filename_key(base_name)
    if key not in trim_table:
        raise RuntimeError(f"no #BGM.* entry for file name: {base_name}")
    candidates = trim_table[key]
    for candidate in candidates:
        if windows_filename_key(candidate.name) == key:
            return candidate
    return candidates[0]


def _normalize_playback_range(
    total_sample_cnt: int,
    start_sample: int,
    end_sample: int,
    repeat_sample: int,
):
    if start_sample < 0:
        raise RuntimeError("invalid start position (start_sample < 0)")
    if repeat_sample < 0:
        raise RuntimeError("invalid repeat position (repeat_sample < 0)")
    if total_sample_cnt <= 0:
        raise RuntimeError("failed to determine audio sample count")
    if end_sample == -1 or end_sample > total_sample_cnt:
        end_sample = total_sample_cnt
    if start_sample > total_sample_cnt:
        raise RuntimeError("invalid start position (start_sample > total_sample_cnt)")
    if start_sample >= end_sample:
        raise RuntimeError("invalid start position (end_sample <= start_sample)")
    if repeat_sample >= end_sample:
        raise RuntimeError("invalid loop range (end_sample <= repeat_sample)")
    return start_sample, end_sample, repeat_sample


def _build_ffplay_audio_filter(
    start_sample: int,
    end_sample: int,
    repeat_sample: int,
    channel_layout: str = "",
) -> str:
    layout_filter = (
        f",aformat=channel_layouts={channel_layout}" if channel_layout else ""
    )
    loop_size = end_sample - repeat_sample
    loop_filter = (
        f"atrim=start_sample={repeat_sample}:end_sample={end_sample},"
        f"asetpts=PTS-STARTPTS,aloop=loop=-1:size={loop_size}{layout_filter}"
    )
    if start_sample == repeat_sample:
        return loop_filter
    intro_end_sample = repeat_sample if start_sample < repeat_sample else end_sample
    return (
        "asplit=2[intro_src][loop_src];"
        f"[intro_src]atrim=start_sample={start_sample}:end_sample={intro_end_sample},"
        f"asetpts=PTS-STARTPTS{layout_filter}[intro];"
        f"[loop_src]{loop_filter}[loop];"
        "[intro][loop]concat=n=2:v=0:a=1"
    )


@dataclass(frozen=True)
class _PreparedPlaybackInput:
    base_name: str
    play_path: str
    tmp_dir: str
    total_sample_cnt: int
    sample_rate: int
    channel_layout: str


def _prepare_playback_input(src_path: str) -> _PreparedPlaybackInput:
    base_name, ext = os.path.splitext(os.path.basename(src_path))
    ext = ext.lower()
    if ext in (".owp", ".ogg"):
        ogg = sound.decode_owp_to_ogg_bytes(src_path)
        sample_rate, pre_skip = sound._ogg_ident_info(ogg) or (44100, 0)
        total_sample_cnt = sound.ogg_calc_smp_cnt(ogg) - pre_skip
        if total_sample_cnt <= 0:
            raise RuntimeError("failed to determine audio sample count")
        tmp_dir = ""
        play_path = src_path
        if ext == ".owp":
            tmp_dir = tempfile.mkdtemp(prefix="siglus_ffplay_")
            try:
                play_path = os.path.join(tmp_dir, base_name + ".ogg")
                write_bytes(play_path, ogg)
            except Exception:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                raise
        return _PreparedPlaybackInput(
            base_name=base_name,
            play_path=play_path,
            tmp_dir=tmp_dir,
            total_sample_cnt=total_sample_cnt,
            sample_rate=sample_rate,
            channel_layout="",
        )
    if ext == ".nwa":
        with open_read(src_path) as f:
            data = f.read()
        pcm, header = sound.decode_nwa_to_pcm_bytes(data)
        bytes_per_sample = header.bits_per_sample // 8
        bytes_per_frame = header.channels * bytes_per_sample
        total_sample_cnt = len(pcm) // bytes_per_frame
        if total_sample_cnt <= 0:
            raise RuntimeError("failed to determine audio sample count")
        if header.samples_per_sec <= 0:
            raise RuntimeError("failed to determine audio sample rate")
        tmp_dir = tempfile.mkdtemp(prefix="siglus_ffplay_")
        try:
            play_path = os.path.join(tmp_dir, base_name + ".wav")
            write_bytes(
                play_path,
                sound._build_wav(
                    pcm,
                    header.channels,
                    header.bits_per_sample,
                    header.samples_per_sec,
                ),
            )
            return _PreparedPlaybackInput(
                base_name=base_name,
                play_path=play_path,
                tmp_dir=tmp_dir,
                total_sample_cnt=total_sample_cnt,
                sample_rate=int(header.samples_per_sec),
                channel_layout="mono" if header.channels == 1 else "stereo",
            )
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
    raise RuntimeError("unsupported file type (expected .nwa, .owp, or .ogg)")


@dataclass(frozen=True)
class _PlaybackEntry:
    path: str
    display_name: str
    base_name: str


@dataclass(frozen=True)
class _PlaybackPlan:
    entry: _PlaybackEntry
    bgm_name: str
    play_path: str
    tmp_dir: str
    start_sample: int
    end_sample: int
    repeat_sample: int
    sample_rate: int
    audio_filter: str


@dataclass
class _RunningPlayback:
    plan: _PlaybackPlan
    process: subprocess.Popen
    started_at: float
    paused: bool = False
    paused_at: float | None = None
    paused_total: float = 0.0


def _make_playback_entry(path: str, root: str = "") -> _PlaybackEntry:
    display_name = (
        os.path.relpath(path, root)
        if root and os.path.isdir(root)
        else os.path.basename(path)
    )
    base_name = os.path.splitext(os.path.basename(path))[0]
    return _PlaybackEntry(path=path, display_name=display_name, base_name=base_name)


def _format_player_time(seconds: float) -> str:
    total_seconds = int(seconds)
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _get_playback_elapsed_seconds(current: _RunningPlayback) -> float:
    end_time = time.monotonic()
    if current.paused and current.paused_at is not None:
        end_time = current.paused_at
    return max(end_time - current.started_at - current.paused_total, 0.0)


def _get_playback_position_sample(current: _RunningPlayback) -> tuple[int, str]:
    plan = current.plan
    elapsed_samples = int(_get_playback_elapsed_seconds(current) * plan.sample_rate)
    first_pass_len = plan.end_sample - plan.start_sample
    loop_len = plan.end_sample - plan.repeat_sample
    if elapsed_samples < first_pass_len:
        return plan.start_sample + elapsed_samples, "first"
    loop_elapsed = elapsed_samples - first_pass_len
    return plan.repeat_sample + (loop_elapsed % loop_len), "loop"


def _build_progress_bar(progress: float, width: int) -> str:
    progress = min(max(float(progress), 0.0), 1.0)
    filled = int(progress * width)
    if filled >= width:
        return "=" * width
    if filled <= 0:
        return ">" + "." * (width - 1)
    return "=" * filled + ">" + "." * (width - filled - 1)


def _collect_playback_entries(inp: str):
    src_is_dir = os.path.isdir(inp)
    if not src_is_dir:
        if missing_input_file(inp):
            return [], 1
        ext = os.path.splitext(inp)[1].lower()
        if ext not in (".nwa", ".owp", ".ogg"):
            eprint(
                "error: unsupported file type for --play (expected .nwa, .owp, or .ogg)"
            )
            return [], 1
        return [_make_playback_entry(inp)], None
    files, rc = collect_batch_files(
        inp,
        True,
        [".nwa", ".owp", ".ogg"],
        "no supported audio files found",
    )
    if rc is not None:
        return [], rc
    return [_make_playback_entry(path, inp) for path in files], None


def _filter_playback_entries(entries, trim_table):
    playable = []
    skipped = []
    for entry in entries:
        if windows_filename_key(entry.base_name) in trim_table:
            playable.append(entry)
            continue
        skipped.append(entry)
    return playable, skipped


def _format_playlist_help(has_playlist: bool) -> str:
    parts = ["pause/resume(p)", "stop(q)", "help(h)"]
    if has_playlist:
        parts = (
            parts[:1]
            + [
                "prev(b)",
                "next(n)",
                "list(l)",
                "play N",
                "page(u/d)",
                "top(gg)",
                "bottom(G)",
            ]
            + parts[1:]
        )
    return "commands: " + ", ".join(parts) + " (ASCII only)"


def _terminal_text_width(text: str) -> int:
    total = 0
    for ch in str(text or ""):
        if unicodedata.category(ch).startswith("M"):
            continue
        total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return total


def _terminal_text_cells(text: str) -> list[tuple[str, int]]:
    cells = []
    current = ""
    current_width = 0
    for ch in str(text or ""):
        if unicodedata.category(ch).startswith("M"):
            if current:
                current += ch
            continue
        if current:
            cells.append((current, current_width))
        current = ch
        current_width = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    if current:
        cells.append((current, current_width))
    return cells


def _fit_terminal_text(text: str, width: int) -> str:
    clean = str(text or "").replace("\r", " ").replace("\n", " ")
    cells = _terminal_text_cells(clean)
    if sum(cell_width for _, cell_width in cells) <= width:
        return clean
    limit = width - 1
    parts = []
    used = 0
    for part, part_width in cells:
        if used + part_width > limit:
            break
        parts.append(part)
        used += part_width
    return "".join(parts) + ">"


def _tail_terminal_text(text: str, width: int) -> str:
    clean = str(text or "").replace("\r", " ").replace("\n", " ")
    cells = _terminal_text_cells(clean)
    parts = []
    used = 0
    for part, part_width in reversed(cells):
        if used + part_width > width:
            break
        parts.append(part)
        used += part_width
    return "".join(reversed(parts))


def _parse_player_command(command: str, has_playlist: bool):
    text = str(command or "")
    if not text.isascii():
        raise ValueError("player commands accept ASCII characters only")
    text = text.strip()
    if not text:
        return "noop", None
    parts = text.split()
    raw_head = parts[0]
    head = raw_head.lower()
    if head in ("h", "help", "?"):
        return "help", None
    if head in ("p", "pause", "toggle"):
        return "toggle_pause", None
    if head in ("q", "quit", "exit", "stop", "s"):
        return "stop", None
    if not has_playlist:
        raise ValueError(f"unknown command: {text}")
    if head in ("n", "next"):
        return "next", None
    if head in ("b", "back", "prev", "previous"):
        return "prev", None
    if head in ("l", "list", "playlist"):
        return "list", None
    if head == "u":
        return "page_up", None
    if head == "d":
        return "page_down", None
    if head == "gg":
        return "top", None
    if raw_head == "G":
        return "bottom", None
    if head in ("play", "go", "goto", "jump"):
        if len(parts) != 2:
            raise ValueError("play expects exactly one playlist index")
        if not parts[1].isdecimal():
            raise ValueError("play expects a decimal playlist index")
        try:
            index = int(parts[1])
        except ValueError as exc:
            raise ValueError("play index is too large") from exc
        if index <= 0:
            raise ValueError("play index must be >= 1")
        return "play", index - 1
    raise ValueError(f"unknown command: {text}")


def _clamp_playlist_offset(total: int, offset: int, rows: int) -> int:
    max_offset = max(int(total) - rows, 0)
    return min(max(int(offset), 0), max_offset)


def _default_play_gameexe_path(inp: str) -> str:
    src_path = os.path.abspath(inp)
    audio_dir = src_path if os.path.isdir(src_path) else os.path.dirname(src_path)
    root_dir = os.path.dirname(audio_dir)
    exact = os.path.join(root_dir, "Gameexe.dat")
    try:
        exact_path = resolve_read_path(exact, kind="file")
    except (FileNotFoundError, NotADirectoryError):
        exact_path = ""
    wildcard_matches = []
    try:
        _, entries = read_directory(root_dir)
        for entry in entries:
            name = entry.name
            path = os.path.join(root_dir, name)
            if not os.path.isfile(path):
                continue
            if not windows_filename_key(name).startswith("gameexe"):
                continue
            if "." not in name:
                continue
            wildcard_matches.append(path)
    except OSError:
        return exact_path or exact
    validate_input_paths(wildcard_matches, warn_only=True)
    if exact_path:
        return exact_path
    if wildcard_matches:
        wildcard_matches.sort(
            key=lambda path: (
                windows_filename_key(os.path.basename(path)) != "gameexe.ini",
                os.path.splitext(path)[1].lower() != ".ini",
                os.path.splitext(path)[1].lower() != ".dat",
                windows_filename_key(os.path.basename(path)),
            )
        )
        return wildcard_matches[0]
    return exact


def _build_playback_plan(entry: _PlaybackEntry, trim_table) -> _PlaybackPlan:
    prepared = _prepare_playback_input(entry.path)
    try:
        bgm_entry = _resolve_bgm_entry(trim_table, prepared.base_name)
        start_pos = bgm_entry.start_sample
        end_pos = bgm_entry.end_sample
        rep_pos = bgm_entry.repeat_sample
        start_pos, end_pos, rep_pos = _normalize_playback_range(
            prepared.total_sample_cnt,
            start_sample=start_pos,
            end_sample=end_pos,
            repeat_sample=rep_pos,
        )
        return _PlaybackPlan(
            entry=entry,
            bgm_name=bgm_entry.name,
            play_path=prepared.play_path,
            tmp_dir=prepared.tmp_dir,
            start_sample=start_pos,
            end_sample=end_pos,
            repeat_sample=rep_pos,
            sample_rate=prepared.sample_rate,
            audio_filter=_build_ffplay_audio_filter(
                start_sample=start_pos,
                end_sample=end_pos,
                repeat_sample=rep_pos,
                channel_layout=prepared.channel_layout,
            ),
        )
    except Exception:
        if prepared.tmp_dir:
            shutil.rmtree(prepared.tmp_dir, ignore_errors=True)
        raise


def _start_playback_process(plan: _PlaybackPlan, ffplay_path: str) -> _RunningPlayback:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        [
            ffplay_path,
            "-hide_banner",
            "-loglevel",
            "error",
            "-nodisp",
            "-autoexit",
            "-i",
            plan.play_path,
            "-af",
            plan.audio_filter,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    return _RunningPlayback(plan=plan, process=process, started_at=time.monotonic())


def _control_process(process: subprocess.Popen, action: str) -> None:
    if process.poll() is not None:
        return
    try:
        proc = psutil.Process(int(process.pid))
        getattr(proc, action)()
    except psutil.NoSuchProcess:
        return


def _stop_running_playback(current: _RunningPlayback | None) -> None:
    if current is None:
        return
    try:
        if current.process.poll() is None:
            with suppress(Exception):
                current.process.terminate()
            with suppress(subprocess.TimeoutExpired):
                current.process.wait(timeout=1.0)
            if current.process.poll() is None:
                with suppress(Exception):
                    current.process.kill()
                with suppress(subprocess.TimeoutExpired):
                    current.process.wait(timeout=1.0)
    finally:
        if current.plan.tmp_dir:
            shutil.rmtree(current.plan.tmp_dir, ignore_errors=True)


def _switch_playback(
    entries,
    current_index: int,
    current: _RunningPlayback | None,
    trim_table,
    ffplay_path: str,
    reporter=eprint,
):
    if not ffplay_path:
        raise RuntimeError("ffplay not found in PATH")
    plan = _build_playback_plan(entries[current_index], trim_table)
    running = _start_playback_process(plan, ffplay_path)
    _stop_running_playback(current)
    reporter(
        f"play [{current_index + 1}/{len(entries)}] {plan.entry.display_name} #{plan.bgm_name}: start {plan.start_sample}, loop {plan.repeat_sample}..{plan.end_sample}"
    )
    return running


class _PlayerScreen:
    def __init__(self) -> None:
        self.enabled = bool(
            getattr(sys.stdin, "isatty", lambda: False)()
            and getattr(sys.stdout, "isatty", lambda: False)()
        )
        self.buffer = ""
        self.message = ""
        self.list_offset = 0
        self._last_frame = ""
        self._last_size = None
        self._stdin_fd = None
        self._term_state = None
        self._stream = sys.stdout

    def __enter__(self):
        if not self.enabled:
            return self
        if os.name != "nt":
            try:
                import termios
                import tty

                self._stdin_fd = sys.stdin.fileno()
                self._term_state = termios.tcgetattr(self._stdin_fd)
                tty.setraw(self._stdin_fd)
            except Exception as exc:
                raise RuntimeError(
                    "interactive --play requires raw terminal input"
                ) from exc
        self._stream.write("\x1b[?1049h\x1b[2J\x1b[H")
        self._stream.flush()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        if not self.enabled:
            return
        if self._term_state is not None and self._stdin_fd is not None:
            with suppress(Exception):
                import termios

                termios.tcsetattr(self._stdin_fd, termios.TCSADRAIN, self._term_state)
        self._stream.write("\x1b[?1049l")
        self._stream.flush()

    def set_message(self, message: str) -> None:
        self.message = str(message or "")

    def _get_size(self) -> tuple[int, int]:
        size = shutil.get_terminal_size(fallback=(120, 30))
        return max(int(size.columns), 40), max(int(size.lines), 12)

    def _compose_lines(self, lines) -> str:
        return "\x1b[K\r\n".join(lines) + "\x1b[K"

    def _playlist_window(self, total: int, rows: int) -> tuple[int, int]:
        start = _clamp_playlist_offset(total, self.list_offset, rows)
        end = min(start + rows, total)
        return start, end

    def _playlist_entry_rows(self) -> int:
        return max(int(shutil.get_terminal_size(fallback=(120, 30)).lines) - 8, 1)

    def focus_current(self, total: int, current_index: int) -> None:
        rows = self._playlist_entry_rows()
        self.list_offset = _clamp_playlist_offset(
            total, current_index - rows // 2, rows
        )

    def scroll_lines(self, total: int, delta: int) -> None:
        self.list_offset = _clamp_playlist_offset(
            total,
            self.list_offset + delta,
            self._playlist_entry_rows(),
        )

    def scroll_pages(self, total: int, delta: int) -> None:
        step = max(self._playlist_entry_rows() - 1, 1)
        self.scroll_lines(total, delta * step)

    def scroll_to_top(self) -> None:
        self.list_offset = 0

    def scroll_to_bottom(self, total: int) -> None:
        self.list_offset = _clamp_playlist_offset(
            total,
            total,
            self._playlist_entry_rows(),
        )

    def _build_playlist_lines(
        self,
        entries,
        current_index: int,
        paused: bool,
        rows: int,
        width: int,
    ) -> tuple[str, list[str]]:
        total = len(entries)
        start, end = self._playlist_window(total, rows)
        header = f"playlist {start + 1}-{end}/{total}"
        lines = []
        for index in range(start, end):
            marker = "  "
            if index == current_index:
                marker = "||" if paused else ">>"
            text = f"{marker} {index + 1:>3}. {entries[index].display_name}"
            lines.append(_fit_terminal_text(text, width))
        return header, lines

    def _prompt_line(self, width: int) -> tuple[str, int]:
        prefix = "player> "
        prefix_width = _terminal_text_width(prefix)
        visible = width - prefix_width
        if _terminal_text_width(self.buffer) <= visible:
            line = prefix + self.buffer
            col = min(prefix_width + _terminal_text_width(self.buffer) + 1, width)
            return line, col
        line = prefix + _tail_terminal_text(self.buffer, visible)
        return line, width

    def _prompt_cursor(self, row: int, col: int) -> str:
        return f"\x1b[{row};{col}H"

    def _read_windows_char(self):
        import msvcrt

        deadline = time.monotonic() + 0.1
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    with suppress(Exception):
                        msvcrt.getwch()
                    return None
                return ch
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.01)

    def _read_posix_char(self):
        import select

        ready, _, _ = select.select([self._stdin_fd], [], [], 0.1)
        if not ready:
            return None
        data = os.read(self._stdin_fd, 1)
        if not data:
            return "\x04"
        text = data.decode("ascii", "replace")
        if text != "\x1b":
            return text
        deadline = time.monotonic() + 0.02
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self._stdin_fd], [], [], 0.005)
            if not ready:
                break
            chunk = os.read(self._stdin_fd, 1)
            if not chunk:
                break
        return None

    def _read_char(self):
        if os.name == "nt":
            return self._read_windows_char()
        return self._read_posix_char()

    def read_event(self):
        ch = self._read_char()
        if ch is None:
            return None
        if ch in ("\r", "\n"):
            text = self.buffer
            self.buffer = ""
            return "command", text
        if ch == "\x03":
            return "interrupt", None
        if ch == "\x04":
            if not self.buffer:
                return "stop", None
            return None
        if ch in ("\b", "\x7f"):
            if self.buffer:
                self.buffer = self.buffer[:-1]
            return "edit", None
        if ch == "\t":
            self.buffer += " "
            return "edit", None
        if ch >= " ":
            self.buffer += ch
            return "edit", None
        return None

    def render(
        self,
        entries,
        current_index: int,
        current: _RunningPlayback | None,
    ) -> None:
        width, height = self._get_size()
        lines = []
        paused = bool(current and current.paused)
        if current is not None:
            resource_path = os.path.abspath(current.plan.entry.path)
        else:
            resource_path = os.path.abspath(entries[current_index].path)
        lines.append(_fit_terminal_text(resource_path, width))
        if current is None:
            lines.append(_fit_terminal_text("state stopped", width))
            lines.append(_fit_terminal_text("[>.......] 00:00/00:00", width))
        else:
            plan = current.plan
            position_sample, phase = _get_playback_position_sample(current)
            position_sec = position_sample / float(plan.sample_rate)
            end_sec = plan.end_sample / float(plan.sample_rate)
            progress = position_sample / float(plan.end_sample)
            if current.paused:
                state_text = "paused"
            elif phase == "first":
                state_text = "first-pass"
            else:
                state_text = phase
            bar_width = min(width - 24, 60)
            lines.append(
                _fit_terminal_text(
                    f"bgm {plan.bgm_name}  state {state_text}  start {_format_player_time(plan.start_sample / plan.sample_rate)}  loop {_format_player_time(plan.repeat_sample / plan.sample_rate)}  end {_format_player_time(end_sec)}",
                    width,
                )
            )
            lines.append(
                _fit_terminal_text(
                    f"[{_build_progress_bar(progress, bar_width)}] {_format_player_time(position_sec)}/{_format_player_time(end_sec)}",
                    width,
                )
            )
        lines.append(_fit_terminal_text(_format_playlist_help(len(entries) > 1), width))
        footer_rows = 2
        playlist_rows = height - len(lines) - footer_rows
        playlist_header, playlist_lines = self._build_playlist_lines(
            entries,
            current_index,
            paused,
            playlist_rows - 1,
            width,
        )
        lines.append(_fit_terminal_text(playlist_header, width))
        lines.extend(playlist_lines)
        while len(lines) < height - footer_rows:
            lines.append("")
        lines.append(_fit_terminal_text(self.message, width))
        prompt_line, prompt_col = self._prompt_line(width)
        lines.append(_fit_terminal_text(prompt_line, width))
        size = (width, height)
        frame = (
            ("\x1b[2J\x1b[H" if size != self._last_size else "\x1b[H")
            + self._compose_lines(lines)
            + "\x1b[J"
            + self._prompt_cursor(height, prompt_col)
        )
        if frame == self._last_frame:
            return
        self._stream.write(frame)
        self._stream.flush()
        self._last_frame = frame
        self._last_size = size


def _handle_player_action(
    action: str,
    value,
    entries,
    current_index: int,
    current: _RunningPlayback,
    trim_table,
    ffplay_path: str,
    reporter,
    list_handler,
    view_handler,
):
    if action == "noop":
        return current_index, current, None
    if action == "help":
        reporter(_format_playlist_help(len(entries) > 1))
        return current_index, current, None
    if action == "list":
        list_handler(entries, current_index)
        return current_index, current, None
    if action in ("page_up", "page_down", "top", "bottom"):
        view_handler(action, entries)
        return current_index, current, None
    if action == "toggle_pause":
        if current.paused:
            _control_process(current.process, "resume")
            if current.paused_at is not None:
                current.paused_total += max(time.monotonic() - current.paused_at, 0.0)
            current.paused = False
            current.paused_at = None
            reporter(
                f"resumed [{current_index + 1}/{len(entries)}] {current.plan.entry.display_name}"
            )
            return current_index, current, None
        _control_process(current.process, "suspend")
        current.paused = True
        current.paused_at = time.monotonic()
        reporter(
            f"paused [{current_index + 1}/{len(entries)}] {current.plan.entry.display_name}"
        )
        return current_index, current, None
    if action == "stop":
        reporter("playback stopped")
        return current_index, current, 0
    if action == "prev":
        if current_index == 0:
            reporter("already at the first track")
            return current_index, current, None
        current_index -= 1
        current = _switch_playback(
            entries,
            current_index,
            current,
            trim_table,
            ffplay_path,
            reporter=reporter,
        )
        return current_index, current, None
    if action == "next":
        if current_index + 1 >= len(entries):
            reporter("already at the last track")
            return current_index, current, None
        current_index += 1
        current = _switch_playback(
            entries,
            current_index,
            current,
            trim_table,
            ffplay_path,
            reporter=reporter,
        )
        return current_index, current, None
    if value >= len(entries):
        reporter(f"playlist index out of range: {value + 1}")
        return current_index, current, None
    current_index = value
    current = _switch_playback(
        entries,
        current_index,
        current,
        trim_table,
        ffplay_path,
        reporter=reporter,
    )
    return current_index, current, None


def _run_interactive_player(entries, trim_table, ffplay_path: str) -> int:
    with _PlayerScreen() as screen:
        if not screen.enabled:
            raise RuntimeError("interactive --play requires a TTY terminal")
        current_index = 0
        current = None
        has_playlist = len(entries) > 1
        screen.focus_current(len(entries), current_index)
        screen.set_message(_format_playlist_help(has_playlist))

        def _screen_list(items, index):
            screen.focus_current(len(items), index)
            screen.set_message(f"playlist {index + 1}/{len(items)} visible")

        def _screen_view(action_name, items):
            if action_name == "page_up":
                screen.scroll_pages(len(items), -1)
                return
            if action_name == "page_down":
                screen.scroll_pages(len(items), 1)
                return
            if action_name == "top":
                screen.scroll_to_top()
                return
            screen.scroll_to_bottom(len(items))

        try:
            current = _switch_playback(
                entries,
                current_index,
                current,
                trim_table,
                ffplay_path,
                reporter=screen.set_message,
            )
            while True:
                if current.process.poll() is not None:
                    raise RuntimeError(
                        f"ffplay exited unexpectedly with code {current.process.returncode}"
                    )
                screen.render(entries, current_index, current)
                event = screen.read_event()
                if event is None:
                    continue
                kind, payload = event
                if kind == "edit":
                    continue
                if kind == "interrupt":
                    screen.set_message("playback stopped")
                    screen.render(entries, current_index, current)
                    return 0
                if kind == "stop":
                    screen.set_message("playback stopped")
                    screen.render(entries, current_index, current)
                    return 0
                try:
                    old_index = current_index
                    action, value = _parse_player_command(payload, has_playlist)
                    current_index, current, exit_code = _handle_player_action(
                        action,
                        value,
                        entries,
                        current_index,
                        current,
                        trim_table,
                        ffplay_path,
                        screen.set_message,
                        _screen_list,
                        _screen_view,
                    )
                    if current_index != old_index:
                        screen.focus_current(len(entries), current_index)
                    if exit_code is not None:
                        screen.render(entries, current_index, current)
                        return exit_code
                except Exception as exc:
                    screen.set_message(f"error: {exc}")
        except KeyboardInterrupt:
            screen.set_message("playback stopped")
            screen.render(entries, current_index, current)
            return 0
        finally:
            _stop_running_playback(current)


def _extract_one(src_path, outputs, entries, trim_table, ffmpeg_path, tmp_dir):
    if entries is not None:
        for out_path, (_, ogg) in zip(
            outputs, sound.iter_ovk_entries(src_path, entries), strict=True
        ):
            with open_atomic_output(out_path) as output:
                output.write(ogg)
        return len(outputs)

    base_name, ext = os.path.splitext(os.path.basename(src_path))
    if trim_table is not None:
        bgm = _resolve_bgm_entry(trim_table, base_name)
        end = bgm.end_sample
        repeat = bgm.repeat_sample
        eprint(
            f"trim {base_name} #{bgm.name}: samples {repeat}..{end if end != -1 else 'EOF'}"
        )
    if ext.lower() == ".owp":
        data = sound.decode_owp_to_ogg_bytes(src_path)
        if trim_table is not None:
            data = _ffmpeg_trim_ogg_bytes(
                data,
                start_sample=repeat,
                end_sample=end,
                ffmpeg_path=ffmpeg_path,
                tmp_dir=tmp_dir,
            )
    elif trim_table is not None:
        data = _trim_nwa_to_wav_bytes(
            read_bytes(src_path), start_sample=repeat, end_sample=end
        )
    else:
        data = sound.decode_nwa_to_wav_bytes(src_path)
    with open_atomic_output(outputs[0]) as output:
        output.write(data)
    return 1


def main(argv) -> int:
    try:
        argv, explicit_angou = consume_angou_option(argv)
    except ValueError as exc:
        eprint(str(exc))
        return 2
    mode, argv, rc = parse_main_argv(
        argv, _hint_help, flags=("--x", "--a", "--c", "--play")
    )
    if rc is not None:
        return rc
    argv, positional_args = split_end_of_options(argv)
    if mode == "a":
        if "--trim" in argv:
            eprint("error: --trim is only valid with --x")
            return 2
        unknown_option = first_option_token(argv)
        if unknown_option is not None:
            eprint(f"error: unknown option: {unknown_option}")
            return 2
        if positional_args is not None:
            argv.extend(positional_args)
        if len(argv) == 1:
            try:
                inp = resolve_read_path(argv[0], kind="file")
            except (FileNotFoundError, NotADirectoryError):
                eprint(f"input not found: {argv[0]}")
                return 1
            return _analyze_one(inp)
        if len(argv) == 2:
            try:
                p1 = resolve_read_path(argv[0], kind="file")
                p2 = resolve_read_path(argv[1], kind="file")
            except (FileNotFoundError, NotADirectoryError):
                eprint("input not found")
                return 1
            validate_input_paths([p1, p2], allow_same_file=True)
            return _compare_ovk(p1, p2)
        eprint("error: expected 1 input file, or 2 .ovk files, for --a")
        _hint_help()
        return 2
    if mode == "c":
        if "--trim" in argv:
            eprint("error: --trim is only valid with --x")
            return 2
        unknown_option = first_option_token(argv)
        if unknown_option is not None:
            eprint(f"error: unknown option: {unknown_option}")
            return 2
        if positional_args is not None:
            argv.extend(positional_args)
        inp, out_root, src_is_dir, rc = prepare_batch_paths(
            argv, _hint_help, "error: expected <input> <output_dir> for --c"
        )
        if rc is not None:
            return rc
        files, rc = collect_batch_files(
            inp, src_is_dir, [".ogg"], "no supported audio files found"
        )
        if rc is not None:
            return rc
        tasks = []
        groups = {}
        suffix_re = re.compile(r"^(?P<base>.+)_(?P<no>-?\d+)$")
        for src_path in files:
            rel_dir = (
                os.path.dirname(os.path.relpath(src_path, inp)) if src_is_dir else ""
            )
            base = os.path.splitext(os.path.basename(src_path))[0]
            match = suffix_re.fullmatch(base) if src_is_dir else None
            if match is None:
                tasks.append(
                    (os.path.join(out_root, rel_dir, base + ".owp"), [(0, src_path)])
                )
            else:
                group = (rel_dir, match.group("base"))
                groups.setdefault(group, []).append((int(match.group("no")), src_path))
        for (rel_dir, base), items in sorted(groups.items()):
            if len(items) > 1:
                tasks.append((os.path.join(out_root, rel_dir, base + ".ovk"), items))
            else:
                source = items[0][1]
                stem = os.path.splitext(os.path.basename(source))[0]
                tasks.append((os.path.join(out_root, rel_dir, stem + ".owp"), items))

        try:
            check_output_inputs((out for out, _ in tasks), files, distinct=True)
        except (OSError, ValueError) as exc:
            eprint(f"audio output: {exc}")
            return 1

        def _proc(task):
            out_path, items = task
            if len(items) == 1:
                data = sound.encode_ogg_to_owp_bytes(read_bytes(items[0][1]))
            else:
                data = sound.encode_oggs_to_ovk_bytes(
                    [
                        (no, read_bytes(path))
                        for no, path in sorted(items, key=lambda item: item[0])
                    ]
                )
            with open_atomic_output(out_path) as output:
                output.write(data)
            return 1, out_path

        return run_batch(tasks, _proc, item_name_fn=lambda task: task[0])
    if mode == "play":
        unknown_option = first_option_token(argv)
        if unknown_option is not None:
            eprint(f"error: unknown option: {unknown_option}")
            return 2
        if positional_args is not None:
            argv.extend(positional_args)
        if len(argv) not in (1, 2):
            eprint(
                "error: expected <input_file|input_dir> [Gameexe.dat|Gameexe.ini] for --play"
            )
            _hint_help()
            return 2
        if psutil is None:
            eprint("error: need psutil: pip install psutil")
            return 1
        try:
            inp = resolve_read_path(argv[0])
        except (FileNotFoundError, NotADirectoryError):
            eprint(f"input not found: {argv[0]}")
            return 1
        trim_path = (
            argv[1] if len(argv) == 2 and argv[1] else _default_play_gameexe_path(inp)
        )
        try:
            trim_path = resolve_read_path(trim_path, kind="file")
        except (FileNotFoundError, NotADirectoryError):
            eprint(f"Gameexe source not found: {trim_path}")
            return 1
        ffplay_path = shutil.which("ffplay") or ""
        trim_table, rc = _load_bgm_table(trim_path, explicit_angou)
        if rc is not None:
            return rc
        entries, rc = _collect_playback_entries(inp)
        if rc is not None:
            return rc
        entries, skipped = _filter_playback_entries(entries, trim_table)
        for entry in skipped:
            eprint(
                f"skip {entry.display_name}: no #BGM.* entry for file name: {entry.base_name}"
            )
        if not entries:
            eprint("error: no playable audio files matched #BGM.* entries")
            return 1
        try:
            return _run_interactive_player(
                entries,
                trim_table=trim_table,
                ffplay_path=ffplay_path,
            )
        except Exception as exc:
            eprint(f"error: {exc}")
            return 1
    trim_path = ""
    if "--trim" in argv:
        if argv.count("--trim") != 1:
            eprint("error: --trim specified more than once")
            _hint_help()
            return 2
        i = argv.index("--trim")
        if i + 1 >= len(argv) or is_option_token(argv[i + 1]):
            eprint("error: --trim expects a path")
            _hint_help()
            return 2
        trim_path = argv[i + 1]
        del argv[i : i + 2]
    unknown_option = first_option_token(argv)
    if unknown_option is not None:
        eprint(f"error: unknown option: {unknown_option}")
        _hint_help()
        return 2
    if positional_args is not None:
        argv.extend(positional_args)
    inp, out_root, src_is_dir, rc = prepare_batch_paths(
        argv,
        _hint_help,
        "error: expected <input> <output_dir> for --x",
        create_output=False,
    )
    if rc is not None:
        return rc
    trim_table = None
    ffmpeg_path = ""
    tmp_dir = ""
    needs_ffmpeg = False
    inputs = set()
    files, rc = collect_batch_files(
        inp, src_is_dir, [".owp", ".nwa", ".ovk"], "no supported audio files found"
    )
    if rc is not None:
        return rc
    if trim_path:
        try:
            trim_path = resolve_read_path(trim_path, kind="file")
        except (FileNotFoundError, NotADirectoryError):
            eprint(f"Gameexe.dat not found: {trim_path}")
            return 1
        inputs.add(trim_path)
        trim_table, rc = _load_bgm_table(trim_path, explicit_angou, read_paths=inputs)
        if rc is not None:
            return rc
        needs_ffmpeg = any(
            os.path.splitext(path)[1].lower() == ".owp" for path in files
        )
        if needs_ffmpeg:
            ffmpeg_path = shutil.which("ffmpeg") or ""
            if not ffmpeg_path:
                eprint("ffmpeg not found in PATH")
                return 1
    inputs.update(files)
    tasks = []
    try:
        for src_path in files:
            rel_dir = (
                os.path.dirname(os.path.relpath(src_path, inp)) if src_is_dir else ""
            )
            out_dir = os.path.join(out_root, rel_dir)
            stem, ext = os.path.splitext(os.path.basename(src_path))
            ext = ext.lower()
            entries = sound.read_ovk_table(src_path) if ext == ".ovk" else None
            if entries is None:
                suffix = ".wav" if ext == ".nwa" else ".ogg"
                outputs = [os.path.join(out_dir, stem + suffix)]
            elif len(entries) == 1:
                outputs = [os.path.join(out_dir, stem + ".ogg")]
            else:
                outputs = [
                    os.path.join(out_dir, f"{stem}_{entry.entry_no}.ogg")
                    for entry in entries
                ]
            tasks.append((src_path, outputs, entries))
        check_output_inputs(
            (target for _, outputs, _ in tasks for target in outputs),
            inputs,
            distinct=True,
        )
    except (OSError, ValueError, EOFError) as exc:
        eprint(f"audio output: {exc}")
        return 1

    if needs_ffmpeg:
        os.makedirs(out_root, exist_ok=True)
        try:
            tmp_dir = tempfile.mkdtemp(prefix=".tmp_ffmpeg_", dir=out_root)
        except OSError:
            tmp_dir = tempfile.mkdtemp(prefix="siglus_ffmpeg_")

    def _proc(task):
        src_path, outputs, entries = task
        n = _extract_one(src_path, outputs, entries, trim_table, ffmpeg_path, tmp_dir)
        return n, outputs[0] if len(outputs) == 1 else f"{n} files for {src_path}"

    try:
        exit_code = run_batch(tasks, _proc, item_name_fn=lambda task: task[0])
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    return exit_code
