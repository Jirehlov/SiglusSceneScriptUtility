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
    ANGOU_DAT_NAME,
    collect_batch_files,
    eprint,
    hint_help as _hint_help,
    fmt_kv as _fmt_kv,
    parse_main_argv,
    prepare_batch_paths,
    write_bytes,
    missing_input_file,
    read_text_auto,
    run_batch,
)
from . import sound
from . import GEI
from . import pck


def _cleanup_tmp_dir(tmp_dir: str, out_root: str, remove_owned: bool = False) -> None:
    if not tmp_dir:
        return
    if not os.path.isdir(tmp_dir):
        return
    if remove_owned:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return
    if os.path.basename(tmp_dir) != ".tmp_ffmpeg":
        return
    out_abs = os.path.abspath(out_root)
    tmp_abs = os.path.abspath(tmp_dir)
    if tmp_abs == os.path.join(out_abs, ".tmp_ffmpeg") or tmp_abs.startswith(
        out_abs + os.sep
    ):
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _analyze_one(path: str) -> int:
    ext = os.path.splitext(path)[1].lower()
    try:
        st = os.stat(path)
        size = st.st_size
    except OSError:
        size = "?"
    print(_fmt_kv("path", path))
    print(_fmt_kv("type", ext.lstrip(".") or "unknown"))
    print(_fmt_kv("size_bytes", size))
    if ext == ".nwa":
        with open(path, "rb") as f:
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
        dur = sample_cnt / float(samples_per_sec) if samples_per_sec else None
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
            print(_fmt_kv(f"entry[{i}].smp_cnt", int(smp_cnt_)))
        return 0
    if ext == ".owp":
        try:
            with open(path, "rb") as f:
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
        table.setdefault(fn.lower(), []).append(
            _BgmLoopEntry(
                name=name,
                start_sample=start,
                end_sample=end,
                repeat_sample=rep,
            )
        )
    return table


def _load_gameexe_ini_text(gameexe_path: str) -> str:
    ext = os.path.splitext(gameexe_path)[1].lower()
    if ext == ".ini":
        return read_text_auto(gameexe_path)
    os_dir = os.path.dirname(os.path.abspath(gameexe_path))
    cands = list(pck.iter_exe_el_candidates(os_dir))
    if not cands:
        cands = [b""]
    last_err = None
    for exe_el in cands:
        try:
            info, txt = GEI.read_gameexe_dat(gameexe_path, exe_el=exe_el)
            if info.get("mode") and not info.get("used_exe_el"):
                raise RuntimeError(
                    f"Gameexe.dat is encrypted with exe angou; missing {ANGOU_DAT_NAME}/key.txt to derive key"
                )
            if not txt:
                raise RuntimeError("Failed to decode Gameexe.dat payload")
            return txt
        except Exception as exc:
            last_err = exc
    if last_err is not None:
        raise last_err
    raise RuntimeError("Failed to decode Gameexe.dat payload")


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
        with suppress(OSError):
            os.remove(in_path)
        with suppress(OSError):
            os.remove(out_path)


def _resolve_bgm_entry(trim_table, base_name: str):
    key = base_name.lower()
    if key not in trim_table:
        raise RuntimeError(f"no #BGM.* entry for file name: {base_name}")
    candidates = list(trim_table[key] or [])
    if not candidates:
        raise RuntimeError(f"no #BGM.* entry for file name: {base_name}")
    for candidate in candidates:
        if candidate.name.lower() == key:
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
    if loop_size <= 0:
        raise RuntimeError("invalid loop size")
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


def _channel_layout_for_channels(channels: int) -> str:
    if channels == 1:
        return "mono"
    if channels == 2:
        return "stereo"
    return ""


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
        total_sample_cnt = sound.ogg_calc_smp_cnt(ogg)
        if total_sample_cnt <= 0:
            raise RuntimeError("failed to determine audio sample count")
        tmp_dir = ""
        play_path = src_path
        if ext == ".owp":
            tmp_dir = tempfile.mkdtemp(prefix="siglus_ffplay_")
            play_path = os.path.join(tmp_dir, base_name + ".ogg")
            write_bytes(play_path, ogg)
        return _PreparedPlaybackInput(
            base_name=base_name,
            play_path=play_path,
            tmp_dir=tmp_dir,
            total_sample_cnt=total_sample_cnt,
            sample_rate=_get_ogg_sample_rate(ogg, total_sample_cnt),
            channel_layout="",
        )
    if ext == ".nwa":
        with open(src_path, "rb") as f:
            data = f.read()
        pcm, header = sound.decode_nwa_to_pcm_bytes(data)
        bytes_per_sample = header.bits_per_sample // 8
        bytes_per_frame = header.channels * bytes_per_sample
        total_sample_cnt = len(pcm) // bytes_per_frame if bytes_per_frame > 0 else 0
        if total_sample_cnt <= 0:
            raise RuntimeError("failed to determine audio sample count")
        if header.samples_per_sec <= 0:
            raise RuntimeError("failed to determine audio sample rate")
        tmp_dir = tempfile.mkdtemp(prefix="siglus_ffplay_")
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
            channel_layout=_channel_layout_for_channels(int(header.channels)),
        )
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


def _ensure_ffplay_available(ffplay_path: str) -> None:
    if not ffplay_path:
        raise RuntimeError("ffplay not found in PATH")


def _make_playback_entry(path: str, root: str = "") -> _PlaybackEntry:
    display_name = (
        os.path.relpath(path, root)
        if root and os.path.isdir(root)
        else os.path.basename(path)
    )
    base_name = os.path.splitext(os.path.basename(path))[0]
    return _PlaybackEntry(path=path, display_name=display_name, base_name=base_name)


def _get_ogg_sample_rate(ogg_bytes: bytes, total_sample_cnt: int = 0) -> int:
    ident_info = getattr(sound, "_ogg_ident_info", None)
    if callable(ident_info):
        info = ident_info(ogg_bytes)
        if info is not None:
            _codec, sample_rate, _pre_skip = info
            if sample_rate > 0:
                return int(sample_rate)
    if total_sample_cnt <= 0:
        total_sample_cnt = sound.ogg_calc_smp_cnt(ogg_bytes)
    duration = sound.estimate_ogg_duration_seconds(ogg_bytes)
    if duration and duration > 0 and total_sample_cnt > 0:
        sample_rate = int(round(total_sample_cnt / duration))
        if sample_rate > 0:
            return sample_rate
    return 44100


def _format_player_time(seconds: float) -> str:
    total_seconds = max(int(seconds), 0)
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _get_playback_elapsed_seconds(
    current: _RunningPlayback,
    now: float | None = None,
) -> float:
    current_time = time.monotonic() if now is None else now
    end_time = current_time
    if current.paused and current.paused_at is not None:
        end_time = current.paused_at
    return max(end_time - current.started_at - current.paused_total, 0.0)


def _get_playback_position_sample(
    current: _RunningPlayback,
    now: float | None = None,
) -> tuple[int, str]:
    plan = current.plan
    sample_rate = max(int(plan.sample_rate), 1)
    elapsed_samples = int(_get_playback_elapsed_seconds(current, now) * sample_rate)
    first_pass_len = max(plan.end_sample - plan.start_sample, 1)
    loop_len = max(plan.end_sample - plan.repeat_sample, 1)
    if elapsed_samples < first_pass_len:
        return min(plan.start_sample + elapsed_samples, plan.end_sample), "first"
    loop_elapsed = max(elapsed_samples - first_pass_len, 0)
    return plan.repeat_sample + (loop_elapsed % loop_len), "loop"


def _build_progress_bar(progress: float, width: int) -> str:
    width = max(int(width), 8)
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
        if entry.base_name.lower() in trim_table:
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
    return "commands: " + ", ".join(parts)


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
    width = max(int(width), 1)
    cells = _terminal_text_cells(clean)
    if sum(cell_width for _, cell_width in cells) <= width:
        return clean
    if width <= 1:
        return ">"
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
    width = max(int(width), 0)
    if width <= 0:
        return ""
    cells = _terminal_text_cells(clean)
    if sum(cell_width for _, cell_width in cells) <= width:
        return clean
    parts = []
    used = 0
    for part, part_width in reversed(cells):
        if used + part_width > width:
            break
        parts.append(part)
        used += part_width
    return "".join(reversed(parts))


def _parse_player_command(command: str, has_playlist: bool):
    text = str(command or "").strip()
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
        try:
            index = int(parts[1])
        except ValueError as exc:
            raise ValueError("play expects an integer playlist index") from exc
        if index <= 0:
            raise ValueError("play index must be >= 1")
        return "play", index - 1
    raise ValueError(f"unknown command: {text}")


def _get_playlist_page_size() -> int:
    return max(int(shutil.get_terminal_size(fallback=(120, 30)).lines) - 8, 1)


def _clamp_playlist_offset(total: int, offset: int, rows: int) -> int:
    rows = max(int(rows), 1)
    max_offset = max(int(total) - rows, 0)
    return min(max(int(offset), 0), max_offset)


def _center_playlist_offset(total: int, current_index: int, rows: int) -> int:
    return _clamp_playlist_offset(total, current_index - rows // 2, rows)


def _default_play_gameexe_path(inp: str) -> str:
    src_path = os.path.abspath(inp)
    audio_dir = src_path if os.path.isdir(src_path) else os.path.dirname(src_path)
    root_dir = os.path.dirname(audio_dir)
    exact = os.path.join(root_dir, "Gameexe.dat")
    if os.path.isfile(exact):
        return exact
    wildcard_matches = []
    try:
        for name in os.listdir(root_dir):
            path = os.path.join(root_dir, name)
            if not os.path.isfile(path):
                continue
            if not name.lower().startswith("gameexe"):
                continue
            if "." not in name:
                continue
            wildcard_matches.append(path)
    except OSError:
        return exact
    if wildcard_matches:
        wildcard_matches.sort(
            key=lambda path: (
                os.path.basename(path).lower() != "gameexe.ini",
                os.path.splitext(path)[1].lower() != ".ini",
                os.path.splitext(path)[1].lower() != ".dat",
                os.path.basename(path).lower(),
            )
        )
        return wildcard_matches[0]
    return exact


def _resolve_play_gameexe_path(inp: str, trim_path: str = "") -> str:
    if trim_path:
        return trim_path
    return _default_play_gameexe_path(inp)


def _build_playback_plan(entry: _PlaybackEntry, trim_table) -> _PlaybackPlan:
    prepared = _prepare_playback_input(entry.path)
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


def _pause_process(process: subprocess.Popen) -> None:
    _control_process(process, "suspend")


def _resume_process(process: subprocess.Popen) -> None:
    _control_process(process, "resume")


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


def _spawn_running_playback(
    entry: _PlaybackEntry,
    trim_table,
    ffplay_path: str,
) -> _RunningPlayback:
    _ensure_ffplay_available(ffplay_path)
    plan = _build_playback_plan(entry, trim_table)
    return _start_playback_process(plan, ffplay_path)


def _switch_playback(
    entries,
    current_index: int,
    current: _RunningPlayback | None,
    trim_table,
    ffplay_path: str,
    reporter=eprint,
):
    running = _spawn_running_playback(entries[current_index], trim_table, ffplay_path)
    old = current
    current = running
    _stop_running_playback(old)
    plan = current.plan
    reporter(
        f"play [{current_index + 1}/{len(entries)}] {plan.entry.display_name} #{plan.bgm_name}: start {plan.start_sample}, loop {plan.repeat_sample}..{plan.end_sample}"
    )
    return current


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
            except Exception:
                raise RuntimeError("interactive --play requires raw terminal input")
        self._stream.write("\x1b[?1049h\x1b[2J\x1b[H")
        self._stream.flush()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self.enabled:
            return
        if self._term_state is not None and self._stdin_fd is not None:
            with suppress(Exception):
                import termios

                termios.tcsetattr(self._stdin_fd, termios.TCSADRAIN, self._term_state)
        self._last_frame = ""
        self._last_size = None
        self._stream.write("\x1b[?1049l")
        self._stream.flush()

    def set_message(self, message: str) -> None:
        self.message = str(message or "")

    def _get_size(self) -> tuple[int, int]:
        size = shutil.get_terminal_size(fallback=(120, 30))
        return max(int(size.columns), 40), max(int(size.lines), 12)

    def _fit(self, text: str, width: int) -> str:
        return _fit_terminal_text(text, width)

    def _compose_lines(self, lines) -> str:
        return "\x1b[K\r\n".join(lines) + "\x1b[K"

    def _playlist_window(self, total: int, rows: int) -> tuple[int, int]:
        rows = max(rows, 1)
        start = _clamp_playlist_offset(total, self.list_offset, rows)
        end = min(start + rows, total)
        return start, end

    def _playlist_entry_rows(self) -> int:
        return _get_playlist_page_size()

    def focus_current(self, total: int, current_index: int) -> None:
        self.list_offset = _center_playlist_offset(
            total,
            current_index,
            self._playlist_entry_rows(),
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
        if total <= 0 or rows <= 0:
            return "playlist 0/0", []
        start, end = self._playlist_window(total, rows)
        header = f"playlist {start + 1}-{end}/{total}"
        lines = []
        for index in range(start, end):
            marker = "  "
            if index == current_index:
                marker = "||" if paused else ">>"
            text = f"{marker} {index + 1:>3}. {entries[index].display_name}"
            lines.append(self._fit(text, width))
        return header, lines

    def _prompt_line(self, width: int) -> tuple[str, int]:
        prefix = "player> "
        prefix_width = _terminal_text_width(prefix)
        visible = width - prefix_width
        if visible <= 0:
            line = _fit_terminal_text(prefix, width)
            return line, max(min(_terminal_text_width(line), width), 1)
        if _terminal_text_width(self.buffer) <= visible:
            line = prefix + self.buffer
            col = min(prefix_width + _terminal_text_width(self.buffer) + 1, width)
            return line, max(col, 1)
        line = prefix + _tail_terminal_text(self.buffer, visible)
        return line, width

    def _prompt_cursor(self, row: int, col: int) -> str:
        return f"\x1b[{max(row, 1)};{max(col, 1)}H"

    def _read_windows_char(self, timeout: float):
        import msvcrt

        deadline = time.monotonic() + max(timeout, 0.0)
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

    def _read_posix_char(self, timeout: float):
        import select

        if self._stdin_fd is None:
            return None
        ready, _, _ = select.select([self._stdin_fd], [], [], max(timeout, 0.0))
        if not ready:
            return None
        data = os.read(self._stdin_fd, 1)
        if not data:
            return "\x04"
        text = data.decode("utf-8", "ignore")
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

    def _read_char(self, timeout: float):
        if not self.enabled:
            return None
        if os.name == "nt":
            return self._read_windows_char(timeout)
        return self._read_posix_char(timeout)

    def read_event(self, timeout: float):
        ch = self._read_char(timeout)
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
        if ch in ("\b", "\x08", "\x7f"):
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
        if not self.enabled:
            return
        width, height = self._get_size()
        lines = []
        paused = bool(current and current.paused)
        if current is not None:
            resource_path = os.path.abspath(current.plan.entry.path)
        elif entries:
            resource_path = os.path.abspath(entries[current_index].path)
        else:
            resource_path = ""
        lines.append(self._fit(resource_path, width))
        if current is None:
            lines.append(self._fit("state stopped", width))
            lines.append(self._fit("[>.......] 00:00/00:00", width))
        else:
            plan = current.plan
            position_sample, phase = _get_playback_position_sample(current)
            position_sec = position_sample / float(max(plan.sample_rate, 1))
            end_sec = plan.end_sample / float(max(plan.sample_rate, 1))
            progress = position_sample / float(max(plan.end_sample, 1))
            if current.paused:
                state_text = "paused"
            elif phase == "first":
                state_text = "first-pass"
            else:
                state_text = phase
            bar_width = max(min(width - 24, 60), 8)
            lines.append(
                self._fit(
                    f"bgm {plan.bgm_name}  state {state_text}  start {_format_player_time(plan.start_sample / plan.sample_rate)}  loop {_format_player_time(plan.repeat_sample / plan.sample_rate)}  end {_format_player_time(end_sec)}",
                    width,
                )
            )
            lines.append(
                self._fit(
                    f"[{_build_progress_bar(progress, bar_width)}] {_format_player_time(position_sec)}/{_format_player_time(end_sec)}",
                    width,
                )
            )
        lines.append(self._fit(_format_playlist_help(len(entries) > 1), width))
        footer_rows = 2
        playlist_rows = max(height - len(lines) - footer_rows, 1)
        playlist_header, playlist_lines = self._build_playlist_lines(
            entries,
            current_index,
            paused,
            playlist_rows - 1,
            width,
        )
        lines.append(self._fit(playlist_header, width))
        lines.extend(playlist_lines)
        while len(lines) < height - footer_rows:
            lines.append("")
        lines.append(self._fit(self.message, width))
        prompt_line, prompt_col = self._prompt_line(width)
        lines.append(self._fit(prompt_line, width))
        lines = lines[:height]
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
    current: _RunningPlayback | None,
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
        list_handler(entries, current_index, current.paused if current else False)
        return current_index, current, None
    if action in ("page_up", "page_down", "top", "bottom"):
        view_handler(
            action, entries, current_index, current.paused if current else False
        )
        return current_index, current, None
    if action == "toggle_pause":
        if current is None:
            return current_index, current, None
        if current.paused:
            _resume_process(current.process)
            if current.paused_at is not None:
                current.paused_total += max(time.monotonic() - current.paused_at, 0.0)
            current.paused = False
            current.paused_at = None
            reporter(
                f"resumed [{current_index + 1}/{len(entries)}] {current.plan.entry.display_name}"
            )
            return current_index, current, None
        _pause_process(current.process)
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
    if action == "play":
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

        def _screen_list(items, index, paused):
            screen.focus_current(len(items), index)
            screen.set_message(f"playlist {index + 1}/{len(items)} visible")

        def _screen_view(action_name, items, index, paused):
            if action_name == "page_up":
                screen.scroll_pages(len(items), -1)
                return
            if action_name == "page_down":
                screen.scroll_pages(len(items), 1)
                return
            if action_name == "top":
                screen.scroll_to_top()
                return
            if action_name == "bottom":
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
                if current is not None and current.process.poll() is not None:
                    raise RuntimeError(
                        f"ffplay exited unexpectedly with code {current.process.returncode}"
                    )
                screen.render(entries, current_index, current)
                event = screen.read_event(0.1)
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


def _pack_one(src_path: str, out_root: str, rel_dir: str) -> int:
    bn = os.path.basename(src_path)
    base_name, ext = os.path.splitext(bn)
    ext = ext.lower()
    out_dir = os.path.join(out_root, rel_dir) if rel_dir else out_root
    os.makedirs(out_dir, exist_ok=True)
    if ext == ".ogg":
        with open(src_path, "rb") as f:
            ogg = f.read()
        owp = sound.encode_ogg_to_owp_bytes(ogg)
        out_path = os.path.join(out_dir, base_name + ".owp")
        write_bytes(out_path, owp)
        return 1
    raise RuntimeError("unsupported file type (expected .ogg)")


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
            bgm_entry = _resolve_bgm_entry(trim_table, base_name)
            end_pos = bgm_entry.end_sample
            rep_pos = bgm_entry.repeat_sample
            eprint(
                f"trim {base_name} #{bgm_entry.name}: samples {rep_pos}..{end_pos if end_pos != -1 else 'EOF'}"
            )
            ogg = _ffmpeg_trim_ogg_bytes(
                ogg,
                start_sample=rep_pos,
                end_sample=end_pos,
                ffmpeg_path=ffmpeg_path,
                tmp_dir=tmp_dir,
            )
        write_bytes(os.path.join(out_dir, base_name + ".ogg"), ogg)
        return 1
    if ext == ".nwa":
        wav = sound.decode_nwa_to_wav_bytes(src_path)
        write_bytes(os.path.join(out_dir, base_name + ".wav"), wav)
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
            write_bytes(os.path.join(out_dir, out_name), ogg)
            wrote += 1
        return wrote
    return 0


def main(argv=None) -> int:
    mode, argv, rc = parse_main_argv(
        argv, _hint_help, flags=("--x", "--a", "--c", "--play")
    )
    if rc is not None:
        return rc
    if mode == "a":
        if "--trim" in argv:
            eprint("error: --trim is only valid with --x")
            return 2
        if len(argv) != 1:
            eprint("error: expected 1 input file for --a")
            _hint_help()
            return 2
        inp = argv[0]
        if missing_input_file(inp):
            return 1
        return _analyze_one(inp)
    if mode == "c":
        if "--trim" in argv:
            eprint("error: --trim is only valid with --x")
            return 2
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
        if src_is_dir:
            suffix_re = re.compile(r"^(?P<base>.+)_(?P<no>-?\d+)$")
            groups = {}
            for src_path in files:
                rel = os.path.relpath(src_path, inp)
                rel_dir = os.path.dirname(rel)
                base, _ = os.path.splitext(os.path.basename(src_path))
                m = suffix_re.match(base)
                if not m:
                    tasks.append(("owp", src_path, rel_dir, base))
                    continue
                base2 = m.group("base")
                no = int(m.group("no"))
                key = (rel_dir, base2)
                groups.setdefault(key, []).append((no, src_path))
            for (rel_dir, base2), items in sorted(
                groups.items(), key=lambda x: (x[0][0], x[0][1])
            ):
                if len(items) >= 2:
                    tasks.append(("ovk", items, rel_dir, base2))
                    continue
                for no, src_path in items:
                    base = os.path.splitext(os.path.basename(src_path))[0]
                    tasks.append(("owp", src_path, rel_dir, base))
        else:
            src_path = files[0]
            rel_dir = ""
            base = os.path.splitext(os.path.basename(src_path))[0]
            tasks.append(("owp", src_path, rel_dir, base))

        def _proc(task):
            kind = task[0]
            if kind == "owp":
                _, src_path, rel_dir, _base = task
                n = _pack_one(src_path, out_root, rel_dir)
                return n, n
            _, items, rel_dir, base2 = task
            out_dir = os.path.join(out_root, rel_dir) if rel_dir else out_root
            os.makedirs(out_dir, exist_ok=True)
            entry_list = []
            for no, src_path in sorted(items, key=lambda x: x[0]):
                with open(src_path, "rb") as f:
                    ogg = f.read()
                entry_list.append((no, ogg))
            ovk = sound.encode_oggs_to_ovk_bytes(entry_list)
            out_path = os.path.join(out_dir, base2 + ".ovk")
            write_bytes(out_path, ovk)
            return 1, 1

        return run_batch(tasks, _proc, item_name_fn=lambda task: task[0])
    if mode == "play":
        if len(argv) not in (1, 2):
            eprint(
                "error: expected <input_file|input_dir> [Gameexe.dat|Gameexe.ini] for --play"
            )
            _hint_help()
            return 2
        if psutil is None:
            eprint("error: need psutil: pip install psutil")
            return 1
        inp = argv[0]
        trim_path = _resolve_play_gameexe_path(inp, argv[1] if len(argv) == 2 else "")
        if not os.path.isfile(trim_path):
            eprint(f"Gameexe source not found: {trim_path}")
            return 1
        ffplay_path = shutil.which("ffplay") or ""
        gei_txt = _load_gameexe_ini_text(trim_path)
        trim_table = _parse_bgm_table(gei_txt)
        if not trim_table:
            eprint("error: no #BGM.* entries found in Gameexe source")
            return 1
        entries, rc = _collect_playback_entries(inp)
        if rc is not None:
            return rc
        entries, skipped = _filter_playback_entries(entries, trim_table)
        if skipped:
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
        i = argv.index("--trim")
        if i + 1 >= len(argv):
            eprint("error: --trim expects a path")
            _hint_help()
            return 2
        trim_path = argv[i + 1]
        del argv[i : i + 2]
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
    tmp_dir_owned = False
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
            tmp_dir_owned = True
    os.makedirs(out_root, exist_ok=True)
    files, rc = collect_batch_files(
        inp, src_is_dir, [".owp", ".nwa", ".ovk"], "no supported audio files found"
    )
    if rc is not None:
        _cleanup_tmp_dir(tmp_dir, out_root, remove_owned=tmp_dir_owned)
        return rc

    def _proc(src_path):
        rel_dir = os.path.dirname(os.path.relpath(src_path, inp)) if src_is_dir else ""
        n = _extract_one(
            src_path,
            out_root,
            rel_dir,
            trim_table=trim_table,
            ffmpeg_path=ffmpeg_path,
            tmp_dir=tmp_dir,
        )
        return n, n

    exit_code = run_batch(files, _proc)
    _cleanup_tmp_dir(tmp_dir, out_root, remove_owned=tmp_dir_owned)
    return exit_code
