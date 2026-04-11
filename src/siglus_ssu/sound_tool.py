import os
import queue
import shutil
import re
import subprocess
import tempfile
import threading
from contextlib import suppress
from dataclasses import dataclass

from .common import (
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
            data = f.read(sound._NWA_HEADER_STRUCT.size)
        try:
            header = sound._parse_nwa_header(data)
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
    r'^\s*#BGM\.\d+\s*=\s*"(?:[^"]*)"\s*,\s*"(?P<fn>[^"]+)"\s*,\s*(?P<start>-?\d+)\s*,\s*(?P<end>-?\d+)\s*,\s*(?P<rep>-?\d+)\s*$',
    re.IGNORECASE,
)


def _parse_bgm_table(gameexe_ini_text: str):
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
        except (TypeError, ValueError):
            continue
        table[fn.lower()] = (start, end, rep)
    return table


def _load_gameexe_ini_text(gameexe_path: str) -> str:
    ext = os.path.splitext(gameexe_path)[1].lower()
    if ext == ".ini":
        return read_text_auto(gameexe_path)
    os_dir = os.path.dirname(os.path.abspath(gameexe_path))
    cands = list(pck._iter_exe_el_candidates(os_dir))
    if not cands:
        cands = [b""]
    last_err = None
    for exe_el in cands:
        try:
            info, txt = GEI.read_gameexe_dat(gameexe_path, exe_el=exe_el)
            if info.get("mode") and not info.get("used_exe_el"):
                raise RuntimeError(
                    "Gameexe.dat is encrypted with exe angou; missing 暗号.dat/key.txt to derive key"
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
    start_pos, end_pos, rep_pos = trim_table[key]
    return int(start_pos), int(end_pos), int(rep_pos)


def _normalize_playback_range(
    ogg_bytes: bytes,
    start_sample: int,
    end_sample: int,
    repeat_sample: int,
):
    if start_sample < 0:
        raise RuntimeError("invalid start position (start_sample < 0)")
    if repeat_sample < 0:
        raise RuntimeError("invalid repeat position (repeat_sample < 0)")

    total_sample_cnt = sound._ogg_calc_smp_cnt(ogg_bytes)
    if total_sample_cnt <= 0:
        raise RuntimeError("failed to determine Ogg sample count")

    if end_sample == -1 or end_sample > total_sample_cnt:
        end_sample = total_sample_cnt

    if start_sample > total_sample_cnt:
        raise RuntimeError("invalid start position (start_sample > total_sample_cnt)")
    if repeat_sample < start_sample:
        raise RuntimeError("invalid repeat position (repeat_sample < start_sample)")
    if repeat_sample >= end_sample:
        raise RuntimeError("invalid loop range (end_sample <= repeat_sample)")

    return start_sample, end_sample, repeat_sample


def _build_ffplay_audio_filter(
    start_sample: int,
    end_sample: int,
    repeat_sample: int,
) -> str:
    loop_size = end_sample - repeat_sample
    if loop_size <= 0:
        raise RuntimeError("invalid loop size")

    loop_filter = (
        f"atrim=start_sample={repeat_sample}:end_sample={end_sample},"
        f"asetpts=PTS-STARTPTS,aloop=loop=-1:size={loop_size}"
    )
    if start_sample == repeat_sample:
        return loop_filter

    return (
        "asplit=2[intro_src][loop_src];"
        f"[intro_src]atrim=start_sample={start_sample}:end_sample={repeat_sample},"
        "asetpts=PTS-STARTPTS[intro];"
        f"[loop_src]{loop_filter}[loop];"
        "[intro][loop]concat=n=2:v=0:a=1"
    )


def _prepare_playback_input(src_path: str):
    base_name, ext = os.path.splitext(os.path.basename(src_path))
    ext = ext.lower()
    if ext not in (".owp", ".ogg"):
        raise RuntimeError("unsupported file type (expected .owp or .ogg)")

    ogg = sound.decode_owp_to_ogg_bytes(src_path)
    tmp_dir = ""
    play_path = src_path
    if ext == ".owp":
        tmp_dir = tempfile.mkdtemp(prefix="siglus_ffplay_")
        play_path = os.path.join(tmp_dir, base_name + ".ogg")
        write_bytes(play_path, ogg)

    return base_name, ogg, play_path, tmp_dir


@dataclass(frozen=True)
class _PlaybackEntry:
    path: str
    display_name: str
    base_name: str


@dataclass(frozen=True)
class _PlaybackPlan:
    entry: _PlaybackEntry
    play_path: str
    tmp_dir: str
    start_sample: int
    end_sample: int
    repeat_sample: int
    audio_filter: str


@dataclass
class _RunningPlayback:
    plan: _PlaybackPlan
    process: subprocess.Popen
    paused: bool = False


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


def _collect_playback_entries(inp: str):
    src_is_dir = os.path.isdir(inp)
    if not src_is_dir:
        if missing_input_file(inp):
            return [], 1
        ext = os.path.splitext(inp)[1].lower()
        if ext not in (".owp", ".ogg"):
            eprint("error: unsupported file type for --play (expected .owp or .ogg)")
            return [], 1
        return [_make_playback_entry(inp)], None

    files, rc = collect_batch_files(
        inp,
        True,
        [".owp", ".ogg"],
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
        parts = parts[:1] + ["prev(b)", "next(n)", "list(l)", "play/g N"] + parts[1:]
    return "commands: " + ", ".join(parts)


def _parse_player_command(command: str, has_playlist: bool):
    text = str(command or "").strip()
    if not text:
        return "noop", None

    parts = text.split()
    head = parts[0].lower()

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
    if head in ("play", "go", "g", "goto", "jump"):
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


def _print_playlist(entries, current_index: int, paused: bool) -> None:
    total = len(entries)
    eprint(f"playlist total={total}")
    for index, entry in enumerate(entries):
        marker = "  "
        if index == current_index:
            marker = "||" if paused else ">>"
        eprint(f"{marker} [{index + 1}/{total}] {entry.display_name}")


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
    base_name, ogg, play_path, tmp_dir = _prepare_playback_input(entry.path)
    start_pos, end_pos, rep_pos = _resolve_bgm_entry(trim_table, base_name)
    start_pos, end_pos, rep_pos = _normalize_playback_range(
        ogg,
        start_sample=start_pos,
        end_sample=end_pos,
        repeat_sample=rep_pos,
    )
    return _PlaybackPlan(
        entry=entry,
        play_path=play_path,
        tmp_dir=tmp_dir,
        start_sample=start_pos,
        end_sample=end_pos,
        repeat_sample=rep_pos,
        audio_filter=_build_ffplay_audio_filter(
            start_sample=start_pos,
            end_sample=end_pos,
            repeat_sample=rep_pos,
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
    return _RunningPlayback(plan=plan, process=process)


def _call_windows_process_op(pid: int, name: str) -> None:
    import ctypes

    process_suspend_resume = 0x0800
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    func = getattr(ntdll, name)
    func.argtypes = [ctypes.c_void_p]
    func.restype = ctypes.c_long
    handle = kernel32.OpenProcess(process_suspend_resume, False, int(pid))
    if not handle:
        err = ctypes.get_last_error()
        raise OSError(err, f"OpenProcess failed for pid={pid}")
    try:
        status = int(func(handle))
        if status != 0:
            raise RuntimeError(f"{name} failed: 0x{status & 0xFFFFFFFF:08X}")
    finally:
        kernel32.CloseHandle(handle)


def _pause_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        _call_windows_process_op(process.pid, "NtSuspendProcess")
        return
    import signal

    os.kill(process.pid, signal.SIGSTOP)


def _resume_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        _call_windows_process_op(process.pid, "NtResumeProcess")
        return
    import signal

    os.kill(process.pid, signal.SIGCONT)


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
):
    running = _spawn_running_playback(entries[current_index], trim_table, ffplay_path)
    old = current
    current = running
    _stop_running_playback(old)
    plan = current.plan
    eprint(
        f"play [{current_index + 1}/{len(entries)}] {plan.entry.display_name}: intro {plan.start_sample}..{plan.repeat_sample}, loop {plan.repeat_sample}..{plan.end_sample}"
    )
    return current


def _run_input_reader(command_queue, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            text = input("player> ")
        except EOFError:
            command_queue.put(("stop", None))
            return
        except KeyboardInterrupt:
            command_queue.put(("interrupt", None))
            return
        command_queue.put(("command", text))


def _run_interactive_player(entries, trim_table, ffplay_path: str) -> int:
    has_playlist = len(entries) > 1
    command_queue = queue.Queue()
    stop_event = threading.Event()
    current_index = 0
    current = None
    reader = threading.Thread(
        target=_run_input_reader,
        args=(command_queue, stop_event),
        daemon=True,
    )
    reader.start()
    eprint(_format_playlist_help(has_playlist))
    try:
        current = _switch_playback(
            entries,
            current_index,
            current,
            trim_table,
            ffplay_path,
        )
        while True:
            if current is not None and current.process.poll() is not None:
                raise RuntimeError(
                    f"ffplay exited unexpectedly with code {current.process.returncode}"
                )
            try:
                kind, payload = command_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if kind == "interrupt":
                eprint("playback stopped")
                return 0
            if kind == "stop":
                eprint("playback stopped")
                return 0
            try:
                action, value = _parse_player_command(payload, has_playlist)
                if action == "noop":
                    continue
                if action == "help":
                    eprint(_format_playlist_help(has_playlist))
                    continue
                if action == "list":
                    _print_playlist(
                        entries,
                        current_index,
                        current.paused if current else False,
                    )
                    continue
                if action == "toggle_pause":
                    if current is None:
                        continue
                    if current.paused:
                        _resume_process(current.process)
                        current.paused = False
                        eprint(
                            f"resumed [{current_index + 1}/{len(entries)}] {current.plan.entry.display_name}"
                        )
                        continue
                    _pause_process(current.process)
                    current.paused = True
                    eprint(
                        f"paused [{current_index + 1}/{len(entries)}] {current.plan.entry.display_name}"
                    )
                    continue
                if action == "stop":
                    eprint("playback stopped")
                    return 0
                if action == "prev":
                    if current_index == 0:
                        eprint("already at the first track")
                        continue
                    current = _switch_playback(
                        entries,
                        current_index - 1,
                        current,
                        trim_table,
                        ffplay_path,
                    )
                    current_index -= 1
                    continue
                if action == "next":
                    if current_index + 1 >= len(entries):
                        eprint("already at the last track")
                        continue
                    current = _switch_playback(
                        entries,
                        current_index + 1,
                        current,
                        trim_table,
                        ffplay_path,
                    )
                    current_index += 1
                    continue
                if action == "play":
                    if value >= len(entries):
                        eprint(f"playlist index out of range: {value + 1}")
                        continue
                    current = _switch_playback(
                        entries,
                        value,
                        current,
                        trim_table,
                        ffplay_path,
                    )
                    current_index = value
                    continue
            except Exception as exc:
                eprint(f"error: {exc}")
    except KeyboardInterrupt:
        eprint("playback stopped")
        return 0
    finally:
        stop_event.set()
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
            start_pos, end_pos, rep_pos = _resolve_bgm_entry(trim_table, base_name)

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
