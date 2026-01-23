import os
import sys


def log_stage(stage, file_path):
    name = os.path.basename(file_path) if file_path else ""
    print(f"{stage}: {name}")


def record_stage_time(ctx, stage, elapsed):
    try:
        if not isinstance(ctx, dict):
            return
        stats = ctx.setdefault("stats", {})
        timings = stats.setdefault("stage_time", {})
        timings[stage] = float(timings.get(stage, 0.0)) + float(elapsed)
    except Exception:
        pass


def set_stage_time(ctx, stage, elapsed):
    try:
        if not isinstance(ctx, dict):
            return
        stats = ctx.setdefault("stats", {})
        timings = stats.setdefault("stage_time", {})
        timings[stage] = float(elapsed)
    except Exception:
        pass


def eprint(msg: str, errors: str = "backslashreplace") -> None:
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        try:
            sys.stderr.buffer.write((msg + "\n").encode("utf-8", errors=errors))
            sys.stderr.flush()
        except Exception:
            pass
