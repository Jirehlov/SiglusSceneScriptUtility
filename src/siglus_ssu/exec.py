import os
import sys
import subprocess
import datetime


def _strip_outer_quotes(value):
    text = str(value)
    if len(text) >= 2 and (
        (text[0] == text[-1] == '"') or (text[0] == text[-1] == "'")
    ):
        return text[1:-1]
    return text


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if len(args) != 3:
        return 2
    engine_path, ss_name, zlabel = args
    engine_path = _strip_outer_quotes(engine_path)
    ss_name = _strip_outer_quotes(ss_name)
    zlabel = _strip_outer_quotes(zlabel)
    if os.path.basename(ss_name) != ss_name:
        sys.stderr.write(f"Invalid scene name: {ss_name}\n")
        return 2
    label = str(zlabel).strip()
    if label.startswith("#"):
        label = label[1:]
    if label.lower().startswith("z"):
        label = label[1:]
    label = label.strip()
    try:
        label_i = int(label, 10)
    except ValueError:
        label_i = None
    if label_i is None or label_i < 0:
        sys.stderr.write(f"Invalid zlabel: {zlabel}\n")
        return 2
    label = str(label_i)
    ss = ss_name
    if ss.lower().endswith(".ss"):
        ss = ss[:-3]
    else:
        ss = os.path.splitext(ss)[0]
    engine_dir = os.path.dirname(os.path.abspath(engine_path))
    work_dir = os.path.join(
        engine_dir, "work_" + datetime.datetime.now().strftime("%Y%m%d")
    )
    os.makedirs(work_dir, exist_ok=True)
    cmd = [
        engine_path,
        f"/work_dir={work_dir}",
        f"/start={ss}",
        f"/z_no={label}",
        "/end_start",
    ]
    try:
        subprocess.Popen(cmd, cwd=engine_dir)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"Failed to launch engine: {e}\n")
        return 1
    return 0
