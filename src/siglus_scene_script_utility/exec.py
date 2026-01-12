import os
import sys
import subprocess
import datetime


def _strip_quotes(s):
    s = str(s)
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if len(args) != 3:
        return 2
    engine_path, ss_path, zlabel = args
    engine_path = _strip_quotes(engine_path)
    ss_path = _strip_quotes(ss_path)
    zlabel = _strip_quotes(zlabel)
    label = str(zlabel).strip()
    if label.startswith("#"):
        label = label[1:]
    if label.lower().startswith("z"):
        label = label[1:]
    label = label.strip()
    try:
        label_i = int(label, 10)
    except Exception:
        label_i = None
    if label_i is None or label_i < 0:
        sys.stderr.write("Invalid zlabel: %s\n" % zlabel)
        return 2
    label = str(label_i)
    ss = os.path.basename(ss_path)
    if ss.lower().endswith(".ss"):
        ss = ss[:-3]
    else:
        ss = os.path.splitext(ss)[0]
    engine_dir = os.path.dirname(os.path.abspath(engine_path))
    work_dir = os.path.join(
        engine_dir, "work_" + datetime.datetime.now().strftime("%Y%m%d")
    )
    try:
        os.makedirs(work_dir, exist_ok=True)
    except Exception:
        pass
    work_dir_q = work_dir
    if os.name == "nt":
        work_dir_q = work_dir.replace("\\", "\\\\")
    cmd = f'"{engine_path}" /work_dir="{work_dir_q}" /start="{ss}" /z_no={label} /end_start'
    try:
        if os.name == "nt":
            subprocess.Popen(cmd, cwd=engine_dir, shell=False)
        else:
            subprocess.Popen(
                [
                    engine_path,
                    f"/work_dir={work_dir}",
                    f"/start={ss}",
                    f"/z_no={label}",
                    "/end_start",
                ],
                cwd=engine_dir,
            )
    except Exception as e:
        sys.stderr.write("Failed to launch engine: %s\n" % e)
        return 1
    return 0
