import os
import sys
import subprocess
import datetime


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if len(args) != 3:
        return 2
    engine_path, ss_name, zlabel = args
    engine_path = str(engine_path)
    if len(engine_path) >= 2 and (
        (engine_path[0] == engine_path[-1] == '"')
        or (engine_path[0] == engine_path[-1] == "'")
    ):
        engine_path = engine_path[1:-1]
    ss_name = str(ss_name)
    if len(ss_name) >= 2 and (
        (ss_name[0] == ss_name[-1] == '"') or (ss_name[0] == ss_name[-1] == "'")
    ):
        ss_name = ss_name[1:-1]
    zlabel = str(zlabel)
    if len(zlabel) >= 2 and (
        (zlabel[0] == zlabel[-1] == '"') or (zlabel[0] == zlabel[-1] == "'")
    ):
        zlabel = zlabel[1:-1]
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
    except Exception:
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
        sys.stderr.write(f"Failed to launch engine: {e}\n")
        return 1
    return 0
