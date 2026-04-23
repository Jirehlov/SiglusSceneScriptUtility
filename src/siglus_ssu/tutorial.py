import json
import os
import sys
import threading
import time
import urllib.parse
import webbrowser
from bisect import bisect_right
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

from . import dat
from . import pck
from . import textmap
from .common import eprint

FORMAT_NAME = "siglus-tutorial/v1"
VIEWER_FILE_NAME = "tutorial_viewer.html"
DIALOGUE_KIND = int(textmap.TEXTMAP_KIND_DIALOGUE)
VIEWER_SERVER_POLL_SECONDS = 0.2
VIEWER_SERVER_START_SECONDS = 15.0
VIEWER_SERVER_IDLE_SECONDS = 4.0
SHORT_RETURN_FRONTIER_MAX_DISTANCE = 12
LATE_RETURN_CHAIN_MAX_DISTANCE = 4
SAME_SCENE_SILENT_MAX_DISTANCE = 48
SAME_SCENE_HELPER_FRONTIER_MAX_DISTANCE = 32
NEAR_RETURN_CHAIN_MAX_DISTANCE = 16
NEAR_RETURN_FRONTIER_MAX_DISTANCE = 24
NEAR_RETURN_ORDER_GAP_MAX = 4
DIRECT_EDGE_KINDS = {"goto", "branch_true", "branch_false", "fallthrough"}
SPLIT_OPS = {
    "CD_GOTO",
    "CD_GOTO_TRUE",
    "CD_GOTO_FALSE",
    "CD_GOSUB",
    "CD_GOSUBSTR",
    "CD_RETURN",
    "CD_EOF",
}


def _usage(out=None):
    if out is None:
        out = sys.stderr
    p = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "siglus-ssu"
    out.write(
        f"usage: {p} -t <input_pck> [output_json]\n"
        "\n"
        "Generate a static tutorial graph JSON from scene dat inside a .pck.\n"
        "If output_json is omitted, the JSON is written next to input_pck.\n"
    )


def _status(message: str) -> None:
    eprint(f"tutorial: {message}", errors="replace")


def _int_or_none(value):
    try:
        return int(value)
    except Exception:
        return None


def _safe_text(value) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _scene_key(scene_no: int) -> str:
    return f"scene:{int(scene_no):d}"


def _block_key(scene_no: int, start_ofs: int) -> tuple[int, int]:
    return (int(scene_no), int(start_ofs))


def _segment_key(scene_no: int, start_ofs: int) -> str:
    return f"segment:{int(scene_no):d}:{int(start_ofs):08X}"


def _is_trace_command_base(ev, base_name: str) -> bool:
    if not isinstance(ev, dict):
        return False
    base_name = str(base_name or "").casefold()
    if not base_name:
        return False
    base = str(ev.get("_call_base_name") or "").casefold()
    if base == base_name:
        return True
    name = str(ev.get("_call_name") or "").casefold()
    return name == base_name or name.endswith("." + base_name)


def _trace_command_name(ev) -> str:
    if not isinstance(ev, dict):
        return ""
    return _safe_text(ev.get("_call_name")).casefold()


def _is_frame_action_start(ev) -> bool:
    name = _trace_command_name(ev)
    return name.endswith("frameaction.start") or name.endswith("frameaction.start_real")


def _is_immediate_selection_command(ev) -> bool:
    if not isinstance(ev, dict):
        return False
    return any(
        _is_trace_command_base(ev, name)
        for name in (
            "sel",
            "sel_cancel",
            "selmsg",
            "selmsg_cancel",
            "selbtn",
            "selbtn_cancel",
        )
    )


def _is_selbtn_startcall_command(ev) -> bool:
    if not isinstance(ev, dict):
        return False
    return _is_trace_command_base(ev, "selbtn") or _is_trace_command_base(
        ev, "selbtn_cancel"
    )


def _is_split_command(ev) -> bool:
    if not isinstance(ev, dict):
        return False
    if _safe_text(ev.get("op")) != "CD_COMMAND":
        return False
    return _is_frame_action_start(ev) or _is_trace_command_base(ev, "set_button_call")


def _default_output_path(input_pck: str) -> str:
    base = os.path.splitext(os.path.basename(input_pck))[0] + ".tutorial.json"
    return os.path.join(os.path.dirname(os.path.abspath(input_pck)) or ".", base)


def _seed_tuple(kind: str, label: str, cross_scene: bool) -> tuple[str, str, bool]:
    return (_safe_text(kind), _safe_text(label), bool(cross_scene))


def _compose_seed(
    prefix_kind: str,
    prefix_label: str,
    prefix_cross_scene: bool,
    suffix_kind: str,
    suffix_label: str,
    suffix_cross_scene: bool,
) -> tuple[str, str, bool]:
    kind = _safe_text(prefix_kind)
    if kind in ("", "fallthrough"):
        next_kind = _safe_text(suffix_kind)
        if next_kind and next_kind != "fallthrough":
            return _seed_tuple(next_kind, suffix_label, suffix_cross_scene)
    if kind:
        return _seed_tuple(kind, prefix_label, prefix_cross_scene)
    return _seed_tuple(suffix_kind, suffix_label, suffix_cross_scene)


def _collapse_edge_records(records) -> tuple[str, str, bool]:
    items = list(records or ())
    if not items:
        return ("flow", "", False)
    if len(items) == 1:
        _target_id, kind, label, cross_scene = items[0]
        return (_safe_text(kind), _safe_text(label), bool(cross_scene))
    preferred_kinds = (
        "branch_true",
        "branch_false",
        "return",
        "sel_start_call",
        "frame_action",
        "button_call",
        "jump",
        "farcall",
        "gosub",
        "gosubstr",
        "goto",
        "fallthrough",
    )
    kind_set = {_safe_text(item[1]) for item in items if _safe_text(item[1])}
    kind = next(
        (name for name in preferred_kinds if name in kind_set),
        _safe_text(items[0][1]) or "flow",
    )
    labels = []
    seen = set()
    for item in items:
        label = _safe_text(item[2]).strip()
        if not label or label == "false":
            continue
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    if not labels:
        fallback = []
        seen = set()
        for item in items:
            label = _safe_text(item[2]).strip()
            if not label:
                continue
            if label in seen:
                continue
            seen.add(label)
            fallback.append(label)
        labels = fallback
    label_set = list(labels)
    label = label_set[0] if len(label_set) == 1 else " / ".join(label_set)
    return (kind or "flow", label, any(bool(item[3]) for item in items))


def _group_unique_edges(records) -> dict:
    grouped = defaultdict(list)
    for record in records or ():
        if not isinstance(record, (list, tuple)) or len(record) < 4:
            continue
        grouped[record[0]].append(
            (
                record[0],
                _safe_text(record[1]),
                _safe_text(record[2]),
                bool(record[3]),
            )
        )
    return dict(grouped)


def _looks_like_spoken_text(text: str) -> bool:
    text_value = _safe_text(text).lstrip()
    if not text_value:
        return False
    return text_value.startswith(("\u300c", "\u300e", "\u201c", '"'))


def _render_payload_line(speaker: str, text: str) -> str:
    speaker_text = _safe_text(speaker)
    text_value = _safe_text(text)
    if not text_value:
        return ""
    if speaker_text and _looks_like_spoken_text(text_value):
        return f"{speaker_text}\uff1a{text_value}"
    return text_value


def _event_line_span(events: list[dict]) -> tuple[int, int]:
    start_line = 0
    end_line = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        line_no = _int_or_none(ev.get("line")) or 0
        if line_no <= 0:
            continue
        if start_line <= 0:
            start_line = int(line_no)
        end_line = int(line_no)
    return (start_line, end_line)


def _member_line_span(members: list[dict]) -> tuple[int, int]:
    start_line = 0
    end_line = 0
    for member in members:
        if not isinstance(member, dict):
            continue
        member_start = int(member.get("start_line", 0) or 0)
        member_end = int(member.get("end_line", 0) or 0)
        if start_line <= 0:
            start_line = member_start or member_end
        if member_end > 0:
            end_line = member_end
        elif member_start > 0:
            end_line = member_start
    return (start_line, end_line)


def _format_line_ref(start_line: int, end_line: int) -> str:
    start_value = int(start_line or 0)
    end_value = int(end_line or 0)
    if start_value > 0 and end_value > 0:
        end_value = max(start_value, end_value)
        if start_value == end_value:
            return f"L{start_value:d}"
        return f"L{start_value:d}-{end_value:d}"
    if start_value > 0:
        return f"L{start_value:d}"
    if end_value > 0:
        return f"L{end_value:d}"
    return ""


class TutorialBuilder:
    def __init__(self, input_pck: str):
        self.input_pck = os.path.abspath(input_pck)
        self.input_name = os.path.basename(self.input_pck)
        self.pack_context = {}
        self.scenes = []
        self.scene_by_no = {}
        self.scene_by_name = {}
        self.scene_by_name_folded = {}
        self.block_index = {}
        self.segment_index = {}
        self.inc_cmd_by_name = {}
        self.inc_cmd_by_name_folded = {}
        self.call_records = []
        self.exit_cache = {}
        self.silent_resolutions = {}
        self.return_frontiers = {}
        self.same_scene_return_frontiers = {}
        self.same_scene_silent_frontiers = {}
        self.same_scene_near_return_frontiers = {}
        self.stats = defaultdict(int)

    def build(self) -> dict:
        _status("loading scenes")
        self._load_scenes()
        _status("building block graph")
        self._build_block_graph()
        _status("building segments")
        self._build_segments()
        _status("resolving silent edges")
        self._build_silent_resolutions()
        _status("building tutorial graph")
        return self._build_tutorial_graph()

    def _register_scene_lookup(self, scene: dict) -> None:
        name = _safe_text(scene.get("scene_name"))
        if name and name not in self.scene_by_name:
            self.scene_by_name[name] = scene
        folded = name.casefold()
        if folded and folded not in self.scene_by_name_folded:
            self.scene_by_name_folded[folded] = scene

    def _lookup_scene(self, scene_name: str):
        name = _safe_text(scene_name)
        if not name:
            return None
        exact = self.scene_by_name.get(name)
        if exact is not None:
            return exact
        return self.scene_by_name_folded.get(name.casefold())

    def _load_pack_context(self, pack_context: dict) -> None:
        self.pack_context = dict(pack_context or {})
        self.inc_cmd_by_name = {}
        self.inc_cmd_by_name_folded = {}
        for item in self.pack_context.get("inc_command_defs") or ():
            if not isinstance(item, dict):
                continue
            name = _safe_text(item.get("name"))
            scene_no = _int_or_none(item.get("scn_no"))
            offset = _int_or_none(item.get("offset"))
            if not name or scene_no is None or offset is None:
                continue
            target = {
                "scene_no": int(scene_no),
                "offset": int(offset),
                "name": name,
            }
            if name not in self.inc_cmd_by_name:
                self.inc_cmd_by_name[name] = target
            folded = name.casefold()
            if folded and folded not in self.inc_cmd_by_name_folded:
                self.inc_cmd_by_name_folded[folded] = target

    def _command_transfer_kind(self, ev: dict) -> str:
        if _safe_text(ev.get("op")) != "CD_COMMAND":
            return ""
        if _is_trace_command_base(ev, "jump"):
            return "jump"
        if _is_trace_command_base(ev, "farcall"):
            return "farcall"
        return ""

    def _freeze_jump_args(self, raw_values) -> tuple:
        values = list(raw_values or [])
        out = []
        for value in values[:2]:
            if value is None:
                out.append(None)
                continue
            if isinstance(value, str):
                out.append(value)
                continue
            out.append(_int_or_none(value))
        return tuple(out)

    def _extract_selbtn_options(self, events: list[dict]) -> tuple[str, ...]:
        for ev in events:
            if _safe_text(ev.get("op")) != "CD_COMMAND":
                continue
            if not _is_immediate_selection_command(ev):
                continue
            return tuple(
                text
                for text in (
                    _safe_text(value).strip()
                    for value in list(ev.get("_arg_values") or ())
                )
                if text
            )
        return ()

    def _extract_async_calls(self, events: list[dict]) -> tuple[dict, ...]:
        calls = []
        seen = set()
        for ev in events:
            if _safe_text(ev.get("op")) != "CD_COMMAND":
                continue
            if _is_frame_action_start(ev):
                arg_values = list(ev.get("_arg_values") or ())
                cmd_name = _safe_text(arg_values[1] if len(arg_values) >= 2 else "")
                key = ("frame_action", cmd_name)
                if key not in seen:
                    seen.add(key)
                    calls.append(
                        {
                            "kind": "frame_action",
                            "cmd_name": cmd_name,
                        }
                    )
                continue
            if _is_trace_command_base(ev, "set_button_call"):
                arg_values = list(ev.get("_arg_values") or ())
                cmd_name = _safe_text(arg_values[0] if arg_values else "")
                key = ("button_call", cmd_name)
                if key not in seen:
                    seen.add(key)
                    calls.append(
                        {
                            "kind": "button_call",
                            "cmd_name": cmd_name,
                        }
                    )
                continue
            if _is_selbtn_startcall_command(ev):
                named_values = dict(ev.get("_named_values") or {})
                scene_name = _safe_text(named_values.get("sel_start_call_scn"))
                entry_arg = named_values.get("sel_start_call_z_no")
                key = ("sel_start_call", scene_name, entry_arg)
                if key not in seen:
                    seen.add(key)
                    calls.append(
                        {
                            "kind": "sel_start_call",
                            "scene_name": scene_name,
                            "entry_arg": entry_arg,
                        }
                    )
        return tuple(calls)

    def _extract_choice_compare_index(self, events: list[dict]) -> int | None:
        if len(events) < 7:
            return None
        if _safe_text(events[-1].get("op")) != "CD_GOTO_FALSE":
            return None
        if (
            _safe_text(events[-2].get("op")) != "CD_OPERATE_2"
            or _int_or_none(events[-2].get("opr")) != 16
        ):
            return None
        if _safe_text(events[-3].get("op")) != "CD_PUSH":
            return None
        if _safe_text(events[-4].get("op")) != "CD_PROPERTY":
            return None
        if (
            _safe_text(events[-5].get("op")) != "CD_PUSH"
            or _int_or_none(events[-5].get("value")) != 0
        ):
            return None
        if (
            _safe_text(events[-6].get("op")) != "CD_PUSH"
            or _int_or_none(events[-6].get("value")) != -1
        ):
            return None
        if (
            _safe_text(events[-7].get("op")) != "CD_PUSH"
            or _int_or_none(events[-7].get("value")) != 25
        ):
            return None
        return _int_or_none(events[-3].get("value"))

    def _collect_dialogues(self, events: list[dict], kind_map: dict) -> dict:
        out = defaultdict(list)
        speaker = ""
        for idx, ev in enumerate(events):
            op = _safe_text(ev.get("op"))
            if op == "CD_NAME":
                speaker = _safe_text(ev.get("text"))
                continue
            if op == "CD_COMMAND" and _is_trace_command_base(ev, "set_namae"):
                arg_values = list(ev.get("_arg_values") or [])
                if arg_values:
                    speaker = _safe_text(arg_values[0])
                continue
            if op == "CD_TEXT":
                str_id = _int_or_none(ev.get("str_id"))
                if str_id is None or int(kind_map.get(str_id, 0) or 0) != DIALOGUE_KIND:
                    continue
                payload = _render_payload_line(speaker, ev.get("text"))
                if payload:
                    out[int(ev["ofs"])].append(payload)
                continue
            if op == "CD_COMMAND" and _is_trace_command_base(ev, "print"):
                prev = events[idx - 1] if idx > 0 else None
                str_id = _int_or_none((prev or {}).get("value"))
                if str_id is None or int(kind_map.get(str_id, 0) or 0) != DIALOGUE_KIND:
                    continue
                arg_values = list(ev.get("_arg_values") or [])
                text_value = _safe_text(arg_values[1] if len(arg_values) >= 2 else "")
                if not text_value:
                    text_value = _safe_text((prev or {}).get("text"))
                payload = _render_payload_line(speaker, text_value)
                if payload:
                    out[int(ev["ofs"])].append(payload)
        self.stats["dialogue_count"] += sum(len(items) for items in out.values())
        return out

    def _build_scene_blocks(
        self,
        scene_no: int,
        scene_name: str,
        events: list[dict],
        dialogue_by_ofs: dict,
    ) -> list[dict]:
        leaders = {int(events[0]["ofs"])}
        for idx, ev in enumerate(events):
            op = _safe_text(ev.get("op"))
            transfer_kind = self._command_transfer_kind(ev)
            split_command = _is_split_command(ev)
            immediate_selection_command = _is_immediate_selection_command(ev)
            target_ofs = _int_or_none(ev.get("target_ofs"))
            if immediate_selection_command:
                leaders.add(int(ev["ofs"]))
            if (
                target_ofs is not None
                and target_ofs >= 0
                and (op in SPLIT_OPS or transfer_kind)
            ):
                leaders.add(target_ofs)
            next_ofs = events[idx + 1]["ofs"] if idx + 1 < len(events) else None
            if next_ofs is not None and (
                op in SPLIT_OPS or transfer_kind or split_command
            ):
                leaders.add(int(next_ofs))
        min_ofs = int(events[0]["ofs"])
        max_ofs = int(events[-1]["ofs"])
        valid_leaders = {ofs for ofs in leaders if min_ofs <= ofs <= max_ofs}
        blocks = []
        current = []
        for ev in events:
            if current and int(ev["ofs"]) in valid_leaders:
                blocks.append(
                    self._make_block(
                        scene_no, scene_name, len(blocks), current, dialogue_by_ofs
                    )
                )
                current = []
            current.append(ev)
        if current:
            blocks.append(
                self._make_block(
                    scene_no, scene_name, len(blocks), current, dialogue_by_ofs
                )
            )
        for idx, block in enumerate(blocks):
            block["next_id"] = blocks[idx + 1]["id"] if idx + 1 < len(blocks) else None
        self._annotate_choice_blocks(blocks)
        return blocks

    def _annotate_choice_blocks(self, blocks: list[dict]) -> None:
        block_by_start = {int(block["start_ofs"]): block for block in blocks}
        for block in blocks:
            block["choice_option"] = ""
            block["choice_next_option"] = ""
            block["choice_index"] = None
            block["choice_count"] = 0
            block["choice_last"] = False
        for block in blocks:
            options = tuple(block.get("selbtn_options") or ())
            if not options:
                continue
            head = block
            if _int_or_none(head.get("choice_compare_index")) != 0:
                head = next(
                    (
                        candidate
                        for candidate in blocks[int(block.get("order", 0) or 0) :]
                        if _int_or_none(candidate.get("choice_compare_index")) == 0
                    ),
                    None,
                )
            cursor = head
            for index, option in enumerate(options):
                if not isinstance(cursor, dict):
                    break
                if _int_or_none(cursor.get("choice_compare_index")) != index:
                    break
                cursor["choice_option"] = option
                cursor["choice_next_option"] = (
                    options[index + 1] if index + 1 < len(options) else ""
                )
                cursor["choice_index"] = index
                cursor["choice_count"] = len(options)
                cursor["choice_last"] = index + 1 >= len(options)
                if index + 1 >= len(options):
                    break
                cursor = block_by_start.get(
                    _int_or_none(cursor.get("tail_target_ofs")) or -1
                )

    def _make_block(
        self,
        scene_no: int,
        scene_name: str,
        order: int,
        events: list[dict],
        dialogue_by_ofs: dict,
    ) -> dict:
        start_ofs = int(events[0]["ofs"])
        end_ofs = int(events[-1]["ofs"])
        start_line, end_line = _event_line_span(events)
        last = events[-1]
        payload = []
        for ev in events:
            payload.extend(dialogue_by_ofs.get(int(ev["ofs"]), ()))
        return {
            "id": _block_key(scene_no, start_ofs),
            "scene_id": _scene_key(scene_no),
            "scene_no": int(scene_no),
            "scene_name": scene_name,
            "start_ofs": start_ofs,
            "end_ofs": end_ofs,
            "start_line": int(start_line),
            "end_line": int(end_line),
            "order": int(order),
            "last_op": _safe_text(last.get("op")),
            "tail_target_ofs": _int_or_none(last.get("target_ofs")),
            "transfer_kind": self._command_transfer_kind(last),
            "arg_values": self._freeze_jump_args(last.get("_arg_values") or ()),
            "selbtn_options": self._extract_selbtn_options(events),
            "async_calls": self._extract_async_calls(events),
            "choice_compare_index": self._extract_choice_compare_index(events),
            "dialogue": tuple(payload),
            "dialogue_count": len(payload),
            "out_edges": [],
            "incoming_count": 0,
            "summary_successors": [],
            "next_id": None,
        }

    def _load_one_scene(self, item: dict):
        scene_no = _int_or_none(item.get("scene_no"))
        if scene_no is None:
            return None
        scene_name = _safe_text(item.get("scene_name")) or f"scene_{scene_no:d}"
        scn_blob = item.get("blob")
        if not isinstance(scn_blob, (bytes, bytearray)):
            self.stats["skipped_scenes"] += 1
            return None
        bundle = dat.dat_disassembly_bundle(
            bytes(scn_blob),
            dat_path=item.get("relpath"),
            pack_context=self.pack_context,
            scene_no=scene_no,
            scene_name=scene_name,
        )
        if not isinstance(bundle, dict):
            self.stats["skipped_scenes"] += 1
            return None
        events = []
        for raw in bundle.get("trace") or []:
            if not isinstance(raw, dict):
                continue
            ofs = _int_or_none(raw.get("ofs"))
            if ofs is None:
                continue
            raw["ofs"] = ofs
            events.append(raw)
        if not events:
            self.stats["skipped_scenes"] += 1
            return None
        label_list = list(bundle.get("label_list") or [])
        z_label_list = list(bundle.get("z_label_list") or [])
        kind_map = textmap._collect_disam_string_kinds(bundle, scene_name)
        dialogue_by_ofs = self._collect_dialogues(events, kind_map)
        blocks = self._build_scene_blocks(scene_no, scene_name, events, dialogue_by_ofs)
        return {
            "scene_id": _scene_key(scene_no),
            "scene_no": int(scene_no),
            "scene_name": scene_name,
            "label_list": label_list,
            "z_label_list": z_label_list,
            "cmd_name_to_ofs": {
                _safe_text(name): int(ofs)
                for name, ofs in zip(
                    list(bundle.get("meta", {}).get("scn_cmd_names") or ()),
                    list(bundle.get("meta", {}).get("scn_cmd_list") or ()),
                )
                if _safe_text(name) and _int_or_none(ofs) is not None
            },
            "blocks": blocks,
            "block_starts": [int(block["start_ofs"]) for block in blocks],
            "block_by_start": {int(block["start_ofs"]): block for block in blocks},
        }

    def _load_scenes(self) -> None:
        blob = Path(self.input_pck).read_bytes()
        if not pck.looks_like_pck(blob):
            raise RuntimeError("input is not a supported .pck file")
        for index, item in enumerate(
            pck.iter_pck_scene_dat_items(blob, input_pck=self.input_pck) or (),
            1,
        ):
            scene_name = _safe_text(item.get("scene_name")) or f"scene#{index:d}"
            _status(f"processing scene {index:d}: {scene_name}")
            if not self.pack_context:
                self._load_pack_context(item.get("pack_context") or {})
            scene = self._load_one_scene(item)
            if not isinstance(scene, dict):
                continue
            self.scenes.append(scene)
            self.scene_by_no[int(scene["scene_no"])] = scene
            self._register_scene_lookup(scene)
            for block in scene.get("blocks") or ():
                self.block_index[block["id"]] = block
        self.scenes.sort(key=lambda item: (int(item["scene_no"]), item["scene_name"]))
        self.stats["scene_count"] = len(self.scenes)
        self.stats["block_count"] = len(self.block_index)
        _status(
            f"loaded {int(self.stats['scene_count']):d} scenes and {int(self.stats['block_count']):d} blocks"
        )

    def _resolve_scene_entry_ofs(self, target_scene: dict, entry_index) -> int | None:
        if entry_index is None:
            return 0
        idx = _int_or_none(entry_index)
        if idx is None or idx < 0:
            return None
        z_label_list = list(target_scene.get("z_label_list") or [])
        if 0 <= idx < len(z_label_list):
            return _int_or_none(z_label_list[idx])
        return None

    def _resolve_scene_command_ofs(
        self, target_scene: dict, cmd_name: str
    ) -> int | None:
        name = _safe_text(cmd_name)
        if not name or not isinstance(target_scene, dict):
            return None
        exact = (target_scene.get("cmd_name_to_ofs") or {}).get(name)
        if exact is not None:
            return _int_or_none(exact)
        folded = name.casefold()
        for current_name, current_ofs in (
            target_scene.get("cmd_name_to_ofs") or {}
        ).items():
            if _safe_text(current_name).casefold() == folded:
                return _int_or_none(current_ofs)
        return None

    def _resolve_user_command_target(self, current_scene: dict, cmd_name: str):
        name = _safe_text(cmd_name)
        if not name:
            return None
        target = self.inc_cmd_by_name.get(name)
        if isinstance(target, dict):
            return target
        target = self.inc_cmd_by_name_folded.get(name.casefold())
        if isinstance(target, dict):
            return target
        if not isinstance(current_scene, dict):
            return None
        target_ofs = self._resolve_scene_command_ofs(current_scene, name)
        if target_ofs is None:
            return None
        return {
            "scene_no": int(current_scene.get("scene_no", -1) or -1),
            "offset": int(target_ofs),
            "name": name,
        }

    def _resolve_transfer(self, block: dict):
        transfer_kind = _safe_text(block.get("transfer_kind"))
        if transfer_kind not in ("jump", "farcall"):
            return None
        args = tuple(block.get("arg_values") or ())
        scene_name = _safe_text(args[0] if len(args) >= 1 else "")
        entry_arg = args[1] if len(args) >= 2 else None
        target_scene = self._lookup_scene(scene_name)
        target_scene_no = (
            int(target_scene["scene_no"]) if isinstance(target_scene, dict) else None
        )
        target_ofs = None
        if isinstance(target_scene, dict):
            target_ofs = self._resolve_scene_entry_ofs(target_scene, entry_arg)
        entry_idx = _int_or_none(entry_arg)
        label = scene_name
        if scene_name and entry_idx is not None:
            label = f"{scene_name}#{entry_idx:d}"
        return {
            "kind": transfer_kind,
            "resolved": target_scene_no is not None and target_ofs is not None,
            "target_scene_no": target_scene_no,
            "target_ofs": target_ofs,
            "label": label,
        }

    def _find_block(self, scene_no: int, ofs: int):
        scene = self.scene_by_no.get(int(scene_no))
        if not isinstance(scene, dict):
            return None
        exact = scene.get("block_by_start", {}).get(int(ofs))
        if isinstance(exact, dict):
            return exact
        starts = list(scene.get("block_starts") or ())
        if not starts:
            return None
        idx = bisect_right(starts, int(ofs)) - 1
        if idx < 0 or idx >= len(scene.get("blocks") or ()):
            return None
        block = scene["blocks"][idx]
        if int(block["start_ofs"]) <= int(ofs) <= int(block["end_ofs"]):
            return block
        return None

    def _add_block_edge(
        self, source_block: dict, target_block: dict, kind: str, label: str = ""
    ) -> None:
        source_id = source_block["id"]
        target_id = target_block["id"]
        edge = (
            target_id,
            _safe_text(kind),
            _safe_text(label),
            bool(source_id[0] != target_id[0]),
        )
        if edge in source_block["out_edges"]:
            return
        source_block["out_edges"].append(edge)
        target_block["incoming_count"] = (
            int(target_block.get("incoming_count", 0) or 0) + 1
        )
        self.stats["block_edge_count"] += 1

    def _build_block_graph(self) -> None:
        self.call_records = []
        self.exit_cache = {}
        self.stats["block_edge_count"] = 0
        for scene in self.scenes:
            for block in scene.get("blocks") or ():
                next_block = self.block_index.get(block.get("next_id"))
                last_op = _safe_text(block.get("last_op"))
                for async_call in block.get("async_calls") or ():
                    async_kind = _safe_text((async_call or {}).get("kind"))
                    if async_kind in ("frame_action", "button_call"):
                        cmd_name = _safe_text((async_call or {}).get("cmd_name"))
                        target_ref = self._resolve_user_command_target(scene, cmd_name)
                        target = (
                            self._find_block(
                                int(target_ref["scene_no"]), int(target_ref["offset"])
                            )
                            if isinstance(target_ref, dict)
                            else None
                        )
                        if isinstance(target, dict):
                            self._add_block_edge(block, target, async_kind, cmd_name)
                        elif cmd_name:
                            self.stats["unresolved_commands"] += 1
                        continue
                    if async_kind == "sel_start_call":
                        target_scene = self._lookup_scene(
                            _safe_text((async_call or {}).get("scene_name"))
                        )
                        target_scene_no = (
                            int(target_scene["scene_no"])
                            if isinstance(target_scene, dict)
                            else None
                        )
                        target_ofs = (
                            self._resolve_scene_entry_ofs(
                                target_scene, (async_call or {}).get("entry_arg")
                            )
                            if isinstance(target_scene, dict)
                            else None
                        )
                        target = (
                            self._find_block(target_scene_no, target_ofs)
                            if target_scene_no is not None and target_ofs is not None
                            else None
                        )
                        if isinstance(target, dict):
                            label = _safe_text((async_call or {}).get("scene_name"))
                            entry_idx = _int_or_none(
                                (async_call or {}).get("entry_arg")
                            )
                            if label and entry_idx is not None:
                                label = f"{label}#{entry_idx:d}"
                            self._add_block_edge(block, target, "sel_start_call", label)
                        elif _safe_text((async_call or {}).get("scene_name")):
                            self.stats["unresolved_commands"] += 1
                if last_op == "CD_GOTO":
                    target = self._find_block(
                        int(scene["scene_no"]),
                        _int_or_none(block.get("tail_target_ofs")) or -1,
                    )
                    if isinstance(target, dict):
                        self._add_block_edge(block, target, "goto")
                    continue
                if last_op == "CD_GOTO_TRUE":
                    target = self._find_block(
                        int(scene["scene_no"]),
                        _int_or_none(block.get("tail_target_ofs")) or -1,
                    )
                    if isinstance(target, dict):
                        self._add_block_edge(block, target, "branch_true", "true")
                    if isinstance(next_block, dict):
                        self._add_block_edge(block, next_block, "fallthrough")
                    continue
                if last_op == "CD_GOTO_FALSE":
                    target = self._find_block(
                        int(scene["scene_no"]),
                        _int_or_none(block.get("tail_target_ofs")) or -1,
                    )
                    choice_option = _safe_text(block.get("choice_option"))
                    if choice_option:
                        choice_index = _int_or_none(block.get("choice_index"))
                        next_choice_index = (
                            None if choice_index is None else choice_index + 1
                        )
                        target_is_next_choice = (
                            isinstance(target, dict)
                            and next_choice_index is not None
                            and _int_or_none(target.get("choice_index"))
                            == next_choice_index
                        )
                        if isinstance(target, dict) and not bool(
                            block.get("choice_last")
                        ):
                            self._add_block_edge(
                                block,
                                target,
                                "fallthrough"
                                if target_is_next_choice
                                else "branch_false",
                                ""
                                if target_is_next_choice
                                else _safe_text(block.get("choice_next_option")),
                            )
                        if isinstance(next_block, dict):
                            self._add_block_edge(
                                block, next_block, "branch_true", choice_option
                            )
                        continue
                    if isinstance(target, dict):
                        self._add_block_edge(block, target, "branch_false", "false")
                    if isinstance(next_block, dict):
                        self._add_block_edge(block, next_block, "fallthrough")
                    continue
                if last_op in ("CD_RETURN", "CD_EOF"):
                    continue
                if last_op in ("CD_GOSUB", "CD_GOSUBSTR"):
                    self.call_records.append(
                        {
                            "source": block["id"],
                            "kind": last_op.casefold().replace("cd_", ""),
                            "label": last_op.casefold().replace("cd_", ""),
                            "target_scene_no": int(scene["scene_no"]),
                            "target_ofs": _int_or_none(block.get("tail_target_ofs")),
                            "return_scene_no": int(scene["scene_no"]),
                            "return_ofs": _int_or_none(
                                (next_block or {}).get("start_ofs")
                            ),
                        }
                    )
                    continue
                transfer = self._resolve_transfer(block)
                if isinstance(transfer, dict):
                    if _safe_text(transfer.get("kind")) == "jump":
                        if bool(transfer.get("resolved")):
                            target = self._find_block(
                                _int_or_none(transfer.get("target_scene_no")) or -1,
                                _int_or_none(transfer.get("target_ofs")) or -1,
                            )
                            if isinstance(target, dict):
                                self._add_block_edge(
                                    block,
                                    target,
                                    "jump",
                                    _safe_text(transfer.get("label")),
                                )
                        else:
                            self.stats["unresolved_commands"] += 1
                        continue
                    if _safe_text(transfer.get("kind")) == "farcall":
                        if bool(transfer.get("resolved")):
                            self.call_records.append(
                                {
                                    "source": block["id"],
                                    "kind": "farcall",
                                    "label": _safe_text(transfer.get("label")),
                                    "target_scene_no": _int_or_none(
                                        transfer.get("target_scene_no")
                                    ),
                                    "target_ofs": _int_or_none(
                                        transfer.get("target_ofs")
                                    ),
                                    "return_scene_no": int(scene["scene_no"]),
                                    "return_ofs": _int_or_none(
                                        (next_block or {}).get("start_ofs")
                                    ),
                                }
                            )
                        else:
                            self.stats["unresolved_commands"] += 1
                        continue
                if isinstance(next_block, dict):
                    self._add_block_edge(block, next_block, "fallthrough")
        for block in self.block_index.values():
            grouped = _group_unique_edges(
                edge
                for edge in block.get("out_edges") or ()
                if (not bool(edge[3])) and edge[1] in DIRECT_EDGE_KINDS
            )
            block["summary_successors"] = list(grouped)
        for call in self.call_records:
            source = self.block_index.get(call.get("source"))
            if not isinstance(source, dict):
                continue
            return_scene_no = _int_or_none(call.get("return_scene_no"))
            return_ofs = _int_or_none(call.get("return_ofs"))
            if return_scene_no is None or return_ofs is None:
                continue
            return_block = self._find_block(return_scene_no, return_ofs)
            if isinstance(return_block, dict) and int(return_block["scene_no"]) == int(
                source["scene_no"]
            ):
                source["summary_successors"].append(return_block["id"])
        for call in self.call_records:
            source = self.block_index.get(call.get("source"))
            if not isinstance(source, dict):
                continue
            target_scene_no = _int_or_none(call.get("target_scene_no"))
            target_ofs = _int_or_none(call.get("target_ofs"))
            return_scene_no = _int_or_none(call.get("return_scene_no"))
            return_ofs = _int_or_none(call.get("return_ofs"))
            target = (
                self._find_block(target_scene_no, target_ofs)
                if target_scene_no is not None and target_ofs is not None
                else None
            )
            return_block = (
                self._find_block(return_scene_no, return_ofs)
                if return_scene_no is not None and return_ofs is not None
                else None
            )
            if not isinstance(target, dict):
                continue
            self._add_block_edge(
                source,
                target,
                _safe_text(call.get("kind")),
                _safe_text(call.get("label")),
            )
            if not isinstance(return_block, dict):
                continue
            mode = "scene" if _safe_text(call.get("kind")) == "farcall" else "procedure"
            for exit_block in self._discover_exits(
                int(target["scene_no"]), int(target["start_ofs"]), mode
            ):
                self._add_block_edge(
                    exit_block, return_block, "return", _safe_text(call.get("label"))
                )
        for scene in self.scenes:
            scene["block_starts"] = []
            scene["block_by_start"] = {}
            scene["label_list"] = []
            scene["z_label_list"] = []
            scene["cmd_name_to_ofs"] = {}

    def _discover_exits(self, scene_no: int, entry_ofs: int, mode: str) -> list[dict]:
        key = (int(scene_no), int(entry_ofs), _safe_text(mode))
        cached = self.exit_cache.get(key)
        if cached is not None:
            return [
                self.block_index[block_id]
                for block_id in cached
                if block_id in self.block_index
            ]
        entry_block = self._find_block(scene_no, entry_ofs)
        if not isinstance(entry_block, dict):
            self.exit_cache[key] = []
            return []
        seen = set()
        queue = deque([entry_block["id"]])
        exits = []
        reachable = []
        while queue:
            block_id = queue.popleft()
            if block_id in seen:
                continue
            seen.add(block_id)
            block = self.block_index.get(block_id)
            if not isinstance(block, dict):
                continue
            reachable.append(block_id)
            successors = list(block.get("summary_successors") or ())
            if mode == "procedure":
                if _safe_text(block.get("last_op")) == "CD_RETURN":
                    exits.append(block_id)
                    continue
            else:
                if (
                    _safe_text(block.get("last_op")) in ("CD_RETURN", "CD_EOF")
                    or not successors
                ):
                    exits.append(block_id)
                    continue
            for next_id in successors:
                if next_id not in seen:
                    queue.append(next_id)
        if not exits and mode != "procedure":
            for block_id in reachable:
                block = self.block_index.get(block_id)
                if isinstance(block, dict) and not list(
                    block.get("summary_successors") or ()
                ):
                    exits.append(block_id)
        self.exit_cache[key] = list(exits)
        return [
            self.block_index[block_id]
            for block_id in exits
            if block_id in self.block_index
        ]

    def _add_segment_edge(
        self, source_segment: dict, target_segment: dict, kind: str, label: str = ""
    ) -> None:
        edge = (
            _safe_text(target_segment.get("id")),
            _safe_text(kind),
            _safe_text(label),
            bool(
                _safe_text(source_segment.get("scene_id"))
                != _safe_text(target_segment.get("scene_id"))
            ),
        )
        if edge in source_segment["out_edges"]:
            return
        source_segment["out_edges"].append(edge)
        target_segment["incoming_count"] = (
            int(target_segment.get("incoming_count", 0) or 0) + 1
        )

    def _build_segments(self) -> None:
        self.segment_index = {}
        self.stats["segment_count"] = 0
        block_to_segment = {}
        segment_lookup = {}
        for scene in self.scenes:
            segments = []
            scene_block_to_segment = {}
            blocks = list(scene.get("blocks") or ())
            unique_outgoing = {}
            unique_incoming = defaultdict(set)
            for block in blocks:
                grouped = _group_unique_edges(block.get("out_edges") or ())
                unique_outgoing[block["id"]] = grouped
                for target_id in grouped:
                    unique_incoming[target_id].add(block["id"])
            for block in blocks:
                if block["id"] in scene_block_to_segment:
                    continue
                members = [block]
                cursor = block
                while True:
                    if _safe_text(cursor.get("choice_option")):
                        break
                    grouped_out = unique_outgoing.get(cursor["id"], {})
                    if len(grouped_out) != 1:
                        break
                    target_id = next(iter(grouped_out))
                    _kind, _label, cross_scene = _collapse_edge_records(
                        grouped_out[target_id]
                    )
                    if cross_scene:
                        break
                    next_block = self.block_index.get(target_id)
                    if not isinstance(next_block, dict):
                        break
                    if _safe_text(next_block.get("choice_option")):
                        break
                    if target_id in scene_block_to_segment:
                        break
                    if len(unique_incoming.get(target_id, ())) != 1:
                        break
                    members.append(next_block)
                    cursor = next_block
                start_line, end_line = _member_line_span(members)
                segment = {
                    "id": _segment_key(
                        int(scene["scene_no"]), int(members[0]["start_ofs"])
                    ),
                    "scene_id": _safe_text(scene.get("scene_id")),
                    "scene_no": int(scene.get("scene_no", 0) or 0),
                    "scene_name": _safe_text(scene.get("scene_name")),
                    "start_ofs": int(members[0].get("start_ofs", 0) or 0),
                    "end_ofs": int(members[-1].get("end_ofs", 0) or 0),
                    "start_line": int(start_line),
                    "end_line": int(end_line),
                    "order": len(segments),
                    "dialogue": tuple(
                        payload
                        for member in members
                        for payload in member.get("dialogue") or ()
                    ),
                    "dialogue_count": sum(
                        int(member.get("dialogue_count", 0) or 0) for member in members
                    ),
                    "first_block_id": members[0]["id"],
                    "last_block_id": members[-1]["id"],
                    "out_edges": [],
                    "incoming_count": 0,
                }
                segments.append(segment)
                segment_id = _safe_text(segment.get("id"))
                self.segment_index[segment_id] = segment
                segment_lookup[segment_id] = segment
                for member in members:
                    scene_block_to_segment[member["id"]] = segment_id
                    block_to_segment[member["id"]] = segment_id
            scene["segments"] = segments
            scene["segment_by_block"] = scene_block_to_segment
            self.stats["segment_count"] += len(segments)
        for scene in self.scenes:
            for segment in scene.get("segments") or ():
                last_block = self.block_index.get(segment.get("last_block_id"))
                if not isinstance(last_block, dict):
                    continue
                for target_id, records in _group_unique_edges(
                    last_block.get("out_edges") or ()
                ).items():
                    kind, label, _cross_scene = _collapse_edge_records(records)
                    target_segment_id = block_to_segment.get(target_id)
                    if not target_segment_id:
                        continue
                    target_segment = segment_lookup.get(target_segment_id)
                    if not isinstance(target_segment, dict):
                        continue
                    if _safe_text(target_segment.get("id")) == _safe_text(
                        segment.get("id")
                    ):
                        continue
                    self._add_segment_edge(segment, target_segment, kind, label)
        for scene in self.scenes:
            scene["blocks"] = []
            scene["block_starts"] = []
            scene["block_by_start"] = {}
            scene["label_list"] = []
            scene["z_label_list"] = []
            scene["segment_by_block"] = {}
        self.block_index = {}
        self.call_records = []
        self.exit_cache = {}

    def _build_silent_resolutions(self) -> None:
        silent_ids = [
            segment_id
            for segment_id, segment in self.segment_index.items()
            if int(segment.get("dialogue_count", 0) or 0) == 0
        ]
        silent_id_set = set(silent_ids)
        nested_opaque = {}
        reverse = defaultdict(set)
        self.scene_has_visible = {}
        self.segment_edge_groups = {}
        for scene in self.scenes:
            scene_no = int(scene.get("scene_no", 0) or 0)
            segments = list(scene.get("segments") or ())
            self.scene_has_visible[scene_no] = any(
                int(segment.get("dialogue_count", 0) or 0) > 0 for segment in segments
            )
            for segment in segments:
                self.segment_edge_groups[_safe_text(segment.get("id"))] = (
                    _group_unique_edges(segment.get("out_edges") or ())
                )
        for segment_id in silent_ids:
            segment = self.segment_index.get(segment_id)
            if not isinstance(segment, dict):
                continue
            grouped_out = self.segment_edge_groups.get(segment_id, {})
            out_degree = len(grouped_out)
            incoming_count = int(segment.get("incoming_count", 0) or 0)
            kind_set = {
                _safe_text(record[1])
                for records in grouped_out.values()
                for record in records
                if _safe_text(record[1])
            }
            nested_opaque[segment_id] = bool(
                "return" in kind_set and (incoming_count > 1 or out_degree > 1)
            )
            for target_id in grouped_out:
                if target_id in silent_id_set:
                    reverse[target_id].add(segment_id)
        nested_resolutions = {segment_id: set() for segment_id in silent_ids}
        queue = deque(silent_ids)
        queued = set(silent_ids)
        while queue:
            segment_id = queue.popleft()
            queued.discard(segment_id)
            segment = self.segment_index.get(segment_id)
            if not isinstance(segment, dict):
                continue
            new_records = set()
            for target_id, records in self.segment_edge_groups.get(
                segment_id, {}
            ).items():
                kind, label, cross_scene = _collapse_edge_records(records)
                target = self.segment_index.get(_safe_text(target_id))
                if not isinstance(target, dict):
                    continue
                if int(target.get("dialogue_count", 0) or 0) > 0:
                    new_records.add(
                        (
                            _safe_text(target.get("id")),
                            _safe_text(kind),
                            _safe_text(label),
                            bool(cross_scene),
                        )
                    )
                    continue
                if bool(nested_opaque.get(segment_id)):
                    continue
                for rec in nested_resolutions.get(_safe_text(target.get("id")), ()):
                    next_kind, next_label, next_cross = _compose_seed(
                        _safe_text(kind),
                        _safe_text(label),
                        bool(cross_scene),
                        rec[1],
                        rec[2],
                        bool(rec[3]),
                    )
                    new_records.add((rec[0], next_kind, next_label, next_cross))
            if new_records == nested_resolutions.get(segment_id):
                continue
            nested_resolutions[segment_id] = new_records
            for pred_id in reverse.get(segment_id, ()):
                if pred_id not in queued:
                    queue.append(pred_id)
                    queued.add(pred_id)
        resolutions = {}
        for segment_id in silent_ids:
            segment = self.segment_index.get(segment_id)
            if not isinstance(segment, dict):
                continue
            new_records = set()
            for target_id, records in self.segment_edge_groups.get(
                segment_id, {}
            ).items():
                kind, label, cross_scene = _collapse_edge_records(records)
                target = self.segment_index.get(_safe_text(target_id))
                if not isinstance(target, dict):
                    continue
                if int(target.get("dialogue_count", 0) or 0) > 0:
                    new_records.add(
                        (
                            _safe_text(target.get("id")),
                            _safe_text(kind),
                            _safe_text(label),
                            bool(cross_scene),
                        )
                    )
                    continue
                for rec in nested_resolutions.get(_safe_text(target.get("id")), ()):
                    next_kind, next_label, next_cross = _compose_seed(
                        _safe_text(kind),
                        _safe_text(label),
                        bool(cross_scene),
                        rec[1],
                        rec[2],
                        bool(rec[3]),
                    )
                    new_records.add((rec[0], next_kind, next_label, next_cross))
            resolutions[segment_id] = new_records
        self.silent_resolutions = resolutions
        self.return_frontiers = {}
        self.same_scene_return_frontiers = {}
        self.same_scene_silent_frontiers = {}
        self.same_scene_near_return_frontiers = {}

    def _resolve_return_frontier_info(
        self, segment_id: str
    ) -> tuple[int | None, tuple[tuple[str, str, str, bool], ...]]:
        key = _safe_text(segment_id)
        cached = self.return_frontiers.get(key)
        if cached is not None:
            return cached
        start = self.segment_index.get(key)
        if not isinstance(start, dict):
            self.return_frontiers[key] = (None, ())
            return (None, ())
        if int(start.get("dialogue_count", 0) or 0) > 0:
            self.return_frontiers[key] = (None, ())
            return (None, ())
        start_scene_no = int(start.get("scene_no", 0) or 0)
        anchor_scene_no = (
            start_scene_no if bool(self.scene_has_visible.get(start_scene_no)) else None
        )
        best_distance = None
        resolved = set()
        queued = set()
        queue = deque()

        def enqueue(
            target_id: str,
            seed_kind: str,
            seed_label: str,
            seed_cross_scene: bool,
            anchor_scene_no_value,
            distance: int,
        ) -> None:
            nonlocal best_distance
            if best_distance is not None and int(distance) > int(best_distance):
                return
            target = self.segment_index.get(_safe_text(target_id))
            if not isinstance(target, dict):
                return
            if int(target.get("dialogue_count", 0) or 0) > 0:
                record = (
                    _safe_text(target.get("id")),
                    _safe_text(seed_kind),
                    _safe_text(seed_label),
                    bool(seed_cross_scene),
                )
                if best_distance is None or int(distance) < int(best_distance):
                    best_distance = int(distance)
                    resolved.clear()
                    resolved.add(record)
                elif int(distance) == int(best_distance):
                    resolved.add(record)
                return
            target_scene_no = int(target.get("scene_no", 0) or 0)
            next_anchor = anchor_scene_no_value
            if next_anchor is None:
                if bool(self.scene_has_visible.get(target_scene_no)):
                    next_anchor = target_scene_no
            elif target_scene_no != next_anchor and bool(
                self.scene_has_visible.get(target_scene_no)
            ):
                return
            if best_distance is not None and int(distance) >= int(best_distance):
                return
            state = (
                _safe_text(target.get("id")),
                _safe_text(seed_kind),
                _safe_text(seed_label),
                bool(seed_cross_scene),
                next_anchor,
            )
            if state in queued:
                return
            queued.add(state)
            queue.append(state + (int(distance),))

        for target_id, records in self.segment_edge_groups.get(key, {}).items():
            kind, label, cross_scene = _collapse_edge_records(records)
            enqueue(target_id, kind, label, bool(cross_scene), anchor_scene_no, 1)
        while queue:
            (
                current_id,
                seed_kind,
                seed_label,
                seed_cross_scene,
                anchor_scene_no_value,
                distance,
            ) = queue.popleft()
            for target_id, records in self.segment_edge_groups.get(
                current_id, {}
            ).items():
                kind, label, cross_scene = _collapse_edge_records(records)
                next_kind, next_label, next_cross = _compose_seed(
                    seed_kind,
                    seed_label,
                    bool(seed_cross_scene),
                    _safe_text(kind),
                    _safe_text(label),
                    bool(cross_scene),
                )
                enqueue(
                    target_id,
                    next_kind,
                    next_label,
                    bool(next_cross),
                    anchor_scene_no_value,
                    int(distance) + 1,
                )
        result = tuple(
            sorted(
                resolved,
                key=lambda item: (
                    int(
                        self.segment_index.get(_safe_text(item[0]), {}).get(
                            "scene_no", 0
                        )
                        or 0
                    ),
                    int(
                        self.segment_index.get(_safe_text(item[0]), {}).get(
                            "start_ofs", 0
                        )
                        or 0
                    ),
                    _safe_text(item[1]),
                    _safe_text(item[2]),
                ),
            )
        )
        info = (
            None if best_distance is None else int(best_distance),
            result,
        )
        self.return_frontiers[key] = info
        return info

    def _resolve_same_scene_return_frontier(
        self, segment_id: str
    ) -> tuple[tuple[str, str, str, bool], ...]:
        key = _safe_text(segment_id)
        cached = self.same_scene_return_frontiers.get(key)
        if cached is not None:
            return cached
        start = self.segment_index.get(key)
        if not isinstance(start, dict):
            self.same_scene_return_frontiers[key] = ()
            return ()
        if int(start.get("dialogue_count", 0) or 0) > 0:
            self.same_scene_return_frontiers[key] = ()
            return ()
        start_scene_no = int(start.get("scene_no", 0) or 0)
        best_distance = None
        resolved = set()
        queued = set()
        queue = deque([(key, "", "", False, 0)])
        while queue:
            current_id, seed_kind, seed_label, seed_cross_scene, distance = (
                queue.popleft()
            )
            if best_distance is not None and int(distance) + 1 + 1 > int(best_distance):
                continue
            for target_id, records in self.segment_edge_groups.get(
                current_id, {}
            ).items():
                kind, label, cross_scene = _collapse_edge_records(records)
                next_kind, next_label, next_cross = _compose_seed(
                    seed_kind,
                    seed_label,
                    bool(seed_cross_scene),
                    _safe_text(kind),
                    _safe_text(label),
                    bool(cross_scene),
                )
                target = self.segment_index.get(_safe_text(target_id))
                if not isinstance(target, dict):
                    continue
                if _safe_text(kind) == "return":
                    frontier_distance, frontier_records = (
                        self._resolve_return_frontier_info(_safe_text(target.get("id")))
                    )
                    frontier_target_ids = {rec[0] for rec in frontier_records}
                    frontier_kind_set = {
                        _safe_text(rec[1])
                        for rec in frontier_records
                        if _safe_text(rec[1])
                    }
                    if (
                        frontier_distance is None
                        or int(frontier_distance) > SHORT_RETURN_FRONTIER_MAX_DISTANCE
                        or len(frontier_target_ids) != 1
                        or "return" in frontier_kind_set
                    ):
                        continue
                    total_distance = int(distance) + 1 + int(frontier_distance)
                    if best_distance is not None and total_distance > int(
                        best_distance
                    ):
                        continue
                    new_records = {
                        (
                            rec[0],
                            *_compose_seed(
                                next_kind,
                                next_label,
                                bool(next_cross),
                                rec[1],
                                rec[2],
                                bool(rec[3]),
                            ),
                        )
                        for rec in frontier_records
                    }
                    if best_distance is None or total_distance < int(best_distance):
                        best_distance = total_distance
                        resolved = set(new_records)
                    elif total_distance == int(best_distance):
                        resolved.update(new_records)
                    continue
                if bool(cross_scene):
                    continue
                if int(target.get("scene_no", -1) or -1) != start_scene_no:
                    continue
                if int(target.get("dialogue_count", 0) or 0) > 0:
                    continue
                next_distance = int(distance) + 1
                if next_distance > LATE_RETURN_CHAIN_MAX_DISTANCE:
                    continue
                state = (
                    _safe_text(target.get("id")),
                    _safe_text(next_kind),
                    _safe_text(next_label),
                    bool(next_cross),
                )
                if state in queued:
                    continue
                queued.add(state)
                queue.append(state + (next_distance,))
        result = tuple(
            sorted(
                resolved,
                key=lambda item: (
                    int(self.segment_index.get(item[0], {}).get("scene_no", 0) or 0),
                    int(self.segment_index.get(item[0], {}).get("start_ofs", 0) or 0),
                    _safe_text(item[1]),
                    _safe_text(item[2]),
                ),
            )
        )
        self.same_scene_return_frontiers[key] = result
        return result

    def _resolve_same_scene_silent_frontier(
        self, segment_id: str
    ) -> tuple[tuple[str, str, str, bool], ...]:
        key = _safe_text(segment_id)
        cached = self.same_scene_silent_frontiers.get(key)
        if cached is not None:
            return cached
        start = self.segment_index.get(key)
        if not isinstance(start, dict):
            self.same_scene_silent_frontiers[key] = ()
            return ()
        if int(start.get("dialogue_count", 0) or 0) > 0:
            self.same_scene_silent_frontiers[key] = ()
            return ()
        start_scene_no = int(start.get("scene_no", 0) or 0)
        best_distance = None
        resolved = set()
        queued = set([(key, "", "", False)])
        queue = deque([(key, "", "", False, 0)])
        while queue:
            current_id, seed_kind, seed_label, seed_cross_scene, distance = (
                queue.popleft()
            )
            if best_distance is not None and int(distance) >= int(best_distance):
                continue
            for target_id, records in self.segment_edge_groups.get(
                current_id, {}
            ).items():
                kind, label, cross_scene = _collapse_edge_records(records)
                if bool(cross_scene) or _safe_text(kind) == "return":
                    continue
                next_kind, next_label, next_cross = _compose_seed(
                    seed_kind,
                    seed_label,
                    bool(seed_cross_scene),
                    _safe_text(kind),
                    _safe_text(label),
                    bool(cross_scene),
                )
                target = self.segment_index.get(_safe_text(target_id))
                if not isinstance(target, dict):
                    continue
                if int(target.get("scene_no", -1) or -1) != start_scene_no:
                    continue
                next_distance = int(distance) + 1
                if int(target.get("dialogue_count", 0) or 0) > 0:
                    record = (
                        _safe_text(target.get("id")),
                        _safe_text(next_kind),
                        _safe_text(next_label),
                        bool(next_cross),
                    )
                    if best_distance is None or next_distance < int(best_distance):
                        best_distance = next_distance
                        resolved = {record}
                    elif next_distance == int(best_distance):
                        resolved.add(record)
                    continue
                if next_distance > SAME_SCENE_SILENT_MAX_DISTANCE:
                    continue
                state = (
                    _safe_text(target.get("id")),
                    _safe_text(next_kind),
                    _safe_text(next_label),
                    bool(next_cross),
                )
                if state in queued:
                    continue
                queued.add(state)
                queue.append(state + (next_distance,))
        result = tuple(
            sorted(
                resolved,
                key=lambda item: (
                    int(self.segment_index.get(item[0], {}).get("scene_no", 0) or 0),
                    int(self.segment_index.get(item[0], {}).get("start_ofs", 0) or 0),
                    _safe_text(item[1]),
                    _safe_text(item[2]),
                ),
            )
        )
        self.same_scene_silent_frontiers[key] = result
        return result

    def _resolve_same_scene_near_return_frontier(
        self, segment_id: str
    ) -> tuple[tuple[str, str, str, bool], ...]:
        key = _safe_text(segment_id)
        cached = self.same_scene_near_return_frontiers.get(key)
        if cached is not None:
            return cached
        start = self.segment_index.get(key)
        if not isinstance(start, dict):
            self.same_scene_near_return_frontiers[key] = ()
            return ()
        if int(start.get("dialogue_count", 0) or 0) > 0:
            self.same_scene_near_return_frontiers[key] = ()
            return ()
        start_scene_no = int(start.get("scene_no", 0) or 0)
        best_distance = None
        resolved = set()
        queued = set()
        queue = deque([(key, "", "", False, 0)])
        while queue:
            current_id, seed_kind, seed_label, seed_cross_scene, distance = (
                queue.popleft()
            )
            if best_distance is not None and int(distance) + 1 + 1 > int(best_distance):
                continue
            for target_id, records in self.segment_edge_groups.get(
                current_id, {}
            ).items():
                kind, label, cross_scene = _collapse_edge_records(records)
                next_kind, next_label, next_cross = _compose_seed(
                    seed_kind,
                    seed_label,
                    bool(seed_cross_scene),
                    _safe_text(kind),
                    _safe_text(label),
                    bool(cross_scene),
                )
                target = self.segment_index.get(_safe_text(target_id))
                if not isinstance(target, dict):
                    continue
                if _safe_text(kind) == "return":
                    frontier_distance, frontier_records = (
                        self._resolve_return_frontier_info(_safe_text(target.get("id")))
                    )
                    frontier_target_ids = {rec[0] for rec in frontier_records}
                    frontier_kind_set = {
                        _safe_text(rec[1])
                        for rec in frontier_records
                        if _safe_text(rec[1])
                    }
                    if (
                        frontier_distance is None
                        or int(frontier_distance) > NEAR_RETURN_FRONTIER_MAX_DISTANCE
                        or len(frontier_target_ids) != 1
                        or "return" in frontier_kind_set
                    ):
                        continue
                    total_distance = int(distance) + 1 + int(frontier_distance)
                    if best_distance is not None and total_distance > int(
                        best_distance
                    ):
                        continue
                    new_records = {
                        (
                            rec[0],
                            *_compose_seed(
                                next_kind,
                                next_label,
                                bool(next_cross),
                                rec[1],
                                rec[2],
                                bool(rec[3]),
                            ),
                        )
                        for rec in frontier_records
                        if int(
                            self.segment_index.get(_safe_text(rec[0]), {}).get(
                                "scene_no", -1
                            )
                            or -1
                        )
                        == start_scene_no
                    }
                    if not new_records:
                        continue
                    if best_distance is None or total_distance < int(best_distance):
                        best_distance = total_distance
                        resolved = set(new_records)
                    elif total_distance == int(best_distance):
                        resolved.update(new_records)
                    continue
                if bool(cross_scene):
                    continue
                if int(target.get("scene_no", -1) or -1) != start_scene_no:
                    continue
                if int(target.get("dialogue_count", 0) or 0) > 0:
                    continue
                next_distance = int(distance) + 1
                if next_distance > NEAR_RETURN_CHAIN_MAX_DISTANCE:
                    continue
                state = (
                    _safe_text(target.get("id")),
                    _safe_text(next_kind),
                    _safe_text(next_label),
                    bool(next_cross),
                )
                if state in queued:
                    continue
                queued.add(state)
                queue.append(state + (next_distance,))
        result = tuple(
            sorted(
                resolved,
                key=lambda item: (
                    int(self.segment_index.get(item[0], {}).get("scene_no", 0) or 0),
                    int(self.segment_index.get(item[0], {}).get("start_ofs", 0) or 0),
                    _safe_text(item[1]),
                    _safe_text(item[2]),
                ),
            )
        )
        self.same_scene_near_return_frontiers[key] = result
        return result

    def _node_title(self, node: dict) -> str:
        scene_name = _safe_text(node.get("scene_name"))
        line_ref = _format_line_ref(
            int(node.get("start_line", 0) or 0), int(node.get("end_line", 0) or 0)
        )
        if scene_name and line_ref:
            return f"{scene_name} @ {line_ref}"
        if scene_name:
            return scene_name
        return line_ref or _safe_text(node.get("id"))

    def _add_plot_edge(
        self,
        edges: list,
        edge_seen: set,
        source_id: str,
        target_id: str,
        kind: str,
        label: str,
        node_by_id: dict,
        merge_barrier: bool = False,
    ) -> None:
        if (
            source_id == target_id
            or source_id not in node_by_id
            or target_id not in node_by_id
        ):
            return
        key = (
            _safe_text(source_id),
            _safe_text(target_id),
            _safe_text(kind),
            _safe_text(label),
        )
        if key in edge_seen:
            return
        edge_seen.add(key)
        edges.append(
            {
                "source": key[0],
                "target": key[1],
                "kind": key[2],
                "label": key[3],
                "cross_scene": bool(
                    _safe_text(node_by_id[key[0]].get("scene_id"))
                    != _safe_text(node_by_id[key[1]].get("scene_id"))
                ),
                "merge_barrier": bool(merge_barrier),
            }
        )

    def _compress_plot_graph(
        self, nodes: list[dict], edges: list[dict]
    ) -> tuple[list[dict], list[dict]]:
        node_by_id = {_safe_text(node.get("id")): node for node in nodes}
        outgoing = defaultdict(list)
        incoming = defaultdict(list)
        for edge in edges:
            outgoing[_safe_text(edge.get("source"))].append(edge)
            incoming[_safe_text(edge.get("target"))].append(edge)
        ordered_ids = sorted(
            node_by_id,
            key=lambda node_id: (
                int(node_by_id[node_id].get("scene_no", 0) or 0),
                int(node_by_id[node_id].get("order", 0) or 0),
                int(node_by_id[node_id].get("start_ofs", 0) or 0),
            ),
        )
        remap = {}
        merged_nodes = []
        merged_node_by_id = {}
        visited = set()
        for node_id in ordered_ids:
            if node_id in visited:
                continue
            members = [node_by_id[node_id]]
            visited.add(node_id)
            cursor_id = node_id
            while True:
                next_edges = outgoing.get(cursor_id, [])
                if len(next_edges) != 1:
                    break
                edge = next_edges[0]
                if bool(edge.get("merge_barrier")):
                    break
                if bool(edge.get("cross_scene")):
                    break
                target_id = _safe_text(edge.get("target"))
                target_node = node_by_id.get(target_id)
                if not isinstance(target_node, dict):
                    break
                if target_id in visited:
                    break
                if len(incoming.get(target_id, [])) != 1:
                    break
                if int(target_node.get("scene_no", -1) or -1) != int(
                    members[0].get("scene_no", -2) or -2
                ):
                    break
                members.append(target_node)
                visited.add(target_id)
                cursor_id = target_id
            merged = dict(members[0])
            merged["end_ofs"] = int(members[-1].get("end_ofs", 0) or 0)
            _start_line, merged_end_line = _member_line_span(members)
            merged["start_line"] = int(_start_line or merged.get("start_line", 0) or 0)
            merged["end_line"] = int(merged_end_line)
            merged["dialogue_count"] = sum(
                int(member.get("dialogue_count", 0) or 0) for member in members
            )
            merged["payload"] = [
                line for member in members for line in list(member.get("payload") or ())
            ]
            merged["order"] = int(members[0].get("order", 0) or 0)
            merged["title"] = self._node_title(merged)
            merged_nodes.append(merged)
            merged_id = _safe_text(merged.get("id"))
            merged_node_by_id[merged_id] = merged
            for member in members:
                remap[_safe_text(member.get("id"))] = merged_id
        merged_grouped = defaultdict(list)
        for edge in edges:
            source_id = remap.get(_safe_text(edge.get("source")))
            target_id = remap.get(_safe_text(edge.get("target")))
            if not source_id or not target_id or source_id == target_id:
                continue
            merged_grouped[(source_id, target_id)].append(edge)
        merged_edges = []
        for key, records in merged_grouped.items():
            source_id, target_id = key
            source_node = merged_node_by_id[source_id]
            target_node = merged_node_by_id[target_id]
            kind, label, _cross_scene = _collapse_edge_records(
                (
                    target_id,
                    _safe_text(record.get("kind")),
                    _safe_text(record.get("label")),
                    bool(record.get("cross_scene")),
                )
                for record in records
            )
            merged_edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "kind": kind,
                    "label": label,
                    "cross_scene": bool(
                        _safe_text(source_node.get("scene_id"))
                        != _safe_text(target_node.get("scene_id"))
                    ),
                    "merge_barrier": any(
                        bool(record.get("merge_barrier")) for record in records
                    ),
                }
            )
        final_incoming = defaultdict(int)
        final_outgoing = defaultdict(int)
        for edge in merged_edges:
            final_outgoing[_safe_text(edge.get("source"))] += 1
            final_incoming[_safe_text(edge.get("target"))] += 1
        for node in merged_nodes:
            node["incoming"] = int(final_incoming.get(_safe_text(node.get("id")), 0))
            node["outgoing"] = int(final_outgoing.get(_safe_text(node.get("id")), 0))
        merged_nodes.sort(
            key=lambda item: (
                int(item["scene_no"]),
                int(item["order"]),
                int(item["start_ofs"]),
            )
        )
        return merged_nodes, merged_edges

    def _prune_shortcut_edges(self, nodes: list[dict], edges: list[dict]) -> list[dict]:
        node_by_id = {_safe_text(node.get("id")): node for node in nodes}
        outgoing = defaultdict(list)
        for edge in edges:
            outgoing[_safe_text(edge.get("source"))].append(edge)
        reachable_cache = {}

        def descendants(start_id: str) -> set[str]:
            cache = reachable_cache.get(start_id)
            if cache is not None:
                return cache
            start_node = node_by_id.get(start_id)
            if not isinstance(start_node, dict):
                reachable_cache[start_id] = set()
                return reachable_cache[start_id]
            scene_no = int(start_node.get("scene_no", -1) or -1)
            seen = set()
            queue = deque([start_id])
            while queue:
                current_id = queue.popleft()
                if current_id in seen:
                    continue
                seen.add(current_id)
                for edge in outgoing.get(current_id, ()):
                    if bool(edge.get("cross_scene")):
                        continue
                    next_id = _safe_text(edge.get("target"))
                    next_node = node_by_id.get(next_id)
                    if not isinstance(next_node, dict):
                        continue
                    if int(next_node.get("scene_no", -2) or -2) != scene_no:
                        continue
                    if next_id not in seen:
                        queue.append(next_id)
            seen.discard(start_id)
            reachable_cache[start_id] = seen
            return seen

        keep_flags = [True] * len(edges)
        edge_index = {id(edge): idx for idx, edge in enumerate(edges)}
        for source_id, edge_list in outgoing.items():
            scene_edges = [
                edge
                for edge in edge_list
                if not bool(edge.get("merge_barrier"))
                if not bool(edge.get("cross_scene"))
                and int(
                    node_by_id.get(_safe_text(edge.get("target")), {}).get(
                        "scene_no", -1
                    )
                    or -1
                )
                == int(node_by_id.get(source_id, {}).get("scene_no", -2) or -2)
            ]
            if len(scene_edges) < 2:
                continue
            for edge in scene_edges:
                target_id = _safe_text(edge.get("target"))
                other_targets = [
                    _safe_text(other_edge.get("target"))
                    for other_edge in scene_edges
                    if other_edge is not edge
                ]
                if other_targets and all(
                    target_id in descendants(other_id) for other_id in other_targets
                ):
                    keep_flags[edge_index[id(edge)]] = False
        return [edge for idx, edge in enumerate(edges) if keep_flags[idx]]

    def _assign_components(self, nodes: list[dict], edges: list[dict]) -> list[dict]:
        node_by_id = {_safe_text(node.get("id")): node for node in nodes}
        adjacency = defaultdict(set)
        for edge in edges:
            source_id = _safe_text(edge.get("source"))
            target_id = _safe_text(edge.get("target"))
            if source_id in node_by_id and target_id in node_by_id:
                adjacency[source_id].add(target_id)
                adjacency[target_id].add(source_id)
        ordered_ids = sorted(
            node_by_id,
            key=lambda node_id: (
                int(node_by_id[node_id].get("scene_no", 0) or 0),
                int(node_by_id[node_id].get("order", 0) or 0),
                int(node_by_id[node_id].get("start_ofs", 0) or 0),
            ),
        )
        component_by_node = {}
        components = []
        for node_id in ordered_ids:
            if node_id in component_by_node:
                continue
            queue = deque([node_id])
            members = []
            component_index = len(components)
            while queue:
                current_id = queue.popleft()
                if current_id in component_by_node:
                    continue
                component_by_node[current_id] = component_index
                members.append(current_id)
                for next_id in sorted(adjacency.get(current_id, ())):
                    if next_id not in component_by_node:
                        queue.append(next_id)
            member_set = set(members)
            component_edges = [
                edge
                for edge in edges
                if _safe_text(edge.get("source")) in member_set
                and _safe_text(edge.get("target")) in member_set
            ]
            scene_ids = sorted(
                {
                    _safe_text(node_by_id[member_id].get("scene_id"))
                    for member_id in members
                }
            )
            components.append(
                {
                    "id": f"component:{component_index + 1:d}",
                    "node_count": len(members),
                    "edge_count": len(component_edges),
                    "scene_count": len(scene_ids),
                    "scene_ids": scene_ids,
                }
            )
        for node_id, component_index in component_by_node.items():
            node = node_by_id[node_id]
            component = components[component_index]
            node["component_id"] = _safe_text(component.get("id"))
            node["component_size"] = int(component.get("node_count", 0) or 0)
        return components

    def _build_tutorial_graph(self) -> dict:
        nodes = []
        node_by_id = {}
        scene_nodes = defaultdict(list)
        order_by_scene = defaultdict(int)
        for scene in self.scenes:
            for segment in scene.get("segments") or ():
                if int(segment.get("dialogue_count", 0) or 0) <= 0:
                    continue
                node = {
                    "id": _safe_text(segment.get("id")),
                    "scene_id": _safe_text(scene.get("scene_id")),
                    "scene_no": int(scene.get("scene_no", 0) or 0),
                    "scene_name": _safe_text(scene.get("scene_name")),
                    "title": self._node_title(segment),
                    "order": int(order_by_scene[int(scene["scene_no"])]),
                    "start_ofs": int(segment.get("start_ofs", 0) or 0),
                    "end_ofs": int(segment.get("end_ofs", 0) or 0),
                    "start_line": int(segment.get("start_line", 0) or 0),
                    "end_line": int(segment.get("end_line", 0) or 0),
                    "dialogue_count": int(segment.get("dialogue_count", 0) or 0),
                    "payload": list(segment.get("dialogue") or ()),
                }
                order_by_scene[int(scene["scene_no"])] += 1
                nodes.append(node)
                node_by_id[node["id"]] = node
                scene_nodes[int(scene["scene_no"])].append(node)
        edges = []
        edge_seen = set()
        for node in nodes:
            segment = self.segment_index.get(_safe_text(node.get("id")))
            if not isinstance(segment, dict):
                continue
            for target_id, kind, label, cross_scene in segment.get("out_edges") or ():
                target = self.segment_index.get(_safe_text(target_id))
                if not isinstance(target, dict):
                    continue
                if int(target.get("dialogue_count", 0) or 0) > 0:
                    self._add_plot_edge(
                        edges,
                        edge_seen,
                        _safe_text(node.get("id")),
                        _safe_text(target.get("id")),
                        _safe_text(kind),
                        _safe_text(label),
                        node_by_id,
                    )
                    continue
                target_scene_no = int(target.get("scene_no", 0) or 0)
                if (
                    not bool(self.scene_has_visible.get(target_scene_no))
                    and _safe_text(kind) != "return"
                ):
                    continue
                frontier_distance = None
                if _safe_text(kind) == "return":
                    frontier_distance, silent_records = (
                        self._resolve_return_frontier_info(_safe_text(target.get("id")))
                    )
                else:
                    silent_records = self.silent_resolutions.get(
                        _safe_text(target.get("id")), ()
                    )
                late_return_safe = False
                if (
                    not silent_records
                    and _safe_text(kind) != "return"
                    and int(target.get("scene_no", -1) or -1)
                    == int(segment.get("scene_no", -2) or -2)
                ):
                    silent_records = self._resolve_same_scene_return_frontier(
                        _safe_text(target.get("id"))
                    )
                    late_return_safe = bool(silent_records)
                same_scene_silent_safe = False
                if not silent_records and int(target.get("scene_no", -1) or -1) == int(
                    segment.get("scene_no", -2) or -2
                ):
                    silent_records = self._resolve_same_scene_silent_frontier(
                        _safe_text(target.get("id"))
                    )
                    same_scene_silent_safe = bool(silent_records)
                same_scene_helper_safe = False
                if not silent_records and int(target.get("scene_no", -1) or -1) == int(
                    segment.get("scene_no", -2) or -2
                ):
                    helper_distance, helper_records = (
                        self._resolve_return_frontier_info(_safe_text(target.get("id")))
                    )
                    helper_target_ids = {rec[0] for rec in helper_records}
                    helper_scene_ids = {
                        _safe_text(
                            node_by_id.get(_safe_text(rec[0]), {}).get("scene_id")
                        )
                        for rec in helper_records
                    }
                    if (
                        helper_distance is not None
                        and int(helper_distance)
                        <= SAME_SCENE_HELPER_FRONTIER_MAX_DISTANCE
                        and len(helper_target_ids) == 1
                        and len(helper_scene_ids) == 1
                        and _safe_text(
                            node_by_id.get(_safe_text(node.get("id")), {}).get(
                                "scene_id"
                            )
                        )
                        in helper_scene_ids
                    ):
                        silent_records = helper_records
                        same_scene_helper_safe = bool(silent_records)
                same_scene_near_return_safe = False
                if int(target.get("scene_no", -1) or -1) == int(
                    segment.get("scene_no", -2) or -2
                ):
                    near_records = self._resolve_same_scene_near_return_frontier(
                        _safe_text(target.get("id"))
                    )
                    near_target_ids = {rec[0] for rec in near_records}
                    near_scene_ids = {
                        _safe_text(
                            node_by_id.get(_safe_text(rec[0]), {}).get("scene_id")
                        )
                        for rec in near_records
                    }
                    near_order_gaps = {
                        int(
                            node_by_id.get(_safe_text(rec[0]), {}).get("order", -999999)
                            or -999999
                        )
                        - int(node.get("order", 0) or 0)
                        for rec in near_records
                    }
                    if (
                        len(near_target_ids) == 1
                        and len(near_scene_ids) == 1
                        and _safe_text(node.get("scene_id")) in near_scene_ids
                        and len(near_order_gaps) == 1
                    ):
                        order_gap = next(iter(near_order_gaps))
                        if 0 < int(order_gap) <= NEAR_RETURN_ORDER_GAP_MAX:
                            existing_forward_near = False
                            for existing_rec in silent_records:
                                if _safe_text(
                                    node_by_id.get(_safe_text(existing_rec[0]), {}).get(
                                        "scene_id"
                                    )
                                ) != _safe_text(node.get("scene_id")):
                                    continue
                                existing_gap = int(
                                    node_by_id.get(_safe_text(existing_rec[0]), {}).get(
                                        "order", -999999
                                    )
                                    or -999999
                                ) - int(node.get("order", 0) or 0)
                                if 0 < int(existing_gap) <= NEAR_RETURN_ORDER_GAP_MAX:
                                    existing_forward_near = True
                                    break
                            if not existing_forward_near:
                                silent_records = near_records
                                same_scene_near_return_safe = bool(silent_records)
                frontier_target_ids = {rec[0] for rec in silent_records}
                frontier_kind_set = {
                    _safe_text(rec[1]) for rec in silent_records if _safe_text(rec[1])
                }
                for rec in silent_records:
                    source_scene_id = _safe_text(
                        node_by_id.get(_safe_text(node.get("id")), {}).get("scene_id")
                    )
                    target_scene_id = _safe_text(
                        node_by_id.get(_safe_text(rec[0]), {}).get("scene_id")
                    )
                    if source_scene_id != target_scene_id:
                        if (
                            _safe_text(kind) != "return"
                            and not bool(late_return_safe)
                            and not bool(same_scene_silent_safe)
                            and not bool(same_scene_helper_safe)
                            and not bool(same_scene_near_return_safe)
                        ):
                            continue
                        if (
                            not bool(late_return_safe)
                            and not bool(same_scene_silent_safe)
                            and not bool(same_scene_helper_safe)
                            and not bool(same_scene_near_return_safe)
                            and (
                                frontier_distance is None
                                or int(frontier_distance)
                                > SHORT_RETURN_FRONTIER_MAX_DISTANCE
                                or len(frontier_target_ids) != 1
                                or "return" in frontier_kind_set
                            )
                        ):
                            continue
                    next_kind, next_label, next_cross = _compose_seed(
                        _safe_text(kind),
                        _safe_text(label),
                        bool(cross_scene),
                        rec[1],
                        rec[2],
                        bool(rec[3]),
                    )
                    self._add_plot_edge(
                        edges,
                        edge_seen,
                        _safe_text(node.get("id")),
                        _safe_text(rec[0]),
                        next_kind,
                        next_label,
                        node_by_id,
                        merge_barrier=bool(
                            same_scene_helper_safe or same_scene_near_return_safe
                        ),
                    )
        grouped_edges = defaultdict(list)
        for edge in edges:
            grouped_edges[
                (_safe_text(edge.get("source")), _safe_text(edge.get("target")))
            ].append(edge)
        collapsed_edges = []
        for key, records in grouped_edges.items():
            source_id, target_id = key
            kind, label, cross_scene = _collapse_edge_records(
                (
                    target_id,
                    _safe_text(record.get("kind")),
                    _safe_text(record.get("label")),
                    bool(record.get("cross_scene")),
                )
                for record in records
            )
            collapsed_edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "kind": kind,
                    "label": label,
                    "cross_scene": cross_scene,
                    "merge_barrier": any(
                        bool(record.get("merge_barrier")) for record in records
                    ),
                }
            )
        edges = collapsed_edges
        incoming = defaultdict(int)
        outgoing = defaultdict(int)
        for edge in edges:
            incoming[_safe_text(edge.get("target"))] += 1
            outgoing[_safe_text(edge.get("source"))] += 1
        for node in nodes:
            node["incoming"] = int(incoming.get(_safe_text(node.get("id")), 0))
            node["outgoing"] = int(outgoing.get(_safe_text(node.get("id")), 0))
        nodes, edges = self._compress_plot_graph(nodes, edges)
        edges = self._prune_shortcut_edges(nodes, edges)
        nodes, edges = self._compress_plot_graph(nodes, edges)
        components_json = self._assign_components(nodes, edges)
        scenes_json = []
        grouped = defaultdict(list)
        for node in nodes:
            grouped[int(node["scene_no"])].append(node)
        for scene in self.scenes:
            group = grouped.get(int(scene["scene_no"]), [])
            if not group:
                continue
            scenes_json.append(
                {
                    "id": _safe_text(scene.get("scene_id")),
                    "scene_no": int(scene.get("scene_no", 0) or 0),
                    "scene_name": _safe_text(scene.get("scene_name")),
                    "node_count": len(group),
                    "dialogue_count": sum(
                        int(node.get("dialogue_count", 0) or 0) for node in group
                    ),
                }
            )
        scenes_json.sort(key=lambda item: (int(item["scene_no"]), item["scene_name"]))
        nodes.sort(
            key=lambda item: (
                int(item["scene_no"]),
                int(item["order"]),
                int(item["start_ofs"]),
            )
        )
        for idx, node in enumerate(nodes, 1):
            node["node_no"] = int(idx)
        for idx, edge in enumerate(edges, 1):
            edge.pop("merge_barrier", None)
            edge["id"] = f"edge:{idx:d}"
        self.stats["node_count"] = len(nodes)
        self.stats["edge_count"] = len(edges)
        return {
            "format": FORMAT_NAME,
            "generated_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "source": {
                "path": self.input_pck,
                "name": self.input_name,
            },
            "stats": {
                "scene_count": int(self.stats.get("scene_count", 0) or 0),
                "dialogue_count": int(self.stats.get("dialogue_count", 0) or 0),
                "node_count": int(self.stats.get("node_count", 0) or 0),
                "edge_count": int(self.stats.get("edge_count", 0) or 0),
                "block_count": int(self.stats.get("block_count", 0) or 0),
                "block_edge_count": int(self.stats.get("block_edge_count", 0) or 0),
                "segment_count": int(self.stats.get("segment_count", 0) or 0),
                "skipped_scenes": int(self.stats.get("skipped_scenes", 0) or 0),
                "unresolved_commands": int(
                    self.stats.get("unresolved_commands", 0) or 0
                ),
                "component_count": len(components_json),
            },
            "scenes": scenes_json,
            "components": components_json,
            "nodes": nodes,
            "edges": edges,
        }


def _write_json(output_json: str, data: dict) -> None:
    out_path = Path(output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, indent=2) + "\r\n"
    out_path.write_text(payload, encoding="utf-8", newline="\r\n")


def _write_viewer_copy(output_json: str) -> str | None:
    template_path = Path(__file__).with_name(VIEWER_FILE_NAME)
    if not template_path.is_file():
        return None
    viewer_path = Path(output_json).with_name(VIEWER_FILE_NAME)
    content = template_path.read_text(encoding="utf-8")
    current = viewer_path.read_text(encoding="utf-8") if viewer_path.is_file() else None
    if current != content:
        viewer_path.write_text(content, encoding="utf-8", newline="\r\n")
    return str(viewer_path)


class _ViewerRequestState:
    def __init__(self):
        self._lock = threading.Lock()
        self.last_request = time.monotonic()
        self.viewer_hits = 0
        self.json_hits = 0

    def record(self, name: str, viewer_name: str, json_name: str) -> None:
        current_name = _safe_text(name)
        with self._lock:
            self.last_request = time.monotonic()
            if current_name == viewer_name:
                self.viewer_hits += 1
            elif current_name == json_name:
                self.json_hits += 1

    def snapshot(self) -> tuple[float, int, int]:
        with self._lock:
            return (self.last_request, self.viewer_hits, self.json_hits)


def _try_open_generated_viewer(viewer_path: str | None, output_json: str) -> bool:
    if not viewer_path:
        return False
    viewer = Path(viewer_path).resolve()
    json_path = Path(output_json).resolve()
    serve_dir = viewer.parent
    viewer_name = viewer.name
    json_name = json_path.name
    if not serve_dir.is_dir():
        return False
    state = _ViewerRequestState()

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *handler_args, **handler_kwargs):
            super().__init__(*handler_args, directory=str(serve_dir), **handler_kwargs)

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            state.record(
                Path(urllib.parse.unquote(parsed.path)).name,
                viewer_name,
                json_name,
            )
            super().do_GET()

        def log_message(self, format, *handler_args):
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except Exception:
        try:
            return bool(webbrowser.open(viewer.as_uri(), new=2))
        except Exception:
            return False
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": VIEWER_SERVER_POLL_SECONDS},
        daemon=True,
    )
    thread.start()
    opened = False
    try:
        quoted_viewer = urllib.parse.quote(viewer_name)
        quoted_json = urllib.parse.quote(json_name)
        url = (
            f"http://127.0.0.1:{int(server.server_port):d}/{quoted_viewer}"
            f"?json={quoted_json}"
        )
        try:
            opened = bool(webbrowser.open(url, new=2))
        except Exception:
            opened = False
        started_at = time.monotonic()
        while True:
            last_request, viewer_hits, json_hits = state.snapshot()
            now = time.monotonic()
            if json_hits > 0 and now - last_request >= VIEWER_SERVER_IDLE_SECONDS:
                break
            if viewer_hits <= 0 and now - started_at >= VIEWER_SERVER_START_SECONDS:
                break
            if (
                viewer_hits > 0
                and json_hits <= 0
                and now - started_at >= VIEWER_SERVER_START_SECONDS
            ):
                break
            time.sleep(VIEWER_SERVER_POLL_SECONDS)
        _last_request, viewer_hits, json_hits = state.snapshot()
        opened = bool(opened or viewer_hits > 0 or json_hits > 0)
    finally:
        server.shutdown()
        thread.join(timeout=VIEWER_SERVER_START_SECONDS)
        server.server_close()
    if opened:
        return True
    try:
        return bool(webbrowser.open(viewer.as_uri(), new=2))
    except Exception:
        return False


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if not args:
        _usage()
        return 2
    if args[0] in ("-h", "--help", "help"):
        _usage(sys.stdout)
        return 0
    if len(args) not in (1, 2):
        _usage()
        return 2
    input_pck = args[0]
    output_json = args[1] if len(args) == 2 else _default_output_path(input_pck)
    if not os.path.isfile(input_pck):
        eprint(f"tutorial: input not found: {input_pck}", errors="replace")
        return 1
    try:
        builder = TutorialBuilder(input_pck)
        data = builder.build()
        _status(f"writing JSON: {os.path.abspath(output_json)}")
        _write_json(output_json, data)
        viewer_path = _write_viewer_copy(output_json)
        if viewer_path:
            _status(f"writing viewer: {os.path.abspath(viewer_path)}")
    except Exception as exc:
        eprint(f"tutorial: {exc}", errors="replace")
        return 1
    opened = _try_open_generated_viewer(viewer_path, output_json)
    _status(
        "opened viewer in default browser" if opened else "could not auto-open viewer"
    )
    print(os.path.abspath(output_json))
    if viewer_path:
        print(os.path.abspath(viewer_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
