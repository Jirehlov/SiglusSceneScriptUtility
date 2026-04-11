from __future__ import annotations
import argparse
import re
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import pefile

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    from capstone.x86 import (
        X86_OP_IMM,
        X86_OP_MEM,
        X86_OP_REG,
        X86_REG_AX,
        X86_REG_CX,
        X86_REG_DX,
        X86_REG_EAX,
        X86_REG_ECX,
        X86_REG_EDX,
    )
except ImportError:
    Cs = None
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LIST_MEMBER_NAMES = {"alloc", "array", "free", "free_all", "get_size", "resize"}
ROOT_FORM_CODES = {1000, 1010, 1020}
FIXED_FORMS = {
    -3: "__argsref",
    -2: "__args",
    -1: "list",
    0: "void",
    1: "voidlist",
}


@dataclass(frozen=True)
class ElementDef:
    type_code: int
    parent_code: int
    form_code: int
    name: str
    owner: int
    group: int
    code: int
    arg_info: str


@dataclass(frozen=True)
class ElementStart:
    raw_offset: int
    base_addr: int
    type_code: int
    parent_code: int
    form_code: int
    name: str


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _s32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _normalize_ident(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip("\x00").strip()
    if not value or not IDENT_RE.fullmatch(value):
        return None
    return value.lower()


def _read_wstr(pe: pefile.PE, va: int) -> str | None:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    if rva < 0:
        return None
    try:
        offset = pe.get_offset_from_rva(rva)
    except pefile.PEFormatError:
        return None
    data = pe.__data__
    end = offset
    while end + 1 < len(data):
        if data[end : end + 2] == b"\x00\x00":
            break
        end += 2
    else:
        return None
    if end == offset:
        return ""
    try:
        return data[offset:end].decode("utf-16le")
    except UnicodeDecodeError:
        return None


def _get_section(pe: pefile.PE, name: str) -> pefile.SectionStructure:
    target = name.encode("ascii")
    for section in pe.sections:
        if section.Name.rstrip(b"\x00") == target:
            return section
    raise RuntimeError(f"missing section: {name}")


def extract_compare_forms(pe: pefile.PE) -> dict[int, str]:
    text = _get_section(pe, ".text").get_data()
    forms: dict[int, str] = {}
    for offset in range(len(text) - 26):
        if text[offset] != 0xBA:
            continue
        if text[offset + 5 : offset + 8] != b"\x8b\xce\xe8":
            continue
        if text[offset + 12 : offset + 14] != b"\x84\xc0":
            continue
        if text[offset + 14] == 0x74:
            code_pos = offset + 16
        elif text[offset + 14 : offset + 16] == b"\x0f\x84":
            code_pos = offset + 20
        else:
            continue
        if code_pos + 7 > len(text):
            continue
        if text[code_pos] != 0xB8 or text[code_pos + 5 : code_pos + 7] != b"\x5e\xc3":
            continue
        name = _normalize_ident(_read_wstr(pe, _u32(text, offset + 1)))
        code = _s32(text, code_pos + 1)
        if name is None or code < -16 or code > 10000:
            continue
        existing = forms.get(code)
        if existing is not None and existing != name:
            raise RuntimeError(
                f"conflicting form names for code {code}: {existing!r} vs {name!r}"
            )
        forms[code] = name
    for code, name in FIXED_FORMS.items():
        forms.setdefault(code, name)
    return forms


def extract_static_forms(pe: pefile.PE) -> dict[int, str]:
    text = _get_section(pe, ".text").get_data()
    forms: dict[int, str] = {}
    prev_base: int | None = None
    run: list[tuple[int, int, str, int]] = []
    best_run: list[tuple[int, int, str, int]] = []
    for offset in range(len(text) - 26):
        if (
            text[offset] != 0x68
            or text[offset + 5] != 0xB9
            or text[offset + 10] != 0xE8
        ):
            continue
        base_addr = _u32(text, offset + 6)
        code_pos = offset + 15
        if text[code_pos : code_pos + 2] != b"\xc7\x05":
            continue
        if _u32(text, code_pos + 2) != base_addr + 0x18:
            continue
        name = _normalize_ident(_read_wstr(pe, _u32(text, offset + 1)))
        if name is None:
            continue
        code = _s32(text, code_pos + 6)
        item = (offset, base_addr, name, code)
        if prev_base is None or base_addr == prev_base + 0x1C:
            run.append(item)
        else:
            if len(run) > len(best_run):
                best_run = run
            run = [item]
        prev_base = base_addr
    if len(run) > len(best_run):
        best_run = run
    for _, _, name, code in best_run:
        forms[code] = name
    return forms


def _scan_element_starts(pe: pefile.PE) -> list[ElementStart]:
    text = _get_section(pe, ".text").get_data()
    starts_by_base: dict[int, ElementStart] = {}
    for offset in range(len(text) - 45):
        if text[offset : offset + 2] != b"\xc7\x05":
            continue
        base_addr = _u32(text, offset + 2)
        if text[offset + 10 : offset + 12] != b"\xc7\x05":
            continue
        if _u32(text, offset + 12) != base_addr + 4:
            continue
        if text[offset + 20 : offset + 22] != b"\xc7\x05":
            continue
        if _u32(text, offset + 22) != base_addr + 8:
            continue
        if (
            text[offset + 30] != 0x68
            or text[offset + 35] != 0xB9
            or text[offset + 40] != 0xE8
        ):
            continue
        if _u32(text, offset + 36) != base_addr + 0x0C:
            continue
        name = _normalize_ident(_read_wstr(pe, _u32(text, offset + 31)))
        if name is None:
            continue
        start = ElementStart(
            raw_offset=offset,
            base_addr=base_addr,
            type_code=_s32(text, offset + 6),
            parent_code=_s32(text, offset + 16),
            form_code=_s32(text, offset + 26),
            name=name,
        )
        starts_by_base.setdefault(base_addr, start)
    return sorted(starts_by_base.values(), key=lambda item: item.raw_offset)


def _make_disassembler() -> Cs:
    if Cs is None:
        raise RuntimeError("export_elmform.py requires the 'capstone' package.")
    disasm = Cs(CS_ARCH_X86, CS_MODE_32)
    disasm.detail = True
    return disasm


def _tracked_reg_name(reg_id: int) -> str | None:
    return {
        X86_REG_AX: "a",
        X86_REG_EAX: "a",
        X86_REG_CX: "c",
        X86_REG_ECX: "c",
        X86_REG_DX: "d",
        X86_REG_EDX: "d",
    }.get(reg_id)


def _absolute_mem_addr(operand) -> int | None:
    if operand.type != X86_OP_MEM:
        return None
    mem = operand.mem
    if mem.base != 0 or mem.index != 0:
        return None
    return mem.disp & 0xFFFFFFFF


def _is_reg_zeroing(insn) -> str | None:
    if insn.mnemonic not in {"sub", "xor"} or len(insn.operands) != 2:
        return None
    dst, src = insn.operands
    if dst.type != X86_OP_REG or src.type != X86_OP_REG or dst.reg != src.reg:
        return None
    return _tracked_reg_name(dst.reg)


def _parse_element_chunk(
    pe: pefile.PE, chunk: bytes, chunk_va: int, start: ElementStart, disasm: Cs
) -> ElementDef | None:
    regs: dict[str, int | None] = {"a": None, "c": None, "d": None}
    owner: int | None = None
    group: int | None = None
    code: int | None = None
    arg_info = ""
    base = start.base_addr
    instructions = list(disasm.disasm(chunk, chunk_va))
    for index, insn in enumerate(instructions):
        zero_reg = _is_reg_zeroing(insn)
        if zero_reg is not None:
            regs[zero_reg] = 0
            continue
        if insn.mnemonic == "mov" and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                reg_name = _tracked_reg_name(dst.reg)
                if reg_name is not None:
                    regs[reg_name] = src.imm & 0xFFFF
                continue
            if dst.type == X86_OP_MEM:
                addr = _absolute_mem_addr(dst)
                if addr is None:
                    continue
                if src.type == X86_OP_IMM:
                    if dst.size == 1:
                        if addr == base + 0x24:
                            owner = src.imm & 0xFF
                        elif addr == base + 0x25:
                            group = src.imm & 0xFF
                    elif dst.size == 2 and addr == base + 0x26:
                        code = src.imm & 0xFFFF
                    continue
                if src.type == X86_OP_REG and dst.size == 2 and addr == base + 0x26:
                    reg_name = _tracked_reg_name(src.reg)
                    if reg_name is not None and regs[reg_name] is not None:
                        code = regs[reg_name]
                    continue
        if index + 2 < len(instructions):
            push_insn = instructions[index]
            mov_insn = instructions[index + 1]
            call_insn = instructions[index + 2]
            if (
                push_insn.mnemonic == "push"
                and len(push_insn.operands) == 1
                and push_insn.operands[0].type == X86_OP_IMM
                and mov_insn.mnemonic == "mov"
                and len(mov_insn.operands) == 2
                and mov_insn.operands[0].type == X86_OP_REG
                and mov_insn.operands[0].reg == X86_REG_ECX
                and mov_insn.operands[1].type == X86_OP_IMM
                and call_insn.mnemonic == "call"
            ):
                str_va = push_insn.operands[0].imm & 0xFFFFFFFF
                addr = mov_insn.operands[1].imm & 0xFFFFFFFF
                if addr == base + 0x28:
                    arg_info = _read_wstr(pe, str_va) or ""
    if owner is None or group is None or code is None:
        return None
    return ElementDef(
        type_code=start.type_code,
        parent_code=start.parent_code,
        form_code=start.form_code,
        name=start.name,
        owner=owner,
        group=group,
        code=code,
        arg_info=arg_info,
    )


def extract_elements(pe: pefile.PE) -> list[ElementDef]:
    text_section = _get_section(pe, ".text")
    text = text_section.get_data()
    text_va = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress
    starts = _scan_element_starts(pe)
    disasm = _make_disassembler()
    elements: list[ElementDef] = []
    for index, start in enumerate(starts):
        next_offset = (
            starts[index + 1].raw_offset if index + 1 < len(starts) else len(text)
        )
        chunk = text[start.raw_offset : min(next_offset, start.raw_offset + 0x180)]
        chunk_va = text_va + start.raw_offset
        element = _parse_element_chunk(pe, chunk, chunk_va, start, disasm)
        if element is not None:
            elements.append(element)
    return elements


def _assign_form_name(form_names: dict[int, str], code: int, name: str) -> bool:
    current = form_names.get(code)
    if current is None:
        if name in form_names.values():
            existing_code = next(
                item_code
                for item_code, item_name in form_names.items()
                if item_name == name
            )
            if existing_code != code:
                return False
        form_names[code] = name
        return True
    return False


def infer_form_names(
    form_names: dict[int, str], elements: list[ElementDef]
) -> tuple[dict[int, str], list[int]]:
    by_parent: dict[int, list[ElementDef]] = defaultdict(list)
    for element in elements:
        by_parent[element.parent_code].append(element)
    changed = True
    while changed:
        changed = False
        for element in elements:
            if element.form_code <= 1 or element.form_code in form_names:
                continue
            children = by_parent.get(element.form_code, [])
            child_names = {child.name for child in children}
            if "array" not in child_names or child_names - LIST_MEMBER_NAMES:
                continue
            list_name = (
                element.name if element.name.endswith("list") else f"{element.name}list"
            )
            singular_name = element.name.removesuffix("list")
            changed |= _assign_form_name(form_names, element.form_code, list_name)
            for child in children:
                if child.name == "array" and child.form_code > 1:
                    changed |= _assign_form_name(
                        form_names, child.form_code, singular_name
                    )
        for parent_code, children in by_parent.items():
            parent_name = form_names.get(parent_code)
            if not parent_name or not parent_name.endswith("list"):
                continue
            singular_name = parent_name[:-4]
            for child in children:
                if child.name == "array" and child.form_code > 1:
                    changed |= _assign_form_name(
                        form_names, child.form_code, singular_name
                    )
        for element in elements:
            if element.parent_code in ROOT_FORM_CODES and element.form_code > 1:
                changed |= _assign_form_name(
                    form_names, element.form_code, element.name
                )
        for element in elements:
            if element.form_code <= 1:
                continue
            if element.name in {"left_stick", "right_stick"}:
                changed |= _assign_form_name(form_names, element.form_code, "joystick")
            elif element.name in {"left_trigger", "right_trigger"}:
                changed |= _assign_form_name(
                    form_names, element.form_code, "joytrigger"
                )
    unresolved = sorted(
        {
            code
            for code in {item.parent_code for item in elements}
            | {item.form_code for item in elements}
            if code not in form_names
        }
    )
    return dict(sorted(form_names.items())), unresolved


def render_output(form_names: dict[int, str], elements: list[ElementDef]) -> str:
    lines = [
        "__all__ = [",
        '    "FORM_TABLE",',
        '    "FORM_NAME_BY_CODE",',
        '    "FORM_CODE_BY_NAME",',
        '    "ELEMENT_TABLE",',
        "]",
        "",
        "FORM_TABLE = (",
    ]
    for code, name in sorted(form_names.items()):
        lines.append(f"    ({code}, {name!r}),")
    lines.extend(
        [
            ")",
            "",
            "FORM_NAME_BY_CODE = dict(FORM_TABLE)",
            "FORM_CODE_BY_NAME = {name: code for code, name in FORM_TABLE}",
            "",
            "ELEMENT_TABLE = (",
        ]
    )
    for element in elements:
        parent_name = form_names.get(element.parent_code)
        form_name = form_names.get(element.form_code)
        lines.append(
            "    "
            + repr(
                (
                    element.type_code,
                    element.parent_code,
                    parent_name,
                    element.form_code,
                    form_name,
                    element.name,
                    element.owner,
                    element.group,
                    element.code,
                    element.arg_info,
                )
            )
            + ","
        )
    lines.append(")")
    lines.append("")
    return "\n".join(lines)


def resolve_output_path(path_text: str) -> Path:
    output_path = Path(path_text)
    if output_path.exists() and output_path.is_dir():
        return output_path / "elmform.py"
    if output_path.suffix.lower() == ".py":
        return output_path
    return output_path / "elmform.py"


def build_elmform(exe_path: Path, output_path: Path) -> tuple[int, int, list[int]]:
    pe = pefile.PE(str(exe_path), fast_load=True)
    form_names = extract_static_forms(pe)
    compare_forms = extract_compare_forms(pe)
    for code, name in compare_forms.items():
        current = form_names.get(code)
        if current is None:
            form_names[code] = name
        elif current != name:
            raise RuntimeError(
                f"form mismatch for code {code}: static={current!r} compare={name!r}"
            )
    elements = extract_elements(pe)
    form_names, unresolved = infer_form_names(form_names, elements)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_output(form_names, elements),
        encoding="utf-8",
        newline="\r\n",
    )
    return len(form_names), len(elements), unresolved


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export SiglusCompiler form and element tables to elmform.py."
    )
    parser.add_argument("exe_path", help="Path to SiglusCompiler.exe")
    parser.add_argument(
        "output_path", help="Output directory or target elmform.py path"
    )
    args = parser.parse_args()
    exe_path = Path(args.exe_path).expanduser().resolve()
    output_path = resolve_output_path(args.output_path).resolve()
    if not exe_path.is_file():
        parser.error(f"exe not found: {exe_path}")
    form_count, element_count, unresolved = build_elmform(exe_path, output_path)
    print(f"wrote {output_path}")
    print(f"forms={form_count} elements={element_count}")
    if unresolved:
        print(
            f"unresolved form codes: {', '.join(str(item) for item in unresolved)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
