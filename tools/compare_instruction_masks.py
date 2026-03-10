#!/usr/bin/env python3
"""
Compare IDA per-instruction CalcRel relbits with Binary Ninja debug mask dumps.

Usage:
  python3 tools/compare_instruction_masks.py \
    --ida-csv /path/to/out.csv \
    --binja-dir /tmp/lumina_debug

The IDA CSV must be produced with `ida_lumina_debug --calcrel-insns`.
The Binary Ninja dump directory must contain `func_*.txt` files produced with
`LUMINA_DEBUG=1`.
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


INSTR_FIELD_RE = re.compile(r"^(0x[0-9A-Fa-f]+):(\d+):([0-9A-Fa-f]*):(.*)$")
FUNC_NAME_RE = re.compile(r"^Function:\s+(.+)$", re.MULTILINE)
FUNC_ADDR_RE = re.compile(r"^Address:\s+(0x[0-9A-Fa-f]+)$", re.MULTILINE)
INSTR_BLOCK_RE = re.compile(
    r"^\s*(0x[0-9A-Fa-f]+):\n"
    r"\s+Raw:\s+([^\n]*)\n"
    r"\s+Mask:\s+([^\n]*)\n"
    r"\s+Normalized:\s+([^\n]*)",
    re.MULTILINE,
)


@dataclass
class InstructionMask:
    ea: int
    size: int
    raw_hex: str
    mask_hex: str


@dataclass
class FunctionMasks:
    ea: int
    name: str
    instructions: List[InstructionMask]


@dataclass
class FunctionComparison:
    ida: FunctionMasks
    binja: Optional[FunctionMasks]
    layout_mismatches: List[str]
    raw_mismatches: List[str]
    mask_mismatches: List[str]

    @property
    def identical(self) -> bool:
        return self.binja is not None and not (
            self.layout_mismatches or self.raw_mismatches or self.mask_mismatches
        )


def compact_hex(text: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", text).upper()


def parse_instruction_field(value: str) -> List[InstructionMask]:
    if not value:
        return []

    instructions: List[InstructionMask] = []
    for part in value.split("|"):
        match = INSTR_FIELD_RE.match(part)
        if not match:
            raise ValueError(f"Unrecognized instruction entry: {part!r}")
        size = int(match.group(2))
        mask_hex = compact_hex(match.group(4))
        if not mask_hex:
            mask_hex = "00" * size
        instructions.append(
            InstructionMask(
                ea=int(match.group(1), 16),
                size=size,
                raw_hex=compact_hex(match.group(3)),
                mask_hex=mask_hex,
            )
        )
    return instructions


def parse_ida_csv(path: pathlib.Path) -> List[FunctionMasks]:
    csv.field_size_limit(sys.maxsize)
    functions: List[FunctionMasks] = []

    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            name = row.get("db_name") or row.get("lumina_name") or row["ea"]
            functions.append(
                FunctionMasks(
                    ea=int(row["ea"], 16),
                    name=name,
                    instructions=parse_instruction_field(
                        row.get("instruction_calcrel", "")
                    ),
                )
            )

    return functions


def parse_binja_dump(path: pathlib.Path) -> FunctionMasks:
    text = path.read_text(errors="replace")

    name_match = FUNC_NAME_RE.search(text)
    addr_match = FUNC_ADDR_RE.search(text)
    if not name_match or not addr_match:
        raise ValueError(f"Missing function header in {path}")

    instructions = [
        InstructionMask(
            ea=int(match.group(1), 16),
            size=len(compact_hex(match.group(2))) // 2,
            raw_hex=compact_hex(match.group(2)),
            mask_hex=compact_hex(match.group(3)),
        )
        for match in INSTR_BLOCK_RE.finditer(text)
    ]

    return FunctionMasks(
        ea=int(addr_match.group(1), 16),
        name=name_match.group(1).strip(),
        instructions=instructions,
    )


def split_fixed_width(
    instructions: List[InstructionMask], width: int
) -> List[InstructionMask]:
    if width <= 0:
        raise ValueError("split width must be positive")

    result: List[InstructionMask] = []
    for insn in instructions:
        if insn.size <= width:
            result.append(insn)
            continue

        if insn.size % width != 0:
            raise ValueError(
                f"Cannot split instruction at 0x{insn.ea:x}: size {insn.size} is not divisible by {width}"
            )

        expected_hex_len = insn.size * 2
        if (
            len(insn.raw_hex) != expected_hex_len
            or len(insn.mask_hex) != expected_hex_len
        ):
            raise ValueError(
                f"Cannot split instruction at 0x{insn.ea:x}: raw/mask hex length does not match size"
            )

        for offset in range(0, insn.size, width):
            hex_start = offset * 2
            hex_end = (offset + width) * 2
            result.append(
                InstructionMask(
                    ea=insn.ea + offset,
                    size=width,
                    raw_hex=insn.raw_hex[hex_start:hex_end],
                    mask_hex=insn.mask_hex[hex_start:hex_end],
                )
            )

    return result


def parse_binja_dir(path: pathlib.Path) -> List[FunctionMasks]:
    return [parse_binja_dump(p) for p in sorted(path.glob("func_*.txt"))]


def build_alias_map(values: Iterable[str]) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"Invalid alias {value!r}, expected ida=binja")
        lhs, rhs = value.split("=", 1)
        aliases[lhs] = rhs
    return aliases


def function_selected(func: FunctionMasks, selectors: List[str]) -> bool:
    if not selectors:
        return True

    candidates = {func.name, f"0x{func.ea:X}", f"0x{func.ea:x}"}
    return any(selector in candidates for selector in selectors)


def choose_binja_function(
    ida_func: FunctionMasks,
    by_addr: Dict[int, FunctionMasks],
    by_name: Dict[str, FunctionMasks],
    aliases: Dict[str, str],
    match_mode: str,
) -> Optional[FunctionMasks]:
    if match_mode in {"auto", "addr"}:
        by_address = by_addr.get(ida_func.ea)
        if by_address is not None:
            return by_address

    if match_mode in {"auto", "name"}:
        lookup_name = aliases.get(ida_func.name, ida_func.name)
        return by_name.get(lookup_name)

    return None


def compare_function(
    ida_func: FunctionMasks, binja_func: Optional[FunctionMasks]
) -> FunctionComparison:
    result = FunctionComparison(
        ida=ida_func,
        binja=binja_func,
        layout_mismatches=[],
        raw_mismatches=[],
        mask_mismatches=[],
    )

    if binja_func is None:
        result.layout_mismatches.append("missing Binary Ninja debug dump")
        return result

    if len(ida_func.instructions) != len(binja_func.instructions):
        result.layout_mismatches.append(
            f"instruction count ida={len(ida_func.instructions)} binja={len(binja_func.instructions)}"
        )

    ida_by_ea = {insn.ea: insn for insn in ida_func.instructions}
    binja_by_ea = {insn.ea: insn for insn in binja_func.instructions}

    for ea in sorted(set(ida_by_ea) - set(binja_by_ea)):
        result.layout_mismatches.append(f"missing in binja @0x{ea:x}")
    for ea in sorted(set(binja_by_ea) - set(ida_by_ea)):
        result.layout_mismatches.append(f"missing in ida @0x{ea:x}")

    for idx, ea in enumerate(sorted(set(ida_by_ea) & set(binja_by_ea))):
        ida_insn = ida_by_ea[ea]
        binja_insn = binja_by_ea[ea]

        if ida_insn.size != binja_insn.size:
            result.layout_mismatches.append(
                f"[{idx}] size @0x{ida_insn.ea:x} ida={ida_insn.size} binja={binja_insn.size}"
            )

        if ida_insn.raw_hex != binja_insn.raw_hex:
            result.raw_mismatches.append(
                f"[{idx}] raw @0x{ida_insn.ea:x} ida={ida_insn.raw_hex} binja={binja_insn.raw_hex}"
            )

        if ida_insn.mask_hex != binja_insn.mask_hex:
            result.mask_mismatches.append(
                f"[{idx}] mask @0x{ida_insn.ea:x} ida={ida_insn.mask_hex or '-'} binja={binja_insn.mask_hex or '-'}"
            )

    return result


def print_detail_block(
    title: str, comparisons: List[FunctionComparison], limit: int
) -> None:
    if not comparisons:
        return

    print(f"\n--- {title} ---")
    shown = 0
    for comp in comparisons:
        if shown >= limit:
            remaining = len(comparisons) - shown
            if remaining > 0:
                print(f"... {remaining} more")
            break
        print(f"{comp.ida.name} @0x{comp.ida.ea:x}")
        for line in comp.layout_mismatches[:limit]:
            print(f"  layout: {line}")
        for line in comp.raw_mismatches[:limit]:
            print(f"  raw:    {line}")
        for line in comp.mask_mismatches[:limit]:
            print(f"  mask:   {line}")
        shown += 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare IDA relbits with Binary Ninja debug masks"
    )
    parser.add_argument(
        "--ida-csv",
        required=True,
        type=pathlib.Path,
        help="ida_lumina_debug CSV produced with --calcrel-insns",
    )
    parser.add_argument(
        "--binja-dir",
        required=True,
        type=pathlib.Path,
        help="Binary Ninja debug dir containing func_*.txt dumps",
    )
    parser.add_argument(
        "--alias", action="append", default=[], help="Optional name alias ida=binja"
    )
    parser.add_argument(
        "--match",
        choices=["auto", "addr", "name"],
        default="auto",
        help="Function matching strategy",
    )
    parser.add_argument(
        "--function",
        action="append",
        default=[],
        help="Restrict to an exact function name or address",
    )
    parser.add_argument(
        "--ida-split-size",
        type=int,
        default=0,
        help="Split each IDA record into fixed-width chunks (use 4 for AArch64 macros)",
    )
    parser.add_argument(
        "--binja-split-size",
        type=int,
        default=0,
        help="Split each Binary Ninja record into fixed-width chunks",
    )
    parser.add_argument(
        "--detail-limit",
        type=int,
        default=10,
        help="Maximum functions to print per mismatch category",
    )
    args = parser.parse_args()

    aliases = build_alias_map(args.alias)
    ida_functions = [
        f for f in parse_ida_csv(args.ida_csv) if function_selected(f, args.function)
    ]
    binja_functions = parse_binja_dir(args.binja_dir)

    if args.ida_split_size:
        ida_functions = [
            FunctionMasks(
                func.ea,
                func.name,
                split_fixed_width(func.instructions, args.ida_split_size),
            )
            for func in ida_functions
        ]

    if args.binja_split_size:
        binja_functions = [
            FunctionMasks(
                func.ea,
                func.name,
                split_fixed_width(func.instructions, args.binja_split_size),
            )
            for func in binja_functions
        ]

    by_addr = {func.ea: func for func in binja_functions}
    by_name = {func.name: func for func in binja_functions}

    comparisons = [
        compare_function(
            ida_func,
            choose_binja_function(ida_func, by_addr, by_name, aliases, args.match),
        )
        for ida_func in ida_functions
    ]

    identical = [comp for comp in comparisons if comp.identical]
    missing = [comp for comp in comparisons if comp.binja is None]
    layout = [
        comp
        for comp in comparisons
        if comp.binja is not None and comp.layout_mismatches
    ]
    raw = [
        comp for comp in comparisons if comp.binja is not None and comp.raw_mismatches
    ]
    mask = [
        comp for comp in comparisons if comp.binja is not None and comp.mask_mismatches
    ]

    print(f"IDA functions considered: {len(ida_functions)}")
    print(f"Binary Ninja dumps found: {len(binja_functions)}")
    print(f"Identical: {len(identical)}")
    print(f"Missing Binary Ninja dump: {len(missing)}")
    print(f"Layout mismatches: {len(layout)}")
    print(f"Raw byte mismatches: {len(raw)}")
    print(f"Mask mismatches: {len(mask)}")

    print_detail_block("Missing", missing, args.detail_limit)
    print_detail_block("Layout Mismatches", layout, args.detail_limit)
    print_detail_block("Raw Byte Mismatches", raw, args.detail_limit)
    print_detail_block("Mask Mismatches", mask, args.detail_limit)


if __name__ == "__main__":
    main()
