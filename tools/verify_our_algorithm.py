#!/usr/bin/env python3
"""
Verify OUR reverse-engineered CalcRel masking algorithm against IDA's dumps.

This implements the 7 UNIVERSAL rules that achieve 98.76% match rate across
77,575 IDA function dumps from multiple binaries.

The remaining 1.24% mismatches are due to binary-specific immediate masking
that IDA performs based on each binary's section layout.

Usage:
    python3 tools/verify_our_algorithm.py [--dump-dir /path/to/dumps]
"""

import hashlib
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # type: ignore
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP  # type: ignore
import struct
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import sys
import argparse

DUMP_DIR = Path("/tmp/lumina_dump")


def compute_calcrel_mask(raw_bytes, func_start):
    """
    Compute CalcRel mask using 7 universal rules.

    Rules:
    1. RIP-relative external displacements
    2. E8 external calls
    3. E9 external jumps
    4. EB short jumps outside function
    5. SIB-no-base displacements (NOT for VEX)
    6. VEX comparison predicate (with RIP-relative memory)
    7. Legacy SSE comparison predicate (with RIP-relative memory)
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    func_end = func_start + len(raw_bytes)
    mask = bytearray(len(raw_bytes))

    for insn in md.disasm(raw_bytes, func_start):
        offset = insn.address - func_start
        raw = bytes(insn.bytes)
        is_vex = len(raw) >= 2 and raw[0] in (0xC4, 0xC5)
        has_rip_mem = False

        # Rule 1: RIP-relative external displacements
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.value.mem.base == X86_REG_RIP:
                has_rip_mem = True
                target = insn.address + insn.size + op.value.mem.disp
                if target < func_start or target >= func_end:
                    if insn.disp_offset:
                        disp_off = offset + insn.disp_offset
                        for i in range(4):
                            if disp_off + i < len(mask):
                                mask[disp_off + i] = 0xFF

        # Rule 2: E8 external calls
        if len(raw) >= 5 and raw[0] == 0xE8:
            target = insn.address + 5 + struct.unpack("<i", raw[1:5])[0]
            if target < func_start or target >= func_end:
                for i in range(4):
                    if offset + 1 + i < len(mask):
                        mask[offset + 1 + i] = 0xFF

        # Rule 3: E9 external jumps
        if len(raw) >= 5 and raw[0] == 0xE9:
            target = insn.address + 5 + struct.unpack("<i", raw[1:5])[0]
            if target < func_start or target >= func_end:
                for i in range(4):
                    if offset + 1 + i < len(mask):
                        mask[offset + 1 + i] = 0xFF

        # Rule 4: EB short jumps outside function
        if len(raw) == 2 and raw[0] == 0xEB:
            rel8 = struct.unpack("b", raw[1:2])[0]
            target = insn.address + 2 + rel8
            if target < func_start or target >= func_end:
                mask[offset + 1] = 0xFF

        # Rule 5: SIB-no-base / absolute addressing (skip for VEX)
        # Use capstone's semantic analysis: base == 0 means no base register
        if not is_vex and insn.disp_offset and not has_rip_mem:
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.value.mem.base == 0:
                    disp_size = (
                        insn.imm_offset - insn.disp_offset
                        if insn.imm_offset
                        else insn.size - insn.disp_offset
                    )
                    if disp_size == 4:
                        disp_off = offset + insn.disp_offset
                        for i in range(4):
                            if disp_off + i < len(mask):
                                mask[disp_off + i] = 0xFF

        # Rule 6: VEX comparison predicate (C4/C5 with opcode 0xC2)
        if is_vex and has_rip_mem:
            opcode_idx = 2 if raw[0] == 0xC5 else 3
            if opcode_idx < len(raw) and raw[opcode_idx] == 0xC2:
                mask[offset + len(raw) - 1] = 0xFF

        # Rule 7: Legacy SSE comparison predicate
        # Covers: 66 0F C2 (cmppd), 0F C2 (cmpps), F2 0F C2 (cmpsd), F3 0F C2 (cmpss)
        if has_rip_mem and len(raw) >= 4:
            if raw[0] == 0x66 and raw[1] == 0x0F and raw[2] == 0xC2:
                mask[offset + len(raw) - 1] = 0xFF
            elif raw[0] in (0xF2, 0xF3) and raw[1] == 0x0F and raw[2] == 0xC2:
                mask[offset + len(raw) - 1] = 0xFF
            elif raw[0] == 0x0F and raw[1] == 0xC2:
                mask[offset + len(raw) - 1] = 0xFF

    return bytes(mask)


def compute_calcrel_hash(raw_bytes, mask):
    """Compute CalcRel hash: MD5(normalized || mask)."""
    normalized = bytes(b & ~m for b, m in zip(raw_bytes, mask))
    return hashlib.md5(normalized + mask).hexdigest()


def parse_dump_file(filepath):
    """Parse dump file and return (func_start, ida_hash, raw_bytes, ida_mask) or None."""
    try:
        content = filepath.read_text(errors="replace")
    except:
        return None

    addr_match = re.search(r"Address:\s*0x([0-9a-fA-F]+)", content)
    md5_match = re.search(r"MD5:\s+([0-9a-fA-F]+)", content)
    orig_match = re.search(r"^Original:\s+([0-9a-fA-F]+)\s*$", content, re.MULTILINE)
    mask_match = re.search(r"^Mask:\s+([0-9a-fA-F]+)\s*$", content, re.MULTILINE)

    if not all([addr_match, md5_match, orig_match, mask_match]):
        return None

    assert addr_match is not None
    assert md5_match is not None
    assert orig_match is not None
    assert mask_match is not None

    func_start = int(addr_match.group(1), 16)
    ida_hash = md5_match.group(1).lower()
    raw_bytes = bytes.fromhex(orig_match.group(1))
    ida_mask = bytes.fromhex(mask_match.group(1))

    if len(raw_bytes) != len(ida_mask):
        return None

    return (filepath.name, func_start, ida_hash, raw_bytes, ida_mask)


def process_file(filepath):
    """Process single file, return result dict."""
    data = parse_dump_file(filepath)
    if data is None:
        return {"status": "parse_error", "name": filepath.name}

    name, func_start, ida_hash, raw_bytes, ida_mask = data

    our_mask = compute_calcrel_mask(raw_bytes, func_start)
    our_hash = compute_calcrel_hash(raw_bytes, our_mask)

    if our_hash == ida_hash:
        return {"status": "match", "name": name}
    else:
        diff_count = sum(1 for a, b in zip(our_mask, ida_mask) if a != b)
        ida_more = sum(1 for a, b in zip(our_mask, ida_mask) if a == 0 and b == 0xFF)
        we_more = sum(1 for a, b in zip(our_mask, ida_mask) if a == 0xFF and b == 0)
        return {
            "status": "mismatch",
            "name": name,
            "size": len(raw_bytes),
            "diff": diff_count,
            "ida_more": ida_more,
            "we_more": we_more,
            "our_hash": our_hash,
            "ida_hash": ida_hash,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Verify CalcRel algorithm against IDA dumps"
    )
    parser.add_argument(
        "--dump-dir",
        type=Path,
        default=DUMP_DIR,
        help="Directory containing IDA dump files",
    )
    args = parser.parse_args()

    dump_files = list(args.dump_dir.glob("*.txt"))
    total = len(dump_files)
    print(f"Processing {total} dump files with 7 universal rules...")
    print()

    matches = []
    mismatches = []
    parse_errors = []

    num_workers = multiprocessing.cpu_count()

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(process_file, f): f for f in dump_files}

        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 5000 == 0:
                print(f"  Processed {done}/{total}...", file=sys.stderr)

            result = future.result()

            if result["status"] == "match":
                matches.append(result["name"])
            elif result["status"] == "mismatch":
                mismatches.append(result)
            else:
                parse_errors.append(result["name"])

    print(f"\n{'=' * 70}")
    print(f"RESULTS: 7 Universal Rules vs IDA's masks")
    print(f"{'=' * 70}")

    valid = len(matches) + len(mismatches)
    if valid > 0:
        match_rate = 100 * len(matches) / valid
    else:
        match_rate = 0

    print(f"  Matches:      {len(matches):6d} ({match_rate:.2f}%)")
    print(f"  Mismatches:   {len(mismatches):6d} ({100 - match_rate:.2f}%)")
    print(f"  Parse errors: {len(parse_errors):6d}")

    if mismatches:
        ida_masks_more = [m for m in mismatches if m["ida_more"] > m["we_more"]]
        we_mask_more = [m for m in mismatches if m["we_more"] > m["ida_more"]]
        equal_diff = [m for m in mismatches if m["ida_more"] == m["we_more"]]

        print(f"\nMismatch breakdown:")
        print(
            f"  IDA masks more bytes: {len(ida_masks_more)} (binary-specific immediates)"
        )
        print(f"  We mask more bytes:   {len(we_mask_more)} (edge cases)")
        print(f"  Equal but different:  {len(equal_diff)}")

        if len(mismatches) <= 50:
            print(f"\nAll mismatches:")
            for m in mismatches:
                print(
                    f"  {m['name']:30} size={m['size']:5} diff={m['diff']:3} "
                    f"(IDA +{m['ida_more']}, we +{m['we_more']})"
                )

    return 0 if len(mismatches) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
