#!/usr/bin/env python3
"""
Compare IDA Lumina push hashes with hashes produced by the Binary Ninja plugin.

Usage:
  python3 tools/compare_hashes.py --push /path/to/push_*.txt --meta /tmp/lumina_debug/meta.log

The script prints a summary and lists mismatching or missing functions.
"""

import argparse
import pathlib
import re
from typing import Dict, List, Tuple


PushEntry = Tuple[str, int, str]  # name, length, ida_hash


def parse_push(path: pathlib.Path) -> List[PushEntry]:
    entries: List[PushEntry] = []
    cur_name: str = ""
    cur_len: int = 0

    name_re = re.compile(r"^Name:\s+'(.+)'")
    len_re = re.compile(r"^Func length:\s+(\d+)")
    hash_re = re.compile(r"Hash:\s+([0-9a-f]{32})")

    for line in path.read_text().splitlines():
        m = name_re.match(line)
        if m:
            cur_name = m.group(1)
            continue

        m = len_re.match(line)
        if m:
            cur_len = int(m.group(1))
            continue

        m = hash_re.search(line)
        if m and cur_name:
            entries.append((cur_name, cur_len, m.group(1)))
            cur_name = ""
            cur_len = 0

    return entries


def parse_meta(path: pathlib.Path) -> Dict[str, List[dict]]:
    """
    Parse /tmp/lumina_debug/meta.log emitted by the plugin.
    Returns name -> list of dicts to keep duplicates if present.
    """
    content = path.read_text()
    blocks = content.split("----")
    result: Dict[str, List[dict]] = {}

    name_re = re.compile(r"Function (\S+) @0x([0-9a-fA-F]+) size=(\d+)")
    hash_re = re.compile(r"Hash: ([0-9a-f]{32})")
    md5_raw_re = re.compile(r"MD5\\(raw\\)=([0-9a-f]{32})")
    md5_norm_re = re.compile(r"MD5\\(norm\\)=([0-9a-f]{32})")
    md5_mask_re = re.compile(r"MD5\\(mask\\)=([0-9a-f]{32})")

    for block in blocks:
        n = name_re.search(block)
        h = hash_re.search(block)
        if not n or not h:
            continue
        md5_raw_match = md5_raw_re.search(block)
        md5_norm_match = md5_norm_re.search(block)
        md5_mask_match = md5_mask_re.search(block)
        name, addr_hex, size_str = n.group(1), n.group(2), n.group(3)
        entry = {
            "name": name,
            "addr": int(addr_hex, 16),
            "size": int(size_str),
            "hash": h.group(1),
            "md5_raw": md5_raw_match.group(1) if md5_raw_match else "",
            "md5_norm": md5_norm_match.group(1) if md5_norm_match else "",
            "md5_mask": md5_mask_match.group(1) if md5_mask_match else "",
        }
        result.setdefault(name, []).append(entry)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare IDA vs Binja Lumina hashes")
    parser.add_argument(
        "--push",
        required=True,
        type=pathlib.Path,
        help="Parsed IDA push txt (push_*_parsed.txt)",
    )
    parser.add_argument(
        "--meta",
        required=True,
        type=pathlib.Path,
        help="Plugin meta log (/tmp/lumina_debug/meta.log)",
    )
    parser.add_argument(
        "--alias",
        action="append",
        default=[],
        help="Optional name alias in form ida=binja (e.g., start=_start)",
    )
    args = parser.parse_args()

    ida_entries = parse_push(args.push)
    meta = parse_meta(args.meta)

    alias_map: Dict[str, str] = {}
    for a in args.alias:
        if "=" in a:
            lhs, rhs = a.split("=", 1)
            alias_map[lhs] = rhs

    matched = []
    mismatched = []
    missing = []

    for name, length, ida_hash in ida_entries:
        lookup = alias_map.get(name, name)
        entries = meta.get(lookup, [])
        if not entries:
            missing.append((name, length, ida_hash))
            continue

        # Prefer an entry with matching size
        entry = next((e for e in entries if e["size"] == length), entries[0])
        if entry["hash"] == ida_hash:
            matched.append((name, entry))
        else:
            mismatched.append((name, ida_hash, entry))

    print(f"IDA functions: {len(ida_entries)}")
    print(f"Matched: {len(matched)}")
    print(f"Mismatched: {len(mismatched)}")
    print(f"Missing in meta log: {len(missing)}")

    if mismatched:
        print("\n--- Mismatches ---")
        for name, ida_hash, entry in mismatched:
            print(
                f"{name}: ida={ida_hash} binja={entry['hash']} "
                f"addr=0x{entry['addr']:x} size={entry['size']} "
                f"md5_raw={entry['md5_raw']} md5_norm={entry['md5_norm']} md5_mask={entry['md5_mask']}"
            )

    if missing:
        print("\n--- Missing in meta log ---")
        for name, length, ida_hash in missing:
            print(f"{name}: ida={ida_hash} len={length}")


if __name__ == "__main__":
    main()
