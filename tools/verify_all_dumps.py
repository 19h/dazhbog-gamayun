#!/usr/bin/env python3
"""
Verify CalcRel hash computation on all IDA dumps in /tmp/lumina_dump.
The dumps contain IDA's raw bytes, normalized bytes, and mask - we verify
that MD5(normalized || mask) == stored_hash.
"""

import hashlib
import re
import sys
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

DUMP_DIR = Path("/tmp/lumina_dump")

def parse_raw_data_section(text):
    """Parse the RAW DATA section which has continuous hex strings."""
    raw_bytes = None
    norm_bytes = None
    mask_bytes = None

    for line in text.split('\n'):
        if line.startswith('Original:'):
            hex_str = line.split(':', 1)[1].strip()
            raw_bytes = bytes.fromhex(hex_str)
        elif line.startswith('Normalized:'):
            hex_str = line.split(':', 1)[1].strip()
            norm_bytes = bytes.fromhex(hex_str)
        elif line.startswith('Mask:'):
            hex_str = line.split(':', 1)[1].strip()
            mask_bytes = bytes.fromhex(hex_str)

    return raw_bytes, norm_bytes, mask_bytes

def parse_dump_file(filepath):
    """Parse a single dump file and return (name, addr, size, expected_hash, raw, norm, mask)."""
    try:
        text = filepath.read_text(errors='replace')
    except Exception as e:
        return None, str(e)

    # Extract metadata
    name_match = re.search(r'Function:\s*(.+)', text)
    addr_match = re.search(r'Address:\s*(0x[0-9a-fA-F]+)', text)
    size_match = re.search(r'Size:\s*(\d+)', text)
    hash_match = re.search(r'MD5:\s*([0-9a-fA-F]{32})', text)

    if not all([name_match, addr_match, size_match, hash_match]):
        return None, f"Missing metadata in {filepath.name}"

    name = name_match.group(1).strip()
    addr = int(addr_match.group(1), 16)
    size = int(size_match.group(1))
    expected_hash = hash_match.group(1).lower()

    # Parse hex from RAW DATA section
    raw_bytes, norm_bytes, mask_bytes = parse_raw_data_section(text)

    # raw_bytes may be None if original wasn't available - that's OK
    if norm_bytes is None:
        return None, f"{name}: missing Normalized hex string"
    if mask_bytes is None:
        return None, f"{name}: missing Mask hex string"

    if len(norm_bytes) != size:
        return None, f"{name}: norm size mismatch ({len(norm_bytes)} vs {size})"
    if len(mask_bytes) != size:
        return None, f"{name}: mask size mismatch ({len(mask_bytes)} vs {size})"
    if raw_bytes is not None and len(raw_bytes) != size:
        return None, f"{name}: raw size mismatch ({len(raw_bytes)} vs {size})"

    return (name, addr, size, expected_hash, raw_bytes, norm_bytes, mask_bytes), None

def verify_hash(raw_bytes, mask_bytes, expected_hash):
    """Verify hash computation: hash = MD5(normalized || mask) where normalized = raw & ~mask."""
    normalized = bytes(b & ~m for b, m in zip(raw_bytes, mask_bytes))
    computed = hashlib.md5(normalized + mask_bytes).hexdigest()
    return computed == expected_hash, computed

def process_file(filepath):
    """Process a single file and return results."""
    data, error = parse_dump_file(filepath)
    if error:
        return ('error', filepath.name, error)

    name, addr, size, expected_hash, raw_bytes, norm_bytes, mask_bytes = data

    if raw_bytes is not None:
        # Verify the provided normalized bytes match raw & ~mask
        our_norm = bytes(b & ~m for b, m in zip(raw_bytes, mask_bytes))
        if our_norm != norm_bytes:
            diff_count = sum(1 for a, b in zip(our_norm, norm_bytes) if a != b)
            return ('norm_mismatch', name, f"norm differs at {diff_count} bytes")

        # Verify hash computation using raw + mask
        match, computed = verify_hash(raw_bytes, mask_bytes, expected_hash)
    else:
        # No raw bytes - verify directly with normalized + mask
        computed = hashlib.md5(norm_bytes + mask_bytes).hexdigest()
        match = computed == expected_hash

    if match:
        return ('match', name, None)
    else:
        return ('hash_mismatch', name, f"expected {expected_hash}, got {computed}")

def main():
    dump_files = list(DUMP_DIR.glob("*.txt"))
    total = len(dump_files)
    print(f"Processing {total} dump files...")

    matches = 0
    errors = 0
    norm_mismatches = 0
    hash_mismatches = 0

    error_examples = []
    norm_mismatch_examples = []
    hash_mismatch_examples = []

    # Use multiprocessing for speed
    num_workers = multiprocessing.cpu_count()

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(process_file, f): f for f in dump_files}

        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 5000 == 0:
                print(f"  Processed {done}/{total}...", file=sys.stderr)

            result_type, name, detail = future.result()

            if result_type == 'match':
                matches += 1
            elif result_type == 'error':
                errors += 1
                if len(error_examples) < 10:
                    error_examples.append((name, detail))
            elif result_type == 'norm_mismatch':
                norm_mismatches += 1
                if len(norm_mismatch_examples) < 10:
                    norm_mismatch_examples.append((name, detail))
            elif result_type == 'hash_mismatch':
                hash_mismatches += 1
                if len(hash_mismatch_examples) < 10:
                    hash_mismatch_examples.append((name, detail))

    print(f"\n{'='*60}")
    print(f"RESULTS: {total} files processed")
    print(f"{'='*60}")
    print(f"  Matches:          {matches:6d} ({100*matches/total:.2f}%)")
    print(f"  Hash mismatches:  {hash_mismatches:6d} ({100*hash_mismatches/total:.2f}%)")
    print(f"  Norm mismatches:  {norm_mismatches:6d} ({100*norm_mismatches/total:.2f}%)")
    print(f"  Parse errors:     {errors:6d} ({100*errors/total:.2f}%)")

    if error_examples:
        print(f"\nParse error examples:")
        for name, detail in error_examples:
            print(f"  {name}: {detail}")

    if norm_mismatch_examples:
        print(f"\nNormalization mismatch examples:")
        for name, detail in norm_mismatch_examples:
            print(f"  {name}: {detail}")

    if hash_mismatch_examples:
        print(f"\nHash mismatch examples:")
        for name, detail in hash_mismatch_examples:
            print(f"  {name}: {detail}")

    # Return exit code based on results
    if matches == total:
        print(f"\n✓ All {total} hashes verified successfully!")
        return 0
    else:
        print(f"\n✗ {total - matches} verification failures")
        return 1

if __name__ == "__main__":
    sys.exit(main())
