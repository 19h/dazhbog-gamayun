# Tools

Supported Python helpers live here.

These scripts are not part of the build, but they are still useful for routine validation and debugging of the CalcRel implementation.

- `compare_hashes.py`
  - Compare IDA push hashes with the plugin's `/tmp/lumina_debug/meta.log` output.
- `compare_instruction_masks.py`
  - Compare IDA `--calcrel-insns` output with Binary Ninja `func_*.txt` debug dumps instruction by instruction.
  - For AArch64, pass `--ida-split-size 4` because IDA can emit CalcRel macro records spanning multiple 4-byte instructions.
- `verify_our_algorithm.py`
  - Re-run the current universal masking rules against an IDA dump corpus.
- `verify_all_dumps.py`
  - Validate that a dump corpus is internally consistent before using it for analysis.

Typical usage:

```bash
python3 tools/compare_hashes.py --push /path/to/push_parsed.txt --meta /tmp/lumina_debug/meta.log
python3 tools/compare_instruction_masks.py --ida-csv /path/to/out.csv --binja-dir /tmp/lumina_debug
python3 tools/compare_instruction_masks.py --ida-csv /path/to/out.csv --binja-dir /tmp/lumina_debug --ida-split-size 4
python3 tools/verify_our_algorithm.py --dump-dir /tmp/lumina_dump
python3 tools/verify_all_dumps.py
```
