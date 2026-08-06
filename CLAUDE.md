# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A collection of 15 independent, single-file Python scripts written for a university Cyber Operations
Engineering program. There is no shared package, build system, or CLI framework — each script is run
directly with `python3 <script>.py` from its own directory. Scripts are grouped into category folders:
`forensics/`, `network/`, `file-analysis/`, `cryptography/`, `text-analysis/`, `web-security/`. See
`README.md` for the full per-script catalog (purpose, techniques, use case) if you need a description of
a specific tool. A small pytest suite in `tests/` covers the trickiest shared logic (chunk-boundary
handling in the memory-forensics scripts); most scripts otherwise have no automated coverage.

Do not introduce a shared library, `setup.py`/`pyproject.toml`, or cross-script imports unless asked —
the scripts are intentionally standalone coursework artifacts, not a package.

## Running scripts

```bash
pip install -r requirements.txt
python3 <category>/<script>.py
```

- Most scripts are **interactive**: they call `input()` to prompt for a file or directory path rather
  than accepting CLI arguments (e.g. `file_metadata_processor.py`, `image_scanner.py`,
  `system_info_logger.py`, `email_url_extractor.py`, `nltk_corpus_analyzer.py`). When testing changes,
  you'll need to supply that input interactively or via piped stdin.
- Several scripts expect a specific file to already exist in the current working directory rather than
  prompting for it:
  - `forensics/memory_forensics_analyzer.py`, `forensics/memory_string_analyzer.py` → `mem.raw`
  - `forensics/firewall_log_parser.py` → `redhat.txt`
- `web-security/web_scraper.py` has the target `URL` hardcoded as a module-level constant — edit the
  script to change target instead of expecting a prompt or argument.
- `network/packet_sniffer.py` requires root/admin privileges (raw sockets) and uses Windows-specific
  socket options (`SIO_RCVALL`/`RCVALL_ON`) — it will not run unmodified on macOS/Linux.
- `network/tcp_server.py` must be started before `network/tcp_client.py`; they communicate over
  `localhost:5555`.
- GitHub Actions CI (`.github/workflows/ci.yml`) runs ruff, bandit, and pip-audit on every push/PR.
  `pytest` (see `tests/`) covers the chunk-boundary logic in the memory-forensics scripts; there is no
  broader test suite or linter config beyond that, so validate other changes by running the affected
  script directly.

## Patterns shared across scripts

- **Chunked binary processing with deferred boundary matches**: the memory-forensics scripts
  (`memory_forensics_analyzer.py`, `memory_string_analyzer.py`, `email_url_extractor.py`) read large
  binary dumps in fixed-size chunks via `file.read(CHUNK_SIZE)`. Each script's `countMatches()` reserves
  a trailing margin (`OVERLAP_SIZE` bytes, still 20) of the buffer as "possibly incomplete": any match
  ending beyond that margin is deferred rather than counted, and the margin is carried forward
  unconditionally even when nothing currently matches there, since a partial match near the end (e.g.
  only 3 of a 5+ letter word) is too short to satisfy the pattern at all yet - there'd be nothing for
  `finditer()` to defer without that floor, and those bytes would be silently lost. Once more data
  arrives (or the final chunk is reached, since nothing can extend a match further at EOF), the deferred
  region is re-evaluated and counted exactly once. This replaced an earlier design that only skipped
  matches *starting* before a fixed overlap boundary, which could silently miscount (undercount or
  mis-match) anything spanning a chunk boundary - see `tests/test_extraction.py` for the boundary cases
  this covers. If you modify chunking logic in one of these, check whether the same fix is needed in the
  others.
- **Streaming hash computation**: file-hashing scripts (`file_hash_analyzer.py`,
  `file_hash_duplicate_detector.py`, `system_info_logger.py`) hash files in `65536`-byte blocks via
  `iter(lambda: f.read(65536), b'')` rather than reading whole files into memory, so hashing works on
  large files.
- **PrettyTable for output**: most scripts render results via `prettytable.PrettyTable`, typically sorted
  with `.get_string(sortby=..., reversesort=True)`. Keep this convention for consistency when adding
  output to an existing script.
- **`os.walk` for recursive traversal**: forensic/file-analysis scripts that scan directory trees
  (`file_hash_analyzer.py`, `file_hash_duplicate_detector.py`, `system_info_logger.py`) build the
  absolute path via `os.path.join(root, name)` + `os.path.abspath(...)` before hashing/stat-ing.
- Scripts generally wrap their top-level logic in a broad `try/except`, printing the error and calling
  `sys.exit(...)` on failure rather than raising — match this style for consistency rather than
  introducing custom exception hierarchies.

## Security context

These are educational/portfolio scripts (network sniffing, rainbow-table generation, web recon). When
editing them, preserve the existing "authorized use only" framing in docstrings/README and don't expand
their capability toward unauthorized or mass-scanning use cases.
