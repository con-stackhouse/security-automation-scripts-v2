# Security Automation & Forensics Tools

[![CI](https://github.com/con-stackhouse/security-automation-scripts-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/con-stackhouse/security-automation-scripts-v2/actions/workflows/ci.yml)

Python tools for digital forensics, file integrity, log analysis, and network inspection, maintained
behind a CI pipeline where linting, static security analysis, dependency auditing, and tests all have to
pass before a change goes in.

## Where to look first

**1. Correct pattern matching across chunk boundaries in memory dumps**
`forensics/memory_forensics_analyzer.py`, `forensics/memory_string_analyzer.py`,
`forensics/email_url_extractor.py`

Memory dumps are too large to load at once, so these tools stream them in fixed-size chunks. The
original design could silently miscount any match that straddled two chunks, either missing it or
recording a truncated fragment as a different, wrong match. The fix holds back a trailing margin of
each chunk and only counts a match once it can no longer grow, so every match is counted exactly once.
`tests/test_extraction.py` runs the same boundary cases against all three implementations, so a fix
to one script can't quietly miss the others.

**2. Security gates in CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))

| Gate | Tool | What fails the build |
| --- | --- | --- |
| Lint | ruff | Any finding under the rule set in `ruff.toml` |
| SAST | bandit | Any new security finding |
| Dependencies | pip-audit | A dependency with a known CVE |
| Tests | pytest | Any failing test |

Two scripts use MD5 on purpose (a rainbow-table demo and a checksum demo). Rather than suppressing
the scanner, those calls declare `usedforsecurity=False`, which documents the intent in the code and
keeps bandit a hard gate for everything else.

**3. Evidence integrity**
File catalogs are hashed with SHA-256 in streamed 64 KB blocks, so large evidence files never have to
fit in memory. `system_info_logger.py` also writes a SHA-256 hash of its finished log next to the log
itself, so later tampering is detectable.

## Tools

| Area | Script | What it does |
| --- | --- | --- |
| Forensics | `forensics/memory_forensics_analyzer.py` | Keyword and word-frequency extraction from memory dumps |
| | `forensics/memory_string_analyzer.py` | Recovers readable strings from binary dumps and ranks them by frequency |
| | `forensics/email_url_extractor.py` | Pulls email addresses and URLs out of memory dumps |
| | `forensics/file_metadata_processor.py` | Extracts file timestamps, permissions, ownership, and header bytes |
| | `forensics/file_hash_duplicate_detector.py` | Finds duplicate files across a directory tree by hash |
| | `forensics/system_info_logger.py` | System profile plus hashed file catalog for evidence collection |
| | `forensics/firewall_log_parser.py` | Parses firewall logs and flags known worm signatures; exports JSON/CSV |
| File analysis | `file-analysis/file_hash_analyzer.py` | SHA-256 integrity baseline of a directory; exports JSON/CSV |
| | `file-analysis/image_scanner.py` | Finds images in a directory tree and reports format and dimensions |
| Network | `network/packet_sniffer.py` | Raw-socket capture with IP/protocol breakdown (Windows only, requires admin) |
| | `network/tcp_server.py`, `network/tcp_client.py` | Client/server pair that verifies message integrity with a checksum |
| Web | `web-security/web_scraper.py` | Link and image enumeration for a single authorized target |
| Crypto | `cryptography/rainbow_table_generator.py` | Shows why unsalted hashes are crackable with precomputed tables |
| Text | `text-analysis/nltk_corpus_analyzer.py` | Word frequency, concordance, and vocabulary analysis of document sets |

## Running

```bash
pip install -r requirements.txt
python3 forensics/firewall_log_parser.py --json findings.json
python3 file-analysis/file_hash_analyzer.py --path ./evidence --csv baseline.csv
```

Scripts are standalone, with no shared package. Several accept flags (`--help` lists them), and the
rest prompt for a path when run. The memory tools read `mem.raw` from the current directory, and the
firewall parser reads `redhat.txt`.

To run the same checks as CI:

```bash
pip install -r requirements-dev.txt ruff bandit pip-audit
ruff check . && bandit -r . -x ./.git,./tests && pip-audit -r requirements.txt && pytest -q
```

## About

Built by **Connor Stackhouse**, Medical Device Security Analyst at HonorHealth, working on
vulnerability management for clinical devices. Before moving into security I spent three and a half
years as a CT technologist, so I know the clinical side of the devices I now help secure.
B.A.S. in Cyber Operations Engineering, University of Arizona (2025). CompTIA Security+.

[LinkedIn](https://www.linkedin.com/in/connor-stackhouse-91570986/) ·
[GitHub](https://github.com/con-stackhouse) · con.stackhouse@gmail.com

## Authorized use only

These tools are for education and for systems you own or have written permission to test. Packet
capture, web enumeration, and hash cracking against systems without authorization may be illegal.
