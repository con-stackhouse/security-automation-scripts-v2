'''
Tests for the chunked file-scanning + regex-extraction logic used by
forensics/email_url_extractor.py, forensics/memory_forensics_analyzer.py,
and forensics/memory_string_analyzer.py.

Each script implements this logic independently (see CLAUDE.md - this repo
intentionally has no shared library), so the same scenarios are exercised
against all three implementations to make sure a fix to one didn't miss
the others.

The scenario that matters most here: a regex match that spans a chunk
boundary must be counted exactly once - not missed, and not double
counted. That includes the specific edge case where a truncated prefix of
the match (the part visible before the boundary) would, on its own,
already satisfy the pattern - which previously produced a wrong, spurious
match instead of the true one.
'''

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(relative_path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


email_url_extractor = _load_module("forensics/email_url_extractor.py", "email_url_extractor")
memory_forensics_analyzer = _load_module("forensics/memory_forensics_analyzer.py", "memory_forensics_analyzer")
memory_string_analyzer = _load_module("forensics/memory_string_analyzer.py", "memory_string_analyzer")


def _write(tmp_path, content):
    filePath = tmp_path / "sample.raw"
    filePath.write_bytes(content)
    return str(filePath)


# --- memory_string_analyzer.processFileInChunks ----------------------------

def test_string_analyzer_match_fully_inside_one_chunk(tmp_path):
    content = b"11" + b"HELLO" + b"2" * 27
    filePath = _write(tmp_path, content)
    counts = memory_string_analyzer.processFileInChunks(filePath, memory_string_analyzer.wPatt, chunkSize=30)
    assert counts == {"HELLO": 1}


def test_string_analyzer_match_spanning_chunk_boundary(tmp_path):
    # "HELLOWORLD" (10 chars) split by a 30-byte chunk read: only 3 of its
    # letters ("HEL") land in the first chunk, below the pattern's 5-char
    # minimum, so it can't be mistaken for a complete match in chunk 1.
    content = b"1" * 27 + b"HELLOWORLD" + b"2" * 10
    filePath = _write(tmp_path, content)
    counts = memory_string_analyzer.processFileInChunks(filePath, memory_string_analyzer.wPatt, chunkSize=30)
    assert counts == {"HELLOWORLD": 1}


def test_string_analyzer_boundary_prefix_would_self_match(tmp_path):
    # "HELLOWORLD" split so "HELLO" (its first 5 letters) already satisfies
    # the {5,15} pattern on its own. Under the old fixed-overlap-size
    # design this produced a spurious "HELLO" match and silently dropped
    # the true "HELLOWORLD" match entirely.
    content = b"1" * 25 + b"HELLOWORLD" + b"2" * 10
    filePath = _write(tmp_path, content)
    counts = memory_string_analyzer.processFileInChunks(filePath, memory_string_analyzer.wPatt, chunkSize=30)
    assert counts == {"HELLOWORLD": 1}


def test_string_analyzer_matches_not_double_counted(tmp_path):
    content = b"1" * 27 + b"HELLOWORLD" + b"2" * 5 + b"HELLOWORLD" + b"3" * 5
    filePath = _write(tmp_path, content)
    counts = memory_string_analyzer.processFileInChunks(filePath, memory_string_analyzer.wPatt, chunkSize=30)
    assert counts == {"HELLOWORLD": 2}


def test_string_analyzer_match_at_true_end_of_file(tmp_path):
    # Match ends exactly at EOF with nothing following - must still count.
    content = b"1" * 25 + b"HELLO"
    filePath = _write(tmp_path, content)
    counts = memory_string_analyzer.processFileInChunks(filePath, memory_string_analyzer.wPatt, chunkSize=30)
    assert counts == {"HELLO": 1}


# --- memory_forensics_analyzer.processFileInChunks --------------------------

def test_forensics_analyzer_match_spanning_chunk_boundary_is_lowercased(tmp_path):
    content = b"1" * 27 + b"Kernel" + b"2" * 10
    filePath = _write(tmp_path, content)
    counts = memory_forensics_analyzer.processFileInChunks(
        filePath, memory_forensics_analyzer.WORDS_PATTERN, chunkSize=30, transform=str.lower
    )
    assert counts == {"kernel": 1}


def test_forensics_analyzer_boundary_prefix_would_self_match(tmp_path):
    # Unbounded pattern ([A-Za-z']+), so even a short visible prefix could
    # be mistaken for a complete word under the old design.
    content = b"1" * 27 + b"encryption" + b"2" * 10
    filePath = _write(tmp_path, content)
    counts = memory_forensics_analyzer.processFileInChunks(
        filePath, memory_forensics_analyzer.WORDS_PATTERN, chunkSize=30
    )
    assert counts == {"encryption": 1}


# --- email_url_extractor.processFile (multi-pattern) -------------------------

def test_email_extractor_email_spanning_chunk_boundary(tmp_path):
    # "!" padding, not digits: the email pattern's character classes
    # include 0-9, so digit padding would merge into the match itself
    # instead of acting as a separator.
    email = b"analyst@example.com"
    content = b"!" * 22 + email + b"!" * 10
    filePath = _write(tmp_path, content)
    emailDict, urlCount, wordDict = email_url_extractor.processFile(filePath, chunkSize=30)
    assert emailDict == {"analyst@example.com": 1}


def test_email_extractor_url_spanning_chunk_boundary(tmp_path):
    url = b"http://example.com/path"
    content = b"!" * 20 + url + b"!" * 10
    filePath = _write(tmp_path, content)
    emailDict, urlCount, wordDict = email_url_extractor.processFile(filePath, chunkSize=30)
    assert urlCount == {"http://example.com/path": 1}


def test_email_extractor_independent_carries_per_pattern(tmp_path):
    # Email straddles the boundary; URL does not. Each pattern must track
    # its own carry independently so the non-boundary URL match isn't
    # affected by the email match's deferral (or vice versa).
    email = b"analyst@example.com"
    url = b"http://example.com/path"
    content = b"!" * 22 + email + b"!" * 5 + url
    filePath = _write(tmp_path, content)
    emailDict, urlCount, wordDict = email_url_extractor.processFile(filePath, chunkSize=30)
    assert emailDict == {"analyst@example.com": 1}
    assert urlCount == {"http://example.com/path": 1}
