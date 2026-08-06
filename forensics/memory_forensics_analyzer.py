'''
Memory Dump Word Frequency Analyzer
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: May 2024

Purpose:
    Scans a raw memory dump in fixed-size chunks and counts occurrences
    of alphabetic word tokens, then reports counts for a few keywords
    of interest (kernel, encrypt, fairwitness).

Security Application:
    - Memory forensics
    - Keyword-based triage of memory dumps
    - Memory-efficient processing of large binary files

Usage:
    python3 memory_forensics_analyzer.py
    (Processes mem.raw file in current directory)

Requirements:
    - Python 3.x
    - mem.raw file in same directory

Output:
    Console counts for the keywords "kernel", "encrypt", and
    "fairwitness" found in the memory dump
'''

import re

# Word token pattern: contiguous letters/apostrophes
WORDS_PATTERN = re.compile(rb"[A-Za-z']+")

CHUNK_SIZE = 65535

# Minimum number of trailing bytes always carried into the next chunk,
# regardless of whether a match was found there. This pattern has no
# upper bound so a match can never be "too short to match at all", but
# the same floor is kept here for consistency with the other two scripts
# that read memory dumps this way (see CLAUDE.md).
OVERLAP_SIZE = 20


def countMatches(pattern, buffer, isFinalChunk, marginSize, counts, transform=None):
    # Matches fully before `limit` are guaranteed complete: nothing in the
    # reserved trailing margin could extend backward into them. A match
    # that ends beyond `limit` might still be truncated by the chunk
    # boundary, so it's deferred - return its start position as the
    # carry-forward point so it's re-checked against the next chunk
    # instead of being counted now. `carryStart` also defaults to `limit`
    # even when no match touches the margin, so a too-short partial match
    # (below the pattern's minimum length) is still carried forward.
    limit = len(buffer) if isFinalChunk else max(0, len(buffer) - marginSize)
    carryStart = limit
    for match in pattern.finditer(buffer):
        if not isFinalChunk and match.end() > limit:
            carryStart = min(carryStart, match.start())
            continue
        key = match.group().decode('utf-8')
        if transform:
            key = transform(key)
        counts[key] = counts.get(key, 0) + 1
    return carryStart


def processFileInChunks(filePath, pattern, chunkSize, marginSize=OVERLAP_SIZE, transform=None):
    counts = {}
    carry = b''
    with open(filePath, 'rb') as target:
        while True:
            raw = target.read(chunkSize)
            buffer = carry + raw
            isFinalChunk = not raw
            carryStart = countMatches(pattern, buffer, isFinalChunk, marginSize, counts, transform=transform)
            if isFinalChunk:
                break
            carry = buffer[carryStart:]
    return counts


if __name__ == '__main__':
    print("Memory Forensics Analyzer")

    wordCount = processFileInChunks("mem.raw", WORDS_PATTERN, CHUNK_SIZE, transform=str.lower)
    print("\nFile Processed:", "mem.raw")

    kernelCount = wordCount.get("kernel", 0)
    encryptCount = wordCount.get("encrypt", 0)
    fairwitnessCount = wordCount.get("fairwitness", 0)

    print("kernelCount: ",      kernelCount)
    print("encryptCount:",      encryptCount)
    print("fairwitnessCount: ", fairwitnessCount)
