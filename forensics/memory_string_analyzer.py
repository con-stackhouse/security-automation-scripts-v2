'''
Memory Dump String Frequency Analyzer
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: September 2024

Purpose:
    Extracts text strings from binary memory dumps and performs
    frequency analysis to identify significant patterns and keywords.

Security Application:
    - Memory forensics
    - Malware analysis (identifying suspicious strings)
    - Artifact recovery from RAM
    - Pattern recognition in memory dumps

Usage:
    python3 memory_string_analyzer.py
    (Processes mem.raw file in current directory)

Requirements:
    - Python 3.x
    - prettytable: pip install prettytable
    - mem.raw file in same directory

Output:
    Top 50 most frequent text strings found in memory
'''

import re
import os
import sys
from prettytable import PrettyTable

# File Chunk Size
CHUNK_SIZE = 1024

# Minimum number of trailing bytes always carried into the next chunk,
# regardless of whether a match was found there. Needed because a partial
# match near the end of the buffer (e.g. only 3 of a 5+ letter word
# visible so far) is too short to satisfy the pattern's minimum length,
# so finditer() won't return a match object for it at all - there would
# be nothing to defer without this floor, and those bytes would be lost.
OVERLAP_SIZE = 20

# Regular expression for continuous alpha string pattern
wPatt = re.compile(b'[a-zA-Z]{5,15}')


def countMatches(pattern, buffer, isFinalChunk, marginSize, counts):
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
        eachWord = match.group().decode()
        counts[eachWord] = counts.get(eachWord, 0) + 1
    return carryStart


def processFileInChunks(filePath, pattern, chunkSize, marginSize=OVERLAP_SIZE):
    counts = {}
    carry = b''
    with open(filePath, 'rb') as binaryFile:
        while True:
            raw = binaryFile.read(chunkSize)
            buffer = carry + raw
            isFinalChunk = not raw
            carryStart = countMatches(pattern, buffer, isFinalChunk, marginSize, counts)
            if isFinalChunk:
                break
            carry = buffer[carryStart:]
    return counts


if __name__ == '__main__':
    if not os.path.isfile('mem.raw'):
        sys.exit("mem.raw not found in current directory")

    wordCount = processFileInChunks('mem.raw', wPatt, CHUNK_SIZE)

    print("\nFile Processed:", 'mem.raw')

    # Display results
    wordTable = PrettyTable(["OCCURS", "WORD"])
    for key, value in wordCount.items():
        wordTable.add_row([value, key])
    wordTable.align = 'l'
    wordTable.sortby = "OCCURS"
    wordTable.reversesort = True

    topResults = 50
    print("\nTop Unique Strings Found:")
    print(wordTable.get_string(start=0, end=topResults))

    print("\nFile Processed ... Script End")
