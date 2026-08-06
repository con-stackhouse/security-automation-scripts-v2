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

print("Memory Forensics Analyzer")

# Word token pattern: contiguous letters/apostrophes
WORDS_PATTERN = re.compile(rb"[A-Za-z']+")

# How many bytes of the previous chunk are carried forward so words
# spanning a chunk boundary aren't missed
OVERLAP_SIZE = 20
CHUNK_SIZE = 65535

wordCount = {}
overlap = b''

with open("mem.raw", 'rb') as target:
    while True:
        fileChunk = target.read(CHUNK_SIZE)
        if not fileChunk:
            print("\nFile Processed:", target.name)
            break

        fileChunk = overlap + fileChunk

        # Only count matches starting at/after the overlap boundary so a
        # word fully contained in the previous chunk's tail isn't counted
        # twice (once as part of the previous chunk, once here)
        for match in WORDS_PATTERN.finditer(fileChunk):
            if match.start() < len(overlap):
                continue
            word = match.group().decode('utf-8').lower()
            wordCount[word] = wordCount.get(word, 0) + 1

        overlap = fileChunk[-OVERLAP_SIZE:]

kernelCount = wordCount.get("kernel", 0)
encryptCount = wordCount.get("encrypt", 0)
fairwitnessCount = wordCount.get("fairwitness", 0)

print("kernelCount: ",      kernelCount)
print("encryptCount:",      encryptCount)
print("fairwitnessCount: ", fairwitnessCount)
