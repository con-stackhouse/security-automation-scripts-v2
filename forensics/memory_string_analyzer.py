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

# How many bytes of the previous chunk are carried forward so matches
# spanning a chunk boundary aren't missed
OVERLAP_SIZE = 20

# Regular expression for continuous alpha string pattern
wPatt = re.compile(b'[a-zA-Z]{5,15}')

# Dictionary to store word occurrences
wordCount = {}

if not os.path.isfile('mem.raw'):
    sys.exit("mem.raw not found in current directory")

# Read the binary file with an overlap
overlap = b''
with open('mem.raw', 'rb') as binaryFile:
    while True:
        chunk = binaryFile.read(CHUNK_SIZE)
        if not chunk:
            break

        chunk = overlap + chunk

        # Only count matches that start at/after the overlap boundary so a
        # word fully contained in the previous chunk's tail isn't counted
        # twice (once as part of the previous chunk, once here)
        for match in wPatt.finditer(chunk):
            if match.start() < len(overlap):
                continue
            eachWord = match.group().decode()
            wordCount[eachWord] = wordCount.get(eachWord, 0) + 1

        overlap = chunk[-OVERLAP_SIZE:]

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
