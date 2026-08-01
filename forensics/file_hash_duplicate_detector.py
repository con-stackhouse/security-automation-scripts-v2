from __future__ import print_function

'''
File Hash Duplicate Detector
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: September 2024

Purpose:
    Recursively scans directories and generates MD5 hashes to identify
    duplicate files. Useful for deduplication and forensic analysis.

Security Application:
    - Duplicate file detection
    - Storage optimization
    - Forensic analysis (identifying file copies)
    - Data integrity verification

Usage:
    python3 file_hash_duplicate_detector.py
    (Scans current directory and subdirectories)

Requirements:
    - Python 3.x
    - prettytable: pip install prettytable

Output:
    Table showing MD5 hash and the file paths that share it

Note:
    Only hashes with more than one file are duplicates; unique hashes
    are omitted from the report.
'''

import os
import hashlib
from prettytable import PrettyTable

directory = "."

fileList = []
fileHashes = {}

for root, dirs, files in os.walk(directory):

    # Walk the path from top to bottom.
    # For each file obtain the filename
    for fileName in files:
        path = os.path.join(root, fileName)
        fullPath = os.path.abspath(path)
        fileList.append(fullPath)

for filePath in fileList:
    hashObj = hashlib.md5()
    try:
        with open(filePath, 'rb') as file:
            # Read in chunks so large files don't need to fit in memory
            for block in iter(lambda: file.read(65536), b''):
                hashObj.update(block)
    except OSError as err:
        print("Could not read", filePath, "-", err)
        continue

    md5Hash = hashObj.hexdigest()
    fileHashes.setdefault(md5Hash, []).append(filePath)

tbl = PrettyTable(["MD5 Hash", "File Path"])
tbl.align = "l"

for md5Hash, paths in fileHashes.items():
    if len(paths) > 1:
        for filePath in paths:
            tbl.add_row([md5Hash, filePath])

print(tbl)
