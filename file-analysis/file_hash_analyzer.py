"""
File Hash Analyzer

Usage:
    python3 file_hash_analyzer.py --path /some/dir
    python3 file_hash_analyzer.py            (prompts for a directory)
    python3 file_hash_analyzer.py --path /some/dir --json out.json --csv out.csv
"""

# Python Standard Libaries
import argparse
import csv
import json
import os
import hashlib
import time

# Python 3rd Party Libraries
from prettytable import PrettyTable  # pip install prettytable

parser = argparse.ArgumentParser(
    description="Recursively catalog files with SHA-256 hashes and metadata."
)
parser.add_argument("--path", help="Directory to scan (prompts interactively if omitted)")
parser.add_argument("--json", metavar="FILE", help="Also write results as JSON to FILE")
parser.add_argument("--csv", metavar="FILE", help="Also write results as CSV to FILE")
args = parser.parse_args()

targetFolder = args.path if args.path else input("Enter Target Folder: ")

# Start of the Script

print("Walking: ", targetFolder, "\n")

COLUMNS = [
    "AbsPath",
    "Type",
    "FileSize",
    "UTC-Modified",
    "UTC-Accessed",
    "UTC-Created",
    "SHA-256 HASH",
]
tbl = PrettyTable(COLUMNS)
records = []

for currentRoot, dirList, fileList in os.walk(targetFolder):
    for nextFile in fileList:
        fullPath = os.path.join(currentRoot, nextFile)
        absPath = os.path.abspath(fullPath)

        try:
            if os.path.islink(fullPath) and not os.path.exists(absPath):
                fileType = "broken link"
            elif os.path.isfile(absPath):
                fileType = "file"
            else:
                fileType = "unknown"

            stats = os.stat(absPath)
            fileSize = stats.st_size
            humanTimeLastModified = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime(stats.st_mtime)
            )
            humanTimeLastAccess = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime(stats.st_atime)
            )
            humanTimeLastCreated = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime(stats.st_ctime)
            )

            sha256Obj = hashlib.sha256()
            with open(absPath, "rb") as target:
                # Read in chunks so large files don't need to fit in memory
                for block in iter(lambda: target.read(65536), b""):
                    sha256Obj.update(block)
            hexDigest = sha256Obj.hexdigest()

        except OSError as err:
            row = [absPath, "error", 0, "-", "-", "-", str(err)]
            tbl.add_row(row)
            records.append(dict(zip(COLUMNS, row)))
            continue

        row = [
            absPath,
            fileType,
            fileSize,
            humanTimeLastModified,
            humanTimeLastAccess,
            humanTimeLastCreated,
            hexDigest,
        ]
        tbl.add_row(row)
        records.append(dict(zip(COLUMNS, row)))

tbl.align = "l"  # align the columns left justified
# display the table
print(tbl.get_string(sortby="FileSize", reversesort=True))

if args.json:
    with open(args.json, "w") as jsonFile:
        json.dump(records, jsonFile, indent=2)
    print("\nJSON written to", args.json)

if args.csv:
    with open(args.csv, "w", newline="") as csvFile:
        writer = csv.DictWriter(csvFile, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(records)
    print("\nCSV written to", args.csv)

print("\nScript-End\n")
