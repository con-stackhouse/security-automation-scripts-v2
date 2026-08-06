from __future__ import print_function

"""
Firewall Log Parser & Worm Detector
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: September 2024

Purpose:
    Parses firewall logs to detect and extract unique worm signatures.
    Demonstrates log analysis and threat detection techniques.

Security Application:
    - Security log analysis
    - Malware detection
    - Threat intelligence gathering
    - Security monitoring

Usage:
    python3 firewall_log_parser.py
    (Requires redhat.txt log file in same directory)
    python3 firewall_log_parser.py --json out.json --csv out.csv

Requirements:
    - Python 3.x
    - No external libraries required

Output:
    Sorted list of unique worm names detected in firewall logs
"""

import argparse
import csv
import json
import sys

parser = argparse.ArgumentParser(
    description="Parse a firewall log and extract unique worm signatures."
)
parser.add_argument("--json", metavar="FILE", help="Also write results as JSON to FILE")
parser.add_argument("--csv", metavar="FILE", help="Also write results as CSV to FILE")
args = parser.parse_args()

LOG_FILE = "redhat.txt"

uniqueWorms = set()

try:
    with open(LOG_FILE, "r") as logFile:
        for eachLine in logFile:
            fields = eachLine.split()

            # check each field for the word worm
            for field in fields:
                if "worm" in field.lower():
                    # add worm to set if found
                    uniqueWorms.add(field)
except FileNotFoundError:
    sys.exit(LOG_FILE + " not found in current directory")

# sort the set
sortedWorms = sorted(uniqueWorms)

# print each instance
for worm in sortedWorms:
    print(worm)

if args.json:
    with open(args.json, "w") as jsonFile:
        json.dump(sortedWorms, jsonFile, indent=2)
    print("\nJSON written to", args.json)

if args.csv:
    with open(args.csv, "w", newline="") as csvFile:
        writer = csv.writer(csvFile)
        writer.writerow(["worm"])
        for worm in sortedWorms:
            writer.writerow([worm])
    print("\nCSV written to", args.csv)
