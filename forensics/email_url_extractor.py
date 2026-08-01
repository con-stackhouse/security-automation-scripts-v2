'''
Email & URL Extractor from Memory Dumps
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: September 2024

Purpose:
    Extracts email addresses and URLs from binary memory dumps using
    regular expressions. Performs frequency analysis to identify
    significant communication artifacts.

Security Application:
    - Memory forensics
    - Investigation of communication patterns
    - Data exfiltration detection
    - Network artifact recovery

Usage:
    python3 email_url_extractor.py
    (Prompts for memory dump file and chunk size)

Requirements:
    - Python 3.x
    - prettytable: pip install prettytable

Output:
    - Sorted tables of email addresses by frequency
    - Sorted tables of URLs by frequency
'''

import os
import re
import sys
from prettytable import PrettyTable

print("\nExtract e-mails and urls from the memory dump provided\n")

try:
    # Prompt for file to process and chunk size
    largeFile = input("Enter the name of the memory dump file: ")
    chunkSize = int(input("What size chunks?  "))

    # Regular expression patterns (raw byte strings so backslash escapes
    # are passed through to the regex engine, not interpreted by Python)
    ePatt = re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}')
    uPatt = re.compile(rb'\w+:\/\/[\w@][\w.:@]+\/?[\w.\.?=%&=\-@$,]*')
    wPatt = re.compile(rb'[a-zA-Z]{5,15}')

    # How many bytes of the previous chunk are carried forward so matches
    # spanning a chunk boundary aren't missed
    OVERLAP_SIZE = 20

    emailDict = {}
    urlCount = {}
    wordDict = {}

    def countMatches(pattern, buffer, overlapLen, counts):
        # Only count matches starting at/after the overlap boundary so a
        # match fully contained in the previous chunk's tail isn't counted
        # twice (once as part of the previous chunk, once here)
        for match in pattern.finditer(buffer):
            if match.start() < overlapLen:
                continue
            key = match.group().decode()
            counts[key] = counts.get(key, 0) + 1

    if os.path.isfile(largeFile):
        overlap = b''

        with open(largeFile, 'rb') as binaryFile:
            while True:
                fileChunk = binaryFile.read(chunkSize)
                if not fileChunk:
                    print("\nFile Processed:", largeFile)
                    print("\nResult Tables:")
                    break

                fileChunk = overlap + fileChunk

                countMatches(ePatt, fileChunk, len(overlap), emailDict)
                countMatches(uPatt, fileChunk, len(overlap), urlCount)
                countMatches(wPatt, fileChunk, len(overlap), wordDict)

                # Manage overlap for next chunk
                overlap = fileChunk[-OVERLAP_SIZE:]

        # Display results
        emailTable = PrettyTable(["OCCURS", "EMAIL"])
        for key, value in emailDict.items():
            emailTable.add_row([value, key])
        emailTable.align = 'l'
        print("\nEmails Found:")
        print(emailTable.get_string(sortby="OCCURS", reversesort=True))

        urlTable = PrettyTable(["OCCURS", "URL"])
        for key, value in urlCount.items():
            urlTable.add_row([value, key])
        urlTable.align = 'l'
        print("\nURLs Found:")
        print(urlTable.get_string(sortby="OCCURS", reversesort=True))

    else:
        print(largeFile, "is not a valid file")
        sys.exit("Script Aborted")

except Exception as err:
    sys.exit("\nException: " + str(err) + " Script Aborted")

print("\nFile Processed ... Script End")
