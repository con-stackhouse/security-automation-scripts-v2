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

# Regular expression patterns (raw byte strings so backslash escapes
# are passed through to the regex engine, not interpreted by Python)
ePatt = re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}')
uPatt = re.compile(rb'\w+:\/\/[\w@][\w.:@]+\/?[\w.\.?=%&=\-@$,]*')
wPatt = re.compile(rb'[a-zA-Z]{5,15}')

# Minimum number of trailing bytes always carried into the next chunk,
# regardless of whether a match was found there. Needed because a partial
# match near the end of the buffer (e.g. only "analyst@exa" of an email)
# is too short to satisfy a pattern's minimum length, so finditer() won't
# return a match object for it at all - there would be nothing to defer
# without this floor, and those bytes would be lost.
OVERLAP_SIZE = 20


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
        key = match.group().decode()
        counts[key] = counts.get(key, 0) + 1
    return carryStart


def processFile(filePath, chunkSize, marginSize=OVERLAP_SIZE):
    emailDict = {}
    urlCount = {}
    wordDict = {}
    # Each pattern can have its own match straddling the chunk boundary,
    # so each needs its own independent carry-forward buffer.
    emailCarry = b''
    urlCarry = b''
    wordCarry = b''

    with open(filePath, 'rb') as binaryFile:
        while True:
            raw = binaryFile.read(chunkSize)
            isFinalChunk = not raw

            emailBuffer = emailCarry + raw
            emailCarryStart = countMatches(ePatt, emailBuffer, isFinalChunk, marginSize, emailDict)

            urlBuffer = urlCarry + raw
            urlCarryStart = countMatches(uPatt, urlBuffer, isFinalChunk, marginSize, urlCount)

            wordBuffer = wordCarry + raw
            wordCarryStart = countMatches(wPatt, wordBuffer, isFinalChunk, marginSize, wordDict)

            if isFinalChunk:
                break

            emailCarry = emailBuffer[emailCarryStart:]
            urlCarry = urlBuffer[urlCarryStart:]
            wordCarry = wordBuffer[wordCarryStart:]

    return emailDict, urlCount, wordDict


if __name__ == '__main__':
    print("\nExtract e-mails and urls from the memory dump provided\n")

    try:
        # Prompt for file to process and chunk size
        largeFile = input("Enter the name of the memory dump file: ")
        chunkSize = int(input("What size chunks?  "))

        if os.path.isfile(largeFile):
            emailDict, urlCount, wordDict = processFile(largeFile, chunkSize)

            print("\nFile Processed:", largeFile)
            print("\nResult Tables:")

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
