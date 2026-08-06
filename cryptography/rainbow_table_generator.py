'''
Rainbow Table Generator
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona

Purpose:
    Builds a simple rainbow table by MD5-hashing every password
    generated from a small fixed character set (4-7 characters from
    "abc123&"), then serializes the table to disk and reloads it to
    demonstrate a basic precomputed hash-lookup attack.

Security Application:
    - Password security education
    - Demonstrating precomputed hash-attack concepts
    - Illustrating why unsalted, fast hashes (like MD5) are unsuitable
      for password storage

Usage:
    python3 rainbow_table_generator.py
    (No arguments; writes rainbow.db in the current directory)

Requirements:
    - Python 3.x
    - prettytable: pip install prettytable

Output:
    - rainbow.db: JSON dictionary mapping MD5 hash to password
    - Console table showing the first and last 5 entries of the
      reloaded table

Note:
    Educational demonstration only. The character set and password
    lengths are intentionally small; this is not a production-scale
    rainbow table. Data is persisted as JSON rather than a pickle
    file to avoid the arbitrary-code-execution risk associated with
    unpickling data, even from a locally, self-generated file.
'''
import itertools
import hashlib
import json
from prettytable import PrettyTable

rainbowTable = {}

print("Create Simple Rainbow Table")
for variations in range(4,8):
    for pwTuple in itertools.product("abc123&", repeat=variations):
        pw = ""
        md5Hash = hashlib.md5()
        for eachChr in pwTuple:
            pw = pw+"".join(eachChr)
        pwBytes = bytes(pw, 'ascii')
        md5Hash.update(pwBytes)
        md5Digest = md5Hash.hexdigest()
        rainbowTable[md5Digest] = pw

print("Rainbow Size: ", len(rainbowTable), "\n")

# Open the destination file (write text) and serialize rainbowTable as JSON
jsonFileWrite = open('rainbow.db', 'w')
json.dump(rainbowTable, jsonFileWrite)
jsonFileWrite.close()


# Open the JSON file (read text)
jsonFileRead = open('rainbow.db', 'r')

# LOAD the serialized data
print("\nLoading The Rainbow Table\n")
retrievedRainbowTable = json.load(jsonFileRead)
jsonFileRead.close()

table = PrettyTable(["MD5 HASH VALUE", "PASSWORD"])

# Convert the dictionary to a list 
entryList = list(retrievedRainbowTable.items())

# Slice the list first 5 last 5 entries
firstFive = entryList[:5]
lastFive  = entryList[-5:]

for key, value in firstFive:
    table.add_row([key, value])
for key, value in lastFive:
    table.add_row([key, value])
table.align = 'l'

print(table)
print("\nScript End")
