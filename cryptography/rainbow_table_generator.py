'''
Week 5 solution
'''
import itertools
import hashlib
import pickle
from prettytable import PrettyTable

rainbowTable = {}

print("Create Simple Rainbow Table")
for variations in range(4,8):
    for pwTuple in itertools.product("abc123&", repeat=variations):
        pw = ""
        md5Hash = hashlib.md5()
        for eachChr in pwTuple:
            pw = pw+"".join(eachChr)
        pw = bytes(pw, 'ascii')
        md5Hash.update(pw)
        md5Digest = md5Hash.hexdigest()
        rainbowTable[md5Digest] = pw

print("Rainbow Size: ", len(rainbowTable), "\n")

# Open the destination File (write binary) serialize rainbowTable
pickleFileWrite = open('rainbow.db', 'wb')
pickle.dump(rainbowTable, pickleFileWrite)
pickleFileWrite.close()


# Open the pickle file (read binary)
pickleFileRead = open('rainbow.db', 'rb')

# LOAD the serialized data 
print("\nLoading The Pickled Rainbow Table\n")
retrievedRainbowTable = pickle.load(pickleFileRead)
pickleFileRead.close()

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
