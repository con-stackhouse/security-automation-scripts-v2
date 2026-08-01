'''
WK-3 STARTER SCRIPT
'''

# Python Standard Libaries
import os
import hashlib
import time

# Python 3rd Party Libraries
from prettytable import PrettyTable     # pip install prettytable

targetFolder = input("Enter Target Folder: ")

# Start of the Script

print("Walking: ", targetFolder, "\n")

tbl = PrettyTable(['AbsPath', 'Type', 'FileSize', 'UTC-Modified', 'UTC-Accessed', 'UTC-Created', 'SHA-256 HASH'])

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
            humanTimeLastModified = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stats.st_mtime))
            humanTimeLastAccess = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stats.st_atime))
            humanTimeLastCreated = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stats.st_ctime))

            sha256Obj = hashlib.sha256()
            with open(absPath, 'rb') as target:
                # Read in chunks so large files don't need to fit in memory
                for block in iter(lambda: target.read(65536), b''):
                    sha256Obj.update(block)
            hexDigest = sha256Obj.hexdigest()

        except OSError as err:
            tbl.add_row([absPath, "error", 0, "-", "-", "-", str(err)])
            continue

        tbl.add_row([absPath, fileType, fileSize, humanTimeLastModified, humanTimeLastAccess, humanTimeLastCreated, hexDigest])

tbl.align = "l"  # align the columns left justified
# display the table
print(tbl.get_string(sortby="FileSize", reversesort=True))

print("\nScript-End\n")
