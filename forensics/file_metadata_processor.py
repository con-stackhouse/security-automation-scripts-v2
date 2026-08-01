'''
File Metadata Processor
Author: Connor Stackhouse
Cyber Operations Engineering - University of Arizona
Date: September 2024

Purpose:
    Object-oriented file forensics tool that extracts and displays
    comprehensive file system metadata and header analysis.

Security Application
     - Digital forensics investigations
     - File integrity verification
     - Evidence collection and documentation
     - Malware analysis (file header identification)

Usage:
     python3 file_metadata_processor.py
     (Script will prompt for a directory to scan)

Requirements:
     Python 3.x
     No external libraries required
'''

import os                           # File system library
import time                         # Time Conversion Library
from binascii import hexlify        # hexlify module


class FileProcessor:
    ''' FileProcessor Class Definition '''

    def __init__(self, path):
        ''' Class Constructor '''
        try:
            self.filePath = path

            if os.path.isfile(self.filePath) and os.access(self.filePath, os.R_OK):

                # Obtain the file metadata
                stats = os.stat(self.filePath)

                # Store each as an instance attribute
                self.fileSize = stats.st_size
                self.fileCreatedTime = time.ctime(stats.st_ctime)
                self.fileModifiedTime = time.ctime(stats.st_mtime)
                self.fileAccessTime = time.ctime(stats.st_atime)
                self.fileMode = '{:016b}'.format(stats.st_mode)
                self.fileUID = stats.st_uid
                self.fileHeader = ''

                self.status = "OK"

            else:
                self.status = "File not accessible"

        except Exception as err:
            # catch any exception and store the results
            # in the instance attribute status
            self.status = err

    def GetFileHeader(self):
        ''' Extract the first 20 bytes of the file header '''
        try:
            with open(self.filePath, 'rb') as fileObj:
                header = fileObj.read(20)
                self.fileHeader = hexlify(header)
                self.status = "OK"
        except Exception as err:
            # Catch any exceptions and store the results
            # in the instance attribute status
            self.status = err

    def PrintFileDetails(self):
        ''' Print the metadata and print the hex representation of the header'''
        print("\nFile Metadata:")
        print("File Path:               ", self.filePath)
        print("File Size:               ", '{:,}'.format(self.fileSize), "Bytes")
        print("File Created Time:       ", self.fileCreatedTime)
        print("File Modified Time:      ", self.fileModifiedTime)
        print("File Access Time:        ", self.fileAccessTime)
        print("File Mode:               ", self.fileMode)
        print("File UID:                ", self.fileUID)
        print("Hex Representation:      ", self.fileHeader)

    def PrintException(self):
        ''' Print the exception/status stored on the instance '''
        print("\nError processing", self.filePath, "-", self.status)


while True:
    # prompt user for directory path
    dirPath = input("Enter a Directory to Scan or Q to Quit: ")

    if dirPath.upper() == 'Q':
        print("\n\nUser Terminated the Script \n\n")
        break

    # Validate the directory exists
    if not os.path.isdir(dirPath):
        # If not force user to re-enter a proper directory
        print("Invalid Directory ... please try again")
        continue

    # Obtain the list of items in the directory path
    fileList = os.listdir(dirPath)

    for possibleFile in fileList:

        # Convert the simple filename to the full and absolute path
        fullPath = os.path.join(dirPath, possibleFile)
        absPath = os.path.abspath(fullPath)

        # Only process files that we have rights to read
        fileObj = FileProcessor(absPath)

        if fileObj.status != 'OK':
            if os.path.isfile(absPath):
                print("\nAccess Denied ", absPath)
            else:
                print("\nFile not an entry ", absPath)
            continue

        # Extract the file header and print the details
        fileObj.GetFileHeader()
        if fileObj.status != 'OK':
            fileObj.PrintException()
            continue

        fileObj.PrintFileDetails()
