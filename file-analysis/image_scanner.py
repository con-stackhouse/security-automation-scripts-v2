"""

Digital Image Scanner & Analyzer
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: September 2024

Purpose:
    Scans directories for digital images and extracts metadata including
    format, dimensions, and file type. Useful for forensic image discovery.

Security Application:
    - Digital evidence discovery
    - Image forensics
    - File type verification
    - Steganography detection preparation

Usage:
    python3 image_scanner.py
    (Prompts for directory path)

Requirements:
    - Python 3.x
    - Pillow (PIL): pip install Pillow
    - prettytable: pip install prettytable

Output:
    Formatted table showing:
    - Image detection status
    - File path and size
    - Image format, dimensions, and color mode

"""

import sys

import os

from PIL import Image

from prettytable import PrettyTable


print("\nScripting Solution\n")


while True:
    path = input("\nProvide path to examine (Q to Quit): ")

    if path.lower() == "q":
        break

    if os.path.isdir(path):
        fileList = os.listdir(path)

        # Create table

        table = PrettyTable(
            ["Image", "File", "FileSize", "Ext", "Format", "Width", "Height", "Type"]
        )

        for file in fileList:
            fullPath = os.path.join(path, file)

            if os.path.isfile(fullPath):
                ext = os.path.splitext(file)[1]

                fileSize = os.path.getsize(fullPath)

                formattedFileSize = "{:,}".format(fileSize)

                try:
                    with Image.open(fullPath) as im:
                        table.add_row(
                            [
                                "YES",
                                fullPath,
                                formattedFileSize,
                                ext,
                                im.format,
                                im.width,
                                im.height,
                                im.mode,
                            ]
                        )

                except Exception as err:
                    table.add_row(
                        [
                            "NO",
                            fullPath,
                            formattedFileSize,
                            ext,
                            "[NA]",
                            "[NA]",
                            "[NA]",
                            "[NA]",
                        ]
                    )

        table.align = "l"

        print(table)

    else:
        print("Path Provided is Not a Folder")


print("Script Done")
