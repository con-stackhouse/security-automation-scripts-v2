'''
Web Scraper & Reconnaissance Tool
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: October 2024

Purpose:
    Extracts links and downloads images from websites for security
    assessment and reconnaissance. Demonstrates web scraping for OSINT.

Security Application:
    - Web application reconnaissance
    - OSINT (Open Source Intelligence)
    - Website enumeration
    - Asset discovery

Usage:
    python3 web_scraper.py
    (Modify URL variable in script before running)

Requirements:
    - Python 3.x
    - requests: pip install requests
    - beautifulsoup4: pip install beautifulsoup4
    - Pillow: pip install Pillow

Output:
    - Downloaded images saved to specified directory
    - List of all links found on page

Note:
    Only use on websites you have permission to scan.
'''

import os
import requests                       # Python library for url requests
from bs4 import BeautifulSoup         # 3rd party BeautifulSoup library
from PIL import Image                 # 3rd party Python Image library
from io import BytesIO
from urllib.parse import urljoin

URL = 'https://casl.website'
saveImg = os.path.join(os.getcwd(), 'images')
REQUEST_TIMEOUT = 10  # seconds

os.makedirs(saveImg, exist_ok=True)

# retrieve web page
page = requests.get(URL, timeout=REQUEST_TIMEOUT)

# convert the page into a beautifulsoup object for processing
soup = BeautifulSoup(page.text, 'html.parser')

pageLinks = set()

linkTags = soup.findAll('a')

if soup.title is not None:
    pageTitle = soup.title.string
else:
    pageTitle = 'No title found'
print("Page Title: " + pageTitle)
print()

if linkTags:
    for eachLink in linkTags:
        newLink = eachLink.get('href')

        if not newLink:
            continue

        newLink = urljoin(URL, newLink)
        pageLinks.add(newLink)

imageTags = soup.findAll('img')
if imageTags:
    for eachImage in imageTags:
        imgURL = eachImage.get('src')
        if not imgURL:
            continue

        try:
            # display the url of the image
            print("Image URL:  ", imgURL)

            # display the alternative text associated with the image
            print("Alt text: ", eachImage.get('alt', 'no alt text provided'))
            imgURL = urljoin(URL, imgURL)  # resolve relative/protocol-relative URLs against the base page
            response = requests.get(imgURL, timeout=REQUEST_TIMEOUT)  # Get image from the URL
            imageName = os.path.basename(imgURL)
            img = Image.open(BytesIO(response.content))  # Download the image
            img.save(os.path.join(saveImg, imageName))  # Save the image

            print("Downloaded " + imageName)

        except Exception as err:
            print("Error with image URL:", imgURL, err)

print("\nPage Links:")
for eachLink in pageLinks:
    print(eachLink)
