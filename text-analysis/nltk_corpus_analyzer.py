'''

NLTK Corpus Text Analysis Tool
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: November 2024

Purpose:
    Natural Language Processing tool for analyzing text corpora.
    Performs word frequency analysis, concordance generation,
    and vocabulary analysis using NLTK.

Security Application:
    - Text analysis for digital forensics
    - Document examination and keyword extraction
    - Communication pattern analysis
    - Threat intelligence from text documents

Usage:
    python3 nltk_corpus_analyzer.py
    (Prompts for a directory path containing .txt files, then for a
    comma-separated list of keywords to search)

Requirements:
    - Python 3.x
    - nltk: pip install nltk
    - prettytable: pip install prettytable

Output:
    Interactive menu with 8 analysis options:
    - Corpus length and token count
    - Vocabulary size and frequency
    - Word concordance and similarities
    - Word indexing and occurrence tracking
    
Example Use Case:
    Analyzing legal documents, security logs, or communication archives
    for specific keywords and patterns.

'''

import os
import sys
import logging
import nltk
from nltk.corpus import PlaintextCorpusReader
from nltk.corpus import stopwords
from time import sleep
from prettytable import PrettyTable

nltk.download('stopwords')

nltk.download('punkt')

nltk.download('punkt_tab')



# Initialize the stopwords set

stopSet = set(stopwords.words('english'))



class classNLTKQuery:

    ''' NLTK Query Class '''



    def textCorpusInit(self, thePath):

        # Validate the path is a directory

        if not os.path.isdir(thePath):

            return "Path is not a Directory"



        # Validate the path is readable

        if not os.access(thePath, os.R_OK):

            return "Directory is not Readable"



        # Attempt to Create a corpus with all .txt files found in the directory

        try:

            self.Corpus = PlaintextCorpusReader(thePath, '.*')

            print ("Processing Files : ")

            print (self.Corpus.fileids())

            print ("Please wait ...")

            self.rawText = self.Corpus.raw()

            self.tokens = nltk.word_tokenize(self.rawText)

            self.TextCorpus = nltk.Text(self.tokens)         

        except:

            return "Corpus Creation Failed"



        self.ActiveTextCorpus = True

        return "Success"



    def printCorpusLength(self):

        print("\n\nCorpus Text Length: ", '{:,}'.format(len(self.rawText)))



    def printTokensFound(self):

        print("\n\nTokens Found: ", '{:,}'.format(len(self.tokens)))



    def printVocabSize(self):

        print("\n\nCalculating Vocabulary Size...")

        vocab = set(self.tokens)

        print("Vocabulary Size: ", '{:,}'.format(len(vocab)))



    def searchWordOccurrence(self):

        testWords = self.testWords

        

        print("\n\nWord Occurrences:")

        for word in testWords:

            # Convert both search word and text to uppercase 

            count = sum(1 for token in self.tokens if token.upper() == word.upper())

            print("'" + word + "' appears " + '{:,}'.format(count) + " times in the corpus")



    def generateConcordance(self):

        testWords = self.testWords

        

        print("\n\nWord Concordance:")

        for word in testWords:

            print("\nConcordance for '" + word + "':")

            self.TextCorpus.concordance(word.upper(), width=100, lines=100)



    def generateSimilarities(self):

        testWords = self.testWords

        

        print("\n\nWord Similarities:")

        for word in testWords:

            print("\nSimilar words to '" + word + "':")

            self.TextCorpus.similar(word.upper(), num=200)



    def printWordIndex(self):

        testWords = self.testWords

        

        print("\n\nWord Index:")

        for word in testWords:

            indices = [i for i, token in enumerate(self.TextCorpus) if token.upper() == word.upper()]

            if indices:

                print("First occurrence of '" + word + "' is at position: " + '{:,}'.format(indices[0]))

                print("Word appears at " + '{:,}'.format(len(indices)) + " positions")                

            else:

                print("'" + word + "' not found in corpus")



    def printVocabulary(self):

        testWords = self.testWords

        

        print("\n\nCompiling Vocabulary Frequencies")

        

        tbl = PrettyTable(["Vocabulary", "Occurs"])

        tbl.align["Vocabulary"] = "l"

        tbl.align["Occurs"] = "r"

        

        # Add test words to table

        for word in testWords:

            count = sum(1 for token in self.tokens if token.upper() == word.upper())

            tbl.add_row([word, '{:,}'.format(count)])

        

        print(tbl)



def printMenu():

    # Function to print the NLTK Query Option Menu

    print("==========NLTK Query Options =========")

    print("[1]    Print Length of Corpus")

    print("[2]    Print Number of Token Found")

    print("[3]    Print Vocabulary Size")

    print("[4]    Search for Word Occurrence")

    print("[5]    Generate Concordance")

    print("[6]    Generate Similarities")

    print("[7]    Print Word Index")

    print("[8]    Print Vocabulary")

    print()

    print("[0]    Exit NLTK Experimentation")

    print()



# Function to obtain user input     

def getUserSelection():

    printMenu()

    

    while True:

        try:

            sel = input('Enter Selection (0-8) >> ')

            menuSelection = int(sel)

        except ValueError:

            print('Invalid input. Enter a value between 0-8.')

            continue

    

        if not menuSelection in range(0, 9):

            print('Invalid input. Enter a value between 0-8.')

            continue

    

        return menuSelection



if __name__ == '__main__':

    print("Welcome to the NLTK Query Experimentation")

    print("Please wait loading NLTK ... \n")

    

    print("Input full path name where intended corpus file or files are stored")

    print("Format for Windows e.g. ./CORPUS \n")

    

    userSpecifiedPath = input("Path: ") 

    

    # Attempt to create a text Corpus

    oNLTK = classNLTKQuery()

    result = oNLTK.textCorpusInit(userSpecifiedPath)

    

    if result == "Success":

        keywordInput = input("Enter keywords to search for (comma-separated): ")
        oNLTK.testWords = [word.strip() for word in keywordInput.split(",") if word.strip()]

        menuSelection = -1

        

        while menuSelection != 0:

            if menuSelection != -1:

                print()

                s = input('Press Enter to continue...')

                printMenu()

                

            menuSelection = getUserSelection()        

            

            if menuSelection == 1:

                oNLTK.printCorpusLength()

            

            elif menuSelection == 2:

                oNLTK.printTokensFound()

    

            elif menuSelection == 3:

                oNLTK.printVocabSize()

    

            elif menuSelection == 4:         

                oNLTK.searchWordOccurrence()      

    

            elif menuSelection == 5:    

                oNLTK.generateConcordance()      

    

            elif menuSelection == 6:

                oNLTK.generateSimilarities()      

    

            elif menuSelection == 7:    

                oNLTK.printWordIndex()

    

            elif menuSelection == 8:    

                oNLTK.printVocabulary()

                

            elif menuSelection == 0:    

                print("Goodbye")

                print()

                

            elif menuSelection == -1:

                continue

            

            else:

                print("unexpected error condition")

                menuSelection = 0

                

            sleep(3)

    

    else:

        print("Closing NLTK Query Experimentation")

