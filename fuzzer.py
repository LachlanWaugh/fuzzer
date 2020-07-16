#!/usr/bin/env python3

import sys
import os
from pwn import *
import csv 
import json
import random 

from csv_fuzzer import *

# argument error checking
    # 1 = binary name
    # 2 = sampleinput

PATH_TO_SANDBOX = "binaries/" # make empty string for deployment

if (len(sys.argv) != 3):
    sys.exit("Usage: python3 fuzzer.py [binaryName] [sampleInput]")

binaryFileName = sys.argv[1]
print("Binary: " + binaryFileName)
sampleInputFileName = sys.argv[2]
print("Input File: " + sampleInputFileName)

binary = PATH_TO_SANDBOX + binaryFileName
if not (os.path.isfile(binary)):
    sys.exit("Binary does not exist")

inputFile = PATH_TO_SANDBOX + sampleInputFileName
if not (os.path.isfile(inputFile)):
    sys.exit('Sample input does not exist')

# open files
# test input to determine input file type

csv_fuzzer(binary, inputFile)







