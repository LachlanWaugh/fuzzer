#!/usr/bin/env python3.8

import sys
import os
import logging

from pwn import *
import random

from json_fuzzer import *
from csv_fuzzer import *
from xml_fuzzer import *
from txt_fuzzer import *
from helper import *

# argument error checking
# 1 = binary name
# 2 = sampleinput

PATH_TO_SANDBOX = "binaries/"  # make empty string for deployment

if len(sys.argv) != 3:
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
    sys.exit("Sample input does not exist")

context.log_level = logging.CRITICAL

# open files
# test input to determine input file type
with open(inputFile) as file:
    if is_json(file):
        json_fuzzer(binary, inputFile)
    elif is_xml(file):
        xml_fuzzer(binary, inputFile)
    elif is_csv(file):
        csv_fuzzer(binary, inputFile)
    else:
        txt_fuzzer(binary, inputFile)

    # Busy wait until workers finsh
    while len(MP.active_children()) > 0:
        sleep(1)

