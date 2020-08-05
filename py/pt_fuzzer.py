import sys
import os
import copy

from pwn import *
from helper import *

class PTFuzzer:
    def __init__(self, input):
        try:
            self._text = input.readlines()
        except Exception as e:
            print(e)

    def _bitflip(self):
        bytes = bytearray(self._text, 'UTF-8')

        for i in range(0, len(bytes)):
            if random.randint(0, 20) == 1:
                bytes[i] ^= random.getrandbits(7)

        return bytes.decode('ascii')

    def _mutate(self, line, functions):
        text = list(self._text)     # Don't overwrite the original text
        index = text.index(line)

        def _overflow():
            return "A" * 0x100

        def _int_overflow():
            return "1000" 

        def _int_underflow():
            return "-1000"

        def _fstring():
            return "%s%x" * 0x100            

        switch = {
            0: _overflow,
            1: _int_overflow,
            2: _int_underflow,
            3: _fstring
        }

        for i in functions:
            try:
                text[index] = switch.get(i)()
            except Exception as e:
                print(i)
                print(e)
    
        return text

    def generate_input(self):
        # test how the binary reacts to no input
        yield ""

        # Test a simple buffer overflow
        yield "A" * 0x1000

        # Test a simple format string
        yield "%s" * 0x100

        ############################################################
        ##                Test valid (format) data                ##

        # Mutate the supplied input data
        for line in self._text:
            yield ''.join(self._mutate(line, [0]))

            # yield ''.join(self._mutate(line, [1]))

            # yield ''.join(self._mutate(line, [2]))

            # yield ''.join(self._mutate(line, [3]))

        ############################################################


        ############################################################
        ##               Test invalid (format) data               ##

        # for i in range(0, 1000):
        #     # test random input (invalid XML)
        #     yield get_random_string((i + 1) * 10)

        #     # test random bitflips on the test input
        #     yield self._bitflip()

        ############################################################

def pt_fuzzer(binary, inputFile):
    context.log_level = 'WARNING'

    with open(inputFile) as input:
        for test_input in PTFuzzer(input).generate_input():
            print("Testing...")            
            test = open("test.txt", "w")
            test.writelines(test_input)
            test.close()

            # Need to write a separate payload method for plaintext as you need to send line by line
            # Can't rely on sending it as a single payload
            try:
                test_payload(binary, test_input)
            except Exception as e:
                print(e)

            print("Testing succeeded")

    #pt_fuzzer(binary, inputFile)