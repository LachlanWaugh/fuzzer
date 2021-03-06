#!/bin/bash

if [[ $# != 1 ]] || ! [[ "$1" =~ [a-zA-Z]+[0-9] ]]; then
    echo "Usage: ./test.sh <binary-name>"
    exit 1
fi

[[ -f bad.txt ]]  && rm bad.txt
./py/fuzzer.py $1 $1.txt

[[ -f bad.txt ]] && sleep 1 && cat bad.txt | binaries/$1
[[ -f core ]] && rm core
