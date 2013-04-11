#!/bin/sh
source ./config

megadl --help

LINK=`megals $ROPTS --export /Root/TestDir/test.dat | cut -d ' ' -f 1`

rm -f test-dl.dat
megadl --path test-dl.dat $LINK

cmp test.dat test-dl.dat || echo "=== FAILED ==="
