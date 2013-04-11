#!/bin/sh
source ./config

megastream --help

rm -f test-stream.dat
megastream $OPTS  /Root/TestDir/test.dat > test-stream.dat

cmp test.dat test-stream.dat || echo "=== FAILED ==="
