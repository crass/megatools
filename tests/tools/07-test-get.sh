#!/bin/sh
source ./config

megaget --help

rm -f test-get.dat
megaget $OPTS --path test-get.dat /Root/TestDir/test.dat

cmp test.dat test-get.dat || echo "=== FAILED ==="
