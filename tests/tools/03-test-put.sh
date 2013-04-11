#!/bin/sh
source ./config

megaput --help

megarm $ROPTS /Root/TestDir/test.dat /Root/TestDir/test2.dat /Root/TestDir/SubDir1/test2.dat

dd if=/dev/urandom of=test.dat bs=267257 count=1

megaput $OPTS --path /Root/TestDir test.dat
megaput $OPTS --path /Root/TestDir/test2.dat test.dat
megaput $OPTS --path /Root/TestDir/SubDir1/test2.dat test.dat
