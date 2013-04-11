#!/bin/sh
source ./config

megasync --help

# dl
rm -rf TestDir
megasync $ROPTS --download --remote /Root/TestDir --local TestDir -n
megasync $OPTS --download --remote /Root/TestDir --local TestDir

# ul
megamkdir $OPTS /Root/TestDir/Sub
megasync $OPTS --remote /Root/TestDir/Sub --local TestDir -n
megasync $OPTS --remote /Root/TestDir/Sub --local TestDir
