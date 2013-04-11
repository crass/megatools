#!/bin/sh
source ./config

megamkdir --help

megamkdir $ROPTS /Root/TestDir
megamkdir $OPTS /Root/TestDir/SubDir1
megamkdir $OPTS /Root/TestDir/SubDir2
megamkdir $OPTS /Root/TestDir/SubDir3
megamkdir $OPTS /Root/TestDir/SubDir3/SubSubDir

megamkdir $OPTS /Contacts/megous@megous.com
