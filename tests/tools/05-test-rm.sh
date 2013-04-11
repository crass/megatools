#!/bin/sh
source ./config

megarm --help

megals $ROPTS

megarm $OPTS /Root/TestDir/SubDir1
megarm $OPTS /Root/TestDir

megarm $OPTS /Contacts/megous@megous.com
