#!/bin/sh
source ./config

megals --help

megals $ROPTS
megals $OPTS -R --long /Root/TestDir
megals $OPTS --long /Root/TestDir
megals $OPTS --export /Root/TestDir
