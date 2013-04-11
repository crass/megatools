#!/bin/sh

export GI_TYPELIB_PATH=../mega
export LD_LIBRARY_PATH=../mega/.libs/

gnome-terminal --geometry 160x35+0+0 --title "Test Server" -e "gjs test-server.js"
sleep 0.5
gnome-terminal --geometry 160x35+0+600 --title "Test Client" -e "sh -c 'gjs test-http.js ; read'"
