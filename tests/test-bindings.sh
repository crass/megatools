#!/bin/sh

export GI_TYPELIB_PATH=../mega
export LD_LIBRARY_PATH=../mega/.libs/

gjs test-bindings.js
python test-bindings.py
lua test-bindings.lua
ruby test-bindings.rb
