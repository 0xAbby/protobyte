#!/bin/bash
# a script to fetch submodule and build everything

git submodule init
git submodule update
cd build
cmake ../
make -j
