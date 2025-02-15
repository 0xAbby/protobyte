#!/bin/bash
# a script to fetch submodule and build everything

export CXX=/usr/bin/clang++
export CC=/usr/bin/clang


binary_build() {
    cd build
    cmake ../
    make -j
    cd ..    
}

unit_tests_cov_build() {
    git submodule init
    git submodule update
    cd src/unit-tests/build
    cmake ../
    make -j
    cd ../../../
}

if [ "$1" == "default" ]; then
    binary_build
elif [ "$1" == "unit_tests" ]; then
    unit_tests_cov_build
elif [ "$1" == "all" ]; then
    binary_build
    unit_tests_cov_build
else
    echo "Please specify build option: "
    echo "   default        build only protobyte binary"
    echo "   unit_tests     build unit-tests and coverage"
    echo "   all            all of the above"
    exit 1
fi

