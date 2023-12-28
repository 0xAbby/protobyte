#//
#// unit_test / Makefile
#//
#//    https://github.com/0xAbby/binlyzer
#//
#// Author:
#//  Abdullah Ada
#//
CC= g++
ARGS= -Wall -O2 -std=c++20
LINK= -lgtest -lgtest_main
BUILD= ./build

default: 
	${CC} ${ARGS} runTests.cpp ${LINK} ../${BUILD}/pe.o  ../${BUILD}/elf.o ../${BUILD}/file_io.o -o runTests

clean:
	rm -rf ./runTests
