#//
#// Makefile
#//
#//    https://github.com/0xAbby/binlyzer
#//
#// Author:
#//  Abdullah Ada
#//
CC= g++
ARGS= -Wall -O2 -std=c++20
SRC= ./src
BUILD= ./build

default: pe.o 
	${CC} ${ARGS} -o binlyzer ${BUILD}/pe.o  ${BUILD}/file_io.o  ${SRC}/main.cpp


pe.o: file_io.o
	${CC} ${ARGS} -c ${SRC}/pe.cpp -o ${BUILD}/pe.o

file_io.o:
	${CC} ${ARGS} -c ${SRC}/file_io.cpp -o ${BUILD}/file_io.o

unit_test:
	cd $(UNIT_TEST) && make

format:
	astyle --style=allman --indent=spaces=2 ./src/*.cpp
	astyle --style=allman --indent=spaces=2 ./src/*.h
	rm ./src/*.orig

clean:
	rm -rf binlyzer ${BUILD}/*.o ./unit_test/runTests