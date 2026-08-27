@echo off


mkdir build
gcc -Iinclude -O2 -c src/*.c
ar rcs build/libdistorm.a *.o


for %%i in (*.o) do del /q "%%i"

