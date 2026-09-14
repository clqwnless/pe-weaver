@echo off


mkdir build
gcc -Iinclude -O2 -c src/*.c
rem ar rcs build/libdistorm.a *.o

for %%i in (*.o) do (
    ar rcs build\libdistorm.a "%%i"
)

for %%i in (*.o) do del /q "%%i"

