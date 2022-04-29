#!/bin/bash

help="usage: $0 -m32/64 <file.asm>"

if [ "$#" -ne 2 ]; then
        echo $help
        exit
fi

if [ $1 == "-m32" ]; then
        /usr/bin/nasm -f elf32 $2 -o out.o
        /usr/bin/ld -m elf_i386 out.o -o executable
        /usr/bin/rm out.o

elif [ $1 == "-m64" ]; then
        /usr/bin/nasm -f elf64 $2 -o out.o
        /usr/bin/ld -m elf_x86_64 out.o -o executable
        /usr/bin/rm out.o

else
        echo $help
        exit
fi
