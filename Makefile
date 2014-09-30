CC=gcc
CFLAGS=-g -Wall 

all: clean inject

inject: inject.c elf_tools.o elf_tools.h
	$(CC) $(CFLAGS) inject.c elf_tools.o -o inject 

elf_tools.o: elf_tools.c elf_tools.h
	$(CC) $(CFLAGS) -c elf_tools.c elf_tools.h

clean:
	rm -rf *.o *.gch inject

