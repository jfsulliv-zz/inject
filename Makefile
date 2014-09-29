CC=gcc
CFLAGS=-g -Wall 

all: clean inject

inject: inject.c
	$(CC) $(CFLAGS) inject.c -o inject 

clean:
	rm -rf *.o inject

