#Compile with some extra warnings, no -pedantic because we don't hate ourselves
CFLAGS=-c -Wall -Wextra

#This should work for most Linux distros, I think
LIBFLAGS=-lpthread

#Actual target rules
all: blockchain

blockchain: main.o peerlist.o archive.o
	gcc main.o peerlist.o archive.o -o blockchain $(LIBFLAGS)

main.o: main.c
	gcc $(CFLAGS) main.c

peerlist.o: peerlist.c
	gcc $(CFLAGS) peerlist.c

archive.o: archive.c
	gcc $(CFLAGS) archive.c

clean:
	rm *.o blockchain*
