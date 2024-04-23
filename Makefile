#We have no special rules for Windows because... well, who's gonna run this on
#Windows anyway?

#Compile with some extra warnings, no -pedantic because we don't hate ourselves
CFLAGS=-std=gnu99 -Wall -Wextra

#This should work for most Linux distros, I think
LIBFLAGS=-lpthread

#Actual target rules
all: blockchain

blockchain: main.o peerlist.o archive.o
	gcc main.o peerlist.o archive.o -o blockchain $(LIBFLAGS)

main.o: main.c
	gcc -c $(CFLAGS) main.c

peerlist.o: peerlist.c
	gcc -c $(CFLAGS) peerlist.c

archive.o: archive.c
	gcc -c $(CFLAGS) archive.c

clean:
	rm *.o blockchain*
