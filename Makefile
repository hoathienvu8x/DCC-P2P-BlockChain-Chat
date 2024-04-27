#We have no special rules for Windows because... well, who's gonna run this on
#Windows anyway?

#Compile with some extra warnings, no -pedantic because we don't hate ourselves
CFLAGS=-std=gnu99 -Wall -Wextra

#This should work for most Linux distros, I think
LIBFLAGS=-lpthread

OBJECTS = peerlist.o archive.o bignum.o rsa.o

#Actual target rules
all: blockchain

blockchain: main.o $(OBJECTS)
	gcc main.o $(OBJECTS) -o blockchain $(LIBFLAGS)
	rm -rf *.o

%.o: %.c
	gcc -c $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) blockchain
