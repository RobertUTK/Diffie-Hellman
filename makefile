CC = g++
CFLAGS = -Wall -g
LIBS = -lssl -lcrypto 

EXECUTABLES = DH RSA

all: $(EXECUTABLES)

RSA: rsa.cpp
	$(CC) $(CFLAGS) -o RSA rsa.cpp $(LIBS)

DH: diffie_hellman.cpp
	$(CC) $(CFLAGS) -o DH diffie_hellman.cpp $(LIBS)

clean:
	rm -f $(EXECUTABLES) *.o
