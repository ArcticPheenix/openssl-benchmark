# Basic Makefile for building main.c with custom OpenSSL paths
CC = gcc
CFLAGS = -I/opt/openssl-3.5.1/include
LDFLAGS = -L/opt/openssl-3.5.1/lib -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic
TARGET = benchmark
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
