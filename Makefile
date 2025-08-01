# Basic Makefile for building benchmark with custom OpenSSL paths
CC = gcc
CFLAGS = -I/opt/openssl-3.5.1/include -D_POSIX_C_SOURCE=200809L
LDFLAGS = -L/opt/openssl-3.5.1/lib -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -lm
TARGET = benchmark
SRC = main.c timing.c rsa_bench.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)