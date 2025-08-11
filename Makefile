# Basic Makefile for building benchmark with custom OpenSSL paths
CC = gcc
CFLAGS = -I/opt/openssl-3.5.1/include -D_POSIX_C_SOURCE=200809L -std=gnu11
LDFLAGS = -L/opt/openssl-3.5.1/lib -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -lm
TARGET = benchmark
SRC = main.c timing.c rsa_bench.c ecdsa_bench.c ed25519_bench.c pqc_bench.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

test-all: $(TARGET)
	@echo "Running all benchmark tests, outputting to results.csv"
	@rm -f results.csv
	@echo "operation,curve_or_keysize,iterations,avg_ms,ops_per_sec,std_dev_us,min_ms,max_ms" > results.csv
	@./$(TARGET) --operation rsa-keygen --key-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation rsa-keygen --key-size 2048 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation rsa-keygen --key-size 3072 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation rsa-keygen --key-size 4096 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation rsa-sign --key-size 1024 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation rsa-sign --key-size 2048 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation rsa-sign --key-size 3072 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation rsa-sign --key-size 4096 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation rsa-verify --key-size 1024 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation rsa-verify --key-size 2048 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation rsa-verify --key-size 3072 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation rsa-verify --key-size 4096 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-keygen --curve P-256 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-keygen --curve P-384 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-keygen --curve P-521 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-sign --curve P-256 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-sign --curve P-384 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-sign --curve P-521 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-verify --curve P-256 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-verify --curve P-384 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation ecdsa-verify --curve P-521 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation ed25519-keygen --curve ed25519 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation ed25519-sign --curve ed25519 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation ed25519-verify --curve ed25519 --data-size 1024 --iterations 1000 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo ML-DSA-44 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo ML-DSA-44 --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo ML-DSA-44 --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo ML-DSA-65 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo ML-DSA-65 --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo ML-DSA-65 --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo ML-DSA-87 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo ML-DSA-87 --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo ML-DSA-87 --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHA2-128s --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHA2-128s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHA2-128s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHA2-128f --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHA2-128f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHA2-128f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHA2-192s --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHA2-192s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHA2-192s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHA2-192f --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHA2-192f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHA2-192f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHA2-256s --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHA2-256s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHA2-256s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHAKE-128s --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHAKE-128s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHAKE-128s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHAKE-128f --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHAKE-128f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHAKE-128f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHAKE-192s --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHAKE-192s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHAKE-192s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHAKE-192f --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHAKE-192f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHAKE-192f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHAKE-256s --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHAKE-256s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHAKE-256s --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-keygen --pqc-algo SLH-DSA-SHAKE-256f --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-sign --pqc-algo SLH-DSA-SHAKE-256f --data-size 1024 --iterations 100 --csv >> results.csv && \
	./$(TARGET) --operation pqc-verify --pqc-algo SLH-DSA-SHAKE-256f --data-size 1024 --iterations 100 --csv >> results.csv
	@echo "All tests completed. Results saved in results.csv"

clean:
	rm -f $(TARGET) results.csv