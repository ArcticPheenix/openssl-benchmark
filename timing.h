#ifndef TIMING_H
#define TIMING_H

#include <time.h>

typedef struct {
    double avg_time_ms;
    double ops_per_sec;
    double std_dev_ms;
    double min_time_ms;
    double max_time_ms;
    int iterations;
} BenchmarkResult;

// Per-iteration timing: Time each operation individually for better granularity
void time_per_iteration(void (*func)(void*), void* arg, int iterations, BenchmarkResult* result);

// Total-delta timing: Time all iterations together for a cumulative result
void time_total_delta(void (*func)(void*), void* arg, int iterations, BenchmarkResult* result);

#endif // TIMING_H