#include "timing.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <linux/time.h>

// Helper function to convert time differential to nanoseconds
static double timespec_diff_ns(struct timespec* start, struct timespec* end) {
    return (end->tv_sec - start->tv_sec) * 1e9 + (end->tv_nsec - start->tv_nsec);
}

// Function to time each operation individually
void time_per_iteration(void (*func)(void*), void* arg, int iterations, BenchmarkResult* result) {
    if (!result || iterations <= 0) {
        fprintf(stderr, "Invalid parameters for time_per_iteration\n");
        return;
    }

    double* deltas = malloc(iterations * sizeof(double));
    if (!deltas) {
        fprintf(stderr, "Memory allocation failed in time_per_iteration\n");
        return;
    }

    // Warm-up phase
    for (int i = 0; i < 20; i++) func(arg);

    // Timing phase for each iteration
    struct timespec start, end;
    double sum = 0, sum_squares = 0, min = 1e9, max = 0;
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        func(arg);
        clock_gettime(CLOCK_MONOTONIC, &end);

        deltas[i] = timespec_diff_ns(&start, &end);
        sum += deltas[i];
        sum_squares += deltas[i] * deltas[i];
        if (deltas[i] < min) min = deltas[i];
        if (deltas[i] > max) max = deltas[i];
    }

    // Compute the results
    result->iterations = iterations;
    result->avg_time_ms = (sum / iterations) / 1e6; // Convert from ns to ms
    result->ops_per_sec = iterations / (sum / 1e9); // Convert from ns to ops per second
    result->min_time_ms = min / 1e6; // Convert from ns to ms
    result->max_time_ms = max / 1e6; // Convert from ns to
    if (iterations > 1) {
        double mean = sum / iterations;
        result->std_dev_ms = sqrt((sum_squares / iterations) - mean * mean) / (iterations - 1) / 1e6;
    } else {
        result ->std_dev_ms = 0.0; // No standard deviation for a single iteration
    }
    free(deltas);
}

void time_total_delta(void (*func)(void*), void* arg, int iterations, BenchmarkResult* result) {
    if (!result || iterations <= 0) {
        fprintf(stderr, "Invalid input to time_total_delta\n");
        return;
    }

    // Warm-up
    for (int i = 0; i < 10; i++) func(arg);

    // Time all iterations
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        func(arg);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    // Compute stats
    double total_ns = timespec_diff_ns(&start, &end);
    result->iterations = iterations;
    result->avg_time_ms = total_ns / iterations / 1e6; // ns to ms
    result->ops_per_sec = iterations / (total_ns / 1e9); // ops per second
    result->std_dev_ms = 0; // Not available
    result->min_time_ms = 0; // Not available
    result->max_time_ms = 0; // Not available
}