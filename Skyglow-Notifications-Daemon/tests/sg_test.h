#ifndef SKYGLOW_SG_TEST_H
#define SKYGLOW_SG_TEST_H

#include <stdio.h>

/* Minimal shared harness for the host-side unit tests. */

static int failures = 0;

#define CHECK(condition, ...) do { if (!(condition)) { \
    failures++; printf("FAIL %s:%d  %s\n      ", __func__, __LINE__, #condition); \
    printf(__VA_ARGS__); printf("\n"); } } while (0)

#endif
