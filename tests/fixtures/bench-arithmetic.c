// SPDX-License-Identifier: Apache-2.0
// Each build of this fixed translation unit receives its own BENCH_VARIANT.
#define FUNCTION(index)                                         \
    unsigned mix_##index(unsigned value, unsigned rounds)       \
    {                                                           \
        for (unsigned i = 0; i < rounds; i++) {                 \
            value ^= value >> 13;                               \
            value = value * 1664525u + BENCH_VARIANT + i;       \
        }                                                       \
        return value;                                           \
    }
#define GROUP(prefix)           \
    FUNCTION(prefix##0) FUNCTION(prefix##1) FUNCTION(prefix##2) FUNCTION(prefix##3) \
    FUNCTION(prefix##4) FUNCTION(prefix##5) FUNCTION(prefix##6) FUNCTION(prefix##7) \
    FUNCTION(prefix##8) FUNCTION(prefix##9)

GROUP(a) GROUP(b) GROUP(c) GROUP(d) GROUP(e) GROUP(f) GROUP(g) GROUP(h)
