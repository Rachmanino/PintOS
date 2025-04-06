/* Implementation of 17.14 fixed-point real number arithmetic. */

#include <debug.h>
#include <stddef.h>
#include <stdint.h>

typedef int fixed_point;

static int f = 16384; // 2^14

UNUSED static fixed_point itof(int n)  {
    return n * f;
}

UNUSED static int ftoi_rzero(fixed_point x) {
    return x / f;
}

UNUSED static int ftoi_rnear(fixed_point x) {
    return (x >= 0) ? (x + f / 2) / f : (x - f / 2) / f;
}

UNUSED static fixed_point ffadd(fixed_point x, fixed_point y) {
    return x + y;
}

UNUSED static fixed_point ffsub(fixed_point x, fixed_point y) {
    return x - y;
}

UNUSED static fixed_point ffmul(fixed_point x, fixed_point y) {
    return ((int64_t) x) * y / f;
}

UNUSED static fixed_point ffdiv(fixed_point x, fixed_point y) {
    return ((int64_t) x) * f / y;
}

UNUSED static fixed_point fiadd(fixed_point x, int n) {
    return x + n * f;
}

UNUSED static fixed_point fisub(fixed_point x, int n) {
    return x - n * f;
}

UNUSED static fixed_point fimul(fixed_point x, int n) {
    return x * n;
}

UNUSED static fixed_point fidiv(fixed_point x, int n) {
    return x / n;
}



