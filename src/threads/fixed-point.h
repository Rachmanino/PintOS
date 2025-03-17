/* Implementation of 17.14 fixed-point real number arithmetic. */
#include <debug.h>
#include <stddef.h>
#include <stdint.h>

typedef int fixed_point;
static int p = 17, 
    q = 14, 
    f = 1 << q;
const fixed_point FIXED_POINT_MAX = 0x7FFFFFFF;
const fixed_point FIXED_POINT_MIN = 0xFFFFFFFF;

fixed_point itof(int n) {
    return n * f;
}

int ftoi_rzero(fixed_point x) {
    return x / f;
}

int ftoi_rnear(fixed_point x) {
    return (x >= 0) ? (x + f / 2) / f : (x - f / 2) / f;
}

fixed_point ffadd(fixed_point x, fixed_point y) {
    return x + y;
}

fixed_point ffsub(fixed_point x, fixed_point y) {
    return x - y;
}

fixed_point ffmul(fixed_point x, fixed_point y) {
    return ((int64_t) x) * y / f;
}

fixed_point ffdiv(fixed_point x, fixed_point y) {
    return ((int64_t) x) * f / y;
}

fixed_point fiadd(fixed_point x, int n) {
    return x + n * f;
}

fixed_point fisub(fixed_point x, int n) {
    return x - n * f;
}

fixed_point fimul(fixed_point x, int n) {
    return x * n;
}

fixed_point fidiv(fixed_point x, int n) {
    return x / n;
}


