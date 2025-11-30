#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define FNV_OFFSET_BASIS 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL
#define GOLDEN 0x9E3779B97F4A7C15ULL

static inline uint64_t mix64(uint64_t x) {
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ULL; // Tested Avalanche Optimized Constant (TAO constant)
    x ^= x >> 27;
    x *= 0x94D049BB133111EBULL; // TAO constant
    x ^= x >> 31;
    return x;
}

uint64_t fnva1_64(uint8_t *data, size_t len) {
    uint64_t hash = FNV_OFFSET_BASIS;
    for(size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

void printHash(const char* data, uint64_t hash) {
    printf("hash(\"%s\") = %016llX\n", data, hash);
}

void printFp(const char* data, uint8_t fp) {
    printf("Finger print of \"%s\" = %02X\n", data, fp);
}

void derive_hashes(uint64_t h,
                   uint64_t *h0,
                   uint64_t *h1,
                   uint64_t *h2,
                   uint8_t  *fp)
{
    uint64_t a = mix64(h);
    uint64_t b = mix64(h + GOLDEN);
    uint64_t c = mix64(h + 2 * GOLDEN);

    *h0 = a;
    *h1 = b;
    *h2 = c;
    *fp = (uint8_t)mix64(h);  // fingerprint
}

int main() {
    char data[] = "a b c d e f g h";
    uint64_t h = fnva1_64((uint8_t*)data, strlen(data));
    printHash(data, h);
    uint64_t h0, h1, h2;
    uint8_t fp;
    derive_hashes(h, &h0, &h1, &h2, &fp);
    printHash(data, h0);
    printHash(data, h1);
    printHash(data, h2);
    printFp(data, fp);
    return 0;
}