#include "Keccak.h"
#include <string.h>

// Keccak-f[1600] 常量
static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int KECCAK_ROTC[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
};

static const int KECCAK_PILN[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void keccakf(uint64_t st[25]) {
    uint64_t bc[5], t;
    for (int round = 0; round < 24; round++) {
        // Theta
        for (int i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        // Rho + Pi
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PILN[i];
            bc[0] = st[j];
            st[j] = rotl64(t, KECCAK_ROTC[i]);
            t = bc[0];
        }
        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j + i];
            for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        // Iota
        st[0] ^= KECCAK_RC[round];
    }
}

#define KECCAK_RATE 136   // keccak256: 1088 bit

static void keccak_absorb_final(const uint8_t *in, size_t len, uint64_t st[25]) {
    uint8_t block[KECCAK_RATE];
    size_t off = 0;
    while (len - off >= KECCAK_RATE) {
        for (int i = 0; i < KECCAK_RATE / 8; i++) {
            uint64_t v;
            memcpy(&v, in + off + i * 8, 8);
            st[i] ^= v;
        }
        keccakf(st);
        off += KECCAK_RATE;
    }
    size_t rem = len - off;
    memset(block, 0, sizeof(block));
    if (rem) memcpy(block, in + off, rem);
    block[rem] ^= 0x01;              // keccak padding（不是 0x06）
    block[KECCAK_RATE - 1] ^= 0x80;
    for (int i = 0; i < KECCAK_RATE / 8; i++) {
        uint64_t v;
        memcpy(&v, block + i * 8, 8);
        st[i] ^= v;
    }
    keccakf(st);
}

void keccak256(const uint8_t *in, size_t len, uint8_t out[32]) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    keccak_absorb_final(in, len, st);
    memcpy(out, st, 32);
}

void keccak256_two(const uint8_t *a, size_t alen,
                   const uint8_t *b, size_t blen,
                   uint8_t out[32]) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));

    // 先吸收 a，再吸收 b（用中间块处理，避免临时拼接）
    uint8_t block[KECCAK_RATE];
    size_t off = 0;

    // 处理 a 的整块
    while (alen - off >= KECCAK_RATE) {
        for (int i = 0; i < KECCAK_RATE / 8; i++) {
            uint64_t v;
            memcpy(&v, a + off + i * 8, 8);
            st[i] ^= v;
        }
        keccakf(st);
        off += KECCAK_RATE;
    }
    size_t rem = alen - off;
    memset(block, 0, sizeof(block));
    if (rem) memcpy(block, a + off, rem);

    // 接着塞 b
    size_t pos = rem;
    size_t boff = 0;
    while (boff < blen) {
        if (pos == KECCAK_RATE) {
            for (int i = 0; i < KECCAK_RATE / 8; i++) {
                uint64_t v;
                memcpy(&v, block + i * 8, 8);
                st[i] ^= v;
            }
            keccakf(st);
            memset(block, 0, sizeof(block));
            pos = 0;
        }
        size_t take = KECCAK_RATE - pos;
        if (take > blen - boff) take = blen - boff;
        memcpy(block + pos, b + boff, take);
        pos += take;
        boff += take;
    }

    block[pos] ^= 0x01;
    block[KECCAK_RATE - 1] ^= 0x80;
    for (int i = 0; i < KECCAK_RATE / 8; i++) {
        uint64_t v;
        memcpy(&v, block + i * 8, 8);
        st[i] ^= v;
    }
    keccakf(st);
    memcpy(out, st, 32);
}
