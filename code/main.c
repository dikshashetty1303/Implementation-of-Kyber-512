#include "stm32f4xx_hal.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
// UART handle
UART_HandleTypeDef huart1;

// Kyber512 parameters
#define KYBER_K 2
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_POLYBYTES 384
#define KYBER_POLYCOMPRESSEDBYTES 128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)  // 2 * 320 = 640 for Kyber512
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)
#define KYBER_ETA1 3
#define KYBER_SYMBYTES 32
#define KYBER_SSBYTES 32



// UART helper
void uart_print(const char *str) {
    HAL_UART_Transmit(&huart1, (uint8_t *)str, strlen(str), HAL_MAX_DELAY);
}
static const uint32_t chacha20_constants[4] = {
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
};

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d)       \
    a += b; d ^= a; d = ROTL32(d,16);  \
    c += d; b ^= c; b = ROTL32(b,12);  \
    a += b; d ^= a; d = ROTL32(d,8);   \
    c += d; b ^= c; b = ROTL32(b,7);

static void chacha20_block(uint32_t output[16], const uint32_t key[8], uint32_t counter, const uint32_t nonce[3]) {
    int i;
    uint32_t state[16];

    state[0] = chacha20_constants[0];
    state[1] = chacha20_constants[1];
    state[2] = chacha20_constants[2];
    state[3] = chacha20_constants[3];

    memcpy(&state[4], key, 32);
    state[12] = counter;
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    for (i = 0; i < 16; i++) output[i] = state[i];

    for (i = 0; i < 10; i++) {
        QUARTERROUND(output[0], output[4], output[8], output[12])
        QUARTERROUND(output[1], output[5], output[9], output[13])
        QUARTERROUND(output[2], output[6], output[10], output[14])
        QUARTERROUND(output[3], output[7], output[11], output[15])

        QUARTERROUND(output[0], output[5], output[10], output[15])
        QUARTERROUND(output[1], output[6], output[11], output[12])
        QUARTERROUND(output[2], output[7], output[8], output[13])
        QUARTERROUND(output[3], output[4], output[9], output[14])
    }

    for (i = 0; i < 16; i++) output[i] += state[i];
}

typedef struct {
    uint32_t key[8];
    uint32_t nonce[3];
    uint32_t counter;
    uint8_t keystream[64];
    uint8_t keystream_index;
} chacha20_prng_ctx_t;

static chacha20_prng_ctx_t prng_ctx;

void chacha20_prng_init(chacha20_prng_ctx_t *ctx, const uint8_t seed[32], const uint8_t nonce[12]) {
    for (int i = 0; i < 8; i++) {
        ctx->key[i] = (uint32_t)seed[4*i] | ((uint32_t)seed[4*i+1] << 8) |
                      ((uint32_t)seed[4*i+2] << 16) | ((uint32_t)seed[4*i+3] << 24);
    }
    for (int i = 0; i < 3; i++) {
        ctx->nonce[i] = (uint32_t)nonce[4*i] | ((uint32_t)nonce[4*i+1] << 8) |
                        ((uint32_t)nonce[4*i+2] << 16) | ((uint32_t)nonce[4*i+3] << 24);
    }
    ctx->counter = 0;
    ctx->keystream_index = 64;
}

static void chacha20_prng_generate_block(chacha20_prng_ctx_t *ctx) {
    chacha20_block((uint32_t *)ctx->keystream, ctx->key, ctx->counter, ctx->nonce);
    ctx->counter++;
    ctx->keystream_index = 0;
}

void randombytes(uint8_t *out, size_t outlen) {
    size_t i = 0;
    while (i < outlen) {
        if (prng_ctx.keystream_index == 64) {
            chacha20_prng_generate_block(&prng_ctx);
        }
        out[i] = prng_ctx.keystream[prng_ctx.keystream_index];
        if (i < 8) {  // Print first 8 bytes generated
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X ", out[i]);
            uart_print(buf);
        }
        prng_ctx.keystream_index++;
        i++;
    }
    if (outlen > 0) uart_print("\r\n");
}


// === [ BEGIN KYBER512 DEFINITIONS ] ===
// All header content follows here...
   // size of shared secret
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_PUBLICKEYBYTES KYBER_INDCPA_PUBLICKEYBYTES
#define KYBER_SECRETKEYBYTES (KYBER_INDCPA_SECRETKEYBYTES + KYBER_PUBLICKEYBYTES + KYBER_SYMBYTES + KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

// ... continue defining all macros, types, and structures used in Kyber
#include <stdlib.h>
#include <math.h>

// === [ Kyber Types ] ===
typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

typedef struct {
    poly vec[KYBER_K];
} polyvec;

// === [ Modular Reduction ] ===
static int16_t montgomery_reduce(int32_t a) {
    int16_t t;
    const int32_t u = (a * 62209) & 0xFFFF;
    t = (a - u * KYBER_Q) >> 16;
    return t;
}

#include <stdint.h>

#define KYBER_N 256
#define KYBER_Q 3329

// Precomputed tables for NTT
extern const int16_t zetas[128];
extern const int16_t zetas_inv[128];
#include <stdint.h>

const int16_t zetas[128] = {
  2285, 2571, 2645,  621,  1577,  182,  962, 2127,
  1855, 1702,  431,  292,  2866,  1574, 1653,  278,
  577, 2004,  1441, 264,   383,  1730,  2860, 2351,
  1123,  1209, 2730, 1872, 202,  1855,  2440,  929,
  2305, 1525, 203,  2841, 1209, 472,  2191, 2648,
  217,  2809, 1787, 2455, 2660, 383,  202, 278,
  2144, 798,  758, 1175, 315, 203, 171,  2175,
  2215, 2374, 1044, 1231, 2648, 1473,  214, 2483,
  913, 1755, 2841, 1791, 269, 1755, 132, 2645,
  401,  2341, 1303,  269,  1493, 2341, 1123, 1822,
  293,  1286, 1804, 1653,  927,  336,  2004, 2483,
  2547, 1294,  827,  1872, 1903, 2440,  2474, 2191,
  1991,  1746, 1473, 1774, 315, 1209,  171, 1231,
  244,  2341, 1493, 132,  1123, 1303,  928,  1044,
  478,  1231,  919, 1286, 227,  292,  227,  958,
  2474, 2571, 2131,  383, 1294,  1101, 1441, 227
};

const int16_t zetas_inv[128] = {
  1323, 2488, 2674, 2542, 1234,  479,  232,  32,
  2899, 2552, 2063, 265,  947,  2285,  563,  700,
  2522, 1855,  2409, 2342,  206,  832, 1123, 132,
  1493, 2341,  2645, 132,  1456,  171, 2645,  919,
  827,  1294, 2547, 2483, 2004,  336,  927, 1653,
  1804, 1286, 293,  1822, 1123, 2341, 1493,  269,
  1303, 2341,  401, 2645, 132, 1755,  269, 1791,
  2841, 1755, 913, 2483,  214, 1473, 2648, 1231,
  1044, 2374, 2215, 2175, 171,  203,  315, 1175,
  758,  798, 2144,  278,  202,  383, 2660, 2455,
  1787, 2809,  217, 2648, 2191, 472, 1209, 2841,
  203, 1525, 2305, 929, 2440, 1855, 202, 1872,
  2730, 1209, 1123, 2351, 2860, 1730, 383, 264,
  1441, 2004, 577,  278, 1653, 1574, 2866, 292,
  431, 1702, 1855, 2127, 962,  182, 1577, 621,
  2645, 2571, 2285, 0 // Padding or ntt_zeta_zero if needed
};

// Barrett reduction
static int16_t barrett_reduce(int16_t a) {
    int16_t t;
    const int32_t v = ((int32_t) a * 5) >> 16;
    t = a - v * KYBER_Q;
    return t;
}
// === [ Polynomial NTT Stub ] ===
void ntt(int16_t r[KYBER_N]) {
    unsigned int len, start, j, k = 1;
    int16_t t, zeta;

    for (len = 128; len >= 1; len >>= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; ++j) {
                t = montgomery_reduce((int32_t)zeta * r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

// Inverse NTT
void invntt(int16_t r[KYBER_N]) {
    unsigned int start, len, j, k = 127;
    int16_t t, zeta;

    for (len = 1; len <= 128; len <<= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas_inv[k--];
            for (j = start; j < start + len; ++j) {
                t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = montgomery_reduce((int32_t)(t - r[j + len]) * zeta);
            }
        }
    }

    // Multiply by n^{-1}
    for (j = 0; j < KYBER_N; ++j) {
        r[j] = montgomery_reduce((int32_t)r[j] * 1441); // 1441 = n^{-1} mod q
    }
}
// === [ PolyVec Functions ] ===
void polyvec_compress(uint8_t *r, const polyvec *a) {
    // Stub: Copy values directly for demonstration
    memcpy(r, a, sizeof(polyvec));
}

void polyvec_decompress(polyvec *r, const uint8_t *a) {
    memcpy(r, a, sizeof(polyvec));
}

void polyvec_tobytes(uint8_t *r, const polyvec *a) {
    memcpy(r, a, sizeof(polyvec));
}

void polyvec_frombytes(polyvec *r, const uint8_t *a) {
    memcpy(r, a, sizeof(polyvec));
}

// === [ Polynomial Functions ] ===
void poly_getnoise(poly *r) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = rand() % KYBER_Q;
    }
}

void poly_frommsg(poly *r, const uint8_t msg[KYBER_SYMBYTES]) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = (msg[i % KYBER_SYMBYTES] & 1) ? KYBER_Q / 2 : 0;
    }
}

void poly_tomsg(uint8_t msg[KYBER_SYMBYTES], const poly *r) {
    for (int i = 0; i < KYBER_SYMBYTES; i++) {
        msg[i] = (r->coeffs[i % KYBER_N] > KYBER_Q / 2) ? 1 : 0;
    }
}
// === [ Minimal Keccak-f[1600] for SHAKE128 ] ===
#define ROL64(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
    10,  7, 11, 17, 18, 3, 5, 16,
     8, 21, 24, 4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9, 6,  1
};

static void keccakf(uint64_t state[25]) {
    int i, j, round;
    uint64_t t, bc[5];

    for (round = 0; round < 24; round++) {
        // θ
        for (i = 0; i < 5; i++)
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                state[j + i] ^= t;
        }

        // ρ and π
        t = state[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = state[j];
            state[j] = ROL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // χ
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = state[j + i];
            for (i = 0; i < 5; i++)
                state[j + i] ^= ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
        }

        // ι
        state[0] ^= keccakf_rndc[round];
    }
}

// === [ SHAKE128 Context & Absorb ] ===
typedef struct {
    uint64_t state[25];
    uint8_t buffer[168];
    int pos;
} shake128ctx;

void shake128_absorb(shake128ctx *s, const uint8_t *input, size_t inlen) {
    size_t i;
    memset(s, 0, sizeof(*s));
    for (i = 0; i < inlen; i++) {
        s->buffer[s->pos++] ^= input[i];
        if (s->pos == 168) {
            for (int j = 0; j < 21; j++)
                ((uint64_t *)s->state)[j] ^= ((uint64_t *)s->buffer)[j];
            keccakf(s->state);
            s->pos = 0;
        }
    }
    s->buffer[s->pos] ^= 0x1F;     // SHAKE domain separator
    s->buffer[167] ^= 0x80;        // Padding
    for (i = 0; i < 21; i++)
        s->state[i] ^= ((uint64_t *)s->buffer)[i];
    keccakf(s->state);
    s->pos = 0;
}

void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *s) {
    for (size_t i = 0; i < nblocks; i++) {
        memcpy(output + i * 168, s->state, 168);
        keccakf(s->state);
    }
}

void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    shake128ctx ctx;
    shake128_absorb(&ctx, input, inlen);
    size_t blocks = outlen / 168;
    shake128_squeezeblocks(output, blocks, &ctx);
    if (outlen % 168) {
        uint8_t tmp[168];
        shake128_squeezeblocks(tmp, 1, &ctx);
        memcpy(output + blocks * 168, tmp, outlen % 168);
    }
}
// === [ High-level KEM API ] ===
void crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    polyvec a, e, s;
    uint8_t seed[KYBER_SYMBYTES];
    randombytes(seed, KYBER_SYMBYTES);

    for (int i = 0; i < KYBER_K; i++) {
        poly_getnoise(&s.vec[i]);
        poly_getnoise(&e.vec[i]);
        ntt(s.vec[i].coeffs); // ✅ RIGHT

        ntt(e.vec[i].coeffs);
    }

    a = s;
    // Public key = a * s + e (mocked)
    polyvec_tobytes(pk, &a);
    memcpy(pk + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);

    polyvec_tobytes(sk, &s);
    memcpy(sk + KYBER_POLYVECBYTES, pk, KYBER_PUBLICKEYBYTES);
    memcpy(sk + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES, seed, KYBER_SYMBYTES);
    memset(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, 0x42, KYBER_SYMBYTES); // For demo
}

void crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t m[KYBER_SYMBYTES];
    randombytes(m, KYBER_SYMBYTES); // simulate randomness
    memcpy(ct, m, KYBER_SYMBYTES);  // just store m directly as ciphertext
    shake128(ss, KYBER_SSBYTES, m, KYBER_SYMBYTES); // derive shared secret from m
}

void crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t m[KYBER_SYMBYTES];
    memcpy(m, ct, KYBER_SYMBYTES); // recover m directly
    shake128(ss, KYBER_SSBYTES, m, KYBER_SYMBYTES); // derive same shared secret
}

void SystemClock_Config(void);
static void MX_USART1_UART_Init(void);
static void MX_GPIO_Init(void);
// === UART Print Helper ===


// === UART Read Line Helper ===
#define MAX_INPUT_SIZE 64
void uart_read(char *buffer, size_t max_len) {
    char c;
    size_t idx = 0;

    while (1) {
        HAL_UART_Receive(&huart1, (uint8_t *)&c, 1, HAL_MAX_DELAY);
        HAL_UART_Transmit(&huart1, (uint8_t *)&c, 1, HAL_MAX_DELAY); // Echo

        if (c == '\r' || c == '\n') {
            buffer[idx] = '\0';
            uart_print("\r\n");
            break;
        }

        if (idx < max_len - 1) {
            buffer[idx++] = c;
        }
    }
}

void process_input(const char *plaintext) {
    uint8_t seed[32];
    srand(HAL_GetTick());
    for (int i = 0; i < 32; i++) seed[i] = rand() & 0xFF;

    uint8_t nonce[12] = {0};
    chacha20_prng_init(&prng_ctx, seed, nonce);

    static uint8_t pk[KYBER_PUBLICKEYBYTES];
    static uint8_t sk[KYBER_SECRETKEYBYTES];
    static uint8_t ct[KYBER_CIPHERTEXTBYTES];
    static uint8_t ss_enc[KYBER_SSBYTES];
    static uint8_t ss_dec[KYBER_SSBYTES];
    uint8_t encrypted_msg[64] = {0};
    char decrypted_msg[64] = {0};

    uint32_t start, end, cycles;

    char msg[64];

    // Keypair generation with timing
    // Keypair generation timing
    uart_print("Generating Kyber512 keypair...\r\n");
    start = DWT->CYCCNT;
    crypto_kem_keypair(pk, sk);
    end = DWT->CYCCNT;
    cycles = end - start;
    uint32_t time_us_int = (uint32_t)(((uint64_t)cycles * 1000000) / SystemCoreClock);
    snprintf(msg, sizeof(msg), "KeyGen time: %lu us, cycles: %lu\r\n", (unsigned long)time_us_int, (unsigned long)cycles);
    uart_print(msg);
    uart_print("Public key:\r\n");
    for (int i = 0; i < KYBER_PUBLICKEYBYTES; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", pk[i]);
        uart_print(buf);
        if ((i + 1) % 32 == 0) uart_print("\r\n");
    }


    // Encapsulation timing
    uart_print("Encapsulating...\r\n");
    start = DWT->CYCCNT;
    crypto_kem_enc(ct, ss_enc, pk);
    end = DWT->CYCCNT;
    cycles = end - start;
    time_us_int = (uint32_t)(((uint64_t)cycles * 1000000) / SystemCoreClock);
    snprintf(msg, sizeof(msg), "Encapsulation time: %lu us, cycles: %lu\r\n", (unsigned long)time_us_int, (unsigned long)cycles);
    uart_print(msg);

    // Decapsulation timing
    start = DWT->CYCCNT;
    crypto_kem_dec(ss_dec, ct, sk);
    end = DWT->CYCCNT;
    cycles = end - start;
    time_us_int = (uint32_t)(((uint64_t)cycles * 1000000) / SystemCoreClock);
    snprintf(msg, sizeof(msg), "Decapsulation time: %lu us, cycles: %lu\r\n", (unsigned long)time_us_int, (unsigned long)cycles);
    uart_print(msg);

    // Display shared secrets
    uart_print("Shared secret (enc):\r\n");
    for (int i = 0; i < KYBER_SSBYTES; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", ss_enc[i]);
        uart_print(buf);
    }
    uart_print("\r\nShared secret (dec):\r\n");
    for (int i = 0; i < KYBER_SSBYTES; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", ss_dec[i]);
        uart_print(buf);
    }
    uart_print("\r\n");

    if (memcmp(ss_enc, ss_dec, KYBER_SSBYTES) != 0) {
        uart_print("ERROR: Shared secrets do not match!\r\n");
        return;
    }

    // XOR Encryption
    size_t msg_len = strlen(plaintext);
    uart_print("Original string: ");
    uart_print(plaintext);
    uart_print("\r\n");

    for (size_t i = 0; i < msg_len; i++) {
        encrypted_msg[i] = plaintext[i] ^ ss_enc[i % KYBER_SSBYTES];
    }

    uart_print("Encrypted string (hex): ");
    for (size_t i = 0; i < msg_len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", encrypted_msg[i]);
        uart_print(buf);
    }
    uart_print("\r\n");

    // XOR Decryption
    for (size_t i = 0; i < msg_len; i++) {
        decrypted_msg[i] = encrypted_msg[i] ^ ss_dec[i % KYBER_SSBYTES];
    }

    uart_print("Decrypted string: ");
    uart_print(decrypted_msg);
    uart_print("\r\n");

    uart_print("SUCCESS: Shared secrets match.\r\n");
}

int main(void) {
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USART1_UART_Init();

    // Enable DWT Cycle Counter
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    uart_print("Kyber512 Encryption Demo\r\n");
    uart_print("Enter a string to encrypt: ");

    char input_buf[64] = {0};
    uart_read(input_buf, sizeof(input_buf));

    process_input(input_buf);

    while (1) {
        HAL_Delay(1000);
    }
}


// === [ HAL Configuration ] ===
void SystemClock_Config(void) {
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
    RCC_OscInitStruct.PLL.PLLM = 16;
    RCC_OscInitStruct.PLL.PLLN = 336;
    RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
    RCC_OscInitStruct.PLL.PLLQ = 7;
    HAL_RCC_OscConfig(&RCC_OscInitStruct);
    HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2);
}


static void MX_GPIO_Init(void) {
    __HAL_RCC_GPIOA_CLK_ENABLE();
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    // USART1 TX (PA9), RX (PA10)
    GPIO_InitStruct.Pin = GPIO_PIN_9 | GPIO_PIN_10;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF7_USART1;  // <<< MUST BE AF7 for USART1
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
}
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
 while(1);
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}
