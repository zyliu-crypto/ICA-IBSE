#include "/usr/local/include/pbc/pbc.h"
#include "sha3.h"
#include "string.h"
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

typedef unsigned char byte;
struct timeval stop1, start1, diff1;
struct timeval stop2, start2, diff2;
struct timeval stop3, start3, diff3;

int main()
{

    char DO[] = "Alice";
    char DU[] = "Bob";
    pairing_t pairing;
    element_t g, x, sk_s, sk_r, r, c_1, c_2, k_1, H_s, H_r, h_2, rh2, k_2, c_1_exp_test, h2_test;
    pbc_param_t par;

    pbc_param_init_a_gen(par, 160, 512);
    pairing_init_pbc_param(pairing, par);

    // Element initial

    element_init_G1(g, pairing);
    element_init_G1(H_s, pairing);
    element_init_G1(H_r, pairing);
    element_init_G2(sk_s, pairing);
    element_init_G2(sk_r, pairing);
    element_init_Zr(x, pairing);
    element_init_Zr(r, pairing);

    element_init_G1(c_1, pairing);
    element_init_G1(c_2, pairing);
    element_init_GT(k_1, pairing);
    element_init_Zr(h_2, pairing);
    element_init_Zr(rh2, pairing);
    element_init_GT(k_2, pairing);
    element_init_Zr(h2_test, pairing);
    element_init_G1(c_1_exp_test, pairing);

    // Generate system parmeter

    element_random(g);
    element_from_hash(H_s, DO, sizeof(DO));
    element_from_hash(H_r, DU, sizeof(DU));

    // KGC secret key
    element_random(x);

    // Generate pk/sk
    element_pow_zn(sk_s, H_s, x);
    element_pow_zn(sk_r, H_r, x);

    // PAEKS

    gettimeofday(&start1, NULL);
    element_random(r);
    element_pow_zn(c_1, g, r);
    pairing_apply(k_1, H_r, sk_s, pairing);

    char keyword_1[] = "Crypto";

    // compute h1 value
    int element_len_1 = element_length_in_bytes(k_1);
    unsigned char elem_bytes_1[element_len_1];

    memset(elem_bytes_1, 0, element_len_1);
    element_snprint(elem_bytes_1, element_len_1, k_1);

    int len_1 = sizeof(DO) + sizeof(DU) + sizeof(elem_bytes_1) + sizeof(keyword_1);
    unsigned char string_bytes_1[len_1];
    memset(string_bytes_1, 0, len_1);

    strncpy(string_bytes_1, DO, sizeof(DO));
    strncat(string_bytes_1, DU, sizeof(DU));
    strncat(string_bytes_1, elem_bytes_1, sizeof(elem_bytes_1));
    strncat(string_bytes_1, keyword_1, sizeof(keyword_1));

    unsigned char h1_hash[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_bytes_1, sizeof(string_bytes_1), h1_hash, sizeof(h1_hash));

    // compute h2 value and convert to Z_q
    int element_len_2 = element_length_in_bytes(c_1);

    unsigned char elem_bytes_2[element_len_2];

    memset(elem_bytes_2, 0, element_len_2);

    element_snprint(elem_bytes_2, element_len_2, c_1);

    int len_2 = sizeof(h1_hash) + sizeof(elem_bytes_2);
    unsigned char string_bytes_2[len_2];
    memset(string_bytes_2, 0, len_2);

    strncpy(string_bytes_2, h1_hash, sizeof(h1_hash));
    strncat(string_bytes_2, elem_bytes_2, sizeof(elem_bytes_2));

    unsigned char h2_hash[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_bytes_2, sizeof(string_bytes_2), h2_hash, sizeof(h2_hash));

    element_from_hash(h_2, h2_hash, 32);
    element_mul(rh2, r, h_2);
    element_pow_zn(c_2, g, rh2);

    gettimeofday(&stop1, NULL);
    timersub(&stop1, &start1, &diff1);

    printf("Enc took %f ms\n", diff1.tv_sec * 1000.0f + diff1.tv_usec / 1000.0f);

    // Trapdoor
    gettimeofday(&start2, NULL);
    char keyword_2[] = "Crypto";

    // compute h1 value

    pairing_apply(k_2, H_s, sk_r, pairing);

    int element_len_3 = element_length_in_bytes(k_2);

    unsigned char elem_bytes_3[element_len_3];
    memset(elem_bytes_3, 0, element_len_3);
    element_snprint(elem_bytes_3, element_len_3, k_2);

    int len_3 = sizeof(DO) + sizeof(DU) + sizeof(elem_bytes_3) + sizeof(keyword_2);
    unsigned char string_bytes_3[len_3];
    memset(string_bytes_3, 0, len_3);
    strncpy(string_bytes_3, DO, sizeof(DO));
    strncat(string_bytes_3, DU, sizeof(DU));
    strncat(string_bytes_3, elem_bytes_3, sizeof(elem_bytes_3));
    strncat(string_bytes_3, keyword_2, sizeof(keyword_2));

    unsigned char h1_hash_td[32];
    memset(h1_hash_td, 0, 32);
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_bytes_3, sizeof(string_bytes_3), h1_hash_td, sizeof(h1_hash_td));

    gettimeofday(&stop2, NULL);
    timersub(&stop2, &start2, &diff2);

    printf("Trapdoor took %f ms\n", diff2.tv_sec * 1000.0f + diff2.tv_usec / 1000.0f);

    // Test
    gettimeofday(&start3, NULL);

    int element_len_4 = element_length_in_bytes(c_1);
    unsigned char elem_bytes_4[element_len_4];
    memset(elem_bytes_4, 0, element_len_4);
    element_snprint(elem_bytes_4, element_len_4, c_1);

    int len_4 = sizeof(h1_hash_td) + sizeof(elem_bytes_4);
    unsigned char string_bytes_4[len_4];
    memset(string_bytes_4, 0, len_4);
    strncpy(string_bytes_4, h1_hash_td, sizeof(h1_hash_td));
    strncat(string_bytes_4, elem_bytes_4, sizeof(elem_bytes_4));

    unsigned char h2_hash_test[32];
    memset(h2_hash_test, 0, 32);
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_bytes_4, sizeof(string_bytes_4), h2_hash_test, sizeof(h2_hash_test));
    element_from_hash(h2_test, h2_hash_test, 32);

    element_pow_zn(c_1_exp_test, c_1, r);

    if (!element_cmp(c_2, c_1_exp_test))
    {
        printf("success\n");
    }
    gettimeofday(&stop3, NULL);
    timersub(&stop3, &start3, &diff3);

    printf("Test took %f ms\n", diff3.tv_sec * 1000.0f + diff3.tv_usec / 1000.0f);
    return 0;
}