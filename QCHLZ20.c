#include "/usr/local/include/pbc/pbc.h"
#include "sha3.h"
#include "string.h"
#include <stdio.h>
#include <sys/time.h>

struct timeval stop1, start1, diff1;
struct timeval stop2, start2, diff2;
struct timeval stop3, start3, diff3;

int main()
{

    char DO[] = "Alice";
    char DU[] = "Bob";
    pairing_t pairing;
    element_t g;
    element_t pk_s, pk_r, sk_s, sk_r;
    element_t r, A, hr, K, h1_w_K, t;
    pbc_param_t par;

    pbc_param_init_a_gen(par, 160, 512);
    pairing_init_pbc_param(pairing, par);

    // element initial

    // generate system parmeter
    element_init_G1(g, pairing);
    element_random(g);
    // generate pk/sk

    element_init_G1(pk_s, pairing);
    element_init_G1(pk_r, pairing);
    element_init_Zr(sk_s, pairing);
    element_init_Zr(sk_r, pairing);
    element_random(sk_s);
    element_random(sk_r);
    element_pow_zn(pk_s, g, sk_s);
    element_pow_zn(pk_r, g, sk_r);

    // PAEKS

    gettimeofday(&start1, NULL);
    char kw_ct[] = "Crypto";

    element_init_Zr(r, pairing);
    element_random(r);
    element_init_G2(A, pairing);
    element_pow_zn(A, g, r);

    element_init_G2(hr, pairing);
    element_pow_zn(hr, pk_r, r);

    element_init_G1(K, pairing);
    element_pow_zn(K, pk_r, sk_s);

    int element_len_K = element_length_in_bytes(K);
    unsigned char elem_bytes_K[element_len_K];
    memset(elem_bytes_K, 0, element_len_K);
    element_snprint(elem_bytes_K, element_len_K, K);

    int len_bytes_w_K = sizeof(kw_ct) + sizeof(elem_bytes_K);
    char string_bytes_w_K[len_bytes_w_K];

    memset(string_bytes_w_K, 0, len_bytes_w_K);

    strncpy(string_bytes_w_K, kw_ct, sizeof(kw_ct));
    strncat(string_bytes_w_K, elem_bytes_K, sizeof(elem_bytes_K));

    element_init_G1(h1_w_K, pairing);
    element_from_hash(h1_w_K, string_bytes_w_K, sizeof(string_bytes_w_K));
    element_init_GT(t, pairing);
    pairing_apply(t, h1_w_K, hr, pairing);

    int element_len_t = element_length_in_bytes(t);
    unsigned char elem_bytes_t[element_len_t];
    memset(elem_bytes_t, 0, element_len_t);
    element_snprint(elem_bytes_t, element_len_t, t);

    unsigned char B[32];
    memset(B, 0, 32);
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, elem_bytes_t, sizeof(elem_bytes_t), B, sizeof(B));

    gettimeofday(&stop1, NULL);
    timersub(&stop1, &start1, &diff1);

    printf("Enc took %f ms\n", diff1.tv_sec * 1000.0f + diff1.tv_usec / 1000.0f);
    // trapdoor

    gettimeofday(&start2, NULL);
    char kw_td[] = "Crypto";
    element_t hx, h1_w_hx, td;
    element_init_G1(hx, pairing);
    element_pow_zn(hx, pk_s, sk_r);

    int element_len_hx = element_length_in_bytes(hx);
    unsigned char elem_bytes_hx[element_len_hx];
    memset(elem_bytes_hx, 0, element_len_hx);
    element_snprint(elem_bytes_hx, element_len_hx, hx);

    int len_bytes_w_hx = sizeof(kw_td) + sizeof(elem_bytes_hx);
    char string_bytes_w_hx[len_bytes_w_hx];

    memset(string_bytes_w_hx, 0, len_bytes_w_hx);

    strncpy(string_bytes_w_hx, kw_td, sizeof(kw_td));
    strncat(string_bytes_w_hx, elem_bytes_hx, sizeof(elem_bytes_hx));

    element_init_G1(h1_w_hx, pairing);
    element_from_hash(h1_w_hx, string_bytes_w_hx, sizeof(string_bytes_w_hx));
    element_init_G1(td, pairing);
    element_pow_zn(td, h1_w_hx, sk_r);

    gettimeofday(&stop2, NULL);
    timersub(&stop2, &start2, &diff2);

    printf("Trapdoor took %f ms\n", diff2.tv_sec * 1000.0f + diff2.tv_usec / 1000.0f);
    // test
    gettimeofday(&start3, NULL);
    element_t e_td_A;
    element_init_GT(e_td_A, pairing);
    pairing_apply(e_td_A, td, A, pairing);

    int element_len_e_td_A = element_length_in_bytes(e_td_A);
    unsigned char elem_bytes_e_td_A[element_len_e_td_A];
    memset(elem_bytes_e_td_A, 0, element_len_e_td_A);
    element_snprint(elem_bytes_e_td_A, element_len_e_td_A, e_td_A);

    unsigned char B_test[32];
    memset(B_test, 0, 32);
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, elem_bytes_e_td_A, sizeof(elem_bytes_e_td_A), B_test, sizeof(B_test));

    if (sizeof(B_test) == sizeof(B) && !strncmp(B_test, B, sizeof(B_test)))
    {
        printf("success\n");
    }

    gettimeofday(&stop3, NULL);
    timersub(&stop3, &start3, &diff3);

    printf("Test took %f ms\n", diff3.tv_sec * 1000.0f + diff3.tv_usec / 1000.0f);

    return 0;
}