#include "/usr/local/include/pbc/pbc.h"
#include "sha3.h"
#include "string.h"
#include <stdio.h>
#include <time.h>
#include <sys/time.h>


typedef unsigned char byte;
struct timeval stop, start, diff;

int main()
{

    char DO[] = "Alice";
    char DU[] = "Bob";
    pairing_t pairing;
    element_t g, h;
    element_t pk_svr, sk_svr;
    element_t msk, mpk;
    element_t H_s, H_r, sk_s, sk_r;
    element_t s;
    element_t c_1, c_2, c_3, k_ct;
    element_t H_k_w_ct;
    element_t pk_s_svr;
    element_t r, h_r, t_1, t_2, k_td, H_k_w_td;
    element_t t_1_sk_svr_c2, t_1_sk_svr;
    element_t t_2_sk_svr_c3, t_2_sk_svr;
    element_t c_1_e_t_2_sk_svr_c_3;
    pbc_param_t par;

    pbc_param_init_a_gen(par, 160, 512);
    pairing_init_pbc_param(pairing, par);

    // Generate system parmeter
    element_init_G1(g, pairing);
    element_init_G1(h, pairing);
    element_init_Zr(sk_svr, pairing);
    element_init_G2(pk_svr, pairing);

    element_random(sk_svr);
    element_pow_zn(pk_svr, g, sk_svr);

    element_init_Zr(msk, pairing);
    element_init_G1(mpk, pairing);
    element_random(msk);
    element_pow_zn(mpk, g, msk);

    // Generate pk/sk

    element_init_G1(H_s, pairing);
    element_init_G1(H_r, pairing);
    element_init_G2(sk_s, pairing);
    element_init_G2(sk_r, pairing);

    element_from_hash(H_s, DO, strlen(DO));
    element_from_hash(H_r, DU, strlen(DU));

    element_pow_zn(sk_s, H_s, msk);
    element_pow_zn(sk_r, H_r, msk);

    // PAEKS

    char kw_ct[] = "Crypto";

    element_init_Zr(s, pairing);
    element_random(s);
    element_init_GT(c_1, pairing);
    element_init_G1(c_2, pairing);
    element_init_G1(c_3, pairing);

    element_init_G1(H_k_w_ct, pairing);
    element_init_G2(pk_s_svr, pairing);
    element_init_GT(k_ct, pairing);

    element_pow_zn(c_2, g, s);
    element_pow_zn(c_3, h, s);

    pairing_apply(k_ct, H_r, sk_s, pairing);

    int element_len_k_ct = element_length_in_bytes(k_ct);
    unsigned char elem_bytes_k_ct[element_len_k_ct];
    memset(elem_bytes_k_ct, 0, element_len_k_ct);
    element_snprint(elem_bytes_k_ct, element_len_k_ct, k_ct);

    int len_k_ct_add_kw_ct = sizeof(elem_bytes_k_ct) + sizeof(kw_ct);
    char string_bytes_k_ct_add_kw_ct[len_k_ct_add_kw_ct];
    memset(string_bytes_k_ct_add_kw_ct, 0, sizeof(string_bytes_k_ct_add_kw_ct));
    strncat(string_bytes_k_ct_add_kw_ct, elem_bytes_k_ct, sizeof(elem_bytes_k_ct));
    strncat(string_bytes_k_ct_add_kw_ct, kw_ct, sizeof(kw_ct));
    element_from_hash(H_k_w_ct, string_bytes_k_ct_add_kw_ct, sizeof(string_bytes_k_ct_add_kw_ct));
    element_pow_zn(pk_s_svr, pk_svr, s);
    pairing_apply(c_1, H_k_w_ct, pk_s_svr, pairing);

    
    // Trapdoor

    char kw_td[] = "Crypto";

    element_init_Zr(r, pairing);
    element_init_G1(h_r, pairing);
    element_init_G2(t_1, pairing);
    element_init_G2(t_2, pairing);
    element_init_G1(H_k_w_td, pairing);
    element_random(r);
    element_pow_zn(h_r, h, r);

    element_init_GT(k_td, pairing);
    pairing_apply(k_td, H_s, sk_r, pairing);

    int element_len_k_td = element_length_in_bytes(k_td);
    unsigned char elem_bytes_k_td[element_len_k_td];
    memset(elem_bytes_k_td, 0, element_len_k_td);
    element_snprint(elem_bytes_k_td, element_len_k_td, k_td);

    int len_k_td_add_kw_td = sizeof(elem_bytes_k_td) + sizeof(kw_td);
    char string_bytes_k_td_add_kw_td[len_k_td_add_kw_td];
    memset(string_bytes_k_td_add_kw_td, 0, sizeof(len_k_td_add_kw_td));
    strncat(string_bytes_k_td_add_kw_td, elem_bytes_k_td, sizeof(elem_bytes_k_td));
    strncat(string_bytes_k_td_add_kw_td, kw_td, sizeof(kw_td));
    element_from_hash(H_k_w_td, string_bytes_k_td_add_kw_td, sizeof(string_bytes_k_td_add_kw_td));

    element_mul(t_1, H_k_w_td, h_r);
    element_pow_zn(t_2, g, r);
    // Test

    gettimeofday(&start, NULL);
    element_init_GT(t_2_sk_svr_c3, pairing);
    element_init_G2(t_2_sk_svr, pairing);

    element_pow_zn(t_2_sk_svr, t_2, sk_svr);
    pairing_apply(t_2_sk_svr_c3, c_3, t_2_sk_svr, pairing);

    element_init_GT(t_1_sk_svr_c2, pairing);
    element_init_G2(t_1_sk_svr, pairing);

    element_pow_zn(t_1_sk_svr, t_1, sk_svr);
    pairing_apply(t_1_sk_svr_c2, c_2, t_1_sk_svr, pairing);

    element_init_GT(c_1_e_t_2_sk_svr_c_3, pairing);
    element_mul(c_1_e_t_2_sk_svr_c_3, c_1, t_2_sk_svr_c3);

    if (!element_cmp(c_1_e_t_2_sk_svr_c_3, t_1_sk_svr_c2))
    {
        printf("success\n");
    }

gettimeofday(&stop, NULL);
    timersub(&stop, &start, &diff);

    double time_used = diff.tv_sec + (double)diff.tv_usec / 1000000.0;

    printf("%f", time_used);
    return 0;
}