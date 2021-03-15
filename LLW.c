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
    element_t p, lambda, p_pub, sk_s_1, sk_s_2, sk_r_1, sk_r_2, p_s_1, p_s_2, p_r_1, p_r_2, cert_s, cert_r;
    element_t beta_s, beta_r, Q_s, Q_r;
    element_t f1_id_s_pk_lambda, f1_id_r_pk_lambda;
    element_t mod_int_hash_string_DO_p_s_Q_s, mod_int_hash_string_DU_p_r_Q_r;
    pbc_param_t par;

    pbc_param_init_a_gen(par, 160, 512);
    pairing_init_pbc_param(pairing, par);

    element_init_G1(p, pairing);
    element_init_Zr(lambda, pairing);

    // generate system parmeter
    element_random(lambda);
    element_init_G1(p_pub, pairing);
    element_pow_zn(p_pub, p, lambda);

    // keygen
    element_init_Zr(sk_s_1, pairing);
    element_init_Zr(sk_r_1, pairing);
    element_init_Zr(sk_s_2, pairing);
    element_init_Zr(sk_r_2, pairing);

    element_random(sk_s_1);
    element_random(sk_r_1);
    element_random(sk_s_2);
    element_random(sk_r_2);

    element_init_G1(p_s_1, pairing);
    element_init_G1(p_r_1, pairing);
    element_init_G1(p_s_2, pairing);
    element_init_G1(p_r_2, pairing);

    element_pow_zn(p_s_1, p, sk_s_1);
    element_pow_zn(p_r_1, p, sk_r_1);
    element_pow_zn(p_s_2, p, sk_s_2);
    element_pow_zn(p_r_2, p, sk_r_2);

    // cert
    element_init_Zr(beta_s, pairing);
    element_init_Zr(beta_r, pairing);
    element_init_G1(Q_s, pairing);
    element_init_G1(Q_r, pairing);

    element_random(beta_s);
    element_random(beta_r);
    element_pow_zn(Q_s, p, beta_s);
    element_pow_zn(Q_r, p, beta_r);

    int p_s_1_len = element_length_in_bytes(p_s_1);
    unsigned char elem_p_s_1[p_s_1_len];
    element_snprint(elem_p_s_1, p_s_1_len, p_s_1);

    int p_s_2_len = element_length_in_bytes(p_s_2);
    unsigned char elem_p_s_2[p_s_2_len];
    element_snprint(elem_p_s_2, p_s_2_len, p_s_2);

    int Q_s_len = element_length_in_bytes(Q_s);
    unsigned char elem_Q_s[Q_s_len];
    element_snprint(elem_Q_s, Q_s_len, Q_s);

    int p_r_1_len = element_length_in_bytes(p_r_1);
    unsigned char elem_p_r_1[p_r_1_len];
    element_snprint(elem_p_r_1, p_r_1_len, p_r_1);

    int p_r_2_len = element_length_in_bytes(p_r_2);
    unsigned char elem_p_r_2[p_r_2_len];
    element_snprint(elem_p_r_2, p_r_2_len, p_r_2);

    int Q_r_len = element_length_in_bytes(Q_r);
    unsigned char elem_Q_r[Q_r_len];
    element_snprint(elem_Q_r, Q_r_len, Q_r);

    // cert_s
    int len_DO_p_s_Q_s = sizeof(DO) + sizeof(elem_p_s_1) + sizeof(elem_p_s_2) + sizeof(elem_Q_s);
    unsigned char string_DO_p_s_Q_s[len_DO_p_s_Q_s];

    memset(string_DO_p_s_Q_s, 0, len_DO_p_s_Q_s);
    strncpy(string_DO_p_s_Q_s, DO, sizeof(DO));
    strncat(string_DO_p_s_Q_s, elem_p_s_1, sizeof(elem_p_s_1));
    strncat(string_DO_p_s_Q_s, elem_p_s_2, sizeof(elem_p_s_2));
    strncat(string_DO_p_s_Q_s, elem_Q_s, sizeof(elem_Q_s));

    unsigned char hash_string_DO_p_s_Q_s[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_DO_p_s_Q_s, sizeof(string_DO_p_s_Q_s), hash_string_DO_p_s_Q_s, sizeof(hash_string_DO_p_s_Q_s));

    element_init_Zr(mod_int_hash_string_DO_p_s_Q_s, pairing);
    element_from_hash(mod_int_hash_string_DO_p_s_Q_s, hash_string_DO_p_s_Q_s, 32);

    element_init_Zr(f1_id_s_pk_lambda, pairing);
    element_pow_zn(f1_id_s_pk_lambda, lambda, mod_int_hash_string_DO_p_s_Q_s);

    element_init_Zr(cert_s, pairing);
    element_add(cert_s, beta_s, f1_id_s_pk_lambda);

    // cert_r
    int len_DU_p_r_Q_r = sizeof(DU) + sizeof(elem_p_r_1) + sizeof(elem_p_r_2) + sizeof(elem_Q_r);
    unsigned char string_DU_p_r_Q_r[len_DU_p_r_Q_r];

    memset(string_DU_p_r_Q_r, 0, len_DU_p_r_Q_r);
    strncpy(string_DU_p_r_Q_r, DU, sizeof(DU));
    strncat(string_DU_p_r_Q_r, elem_p_s_1, sizeof(elem_p_r_1));
    strncat(string_DU_p_r_Q_r, elem_p_s_2, sizeof(elem_p_r_2));
    strncat(string_DU_p_r_Q_r, elem_Q_s, sizeof(elem_Q_r));

    unsigned char hash_string_DU_p_r_Q_r[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_DU_p_r_Q_r, sizeof(string_DU_p_r_Q_r), hash_string_DU_p_r_Q_r, sizeof(hash_string_DU_p_r_Q_r));

    element_init_Zr(mod_int_hash_string_DU_p_r_Q_r, pairing);
    element_from_hash(mod_int_hash_string_DU_p_r_Q_r, hash_string_DU_p_r_Q_r, 32);

    element_init_Zr(f1_id_r_pk_lambda, pairing);
    element_pow_zn(f1_id_r_pk_lambda, lambda, mod_int_hash_string_DU_p_r_Q_r);

    element_init_Zr(cert_r, pairing);
    element_add(cert_r, beta_r, f1_id_r_pk_lambda);

    // PAEKS

    gettimeofday(&start, NULL);
    char kw_ct[] = "Crypto";

    element_t r, c_1, mu, kappa_ct, R_B;
    element_init_Zr(r, pairing);
    element_init_G1(kappa_ct, pairing);
    element_init_G1(c_1, pairing);
    element_random(r);
    element_pow_zn(c_1, p, r);

    element_pow_zn(kappa_ct, p_r_1, sk_s_1);

    int len_IDB_PKB = sizeof(DU) + sizeof(elem_p_r_1) + sizeof(elem_p_r_2) + sizeof(elem_Q_r);
    unsigned char string_IDB_PKB[len_IDB_PKB];

    memset(string_IDB_PKB, 0, len_IDB_PKB);
    strncpy(string_IDB_PKB, DU, sizeof(DU));
    strncat(string_IDB_PKB, elem_p_r_1, sizeof(elem_p_r_1));
    strncat(string_IDB_PKB, elem_p_r_2, sizeof(elem_p_r_2));
    strncat(string_IDB_PKB, elem_Q_r, sizeof(elem_Q_r));

    unsigned char hash_string_IDB_PKB[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_IDB_PKB, sizeof(string_IDB_PKB), hash_string_IDB_PKB, sizeof(hash_string_IDB_PKB));

    element_t mod_int_hash_string_IDB_PKB;
    element_init_Zr(mod_int_hash_string_IDB_PKB, pairing);
    element_from_hash(mod_int_hash_string_IDB_PKB, hash_string_IDB_PKB, 32);

    element_t p_pub_mod_int_hash_string_IDB_PKB;
    element_init_G1(p_pub_mod_int_hash_string_IDB_PKB, pairing);
    element_pow_zn(p_pub_mod_int_hash_string_IDB_PKB, p_pub, mod_int_hash_string_IDB_PKB);

    element_t tmp_RB;
    element_init_G1(tmp_RB, pairing);
    element_add(tmp_RB, p_r_2, Q_r);
    element_init_G1(R_B, pairing);
    element_add(R_B, tmp_RB, p_pub_mod_int_hash_string_IDB_PKB);

    int kappa_len = element_length_in_bytes(kappa_ct);
    unsigned char elem_kappa[kappa_len];
    element_snprint(elem_kappa, kappa_len, kappa_ct);

    int len_IDA_IDB_kappa_kw = sizeof(DO) + sizeof(DU) + sizeof(elem_kappa) + sizeof(kw_ct);
    unsigned char string_IDA_IDB_kappa_kw[len_IDA_IDB_kappa_kw];

    memset(string_IDA_IDB_kappa_kw, 0, len_IDB_PKB);
    strncpy(string_IDA_IDB_kappa_kw, DO, sizeof(DU));
    strncat(string_IDA_IDB_kappa_kw, DU, sizeof(DU));
    strncat(string_IDA_IDB_kappa_kw, elem_kappa, sizeof(elem_kappa));
    strncat(string_IDA_IDB_kappa_kw, kw_ct, sizeof(kw_ct));

    unsigned char hash_string_IDA_IDB_kappa_kw[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_IDA_IDB_kappa_kw, sizeof(string_IDA_IDB_kappa_kw), hash_string_IDA_IDB_kappa_kw, sizeof(hash_string_IDA_IDB_kappa_kw));

    element_t mod_int_hash_string_IDA_IDB_kappa_kw;
    element_init_Zr(mod_int_hash_string_IDA_IDB_kappa_kw, pairing);
    element_from_hash(mod_int_hash_string_IDA_IDB_kappa_kw, hash_string_IDA_IDB_kappa_kw, 32);

    element_t r_mod_int_hash_string_IDA_IDB_kappa_kw;
    element_init_Zr(r_mod_int_hash_string_IDA_IDB_kappa_kw, pairing);
    element_pow_zn(r_mod_int_hash_string_IDA_IDB_kappa_kw, r, mod_int_hash_string_IDA_IDB_kappa_kw);
    element_init_G1(mu, pairing);
    element_pow_zn(mu, R_B, r_mod_int_hash_string_IDA_IDB_kappa_kw);

    element_t s_ct, c_2, v_ct, sk_s_2_cert_s, inv_sk_s_2_cert_s;
    element_init_Zr(s_ct, pairing);
    element_init_Zr(c_2, pairing);
    element_init_Zr(sk_s_2_cert_s, pairing);
    element_init_Zr(inv_sk_s_2_cert_s, pairing);
    element_init_G1(v_ct, pairing);

    element_random(s_ct);
    element_add(sk_s_2_cert_s, sk_s_2, cert_s);
    element_invert(inv_sk_s_2_cert_s, sk_s_2_cert_s);
    element_pow_zn(c_2, s_ct, inv_sk_s_2_cert_s);
    element_pow_zn(v_ct, p, s_ct);

    element_t c_3, t_ct, f_3_mu_v;
    element_init_Zr(t_ct, pairing);
    element_init_Zr(f_3_mu_v, pairing);
    element_init_Zr(c_3, pairing);
    element_init_Zr(c_3, pairing);
    element_random(t_ct);

    int mu_ct_len = element_length_in_bytes(mu);
    unsigned char elem_mu_ct[mu_ct_len];
    element_snprint(elem_mu_ct, mu_ct_len, mu);

    int v_ct_len = element_length_in_bytes(v_ct);
    unsigned char elem_v_ct[v_ct_len];
    element_snprint(elem_v_ct, v_ct_len, v_ct);

    int len_mu_v_ct = sizeof(elem_mu_ct) + sizeof(elem_v_ct);
    unsigned char string_mu_v_ct[len_mu_v_ct];

    memset(string_mu_v_ct, 0, len_mu_v_ct);
    strncpy(string_mu_v_ct, elem_mu_ct, sizeof(elem_mu_ct));
    strncat(string_mu_v_ct, elem_v_ct, sizeof(elem_v_ct));

    unsigned char hash_string_mu_v_ct[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_mu_v_ct, sizeof(string_mu_v_ct), hash_string_mu_v_ct, sizeof(hash_string_mu_v_ct));

    element_t mod_int_hash_string_mu_v_ct;
    element_init_Zr(mod_int_hash_string_mu_v_ct, pairing);
    element_from_hash(mod_int_hash_string_mu_v_ct, hash_string_mu_v_ct, 32);

    element_sub(c_3, t_ct, mod_int_hash_string_mu_v_ct);

    // compute c_4
    int c_1_len = element_length_in_bytes(c_1);
    unsigned char elem_c_1[c_1_len];
    element_snprint(elem_c_1, c_1_len, c_1);

    int c_2_len = element_length_in_bytes(c_2);
    unsigned char elem_c_2[c_2_len];
    element_snprint(elem_c_2, c_2_len, c_2);

    int c_3_len = element_length_in_bytes(c_3);
    unsigned char elem_c_3[c_3_len];
    element_snprint(elem_c_3, c_3_len, c_3);

    int t_ct_len = element_length_in_bytes(t_ct);
    unsigned char elem_t_ct[t_ct_len];
    element_snprint(elem_t_ct, t_ct_len, t_ct);

    int len_c1_c2_c3_tct = sizeof(elem_c_1) + sizeof(elem_c_2) + sizeof(elem_c_3) + sizeof(elem_t_ct);
    unsigned char string_c1_c2_c3_tct[len_c1_c2_c3_tct];

    memset(string_c1_c2_c3_tct, 0, len_c1_c2_c3_tct);
    strncpy(string_c1_c2_c3_tct, elem_c_1, sizeof(elem_c_1));
    strncat(string_c1_c2_c3_tct, elem_c_2, sizeof(elem_c_1));
    strncat(string_c1_c2_c3_tct, elem_c_3, sizeof(elem_c_3));
    strncat(string_c1_c2_c3_tct, elem_t_ct, sizeof(elem_t_ct));

    unsigned char c_4[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_c1_c2_c3_tct, sizeof(string_c1_c2_c3_tct), c_4, sizeof(c_4));

    gettimeofday(&stop, NULL);
    // Trapdoor

    char kw_td[] = "Crypto";
    element_t kappa_td, td_1, td_2;
    element_init_G1(kappa_td, pairing);
    element_pow_zn(kappa_td, p_s_1, sk_r_1);

    int kappa_td_len = element_length_in_bytes(kappa_td);
    unsigned char elem_kappa_td[kappa_td_len];
    element_snprint(elem_kappa_td, kappa_td_len, kappa_td);

    int len_td_IDA_IDB_kappa_kw = sizeof(DO) + sizeof(DU) + sizeof(elem_kappa_td) + sizeof(kw_td);
    unsigned char string_td_IDA_IDB_kappa_kw[len_td_IDA_IDB_kappa_kw];

    memset(string_td_IDA_IDB_kappa_kw, 0, len_td_IDA_IDB_kappa_kw);
    strncpy(string_td_IDA_IDB_kappa_kw, DO, sizeof(DU));
    strncat(string_td_IDA_IDB_kappa_kw, DU, sizeof(DU));
    strncat(string_td_IDA_IDB_kappa_kw, elem_kappa_td, sizeof(elem_kappa_td));
    strncat(string_td_IDA_IDB_kappa_kw, kw_td, sizeof(kw_td));

    unsigned char hash_string_td_IDA_IDB_kappa_kw[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_td_IDA_IDB_kappa_kw, sizeof(string_td_IDA_IDB_kappa_kw), hash_string_td_IDA_IDB_kappa_kw, sizeof(hash_string_td_IDA_IDB_kappa_kw));

    element_t mod_int_hash_string_td_IDA_IDB_kappa_kw;
    element_init_Zr(mod_int_hash_string_td_IDA_IDB_kappa_kw, pairing);
    element_from_hash(mod_int_hash_string_td_IDA_IDB_kappa_kw, hash_string_td_IDA_IDB_kappa_kw, 32);

    element_t sk_r_2_cert_r;
    element_init_Zr(sk_r_2_cert_r, pairing);
    element_add(sk_r_2_cert_r, sk_r_2, cert_r);
    element_init_Zr(td_1, pairing);
    element_pow_zn(td_1, mod_int_hash_string_td_IDA_IDB_kappa_kw, sk_r_2_cert_r);

    int len_IDA_PKA = sizeof(DO) + sizeof(elem_p_s_1) + sizeof(elem_p_s_2) + sizeof(elem_Q_s);
    unsigned char string_IDA_PKA[len_IDA_PKA];

    memset(string_IDA_PKA, 0, len_IDA_PKA);
    strncpy(string_IDA_PKA, DO, sizeof(DO));
    strncat(string_IDA_PKA, elem_p_s_1, sizeof(elem_p_s_1));
    strncat(string_IDA_PKA, elem_p_s_2, sizeof(elem_p_s_2));
    strncat(string_IDA_PKA, elem_Q_s, sizeof(elem_Q_s));

    unsigned char hash_string_IDA_PKA[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_IDA_PKA, sizeof(string_IDA_PKA), hash_string_IDA_PKA, sizeof(hash_string_IDA_PKA));

    element_t mod_int_hash_string_IDA_PKA;
    element_init_Zr(mod_int_hash_string_IDA_PKA, pairing);


    element_from_hash(mod_int_hash_string_IDA_PKA, hash_string_IDA_PKA, 32);

    element_t p_pub_mod_int_hash_string_IDA_PKA;
    element_init_G1(p_pub_mod_int_hash_string_IDA_PKA, pairing);
    element_pow_zn(p_pub_mod_int_hash_string_IDA_PKA, p_pub, mod_int_hash_string_IDA_PKA);

    element_t tmp_td_2;
    element_init_G1(tmp_td_2, pairing);
    element_add(tmp_td_2, p_s_2, Q_s);
    element_init_G1(td_2, pairing);
    element_add(td_2, tmp_td_2, p_pub_mod_int_hash_string_IDA_PKA);

    // Test

    element_t mu_test, v_test, t_test;
    element_init_G1(mu_test, pairing);
    element_init_G1(v_test, pairing);
    element_init_Zr(t_test, pairing);
    element_pow_zn(mu_test, c_1, td_1);
    element_pow_zn(v_test, td_2, c_2);

    int mu_test_len = element_length_in_bytes(mu_test);
    unsigned char elem_mu_test[mu_test_len];
    element_snprint(elem_mu_test, mu_test_len, mu_test);

    int v_test_len = element_length_in_bytes(v_test);
    unsigned char elem_v_test[v_test_len];
    element_snprint(elem_v_test, v_test_len, v_test);

    int len_mu_v_test = sizeof(elem_mu_test) + sizeof(elem_v_test);
    unsigned char string_mu_v_test[len_mu_v_test];

    memset(string_mu_v_test, 0, len_mu_v_test);
    strncpy(string_mu_v_test, elem_mu_ct, sizeof(elem_mu_test));
    strncat(string_mu_v_test, elem_v_ct, sizeof(elem_v_test));

    unsigned char hash_string_mu_v_test[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_mu_v_test, sizeof(string_mu_v_test), hash_string_mu_v_test, sizeof(hash_string_mu_v_test));

    element_t mod_int_hash_string_mu_v_test;
    element_init_Zr(mod_int_hash_string_mu_v_test, pairing);
    element_from_hash(mod_int_hash_string_mu_v_test, hash_string_mu_v_test, 32);

    element_add(t_test, c_3, mod_int_hash_string_mu_v_test);

    // compute c_4_test
    int c_1_test_len = element_length_in_bytes(c_1);
    unsigned char elem_c_1_test[c_1_test_len];
    element_snprint(elem_c_1_test, c_1_test_len, c_1);

    int c_2_test_len = element_length_in_bytes(c_2);
    unsigned char elem_c_2_test[c_2_test_len];
    element_snprint(elem_c_2_test, c_2_test_len, c_2);

    int c_3_test_len = element_length_in_bytes(c_3);
    unsigned char elem_c_3_test[c_3_test_len];
    element_snprint(elem_c_3_test, c_3_test_len, c_3);

    int t_test_len = element_length_in_bytes(t_test);
    unsigned char elem_t_test[t_test_len];
    element_snprint(elem_t_test, t_test_len, t_test);

    int len_c1_c2_c3_t_test = sizeof(elem_c_1_test) + sizeof(elem_c_2_test) + sizeof(elem_c_3_test) + sizeof(elem_t_test);
    unsigned char string_c1_c2_c3_t_test[len_c1_c2_c3_t_test];

    memset(string_c1_c2_c3_t_test, 0, len_c1_c2_c3_t_test);
    strncpy(string_c1_c2_c3_t_test, elem_c_1_test, sizeof(elem_c_1_test));
    strncat(string_c1_c2_c3_t_test, elem_c_2_test, sizeof(elem_c_2_test));
    strncat(string_c1_c2_c3_t_test, elem_c_3_test, sizeof(elem_c_3_test));
    strncat(string_c1_c2_c3_t_test, elem_t_test, sizeof(elem_t_test));

    unsigned char c_4_test[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_c1_c2_c3_t_test, sizeof(string_c1_c2_c3_t_test), c_4_test, sizeof(c_4_test));

    if (sizeof(c_4) == sizeof(c_4_test) && !strncmp(c_4, c_4_test, sizeof(c_4)))
    {
        printf("success\n");
    }

    timersub(&stop, &start, &diff);

    double time_used = diff.tv_sec + (double)diff.tv_usec / 1000000.0;

    printf("%f", time_used);

    return 0;
}