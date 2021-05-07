// gcc -c LLW_miracl.c
// gcc -o main LLW_miracl.o  -lmiracl
// https://www.ic.unicamp.br/~leob/publications/inss08/TinyPBC.pdf 160bit
// https://www.itread01.com/xfifhk.html

#include <miracl/miracl.h>
#include <miracl/mirdef.h>

#include "sha3.h"
#include "string.h"
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
struct timeval stop1, start1, diff1;
struct timeval stop2, start2, diff2;
struct timeval stop3, start3, diff3;
;

char *ecp = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF";

/* elliptic curve parameter B */

char *ecb = "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45";

/* elliptic curve - point of prime order (x,y) */

char *ecx = "4A96B5688EF573284664698968C38BB913CBFC82";
char *ecy = "23A628553168947D59DCC912042351377AC5FB32";

char DO[] = "Alice";
char DU[] = "Bob";
int main()
{

    time_t seed;

    big a, b, p, q, x, y;
    miracl *mip;

    big lambda;
    epoint *P, *P_pub;

#ifndef MR_NOFULLWIDTH
    mip = mirsys(36, 0);
#else
    mip = mirsys(36, MAXBASE);
#endif
    a = mirvar(0);
    b = mirvar(0);
    p = mirvar(0);
    q = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);

    lambda = mirvar(0);

    time(&seed);
    irand((unsigned long)seed); /* change parameter for different values */

    convert(-3, a);
    mip->IOBASE = 16;
    cinstr(b, ecb);
    cinstr(p, ecp);
    ecurve_init(a, b, p, MR_BEST); /* Use PROJECTIVE if possible, else AFFINE coordinates */

    P = epoint_init();
    P_pub = epoint_init();
    cinstr(x, ecx);
    cinstr(y, ecy);
    mip->IOBASE = 10;
    epoint_set(x, y, 0, P);

    bigbits(160, lambda);
    ecurve_mult(lambda, P, P_pub);

    // Key Gen S

    big SK_U1_S, SK_U2_S;
    epoint *P_U1_S, *P_U2_S;

    SK_U1_S = mirvar(0);
    SK_U2_S = mirvar(0);
    P_U1_S = epoint_init();
    P_U2_S = epoint_init();
    bigbits(160, SK_U1_S);
    bigbits(160, SK_U2_S);
    ecurve_mult(SK_U1_S, P, P_U1_S);
    ecurve_mult(SK_U2_S, P, P_U2_S);

    // Key Gen R

    big SK_U1_R, SK_U2_R;
    epoint *P_U1_R, *P_U2_R;

    SK_U1_R = mirvar(0);
    SK_U2_R = mirvar(0);
    P_U1_R = epoint_init();
    P_U2_R = epoint_init();
    bigbits(160, SK_U1_R);
    bigbits(160, SK_U2_R);
    ecurve_mult(SK_U1_R, P, P_U1_R);
    ecurve_mult(SK_U2_R, P, P_U2_R);

    // User Certify S

    big beta_U_S;
    epoint *Q_U_S; // Q_U = PK_U3
    beta_U_S = mirvar(0);
    Q_U_S = epoint_init();
    bigbits(160, beta_U_S);
    ecurve_mult(beta_U_S, P, Q_U_S);

    big P_U1_S_big, P_U2_S_big, Q_U_S_big;
    P_U1_S_big = mirvar(0);
    P_U2_S_big = mirvar(0);
    Q_U_S_big = mirvar(0);

    epoint_get(P_U1_S, P_U1_S_big, P_U1_S_big);
    epoint_get(P_U2_S, P_U2_S_big, P_U2_S_big);
    epoint_get(Q_U_S, Q_U_S_big, Q_U_S_big);

    char P_U1_S_byte[25], P_U2_S_byte[25], Q_U_S_byte[25];

    big_to_bytes(0, P_U1_S_big, P_U1_S_byte, FALSE);
    big_to_bytes(0, P_U2_S_big, P_U2_S_byte, FALSE);
    big_to_bytes(0, Q_U_S_big, Q_U_S_byte, FALSE);

    int DO_PK_len = sizeof(DO) + sizeof(P_U1_S_byte) + sizeof(P_U2_S_byte) + sizeof(Q_U_S_byte);
    unsigned char string_DO_PK[DO_PK_len];
    memset(string_DO_PK, 0, DO_PK_len);

    strncpy(string_DO_PK, DO, sizeof(DO));
    strncat(string_DO_PK, P_U1_S_byte, sizeof(P_U1_S_byte));
    strncat(string_DO_PK, P_U2_S_byte, sizeof(P_U2_S_byte));
    strncat(string_DO_PK, Q_U_S_byte, sizeof(Q_U_S_byte));

    unsigned char f1_string_DO_PK[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_DO_PK, sizeof(string_DO_PK), f1_string_DO_PK, sizeof(f1_string_DO_PK));

    big Big_f1_string_DO_PK;
    Big_f1_string_DO_PK = mirvar(0);

    bytes_to_big(sizeof(f1_string_DO_PK), f1_string_DO_PK, Big_f1_string_DO_PK);

    big Big_f1_string_DO_PK_mul_lambda;
    Big_f1_string_DO_PK_mul_lambda = mirvar(0);
    multiply(lambda, Big_f1_string_DO_PK, Big_f1_string_DO_PK_mul_lambda);

    big Cert_S;
    Cert_S = mirvar(0);
    add(beta_U_S, Big_f1_string_DO_PK_mul_lambda, Cert_S);

    /*
    epoint *test1, *test2;
    test1 = epoint_init();
    test2 = epoint_init();
    
    ecurve_mult(Cert_U, P, test1);
    ecurve_mult(Big_f1_string_DO_PK, P_pub, test2);
    ecurve_add(Q_U_S, test2);

    printf("%d", epoint_comp(test1, test2));
    */

    // User Certify R

    big beta_U_R;
    epoint *Q_U_R; // Q_U = PK_U3
    beta_U_R = mirvar(0);
    Q_U_R = epoint_init();
    bigbits(160, beta_U_R);
    ecurve_mult(beta_U_R, P, Q_U_R);

    big P_U1_R_big, P_U2_R_big, Q_U_R_big;
    P_U1_R_big = mirvar(0);
    P_U2_R_big = mirvar(0);
    Q_U_R_big = mirvar(0);

    epoint_get(P_U1_R, P_U1_R_big, P_U1_R_big);
    epoint_get(P_U2_R, P_U2_R_big, P_U2_R_big);
    epoint_get(Q_U_R, Q_U_R_big, Q_U_R_big);

    char P_U1_R_byte[25], P_U2_R_byte[25], Q_U_R_byte[25];

    big_to_bytes(0, P_U1_R_big, P_U1_R_byte, FALSE);
    big_to_bytes(0, P_U2_R_big, P_U2_R_byte, FALSE);
    big_to_bytes(0, Q_U_R_big, Q_U_R_byte, FALSE);

    int DU_PK_len = sizeof(DU) + sizeof(P_U1_R_byte) + sizeof(P_U2_R_byte) + sizeof(Q_U_R_byte);
    unsigned char string_DU_PK[DU_PK_len];
    memset(string_DU_PK, 0, DU_PK_len);

    strncpy(string_DU_PK, DU, sizeof(DU));
    strncat(string_DU_PK, P_U1_R_byte, sizeof(P_U1_R_byte));
    strncat(string_DU_PK, P_U2_R_byte, sizeof(P_U2_R_byte));
    strncat(string_DU_PK, Q_U_R_byte, sizeof(Q_U_R_byte));

    unsigned char f1_string_DU_PK[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, string_DU_PK, sizeof(string_DU_PK), f1_string_DU_PK, sizeof(f1_string_DU_PK));

    big Big_f1_string_DU_PK;
    Big_f1_string_DU_PK = mirvar(0);

    bytes_to_big(sizeof(f1_string_DU_PK), f1_string_DU_PK, Big_f1_string_DU_PK);

    big Big_f1_string_DU_PK_mul_lambda;
    Big_f1_string_DU_PK_mul_lambda = mirvar(0);
    multiply(lambda, Big_f1_string_DU_PK, Big_f1_string_DU_PK_mul_lambda);

    big Cert_R;
    Cert_R = mirvar(0);
    add(beta_U_R, Big_f1_string_DU_PK_mul_lambda, Cert_R);

    // Enc

    gettimeofday(&start3, NULL);

    char keyword_1[] = "Crypto";
    big r;
    epoint *C1, *kappa, *Enc_f1_P_pub;

    r = mirvar(0);

    bigbits(160, r);
    C1 = epoint_init();
    kappa = epoint_init();
    Enc_f1_P_pub = epoint_init();

    ecurve_mult(r, P, C1);
    ecurve_mult(SK_U1_S, P_U1_R, kappa);

    big Enc_P_U1_R_big, Enc_P_U2_R_big, Enc_Q_U_R_big;
    Enc_P_U1_R_big = mirvar(0);
    Enc_P_U2_R_big = mirvar(0);
    Enc_Q_U_R_big = mirvar(0);

    epoint_get(P_U1_R, Enc_P_U1_R_big, Enc_P_U1_R_big);
    epoint_get(P_U2_R, Enc_P_U2_R_big, Enc_P_U2_R_big);
    epoint_get(Q_U_R, Enc_Q_U_R_big, Enc_Q_U_R_big);

    char Enc_P_U1_R_byte[25], Enc_P_U2_R_byte[25], Enc_Q_U_R_byte[25];

    big_to_bytes(0, Enc_P_U1_R_big, Enc_P_U1_R_byte, FALSE);
    big_to_bytes(0, Enc_P_U2_R_big, Enc_P_U2_R_byte, FALSE);
    big_to_bytes(0, Enc_Q_U_R_big, Enc_Q_U_R_byte, FALSE);

    int Enc_DU_PK_len = sizeof(DU) + sizeof(Enc_P_U1_R_byte) + sizeof(Enc_P_U2_R_byte) + sizeof(Enc_Q_U_R_byte);
    unsigned char Enc_string_DU_PK[Enc_DU_PK_len];
    memset(Enc_string_DU_PK, 0, Enc_DU_PK_len);

    strncpy(Enc_string_DU_PK, DU, sizeof(DU));
    strncat(Enc_string_DU_PK, Enc_P_U1_R_byte, sizeof(Enc_P_U1_R_byte));
    strncat(Enc_string_DU_PK, Enc_P_U2_R_byte, sizeof(Enc_P_U2_R_byte));
    strncat(Enc_string_DU_PK, Enc_Q_U_R_byte, sizeof(Enc_Q_U_R_byte));

    unsigned char Enc_f1_string_DU_PK[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, Enc_string_DU_PK, sizeof(Enc_string_DU_PK), Enc_f1_string_DU_PK, sizeof(Enc_f1_string_DU_PK));

    big Enc_Big_f1_string_DU_PK;
    Enc_Big_f1_string_DU_PK = mirvar(0);

    bytes_to_big(sizeof(Enc_f1_string_DU_PK), Enc_f1_string_DU_PK, Enc_Big_f1_string_DU_PK);

    epoint *Enc_Big_f1_string_DU_PK_mul_P_pub;
    Enc_Big_f1_string_DU_PK_mul_P_pub = epoint_init();
    ecurve_mult(Enc_Big_f1_string_DU_PK, P_pub, Enc_Big_f1_string_DU_PK_mul_P_pub);

    epoint *R_B_tmp1, *R_B_tmp2, *R_B;
    R_B = epoint_init();
    epoint_copy(P_U2_R, R_B);
    ecurve_add(Q_U_R, R_B);
    ecurve_add(Enc_Big_f1_string_DU_PK_mul_P_pub, R_B);

    big Enc_kappa_big;
    Enc_kappa_big = mirvar(0);
    epoint_get(kappa, Enc_kappa_big, Enc_kappa_big);

    char Enc_kappa_byte[25];

    big_to_bytes(0, Enc_kappa_big, Enc_kappa_byte, FALSE);

    int Enc_DO_DU_kappa_kw_len = sizeof(DO) + sizeof(DU) + sizeof(Enc_kappa_byte) + sizeof(keyword_1);
    unsigned char Enc_DO_DU_kappa_kw[Enc_DO_DU_kappa_kw_len];
    memset(Enc_DO_DU_kappa_kw, 0, Enc_DO_DU_kappa_kw_len);

    strncpy(Enc_DO_DU_kappa_kw, DO, sizeof(DO));
    strncat(Enc_DO_DU_kappa_kw, DU, sizeof(DU));
    strncat(Enc_DO_DU_kappa_kw, Enc_kappa_byte, sizeof(Enc_kappa_byte));
    strncat(Enc_DO_DU_kappa_kw, keyword_1, sizeof(keyword_1));

    big Enc_Big_DO_DU_kappa_kw;
    Enc_Big_DO_DU_kappa_kw = mirvar(0);

    bytes_to_big(sizeof(Enc_DO_DU_kappa_kw), Enc_DO_DU_kappa_kw, Enc_Big_DO_DU_kappa_kw);

    big r_mul_Enc_Big_DO_DU_kappa_kw;
    r_mul_Enc_Big_DO_DU_kappa_kw = mirvar(0);
    multiply(r, Enc_Big_DO_DU_kappa_kw, r_mul_Enc_Big_DO_DU_kappa_kw);

    epoint *mu;
    mu = epoint_init();
    ecurve_mult(r_mul_Enc_Big_DO_DU_kappa_kw, R_B, mu);

    big s, SK_U2_S_add_Cert_S, inv_SK_U2_S_add_Cert_S, C2;
    epoint *v;

    s = mirvar(0);
    bigbits(160, s);
    SK_U2_S_add_Cert_S = mirvar(0);
    inv_SK_U2_S_add_Cert_S = mirvar(0);
    add(Cert_S, SK_U2_S, SK_U2_S_add_Cert_S);
    xgcd(SK_U2_S_add_Cert_S, p, inv_SK_U2_S_add_Cert_S, inv_SK_U2_S_add_Cert_S, inv_SK_U2_S_add_Cert_S);

    C2 = mirvar(0);
    multiply(s, inv_SK_U2_S_add_Cert_S, C2);

    v = epoint_init();
    ecurve_mult(s, P, v);

    big t;
    s = mirvar(0);
    bigbits(160, t);

    char Enc_mu_byte[25], Enc_v_byte[25];
    big Enc_mu_big, Enc_v_big;
    Enc_mu_big = mirvar(0);
    Enc_v_big = mirvar(0);
    epoint_get(mu, Enc_mu_big, Enc_mu_big);
    epoint_get(v, Enc_v_big, Enc_v_big);
    big_to_bytes(0, Enc_mu_big, Enc_mu_byte, FALSE);
    big_to_bytes(0, Enc_v_big, Enc_v_byte, FALSE);

    int Enc_mu_v_len = sizeof(Enc_mu_byte) + sizeof(Enc_v_byte);
    unsigned char Enc_string_mu_v[Enc_mu_v_len];
    memset(Enc_string_mu_v, 0, Enc_mu_v_len);

    strncpy(Enc_string_mu_v, Enc_mu_byte, sizeof(Enc_mu_byte));
    strncat(Enc_string_mu_v, Enc_v_byte, sizeof(Enc_v_byte));

    unsigned char Enc_f3_string_mu_v[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, Enc_string_mu_v, sizeof(Enc_string_mu_v), Enc_f3_string_mu_v, sizeof(Enc_f3_string_mu_v));

    big Enc_Big_f3_string_mu_v;
    Enc_Big_f3_string_mu_v = mirvar(0);

    big C3;
    C3 = mirvar(0);

    bytes_to_big(sizeof(Enc_f3_string_mu_v), Enc_f3_string_mu_v, Enc_Big_f3_string_mu_v);
    subtract(t, Enc_Big_f3_string_mu_v, C3);

    unsigned char C4[32];
    char Enc_C1_byte[25], Enc_C2_byte[25], Enc_C3_byte[25], Enc_t_byte[25];
    big Enc_C1_big;
    Enc_C1_big = mirvar(0);
    epoint_get(C1, Enc_C1_big, Enc_C1_big);
    big_to_bytes(0, Enc_C1_big, Enc_C1_byte, FALSE);
    big_to_bytes(0, C2, Enc_C2_byte, FALSE);
    big_to_bytes(0, C3, Enc_C3_byte, FALSE);
    big_to_bytes(0, t, Enc_t_byte, FALSE);

    int Enc_C1C2C3t_len = sizeof(Enc_C1_byte) + sizeof(Enc_C2_byte) + sizeof(Enc_C3_byte) sizeof(Enc_t_byte);
    unsigned char Enc_string_C1C2C3t[Enc_C1C2C3t_len];
    memset(Enc_string_C1C2C3t, 0, Enc_C1C2C3t_len);

    strncpy(Enc_string_C1C2C3t, Enc_C1_byte, sizeof(Enc_C1_byte));
    strncat(Enc_string_C1C2C3t, Enc_C2_byte, sizeof(Enc_C2_byte));
    strncat(Enc_string_C1C2C3t, Enc_C3_byte, sizeof(Enc_C3_byte));
    strncat(Enc_string_C1C2C3t, Enc_t_byte, sizeof(Enc_t_byte));

    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, Enc_string_C1C2C3t, sizeof(Enc_string_C1C2C3t), C4, sizeof(C4));

    gettimeofday(&stop3, NULL);
    timersub(&stop3, &start3, &diff3);

    printf("Test took %f ms\n", diff3.tv_sec * 1000.0f + diff3.tv_usec / 1000.0f);

    // Trapdoor
}
