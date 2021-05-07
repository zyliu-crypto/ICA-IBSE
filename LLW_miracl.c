// gcc -c LLW_miracl.c 
// gcc -o main LLW_miracl.o  -lmiracl
// https://www.ic.unicamp.br/~leob/publications/inss08/TinyPBC.pdf 160bit
// https://www.itread01.com/xfifhk.html

#include<miracl/miracl.h>
#include<miracl/mirdef.h>

#include "sha3.h"
#include "string.h"
#include <stdio.h>
#include <time.h>

char *ecp="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF";

/* elliptic curve parameter B */

char *ecb="1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45";

/* elliptic curve - point of prime order (x,y) */

char *ecx="4A96B5688EF573284664698968C38BB913CBFC82";
char *ecy="23A628553168947D59DCC912042351377AC5FB32";


char *text="MIRACL - Best multi-precision library in the World!\n";
char DO[] = "Alice";
char DU[] = "Bob";
int main() {

    time_t seed;

    big a,b,p,q, x, y;
    miracl *mip;

    big lambda;
    epoint *P, *P_pub;


#ifndef MR_NOFULLWIDTH   
    mip=mirsys(36,0);
#else
    mip=mirsys(36,MAXBASE);
#endif
    a=mirvar(0);
    b=mirvar(0);
    p=mirvar(0);
    q=mirvar(0);
    x=mirvar(0);
    y=mirvar(0);

    lambda=mirvar(0);

    time(&seed);
    irand((unsigned long)seed);   /* change parameter for different values */

    convert(-3,a);
    mip->IOBASE=16;
    cinstr(b,ecb);
    cinstr(p,ecp);      
    ecurve_init(a,b,p,MR_BEST);  /* Use PROJECTIVE if possible, else AFFINE coordinates */

    P = epoint_init();
    P_pub = epoint_init();
    cinstr(x,ecx);
    cinstr(y,ecy);
    mip->IOBASE=10;
    epoint_set(x,y,0,P);


    bigbits(160, lambda);
    ecurve_mult(lambda, P, P_pub);

    // Key Gen S

    big SK_U1_S, SK_U2_S;
    epoint *P_U1_S, *P_U2_S;

    SK_U1_S=mirvar(0);
    SK_U2_S=mirvar(0);
    P_U1_S = epoint_init();
    P_U2_S = epoint_init();
    bigbits(160, SK_U1_S);
    bigbits(160, SK_U2_S);
    ecurve_mult(SK_U1_S, P, P_U1_S);
    ecurve_mult(SK_U2_S, P, P_U2_S);


 // Key Gen R

    big SK_U1_R, SK_U2_R;
    epoint *P_U1_R, *P_U2_R;

    SK_U1_R=mirvar(0);
    SK_U2_R=mirvar(0);
    P_U1_R = epoint_init();
    P_U2_R = epoint_init();
    bigbits(160, SK_U1_R);
    bigbits(160, SK_U2_R);
    ecurve_mult(SK_U1_R, P, P_U1_R);
    ecurve_mult(SK_U2_R, P, P_U2_R);


    // User Certify S

    
    big beta_U_S;
    epoint *Q_U_S;   // Q_U = PK_U3
    beta_U_S=mirvar(0);
    Q_U_S = epoint_init();
    bigbits(160, beta_U_S);
    ecurve_mult(beta_U_S, P, Q_U_S);

    big P_U1_S_big, P_U2_S_big, Q_U_S_big;
    P_U1_S_big=mirvar(0);
    P_U2_S_big=mirvar(0);
    Q_U_S_big=mirvar(0);

    epoint_get(P_U1_S, P_U1_S_big, P_U1_S_big);
    epoint_get(P_U2_S, P_U2_S_big, P_U2_S_big);
    epoint_get(Q_U_S, Q_U_S_big, Q_U_S_big);

    char P_U1_S_byte[100], P_U2_S_byte[100], Q_U_S_byte[100];

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

    big Cert_U;
    Cert_U = mirvar(0);
    add(beta_U_S, Big_f1_string_DO_PK_mul_lambda, Cert_U);

    /*
    epoint *test1, *test2;
    test1 = epoint_init();
    test2 = epoint_init();
    
    ecurve_mult(Cert_U, P, test1);
    ecurve_mult(Big_f1_string_DO_PK, P_pub, test2);
    ecurve_add(Q_U_S, test2);

    printf("%d", epoint_comp(test1, test2));
    */
}