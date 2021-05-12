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

#define times_for_average 1000
struct timeval stop_mi, start_mi, diff_mi; // modular inverse over Z_p
struct timeval stop_pa, start_pa, diff_pa; // point add over G_ec
struct timeval stop_sm, start_sm, diff_sm; // scalar mul over G_ec

char *ecp = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF";

/* elliptic curve parameter B */

char *ecb = "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45";

/* elliptic curve - point of prime order (x,y) */

char *ecx = "4A96B5688EF573284664698968C38BB913CBFC82";
char *ecy = "23A628553168947D59DCC912042351377AC5FB32";

char *ecq = "100000000000000000001F4C8F927AED3CA752257";

int main()
{

    time_t seed;

    big a, b, p, q, x, y;
    miracl *mip;

    epoint *P;

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

    time(&seed);
    irand((unsigned long)seed); /* change parameter for different values */

    convert(-3, a);
    mip->IOBASE = 16;
    cinstr(b, ecb);
    cinstr(p, ecp);
    ecurve_init(a, b, p, MR_BEST); /* Use PROJECTIVE if possible, else AFFINE coordinates */

    cinstr(q, ecq);
    P = epoint_init();
    cinstr(x, ecx);
    cinstr(y, ecy);
    mip->IOBASE = 10;
    epoint_set(x, y, 0, P);


    // test scalar mul
    big random_big1;
    epoint *P1, *P2;

    random_big1 = mirvar(0);
    P1 = epoint_init();
    P2 = epoint_init();
    bigbits(160, random_big1);

    ecurve_mult(random_big1, P, P1);

    float total_time_sm = 0.0;
    for (int i = 0; i < times_for_average; i++)
    {
        gettimeofday(&start_sm, NULL);

        ecurve_mult(random_big1, P1, P2);
        gettimeofday(&stop_sm, NULL);
        timersub(&stop_sm, &start_sm, &diff_sm);
        total_time_sm += (diff_sm.tv_sec * 1000.0f + diff_sm.tv_usec / 1000.0f);
    }

    printf("scalar mul operation took %f ms\n", total_time_sm / times_for_average);

    // test modular inverse
    big before_inv, inv;
    before_inv = mirvar(0);
    inv = mirvar(0);

    bigbits(160, before_inv);
    float total_time_mi = 0.0;
    for (int i = 0; i < times_for_average; i++)
    {
        gettimeofday(&start_mi, NULL);

        xgcd(before_inv, q, inv, inv, inv);

        gettimeofday(&stop_mi, NULL);
        timersub(&stop_mi, &start_mi, &diff_mi);
        total_time_mi += (diff_mi.tv_sec * 1000.0f + diff_mi.tv_usec / 1000.0f);
    }

    printf("modular inverse operation took %f ms\n", total_time_mi / times_for_average);

    // test point add
    float total_time_pa = 0.0;
    for (int i = 0; i < times_for_average; i++)
    {
        gettimeofday(&start_pa, NULL);

        ecurve_add(P1, P2);

        gettimeofday(&stop_pa, NULL);
        timersub(&stop_pa, &start_pa, &diff_pa);
        total_time_pa += (diff_pa.tv_sec * 1000.0f + diff_pa.tv_usec / 1000.0f);
    }

    printf("point add operation took %f ms\n", total_time_pa / times_for_average);
}
