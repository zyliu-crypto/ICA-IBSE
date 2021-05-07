#include "/usr/local/include/pbc/pbc.h"
#include "sha3.h"
#include "string.h"
#include <stdio.h>
#include <time.h>
#include <sys/time.h>


struct timeval stop_H, start_H, diff_H; // hash to point
struct timeval stop_h, start_h, diff_h; // hash
struct timeval stop_P, start_P, diff_P; // pairing
struct timeval stop_E, start_E, diff_E; // exp



int main()
{

    char rnd_string[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcedfghijklmnopqrstuvwxyz0123456789aa";
    pairing_t pairing;
    pbc_param_t par;
    pbc_param_init_a_gen(par, 160, 512);
    pairing_init_pbc_param(pairing, par);
    
    // test H operation: mapping a 512 bits string to a G element

    element_t G_element;
    element_init_G1(G_element, pairing);
    gettimeofday(&start_H, NULL);
    element_from_hash(G_element, rnd_string, sizeof(rnd_string));
    gettimeofday(&stop_H, NULL);
    timersub(&stop_H, &start_H, &diff_H);
    printf("H operation took %f ms\n", diff_H.tv_sec * 1000.0f + diff_H.tv_usec/1000.0f); 


    // test h operation: mapping a 512 bits string to a 256bit hash value

    unsigned char hash_value[32];
    memset(hash_value, 0, 32);

    gettimeofday(&start_h, NULL);
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, rnd_string, sizeof(rnd_string), hash_value, sizeof(hash_value));
    gettimeofday(&stop_h, NULL);
    timersub(&stop_h, &start_h, &diff_h);
    printf("h operation took %f ms\n", diff_h.tv_sec * 1000.0f + diff_h.tv_usec/1000.0f); 

    // test pairing operation e(g^a,g^b)
    element_t g1, g2, a, b, g1a, g2b, pairing_result;
    element_init_G1(g1, pairing);
    element_init_G1(g1a, pairing);
    element_init_G2(g2, pairing);
    element_init_G2(g2b, pairing);
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);
    element_init_GT(pairing_result, pairing);
    element_random(g1);
    element_random(g2);
    element_random(a);
    element_random(b);

    element_pow_zn(g1a, g1, a);
    element_pow_zn(g2b, g2, b);
    gettimeofday(&start_P, NULL);
    pairing_apply(pairing_result, g1a, g2b, pairing);
    gettimeofday(&stop_P, NULL);
    timersub(&stop_P, &start_P, &diff_P);
    printf("pairing operation took %f ms\n", diff_P.tv_sec * 1000.0f + diff_P.tv_usec/1000.0f); 


    // test exp operation g^r
    element_t g3, exp_result, rnd_r;
    element_init_G1(g3, pairing);
    element_init_G1(exp_result, pairing);
    element_init_Zr(rnd_r, pairing);
    element_random(g3);
    element_random(rnd_r);
    
    gettimeofday(&start_E, NULL);
    element_pow_zn(exp_result, g3, rnd_r);
    gettimeofday(&stop_E, NULL);
    timersub(&stop_E, &start_E, &diff_E);
    printf("exp operation took %f ms\n", diff_E.tv_sec * 1000.0f + diff_E.tv_usec/1000.0f); 

}
