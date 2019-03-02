/*
 * File       :  dsa.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     187J3X1       first version
 */

#ifndef _CRYPTOC_DSA_H_
#define _CRYPTOC_DSA_H_

#ifdef __cplusplus
extern "C" {
#endif


typedef struct{
    DSBASE super;
    enum dsa_size_e size;
    b_uint32_t* p;       /* L bits prime p */
    b_uint32_t* q;       /* N bits prime q */
    b_uint32_t* g;       /* a generator of a subgroup of order q in GF(P), 1 < g < p */
    b_uint32_t* x;       /* private key */
    b_uint32_t* y;       /* public key  */
}DSA;


#ifdef __cplusplus
}
#endif

#endif
