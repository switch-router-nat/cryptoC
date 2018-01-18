/*
 * File       :  dsa.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     QshLyc       first version
 */

#ifndef _CRYPTOC_DSA_H_
#define _CRYPTOC_DSA_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const void* Dsa;


enum dsa_size_e{
	DSA_L1024_N160,
	DSA_L2048_N224,
	DSA_L2048_N256,
	DSA_L3072_N256,
};

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
