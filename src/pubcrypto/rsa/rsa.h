/*
 * File       :  rsa.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     187J3X1       first version
 */

#ifndef _CRYPTOC_RSA_H_
#define _CRYPTOC_RSA_H_

#ifdef __cplusplus
extern "C" {
#endif



typedef struct{
    const void* object;
    b_uint32_t* d;       /* 1024 bit private key*/
    b_uint32_t* e;       /* 1024 bit public key*/
    b_uint32_t* n;       /* 1024 bit mod */
    b_uint32_t* p;       /* 512 bit prime */
    b_uint32_t* q;       /* 512 bit prime */
    b_uint32_t* dp;      /* 512 bit d mod p-1 */
    b_uint32_t* dq;      /* 512 bit d mod q-1 */
    b_uint32_t* cp;      /* 512 bit q^(-1) mod p */
    b_uint32_t* cq;		 /* 512 bit p^(-1) mod q */
    b_uint32_t* qcp;     /* 1024bit, q*cp */
    b_uint32_t* pcq;     /* 1024bit, p*cq */
    int ready;          /* all varible is calculated */
    b_uint32_t* version;
}RSA;



#ifdef __cplusplus
}
#endif

#endif
