/*
 * File       :  rsa.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     QshLyc       first version
 */

#ifndef _CRYPTOC_RSA_H_
#define _CRYPTOC_RSA_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const void* Rsa;

typedef struct{
	const void* object;
	b_uint32_t* prikey;    /* 1024 bit private key*/
	b_uint32_t* pubkey;    /* 1024 bit public key*/
	b_uint32_t* n;         /* 1024 bit mod */
}RSA;


void rsa_key_generate(void* _self);
int rsa_encryption(void* _self, b_uint32_t* x, b_uint32_t* y);
int rsa_decryption(void* _self, b_uint32_t* y, b_uint32_t* x);


#ifdef __cplusplus
}
#endif

#endif
