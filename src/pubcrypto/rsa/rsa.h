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


enum rsa_format {
	RSA_FORMAT_PKCS1,
	RSA_FORMAT_PKCS8
};

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
//	void* m_asn1_pubkey_pkcs1;
//	void* m_asn1_prikey_pkcs1;
//	struct asn1_buff* m_asb;
}RSA;

void rsa_key_generate(void* _self);
int rsa_encryption(void* _self, b_uint32_t* x, b_uint32_t* y);
int rsa_decryption(void* _self, b_uint32_t* y, b_uint32_t* x);

int rsa_gen_pubkeypem(void* _self, char* filename, enum rsa_format format);
int rsa_gen_prikeypem(void* _self, char* filename, enum rsa_format format);

#ifdef __cplusplus
}
#endif

#endif
