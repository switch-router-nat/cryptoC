/*
 * File       : cryptoc.h *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-06     QshLyc       first version
 */

#ifndef _CRYPTOC_H_
#define _CRYPTOC_H_

/* base */
void *new (const void* _object,...);
void delete (void* self);


/***************** block cipher ***************/

/***** AES start ********/
enum aes_type_e{
	AES_TYPE_128 = 0,
	AES_TYPE_192,
	AES_TYPE_256
};
extern const void* Aes;
/*****AES end ***********/

enum blockcipher_mode_e{
	BLOCKCIPHER_MODE_ECB = 0,
	BLOCKCIPHER_MODE_CBC,
};

enum blockcipher_pad_e{
	BLOCKCIPHER_PAD_ZERO = 0,
	BLOCKCIPHER_PAD_PKCS7,
};
int BlockCipher_SetKey(void* _self, const char* userkey);
int BlockCipher_SetMode(void* _self, enum blockcipher_mode_e mode);
int BlockCipher_SetIV(void* _self, uint8_t* iv, uint8_t iv_len);
int BlockCipher_SetPad(void* _self, enum blockcipher_pad_e pad);
int BlockCipher_ProcessBlock(void* _self, const uint8_t* inblock, uint8_t* outblock);
int BlockCipher_Encryption(void* _self, const uint8_t* plaintext, uint32_t plainlen, uint8_t* cipertext, uint32_t* cipherlen);
int BlockCipher_Decryption(void* _self, const uint8_t* ciphertext, uint32_t cipherlen, uint8_t* plaintext, uint32_t* plainlen);


/*********************/

typedef struct{
	uint32_t *data;
	int len;   
	int top;   /* the first non-zero uint32_t from the left */
	int topbit;/* the first non-zero bit in data[top]       */
	int neg;
}b_uint32_t;

typedef struct{
	int depth1;
	int depth2;
	int depth4;
}b_ctx_bkp_t;

#define B_CTX_SIZE  16
typedef struct{
	int len;
	int depth1;
	int depth2;
	int depth4;
	b_uint32_t ctx1[B_CTX_SIZE];
	b_uint32_t ctx2[B_CTX_SIZE];
	b_uint32_t ctx4[B_CTX_SIZE];
}b_ctx_t;

void b_ctx_init(b_ctx_t* ctx, int len);
void b_ctx_save(b_ctx_t* ctx, b_ctx_bkp_t* bkp);
void b_ctx_restore(b_ctx_t* ctx, b_ctx_bkp_t* bkp);
b_uint32_t* b_ctx_alloc(b_ctx_t* ctx, int len);
void b_ctx_fini(b_ctx_t* ctx);

b_uint32_t* b_create(int len);
void b_destroy(b_uint32_t* a);

void b_zero(b_uint32_t *a);
void b_assign(b_uint32_t* a, uint32_t val);
void b_input(b_uint32_t *a, uint8_t* data, uint32_t len);
uint32_t b_output(b_uint32_t *a, uint8_t* data);
void b_toggle(b_uint32_t* a);
void b_swap(b_uint32_t** a, b_uint32_t** b);
void b_swap3(b_uint32_t** a, b_uint32_t** b, b_uint32_t** c);
int b_valid_bit(uint32_t a, int* bitbegin);
int b_valid_top(b_uint32_t* a);
int  b_valid_topbit(b_uint32_t* a);
void b_mov(b_uint32_t* a, b_uint32_t* b);
void b_add2(b_uint32_t *a, uint32_t b, int l);
int b_add(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c);
void b_sub2(b_uint32_t *a, uint32_t b, int l);
void b_sub(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c);
void b_mul(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c);
int b_cmp(b_uint32_t* a, b_uint32_t* b);
int b_cmp2(b_uint32_t* a, uint32_t b);
void b_add_ex(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c);
void b_sub_ex(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c);
void b_leftshift(b_uint32_t* a, int n, b_uint32_t* c);
void b_rightshiftbit(b_uint32_t* a, int b, b_uint32_t* c);
void b_leftshiftbit(b_uint32_t* a, int b, b_uint32_t* c);
void b_mod(b_uint32_t* a, b_uint32_t* n, b_uint32_t* c, b_ctx_t* ctx);
void b_addmod(b_uint32_t *a, b_uint32_t *b, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx);
void b_submod(b_uint32_t *a, b_uint32_t *b, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx);
void b_mulmod(b_uint32_t *a, b_uint32_t *b, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx);
void b_expmod(b_uint32_t *a, b_uint32_t* x, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx);
void b_div(b_uint32_t* de, b_uint32_t* di, b_uint32_t* q, b_uint32_t* r, b_ctx_t* ctx);
int is_prime(b_uint32_t* p, int security, b_ctx_t* ctx);
void b_random(b_uint32_t* a);
void b_odd(b_uint32_t* a);
void b_even(b_uint32_t* a);
void prime_random(b_uint32_t* p, b_ctx_t* ctx);
void euclidean_algorithm(b_uint32_t* r0, b_uint32_t* r1, b_uint32_t* gcd, b_ctx_t* ctx);
void ex_euclidean_algorithm(b_uint32_t* r0, b_uint32_t* r1, b_uint32_t* gcd, b_uint32_t* t, b_ctx_t* ctx);
int b_inverse(b_uint32_t* a, b_uint32_t* n, b_uint32_t* t, b_ctx_t* ctx);
int b_divmod(b_uint32_t* a, b_uint32_t* b, b_uint32_t* n, b_uint32_t* c, b_ctx_t* ctx);
int is_coprime(b_uint32_t* a, b_uint32_t* b, b_ctx_t* ctx);

void dump(char* string, b_uint32_t *a);



/*********************/

/*********************/
extern const void* Dsa;

enum dsa_size_e{
	DSA_L1024_N160,
	DSA_L2048_N224,
	DSA_L2048_N256,
	DSA_L3072_N256,
};


int DS_KeyGenerate(void* _self);
int DS_Signature(void* _self, const uint8_t* msg, uint32_t msglen, uint8_t* sig, uint32_t* siglen);
int DS_Verify(void* _self, const uint8_t* msg, uint32_t msglen, uint8_t* sig, uint32_t siglen);

/*********************/
/*********************/
enum ecc_curve_e{
	ECC_CURVE_SECP192K1 = 0,
};

extern const void* Ecc;

typedef struct{
	b_uint32_t* p;    /* prime */     
	b_uint32_t* a;   
	b_uint32_t* b;   
	b_uint32_t* Gx; 	
	b_uint32_t* Gy;	
	b_uint32_t* n;	
	b_uint32_t* h;	
}ecc_curve_t;

extern const void* Ecc_Point;

typedef struct{
	const void* object;
	b_uint32_t* x;
	b_uint32_t* y;
}ECC_POINT;

typedef struct{
	const void* object;
	ecc_curve_t* curve;
}ECC;

int ecc_multiplication(void* _self, b_uint32_t* d, void* _pt1, void* _pt2, b_ctx_t* ctx);

/****************************/
extern const void* Rsa;

enum rsa_format {
	RSA_FORMAT_PKCS1,
	RSA_FORMAT_PKCS8
};

void rsa_key_generate(void* _self);
int rsa_encryption(void* _self, b_uint32_t* x, b_uint32_t* y);
int rsa_decryption(void* _self, b_uint32_t* y, b_uint32_t* x);

int rsa_gen_pubkeypem(void* _self, char* filename, enum rsa_format format);
int rsa_gen_prikeypem(void* _self, char* filename, enum rsa_format format);
/****************************/

/****************************/
extern const void* Sha1;
extern const void* Sha512;

void SHA_CalculateDigest(void* _self, const uint8_t *data, uint64_t size, uint8_t *digest);

/****************************/
extern const void* Md5;

/* Calc MD5 Digest */
/* @digest: output which must have 128bit space */
void MD5_CalculateDigest(void* _self, uint8_t* input, uint32_t inputlen, uint8_t *digest);
/*********************/

#endif
