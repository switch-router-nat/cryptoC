/*
 * File       :  bn.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     QshLyc       first version
 */

#ifndef _CRYPTOC_BN_H_
#define _CRYPTOC_BN_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct{
	uint32_t *data;
	int len;   
	int top;   /* the first non-zero uint32_t from the left */
	int topbit;/* the first non-zero bit in data[top]       */
	int neg;
}b_uint32_t;


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

typedef struct{
	int depth1;
	int depth2;
	int depth4;
}b_ctx_bkp_t;


void b_ctx_init(b_ctx_t* ctx, int len);
void b_ctx_save(b_ctx_t* ctx, b_ctx_bkp_t* bkp);
void b_ctx_load(b_ctx_t* ctx, b_ctx_bkp_t* bkp);
b_uint32_t* b_ctx_alloc(b_ctx_t* ctx, int len);
void b_ctx_fini(b_ctx_t* ctx);


b_uint32_t* b_create(int len);
void b_destroy(b_uint32_t* a);

void b_zero(b_uint32_t *a);
void b_one(b_uint32_t* a);
void b_ten(b_uint32_t* a);
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
void b_leftshift(b_uint32_t* a, int n, b_uint32_t* c);
void b_rightshiftbit(b_uint32_t* a, int b, b_uint32_t* c);
void b_leftshiftbit(b_uint32_t* a, int b, b_uint32_t* c);
void b_mod(b_uint32_t* a, b_uint32_t* n, b_uint32_t* c, b_ctx_t* ctx);
void b_addmod(b_uint32_t *a, b_uint32_t *b, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx);
void b_mulmod(b_uint32_t *a, b_uint32_t *b, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx);
void b_expmod(b_uint32_t *a, b_uint32_t* x, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx);
void b_div(b_uint32_t* de, b_uint32_t* di, b_uint32_t* q, b_uint32_t* r, b_ctx_t* ctx);
int is_prime(b_uint32_t* p, int security, b_ctx_t* ctx);
void b_random(b_uint32_t* a);
void b_odd(b_uint32_t* a);
void prime_random(b_uint32_t* p, b_ctx_t* ctx);
void euclidean_algorithm(b_uint32_t* r0, b_uint32_t* r1, b_uint32_t* gcd, b_ctx_t* ctx);
void ex_euclidean_algorithm(b_uint32_t* r0, b_uint32_t* r1, b_uint32_t* gcd, b_uint32_t* t, b_ctx_t* ctx);
int is_coprime(b_uint32_t* a, b_uint32_t* b, b_ctx_t* ctx);



void dump(char* string, b_uint32_t *a);


#ifdef __cplusplus
}
#endif

#endif
