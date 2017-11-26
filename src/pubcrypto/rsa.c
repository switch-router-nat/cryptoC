/*
 * File       : rsa.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     QshLyc       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../base/object.h"
#include "../util/bn.h"
#include "../util/base64.h"
#include "rsa.h"

static  uint32_t _rsa_e_2pow16_1[32] = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  									    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
									 	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
									    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00010001};

static b_uint32_t rsa_e_2pow16_1 = {_rsa_e_2pow16_1, 32, 31, 15, 0};

static void* rsa_ctor(void *_self, va_list *app)
{
	RSA* self = (RSA*)_self;

	self->e = &rsa_e_2pow16_1;
	self->d = b_create(32);
	self->n = b_create(32);

	self->p   = b_create(16);
	self->q   = b_create(16);
	self->dp  = b_create(16);
	self->dq  = b_create(16);
	self->cp  = b_create(16);
	self->cq  = b_create(16);
	self->qcp = b_create(32);
	self->pcq = b_create(32);

	self->pubkey = NULL;
	self->pubkeysize = 0;
	self->prikey = NULL;
	self->prikeysize = 0;

	self->ready = 0;

	return _self;
}

static void* rsa_dtor(void* _self)
{
	RSA* self = (RSA*)_self;

	b_destroy(self->d);
	b_destroy(self->n);
	b_destroy(self->p);
	b_destroy(self->q);
	b_destroy(self->dp);
	b_destroy(self->dq);
	b_destroy(self->cp);
	b_destroy(self->cq);
	b_destroy(self->qcp);
	b_destroy(self->pcq);

	if (self->pubkey)
	{
		free(self->pubkey);
	}

	if (self->prikey)
	{
		free(self->prikey);
	}

	return _self;
}

static void rsa_gen_d(RSA* self, b_uint32_t* fn, b_ctx_t* ctx)
{
	b_uint32_t* e = self->e;
	b_uint32_t* d = self->d;
	b_uint32_t* gcd;
	b_ctx_bkp_t bkp;

	b_ctx_save(ctx, &bkp);
	gcd = b_ctx_alloc(ctx, fn->len);
	b_zero(gcd);

	b_zero(d);

	ex_euclidean_algorithm(fn, e, gcd, d, ctx);

	b_uint32_t* c;
	c = b_ctx_alloc(ctx, fn->len<<1);
	b_zero(c);
	b_mulmod(e, d, fn, c, ctx); 

	if (d->neg)
	{
		b_sub(fn, d, d);
		d->neg = 0;
		b_zero(c);
		b_mulmod(e, d, fn, c, ctx);
	}

	b_ctx_load(ctx, &bkp);

	return;
}


/*
 * @buffer: destination buffer
 * @i: start position to fill
 * @tlsize: element tl size
 * @vsize:  element v size
*/
static void rsa_fill_elementdata(uint8_t* buffer, uint32_t i, b_uint32_t* bn, uint8_t tlsize, uint8_t vsize, int plusminusbit)
{
	buffer[i++] = 0x02;
	
	if (tlsize == 3)
	{
		buffer[i++] = 0x81;
	}
	
	buffer[i++] = vsize;
	
	if (plusminusbit)
	{
		buffer[i++] = bn->neg ? 0x01:0x00;
		vsize--;
	}

	switch (vsize % 4)
	{
		case 0:
		{
			buffer[i++] = (bn->data[bn->top] >> 24) & 0xff;
		}
		/* fall through */
		case 3:
		{
			buffer[i++] = (bn->data[bn->top] >> 16) & 0xff; 
		}
		/* fall through */
		case 2:
		{
			buffer[i++] = (bn->data[bn->top] >> 8) & 0xff; 
		}
		/* fall through */
		case 1:
		{
			buffer[i++] = (bn->data[bn->top]) & 0xff; 
		}
	}
	
	int j;
	
	for (j = bn->top + 1;j < bn->len ;j++)
	{
		buffer[i++] = (bn->data[j] >> 24) & 0xff;
		buffer[i++] = (bn->data[j] >> 16) & 0xff;
		buffer[i++] = (bn->data[j] >> 8) & 0xff;
		buffer[i++] = (bn->data[j]) & 0xff;
	}

	return; 
}

/*
 *  calculate element size 
 *  @plusminusbit indicates if there is 1 byte for bn->neg
 */
static void rsa_calc_elementsize(b_uint32_t* bn, int plusminusbit, uint8_t* tlsize, uint8_t* vsize)
{
	int topbit;
	b_valid_top(bn);
	b_valid_bit(bn->data[bn->top], &topbit);

	uint8_t len = (bn->len - bn->top)*4;
	if (topbit >= 24)
	{
		len -= 3;
	}
	else if (topbit >= 16)
	{
		len -= 2;
	}
	else if (topbit >= 8)
	{
		len -= 1;
	}

	if (plusminusbit)
	{
		/* if plusminusbit is set, we need byte for plusminus   */
		len ++;
	}

	*vsize = len;

	if (len >= 128)
	{
		*tlsize = 3; /* t:1 byte   l:2 bytes */
	}
	else
	{
		*tlsize = 2; /* t:1 byte   l:1 bytes */
	}

	return;
}

static void rsa_gen_pubkey(RSA* self)
{
	/*
	 * An RSA public key should be represented with theASN.1 type RSAPublickey:

	 * RSAPublickey ::= SEQUENCE {
   	 * modulus INTEGER, -- n
  	 * publicExponent INTEGER   -- e
	 * }
	 *
	 * 
	*/
	uint8_t* pubkey = NULL;
	uint32_t elements_size = 0;
	uint8_t n_vsize, e_vsize;
	uint8_t n_tlsize, e_tlsize;
	uint32_t total_size = 0;
	uint32_t i = 0;
	
	rsa_calc_elementsize(self->n, 1, &n_tlsize, &n_vsize);
	rsa_calc_elementsize(self->e, 0, &e_tlsize, &e_vsize);

	elements_size = n_tlsize + n_vsize + 
					e_tlsize + e_vsize;

	total_size = elements_size;			
	if (elements_size >= 256)
	{
		/* we need another 2 bytes for identity header */
		total_size += 2;
	}
	else if (elements_size >= 128)
	{
		/* we need another 1 byte for identity header */
		total_size ++;
	}

	/* 2 byte identity header */
	total_size += 2;  

	/********************* fill header **************************/
	pubkey = calloc(1, total_size);
	pubkey[i++] = 0x30;
	if (elements_size >= 256)
	{
		pubkey[i++] = 0x82;
		pubkey[i++] = elements_size >> 8;
		pubkey[i++] = elements_size & 0xff;
	}
	else if (elements_size >= 128)
	{
		pubkey[i++] = 0x81;
		pubkey[i++] = elements_size;
	}
	else
	{
		pubkey[i++] = elements_size;
	}

	/********************* fill elements **************************/

	/* fill the pubkey buffer: n */
	rsa_fill_elementdata(pubkey, i, self->n, n_tlsize, n_vsize, 1);
	i = i + n_tlsize + n_vsize;

	/* fill the pubkey buffer: e */
	rsa_fill_elementdata(pubkey, i, self->e, e_tlsize, e_vsize, 0);
	i = i + e_tlsize + e_vsize;

	printf("\nrsa_gen_pubkey i = %d, total_size = %d", i, total_size);

	self->pubkey = pubkey;
	self->pubkeysize = total_size;

	/*
	printf("pubkey:----------\n");
	for (int j = 0; j < total_size; ++j)
	{
		printf("0x%x ",self->pubkey[j]);
	}
	printf("-----------\n");
	*/
	
	return;
}

static void rsa_gen_prikey(RSA* self)
{
	/*
	 * An RSA private key should be represented with theASN.1 type RSAPrivateKey:
	 * RSAPrivateKey :: = SEQUENCE{
	 * version            Version,
	 * modulus            INTEGER,   ------ n
	 * publicExponent     INTEGER,   ------ e
     * privateExponent    INTEGER,   ------ d
     * prime1             INTEGER,   ------ p
     * prime2             INTEGER,   ------ q
     * exponent1          INTEGER,   ------ d mod (p-1)
     * exponent2          INTEGER,   ------ d mod (q-1)
     * coefficient        INTEGER,   ------- (inverse of q) mod p
     * otherPrimeInfos    OtherPrimeInfos   ------ OPTIONAL exist when Version=1 
     }b
	 *
	*/

	uint8_t* prikey = NULL;
	uint32_t elements_size = 0;
	uint8_t n_tlsize, e_tlsize, d_tlsize, p_tlsize, q_tlsize, dp_tlsize, dq_tlsize, cp_tlsize;
	uint8_t  n_vsize,  e_vsize,  d_vsize,  p_vsize,  q_vsize,  dp_vsize,  dq_vsize,  cp_vsize;
	uint32_t total_size = 0;
	uint32_t i = 0;
	
	rsa_calc_elementsize(self->n, 1, &n_tlsize, &n_vsize);
	rsa_calc_elementsize(self->e, 0, &e_tlsize, &e_vsize);
	rsa_calc_elementsize(self->d, 0, &d_tlsize, &d_vsize);
	rsa_calc_elementsize(self->p, 1, &p_tlsize, &p_vsize);
	rsa_calc_elementsize(self->q, 1, &q_tlsize, &q_vsize);
	rsa_calc_elementsize(self->dp, 0, &dp_tlsize, &dp_vsize);
	rsa_calc_elementsize(self->dq, 0, &dq_tlsize, &dq_vsize);
	rsa_calc_elementsize(self->cp, 1, &cp_tlsize, &cp_vsize);

	elements_size = n_tlsize + n_vsize + 
					e_tlsize + e_vsize +
					d_tlsize + d_vsize +
					p_tlsize + p_vsize +
					q_tlsize + q_vsize +
					dp_tlsize + dp_vsize +
					dq_tlsize + dq_vsize +
					cp_tlsize + cp_vsize;

	/* 3 bytes version */
	elements_size += 3;

	total_size = elements_size;			
	if (elements_size >= 256)
	{
		/* we need another 2 bytes for identity header */
		total_size += 2;
	}
	else if (elements_size >= 128)
	{
		/* we need another 1 byte for identity header */
		total_size ++;
	}

	/* 2 byte identity header */
	total_size += 2;  

	/********************* fill header **************************/
	prikey = calloc(1, total_size);
	prikey[i++] = 0x30;
	if (elements_size >= 256)
	{
		prikey[i++] = 0x82;
		prikey[i++] = elements_size >> 8;
		prikey[i++] = elements_size & 0xff;
	}
	else if (elements_size >= 128)
	{
		prikey[i++] = 0x81;
		prikey[i++] = elements_size;
	}
	else
	{
		prikey[i++] = elements_size;
	}

	/********************* fill elements **************************/

	/* version = 0 */
	prikey[i++] = 0x02;
	prikey[i++] = 0x01;
	prikey[i++] = 0x00;

	/* fill the pubkey buffer: n */
	rsa_fill_elementdata(prikey, i, self->n, n_tlsize, n_vsize, 1);
	i = i + n_tlsize + n_vsize;

	/* fill the pubkey buffer: e */
	rsa_fill_elementdata(prikey, i, self->e, e_tlsize, e_vsize, 0);
	i = i + e_tlsize + e_vsize;

	/* fill the pubkey buffer: d */
	rsa_fill_elementdata(prikey, i, self->d, d_tlsize, d_vsize, 0);
	i = i + d_tlsize + d_vsize;

	/* fill the pubkey buffer: p */
	rsa_fill_elementdata(prikey, i, self->p, p_tlsize, p_vsize, 1);
	i = i + p_tlsize + p_vsize;

	/* fill the pubkey buffer: q */
	rsa_fill_elementdata(prikey, i, self->q, q_tlsize, q_vsize, 1);
	i = i + q_tlsize + q_vsize;

	/* fill the pubkey buffer: dp */
	rsa_fill_elementdata(prikey, i, self->dp, dp_tlsize, dp_vsize, 0);
	i = i + dp_tlsize + dp_vsize;

	/* fill the pubkey buffer: dp */
	rsa_fill_elementdata(prikey, i, self->dq, dq_tlsize, dq_vsize, 0);
	i = i + dq_tlsize + dq_vsize;

	/* fill the pubkey buffer: cp */
	rsa_fill_elementdata(prikey, i, self->cp, cp_tlsize, cp_vsize, 1);
	i = i + cp_tlsize + cp_vsize;

	self->prikey = prikey;
	self->prikeysize = total_size;

	/*
	printf("prikey:----------\n");
	for (int j = 0; j < total_size; ++j)
	{
		printf("0x%x ",self->prikey[j]);
	}
	printf("-----------\n");
	*/

	return;
}

void rsa_key_generate(void* _self)
{
	RSA* self = (RSA*)_self;

	b_uint32_t* fn;
	b_uint32_t* gcd;
	b_uint32_t* tmp;

	int len = 16;
	b_ctx_t ctx;
	b_ctx_init(&ctx, len);

	fn  = b_ctx_alloc(&ctx, len<<1);
	gcd = b_ctx_alloc(&ctx, len);
	tmp = b_ctx_alloc(&ctx, len);

	prime_random(self->p, &ctx);
	dump("prime p", self->p);

	prime_random(self->q, &ctx);
	dump("prime q", self->q);

	b_mul(self->p, self->q, self->n);

	b_sub2(self->p, 0x00000001, 0);
	b_sub2(self->q, 0x00000001, 0);

	/* fn = (p-1)*(q-1) */
	b_mul(self->p, self->q, fn);

	rsa_gen_d(self, fn, &ctx);

	dump("generate e", self->e);

	dump("generate d", self->d);

	/* dp = d mod (p-1) */
	b_mod(self->d, self->p, self->dp, &ctx);

	/* dq = d mod (q-1) */
	b_mod(self->d, self->q, self->dq, &ctx);

	b_add2(self->p, 0x00000001, 0);
	b_add2(self->q, 0x00000001, 0);

	if (b_cmp(self->p, self->q) > 0)
	{
		/* cp = q^(-1) mod p */
 		ex_euclidean_algorithm(self->p, self->q, gcd, self->cp, &ctx);
	
 		b_mod(self->p, self->q, tmp, &ctx);

		/* cq = p^(-1) mod q = (p mod q)^(-1) mod q*/
 		ex_euclidean_algorithm(self->q, tmp, gcd, self->cq, &ctx); 		
	}
	else
	{
		/* cq = p^(-1) mod q */
 		ex_euclidean_algorithm(self->q, self->p, gcd, self->cq, &ctx); 

 		b_mod(self->q, self->p, tmp, &ctx);

		/* cp = q^(-1) mod p = (q mod p)^(-1) mod p */
 		ex_euclidean_algorithm(self->p, tmp, gcd, self->cp, &ctx); 		
	}

	/* qcp = q*cp */
	b_mul(self->q, self->cp, self->qcp);
	
	/* pcq = p*cq */
	b_mul(self->p, self->cq, self->pcq);

	rsa_gen_prikey(self);

	rsa_gen_pubkey(self);

	self->ready = 1;

	b_ctx_fini(&ctx);

	return;
}

int rsa_encryption(void* _self, b_uint32_t* x, b_uint32_t* y)
{
	RSA* self = (RSA*)_self;
	b_ctx_t ctx;
	b_ctx_init(&ctx, 16);

	if (!self->e)
	{
		return -1;
	}

	b_expmod(x, self->e, self->n, y, &ctx);

	b_ctx_fini(&ctx);

	return 0;
}

int rsa_gen_pubkeypem(void* _self, char* filename)
{
	RSA* self = (RSA*)_self;
	FILE* fp = NULL;

	if  (!self->ready)
	{
		return -1;
	}

	fp = fopen(filename, "w");
	if (fp == NULL)
	{
		return -1;
	}

	fwrite(self->pubkey, self->pubkeysize, 1, fp);

	fclose(fp);

	return 0;
}

int rsa_gen_prikeypem(void* _self, char* filename)
{
	RSA* self = (RSA*)_self;
	FILE* fp = NULL;

	if  (!self->ready)
	{
		return -1;
	}

	fp = fopen(filename, "w");
	if (fp == NULL)
	{
		return -1;
	}

	fwrite(self->prikey, self->prikeysize, 1, fp);

	fclose(fp);

	return 0;
}

int rsa_decryption(void* _self, b_uint32_t* y, b_uint32_t* x)
{
	RSA* self = (RSA*)_self;
	b_uint32_t* xp;
	b_uint32_t* xq;
	b_uint32_t* yp;
	b_uint32_t* yq;
	b_uint32_t* x1;
	b_uint32_t* x2;

	b_ctx_t ctx;
	b_ctx_init(&ctx, 16);

	if (0 == self->ready)
	{
		return -1;
	}

	xp = b_ctx_alloc(&ctx, 16);
	xq = b_ctx_alloc(&ctx, 16);
	yp = b_ctx_alloc(&ctx, 16);
	yq = b_ctx_alloc(&ctx, 16);
	x1 = b_ctx_alloc(&ctx, 32);
	x2 = b_ctx_alloc(&ctx, 32);

	/* yp = y mod p */
	b_mod(y, self->p, yp, &ctx);

	/* yq = y mod q */
	b_mod(y, self->q, yq, &ctx);

	/* xp = yp^dp mod p */
	b_expmod(y, self->dp, self->p, xp, &ctx);

	/* xq = yq^dq mod q */
	b_expmod(y, self->dq, self->q, xq, &ctx);

	/* x1 = [qcp] * xp mod n */
	b_mulmod(self->qcp, xp, self->n, x1, &ctx);

	/* x2 = [pcq] * xq mod n  */
	b_mulmod(self->pcq, xq, self->n, x2, &ctx);

	/* x = (x1 + x2) mod n */
	b_addmod(x1, x2, self->n, x, &ctx);

	b_ctx_fini(&ctx);

	return 0;
}

static const OBJECT _Rsa = {
    sizeof(RSA),
    NULL,
    rsa_ctor, 
    rsa_dtor,	
};

const void* Rsa = &_Rsa;
