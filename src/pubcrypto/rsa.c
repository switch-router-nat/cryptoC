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
 * 
 * 
*/
static void rsa_fill_elementdata(uint8_t* buffer, uint32_t i, b_uint32_t* bn, uint8_t size, uint8_t extralen)
{
	buffer[i++] = 0x02;
	if (extralen)
	{
		buffer[i++] = 0x81;
	}
	buffer[i++] = size;

	switch (size % 4)
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

static uint8_t rsa_calc_asn1byte(b_uint32_t* bn)
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

	return len;
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
	uint8_t n_byte, e_byte, element_total_byte;
	uint32_t bufsize = 0;
	uint32_t i = 0;
	uint8_t n_extralen = 0;      /* need an extra byte to identify n's len  */
	uint8_t e_extralen = 0;      /* need an extra byte to identify e's len   */
	uint8_t total_extralen = 0;  /* need an extra byte to identify total len */
	
	b_uint32_t* n = self->n;
	n_byte = rsa_calc_asn1byte(n);

	b_uint32_t* e = self->e;
	e_byte = rsa_calc_asn1byte(e);

	bufsize = 2 + n_byte + 2 + e_byte;  /* for each element, at least 2 bytes header */
	if (n_byte > 128)
	{
		n_extralen = 1;
		bufsize++;
	}
	if (e_byte > 128)
	{
		e_extralen = 1;
		bufsize++;
	}

	element_total_byte = bufsize;

	if (bufsize > 128)
	{
		total_extralen = 1;
		bufsize++;
	}

	bufsize += 2;  /* identity header */

	/* fill the pubkey buffer:identity header */
	pubkey = calloc(1, bufsize);
	pubkey[i++] = 0x30;
	if (total_extralen)
	{
		pubkey[i++] = 0x81;
	}
	pubkey[i++] = element_total_byte;

	/* fill the pubkey buffer: n */
	rsa_fill_elementdata(pubkey, i, self->n, n_byte, n_extralen);
	i = i + 2 + n_byte + n_extralen;

	/* fill the pubkey buffer: e */
	rsa_fill_elementdata(pubkey, i, self->e, e_byte, e_extralen);
	i = i + 2 + e_byte + e_extralen;

	self->pubkey = pubkey;
	self->pubkeysize = bufsize;

	printf("pubkey:----------\n");
	for (int j = 0; j < bufsize; ++j)
	{
		printf("0x%x ",self->pubkey[j]);
	}
	printf("-----------\n");

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
     }
	 *
	*/
	uint8_t* pubkey = NULL;
	uint8_t n_byte, e_byte, element_total_byte;
	uint32_t bufsize = 0;
	uint32_t i = 0;
	uint8_t n_extralen = 0;      /* need an extra byte to identify n's len  */
	uint8_t e_extralen = 0;      /* need an extra byte to identify e's len   */
	uint8_t total_extralen = 0;  /* need an extra byte to identify total len */
	
	b_uint32_t* n = self->n;
	n_byte = rsa_calc_asn1byte(n);

	b_uint32_t* e = self->e;
	e_byte = rsa_calc_asn1byte(e);

	bufsize = 2 + n_byte + 2 + e_byte;  /* for each element, at least 2 bytes header */
	if (n_byte > 128)
	{
		n_extralen = 1;
		bufsize++;
	}
	if (e_byte > 128)
	{
		e_extralen = 1;
		bufsize++;
	}

	element_total_byte = bufsize;

	if (bufsize > 128)
	{
		total_extralen = 1;
		bufsize++;
	}

	bufsize += 2;  /* identity header */

	/* fill the pubkey buffer:identity header */
	pubkey = calloc(1, bufsize);
	pubkey[i++] = 0x30;
	if (total_extralen)
	{
		pubkey[i++] = 0x81;
	}
	pubkey[i++] = element_total_byte;

	/* fill the pubkey buffer: n */
	rsa_fill_elementdata(pubkey, i, self->n, n_byte, n_extralen);
	i = i + 2 + n_byte + n_extralen;

	/* fill the pubkey buffer: e */
	rsa_fill_elementdata(pubkey, i, self->e, e_byte, e_extralen);
	i = i + 2 + e_byte + e_extralen;

	self->pubkey = pubkey;
	self->pubkeysize = bufsize;

	printf("pubkey:----------\n");
	for (int j = 0; j < bufsize; ++j)
	{
		printf("0x%x ",self->pubkey[j]);
	}
	printf("-----------\n");

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
 		ex_euclidean_algorithm(tmp, self->q, gcd, self->cq, &ctx); 		
	}
	else
	{
		/* cq = p^(-1) mod q */
 		ex_euclidean_algorithm(self->q, self->p, gcd, self->cq, &ctx); 

 		b_mod(self->q, self->p, tmp, &ctx);

		/* cp = q^(-1) mod p = (q mod p)^(-1) mod p */
 		ex_euclidean_algorithm(tmp, self->p, gcd, self->cp, &ctx); 		
	}

	/* qcp = q*cp */
	b_mul(self->q, self->cp, self->qcp);
	
	/* pcq = p*cq */
	b_mul(self->p, self->cq, self->pcq);

	//rsa_gen_prikey(self);

	rsa_gen_pubkey(self);

	//dump("c = e*d mod fn", c);

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

int rsa_decryption(void* _self, b_uint32_t* y, b_uint32_t* x)
{
	RSA* self = (RSA*)_self;
	b_ctx_t ctx;
	b_ctx_init(&ctx, 16);

	if (!self->e)
	{
		return -1;
	}

	b_expmod(y, self->d, self->n, x, &ctx);

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
