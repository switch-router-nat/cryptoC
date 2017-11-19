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


static void* rsa_ctor(void *_self, va_list *app)
{
	RSA* self = (RSA*)_self;

	self->prikey = b_create(32);
	self->pubkey = b_create(32);
	self->n      = b_create(32);

	return _self;
}

static void* rsa_dtor(void* _self)
{
	RSA* self = (RSA*)_self;

	b_destroy(self->prikey);
	b_destroy(self->pubkey);
	b_destroy(self->n);

	return _self;
}

void rsa_gen_e(b_uint32_t* fn, b_uint32_t* e, b_ctx_t* ctx)
{
	b_random(e);
	b_odd(e);

	if (b_cmp(e,fn) > 0)
	{
		b_mod(e, fn, e, ctx); 
		b_odd(e);
	}

	while(!is_coprime(fn, e, ctx))
	{
		b_add2(e, 0x00000002, 0);
	}

	return;
}

void rsa_gen_d(b_uint32_t* fn, b_uint32_t* e, b_uint32_t* d, b_ctx_t* ctx)
{
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

void rsa_key_generate(void* _self)
{
	RSA* self = (RSA*)_self;
	b_uint32_t* e = self->pubkey;
	b_uint32_t* d = self->prikey;
	b_uint32_t* n = self->n;

	b_uint32_t* p;
	b_uint32_t* q;
	b_uint32_t* fn;
	b_uint32_t* c;
	b_uint32_t* x;
	b_uint32_t* y;

	int len = 16;
	b_ctx_t ctx;
	b_ctx_init(&ctx, len);

	p = b_ctx_alloc(&ctx, len);
	q = b_ctx_alloc(&ctx, len);
	fn= b_ctx_alloc(&ctx, len<<1);
	c=  b_ctx_alloc(&ctx, len<<1);

	prime_random(p, &ctx);
	dump("prime p", p);

	prime_random(q, &ctx);
	dump("prime q", q);

	b_mul(p, q, n);

	b_sub2(p, 0x00000001, 0);
	b_sub2(q, 0x00000001, 0);

	b_mul(p, q, fn);

	rsa_gen_e(fn, e, &ctx);

	rsa_gen_d(fn, e, d, &ctx);

	b_mulmod(e, d, fn, c, &ctx);

	dump("generate public  key", e);

	dump("generate private key", d);
	//dump("c = e*d mod fn", c);

	b_ctx_fini(&ctx);

	return;
}


int rsa_encryption(void* _self, b_uint32_t* x, b_uint32_t* y)
{
	RSA* self = (RSA*)_self;
	b_ctx_t ctx;
	b_ctx_init(&ctx, 16);

	if (!self->pubkey)
	{
		return -1;
	}

	b_expmod(x, self->pubkey, self->n, y, &ctx);

	b_ctx_fini(&ctx);

	return 0;
}

int rsa_decryption(void* _self, b_uint32_t* y, b_uint32_t* x)
{
	RSA* self = (RSA*)_self;
	b_ctx_t ctx;
	b_ctx_init(&ctx, 16);

	if (!self->pubkey)
	{
		return -1;
	}

	b_expmod(y, self->prikey, self->n, x, &ctx);

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
