/*
 * File       : aes.c
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
#include "../bn/bn.h"
#include "ds.h"
#include "dsa.h"


static void* dsa_ctor(void *_self, va_list *app)
{
    DSA *self = _self;
    ((const OBJECT*)DSbase)->ctor(_self, app);

	self->size = va_arg(*app, enum dsa_size_e);

	switch(self->size)
	{
		case (DSA_L1024_N160):
		{
			self->p = b_create(32);
			self->q = b_create(5);
			self->g = b_create(32);
			self->x = b_create(5);
			self->y = b_create(32);
			break;
		}
	}


	return self;
}

static void* dsa_dtor(void* _self)
{
	DSA *self = _self;
	((const OBJECT*)DSbase)->dtor(_self);
	
	b_destroy(self->p);
	b_destroy(self->q);
	b_destroy(self->g);
	b_destroy(self->x);
	b_destroy(self->y);

	return _self;
}

static int dsa_keygenerate(void* _self)
{
	DSA *self = _self;
	b_ctx_t ctx_p, ctx_q;

	b_ctx_init(&ctx_p, self->p->len);
	b_ctx_init(&ctx_q, self->q->len);

	b_uint32_t* M  = b_ctx_alloc(&ctx_p, self->p->len);	
	b_uint32_t* Mr = b_ctx_alloc(&ctx_p, self->p->len);
	b_uint32_t* double_q = b_ctx_alloc(&ctx_p, self->p->len);

	/* generate prime q */
	prime_random(self->q, &ctx_q);

	dump("q", self->q);

	b_add(self->q, self->q, double_q);

	dump("2q", double_q);

	for (int i = 0; i < 4096; ++i)
	{
		b_random(M);
		
		b_mod(M, double_q, Mr, &ctx_p);

		b_sub(M, Mr, self->p);

		b_add2(self->p, 0x00000001, 0);

		dump("p", self->p);

		if (is_prime(self->p, 3, &ctx_p))
		{
			printf("finish %d\n", i);
			break;
		}
	}

	b_ctx_fini(&ctx_p);
	b_ctx_fini(&ctx_q);

	return 0;
}

static int dsa_signature(void* _self)
{
	return 0;
}

static int dsa_verify(void* _self)
{
	return 0;
}

static DSBASEvtbl const dsa_vtbl = {
	&dsa_keygenerate,
	NULL,
	NULL,
};

static const OBJECT _Dsa = {
    sizeof(DSA),
    &dsa_vtbl,
    dsa_ctor, 
    dsa_dtor,	
};

const void* Dsa = &_Dsa;
