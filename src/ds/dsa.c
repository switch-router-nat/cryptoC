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
#include "../hash/sha.h"
#include "../hash/sha1.h"
#include "ds.h"
#include "dsa.h"

/*
   the constructor of dsa
*/
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

/*
   the destructor of dsa
*/
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

/*
	generate DSA key pair
*/
static int dsa_keygenerate(void* _self)
{
	DSA *self = _self;
	int p_len = self->p->len;
	int q_len = self->q->len;
	uint count = 0;
	b_ctx_t ctx_p, ctx_q;

	b_ctx_init(&ctx_p, p_len);
	b_ctx_init(&ctx_q, q_len);

	b_uint32_t* primtive = b_ctx_alloc(&ctx_p, p_len); /* the primtive of GF(P) */
	b_uint32_t* tmp1 = b_create(q_len + 1);
	b_uint32_t* tmp2 = b_create(p_len - q_len);

	/* generate prime q */
	prime_random(self->q, &ctx_q);

	//dump("q   ", self->q);

	/* tmp1 = 2q */
	b_add(self->q, self->q, tmp1);

	//dump("2q  ", tmp1);

	b_random(tmp2);

	tmp2->data[0] |= 0xc0000000;

	/* force even */
	tmp2->data[tmp2->len - 1] &=~ 1;

	/* p = tmp2 * q + 1 */
	b_mul(tmp2, self->q, self->p);
	b_add2(self->p, 0x00000001, 0);

	printf(".......\n");
	/* until p is a prime */
	while(!is_prime(self->p, 3, &ctx_p))
	{
		/* p = p + 2q */
		b_add(self->p, tmp1,self->p);

		count++;
		printf(".");
		fflush(stdout);
	}

	/* tmp2 += 2*count = p-1/q */
	b_add2(tmp2, 2*count, 0);

	/* primtive = 1 */
	b_assign(primtive, 0x00000002);

	do {
		/* primtive = primtive + 1*/
		b_add2(primtive, 1, 0);

		/* self->g = primtive^tmp2 mod p */
		b_expmod(primtive, tmp2, self->p, self->g, &ctx_p);
	
	}while(!b_cmp2(self->g, 0x00000001));

	dump("g   ",self->g);

	/* generate random private key:self->x */
	b_random(self->x);
	b_mod(self->x, self->q, self->x, &ctx_q);

	dump("x   ",self->x);
	/* calc public key self->y */
	b_expmod(self->g, self->x, self->p, self->y, &ctx_p);
	
	dump("y   ",self->y);

	b_destroy(tmp1);
	b_destroy(tmp2);

	b_ctx_fini(&ctx_p);
	b_ctx_fini(&ctx_q);

	return 0;
}

/*
	signature message
	@msg   : the message to signature
	@msglen: the message length (bytes)
	@sig   : the output signature
	@siglen: the signature length (bytes)
*/
static int dsa_signature(void* _self, const uint8_t* msg, uint32_t msglen, uint8_t* sig, uint32_t siglen)
{
	DSA *self = _self;
	int p_len = self->p->len;
	int q_len = self->q->len;
	b_ctx_t ctx_p, ctx_q;

	b_ctx_init(&ctx_p, p_len);
	b_ctx_init(&ctx_q, q_len);

	b_uint32_t* r = b_ctx_alloc(&ctx_q, q_len);
	b_uint32_t* s = b_ctx_alloc(&ctx_q, q_len);
	b_uint32_t* k = b_ctx_alloc(&ctx_q, q_len);
	b_uint32_t* invk = b_ctx_alloc(&ctx_q, q_len);
	b_uint32_t* tmp1 = b_ctx_alloc(&ctx_p, p_len);
	b_uint32_t* tmp2 = b_ctx_alloc(&ctx_q, q_len);
	b_uint32_t* tmp3 = b_ctx_alloc(&ctx_q, q_len);
	b_uint32_t* z = b_ctx_alloc(&ctx_q, q_len);

	b_random(k);

	/* calc the inverse of k */
	b_inverse(k, self->q, invk, &ctx_q);

	/* tmp1 = g^k mod p */
	b_expmod(self->g, k, self->p, tmp1, &ctx_p);

	/* r = (g^k mod p) mod q*/
	b_mod(tmp1, self->q, r, &ctx_p);

	/* tmp2 = xr mod q */
	b_mulmod(self->x, r, self->q, tmp2, &ctx_q);

	void* sha1 = new(Sha1);
	uint8_t digest[20];

	SHA_CalculateDigest(sha1, msg, msglen << 3, digest);
	
	b_assign2(z, digest, sizeof(digest));

	b_mod(z, self->q, z, &ctx_q);

	/* tmp3 = (z + xr) mod q */
	b_addmod(z, tmp2, self->q, tmp3, &ctx_q);

	/* s = k^(-1) * (z+xr) mod q  */
	b_mulmod(invk, tmp3, self->q, s, &ctx_q);

	dump("r" ,r);
	dump("s" ,s);

	/* tmp2 = s^(-1) mod q */
	b_inverse(s, self->q, tmp2, &ctx_q);

	b_uint32_t* u1 = b_ctx_alloc(&ctx_q, q_len);
	b_uint32_t* u2 = b_ctx_alloc(&ctx_q, q_len);
	b_uint32_t* vp = b_ctx_alloc(&ctx_p, p_len);
	b_uint32_t* v = b_ctx_alloc(&ctx_q, q_len);

	/* u1 = s^(-1)*SHA(msg) mod q */
	b_mulmod(tmp2, z, self->q, u1, &ctx_q);

	/* u2 = tmp2*r mod q */
	b_mulmod(tmp2, r, self->q, u2, &ctx_q);

	b_uint32_t* tmp4 = b_ctx_alloc(&ctx_p, p_len);
	b_uint32_t* tmp5 = b_ctx_alloc(&ctx_p, p_len);

	/* tmp4 = g^(u1) mod p */
	b_expmod(self->g, u1, self->p, tmp4, &ctx_p);

	/* tmp5 = y^(u2) mod p */
	b_expmod(self->y, u2, self->p, tmp5, &ctx_p);

	/* vp = g^(u1) * y^(u2) mod p */
	b_mulmod(tmp4, tmp5, self->p, vp, &ctx_p);

	b_mod(vp, self->q, v, &ctx_p);

	dump("v", v);

	b_ctx_fini(&ctx_p);
	b_ctx_fini(&ctx_q);

	delete(sha1);

	return 0;
}

static int dsa_verify(void* _self)
{
	return 0;
}

static DSBASEvtbl const dsa_vtbl = {
	&dsa_keygenerate,
	&dsa_signature,
	NULL,
};

static const OBJECT _Dsa = {
    sizeof(DSA),
    &dsa_vtbl,
    dsa_ctor, 
    dsa_dtor,	
};

const void* Dsa = &_Dsa;
