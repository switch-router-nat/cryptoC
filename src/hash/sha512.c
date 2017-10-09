/*
 * File       : sha512.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-06     QshLyc       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include "../base/object.h"
#include "../util/rolate_shift.h"
#include "sha.h"
#include "sha512.h"

#define SHA512_CHUNKSIZE       1024 
#define SHA512_CHUNKSIZE_BYTE   128 
#define SHA512_LENGTHSIZE_BYTE   16   

static const uint64_t sha512_kc[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};


static void sha512_initstate(uint64_t* state)
{  
    state[0] = 0x6a09e667f3bcc908;  
    state[1] = 0xbb67ae8584caa73b; 
    state[2] = 0x3c6ef372fe94f82b;  
    state[3] = 0xa54ff53a5f1d36f1;  
    state[4] = 0x510e527fade682d1;  
    state[5] = 0x9b05688c2b3e6c1f;  
    state[6] = 0x1f83d9abfb41bd6b;  
    state[7] = 0x5be0cd19137e2179;  
} 

static void sha512_expandword(const uint8_t* pdata, uint64_t* W)
{
	uint8_t i;
	uint64_t s0, s1;

	for (i = 0; i < 16; i++)
	{
		W[i] = ((((uint64_t)(pdata[i * 8 + 0])) << 56) |
			   (((uint64_t)(pdata[i * 8 + 1])) << 48) |
			   (((uint64_t)(pdata[i * 8 + 2])) << 40) |
			   (((uint64_t)(pdata[i * 8 + 3])) << 32) |
			   (((uint64_t)(pdata[i * 8 + 4])) << 24) |
			   (((uint64_t)(pdata[i * 8 + 5])) << 16) |
			   (((uint64_t)(pdata[i * 8 + 6])) << 8) |
			   (((uint64_t)(pdata[i * 8 + 7])) << 0));
	}

	for (i = 16; i < 80; i++)
	{
		/* Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array: */
		s0 = Rotr64(W[i-15], 1) ^ Rotr64(W[i-15], 8) ^ (W[i-15] >> 7);
		s1 = Rotr64(W[i-2], 19) ^ Rotr64(W[i-2], 61) ^ (W[i-2] >> 6);
		W[i] = W[i-16] + s0 + W[i-7] + s1;
	}
}

static void sha512_round(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d, uint64_t* e, uint64_t* f, uint64_t* g, uint64_t* h, uint64_t W, uint64_t Kc)
{
	uint64_t ta,tb, tc,td,te,tf,tg,th;
	uint64_t S0,S1;
	uint64_t ch,maj;
	uint64_t temp1,temp2;

	ta = *a;
	tb = *b;
	tc = *c; 
	td = *d;
	te = *e;
	tf = *f;
	tg = *g;
	th = *h;
 
	S1 = Rotr64(te, 14) ^ Rotr64(te, 18) ^ Rotr64(te, 41); 
 	ch = (te & tf) ^ ((~te) & tg);
 	temp1 = th + S1 + ch + Kc + W;

 	S0  = Rotr64(ta, 28) ^ Rotr64(ta, 34) ^ Rotr64(ta, 39); 
 	maj = (ta & tb) ^ (ta & tc) ^ (tb & tc);
 	temp2 = S0 + maj;

 	*a = temp1 + temp2;
 	*b = ta;
 	*c = tb;
 	*d = tc;
 	*e = td + temp1;
 	*f = te;
 	*g = tf;
 	*h = tg;

 	return;
}
/*
	@state: 8 * 64bit
	@pdata: 128 bytes , 1024 bits
*/
static void sha512_transform(uint64_t *state, const uint8_t *pdata)
{
	uint64_t W[80] = {0x0};

    sha512_expandword(pdata, W);

    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
	uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];    

    for (int i = 0; i < 80; ++i)
    {
    	sha512_round(&a, &b, &c, &d, &e, &f, &g, &h, W[i], sha512_kc[i]); 
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h; 

    return;
}


/*
    @data: the data to be calulate
    @size: the size(bit) of @data 
    @digest: result
*/
static void sha512_calculatedigest(void* _self, const uint8_t *data, uint64_t size, uint8_t *digest)
{
	const uint8_t* pdata = data;
	uint64_t state[8];
	uint64_t unhashbyte;
	uint8_t last_chunk[SHA512_CHUNKSIZE_BYTE];
	uint8_t secondlast_chunk[SHA512_CHUNKSIZE_BYTE];
	uint8_t i;

	memset(last_chunk, 0, SHA512_CHUNKSIZE_BYTE);
	memset(secondlast_chunk, 0, SHA512_CHUNKSIZE_BYTE);

    unhashbyte = size >> 3;

    sha512_initstate(state);

	while (unhashbyte >= SHA512_CHUNKSIZE_BYTE)
	{
		sha512_transform(state, pdata);
		
		pdata += SHA512_CHUNKSIZE_BYTE;
		
		unhashbyte -= SHA512_CHUNKSIZE_BYTE;
	}

	if (unhashbyte < (SHA512_CHUNKSIZE_BYTE - SHA512_LENGTHSIZE_BYTE))
	{
		memcpy(last_chunk, pdata, unhashbyte);
		
		last_chunk[unhashbyte] = 0x80;		
	}
	else if (unhashbyte == (SHA512_CHUNKSIZE_BYTE - SHA512_LENGTHSIZE_BYTE))
	{
		memcpy(last_chunk, pdata, unhashbyte);
	}
	else
	{
		memcpy(secondlast_chunk, pdata, unhashbyte);
		
		secondlast_chunk[unhashbyte] = 0x80;

		sha512_transform(state, secondlast_chunk);
	}

	last_chunk[SHA512_CHUNKSIZE_BYTE - 8] = (uint8_t)(size >> 56);
	last_chunk[SHA512_CHUNKSIZE_BYTE - 7] = (uint8_t)(size >> 48);
	last_chunk[SHA512_CHUNKSIZE_BYTE - 6] = (uint8_t)(size >> 40);
	last_chunk[SHA512_CHUNKSIZE_BYTE - 5] = (uint8_t)(size >> 32);
	last_chunk[SHA512_CHUNKSIZE_BYTE - 4] = (uint8_t)(size >> 24);
	last_chunk[SHA512_CHUNKSIZE_BYTE - 3] = (uint8_t)(size >> 16);
	last_chunk[SHA512_CHUNKSIZE_BYTE - 2] = (uint8_t)(size >> 8);
	last_chunk[SHA512_CHUNKSIZE_BYTE - 1] = (uint8_t)(size);

	sha512_transform(state, last_chunk);

	for (i = 0; i < 8; i++)
	{
		digest[i * 8 + 0] = (uint8_t)(state[i] >> 56);
		digest[i * 8 + 1] = (uint8_t)(state[i] >> 48);
		digest[i * 8 + 2] = (uint8_t)(state[i] >> 40);
		digest[i * 8 + 3] = (uint8_t)(state[i] >> 32);
		digest[i * 8 + 4] = (uint8_t)(state[i] >> 24);
		digest[i * 8 + 5] = (uint8_t)(state[i] >> 16);
		digest[i * 8 + 6] = (uint8_t)(state[i] >> 8);
		digest[i * 8 + 7] = (uint8_t)(state[i]);
	}

	return;
} 

static SHAvtbl const vtbl = {
	&sha512_calculatedigest,
};

static void* sha512_ctor(void *_self, va_list *app)
{
	SHA512 *self = _self;
	
	((const OBJECT*)Sha)->ctor(_self, app);

	return _self;
}

static void* sha512_dtor(void* _self)
{
	SHA512* self = _self;
	
	((const OBJECT*)Sha)->dtor(self);

	return _self;
}

static const OBJECT _Sha512 = {
    sizeof(SHA512),
    &vtbl,
    sha512_ctor, 
    sha512_dtor,	
};

const void* Sha512 = &_Sha512;