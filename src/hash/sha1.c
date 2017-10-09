/*
 * File       : sha1.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-05     QshLyc       first version
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
#include "sha1.h"

#define SHA1_CHUNKSIZE        512 
#define SHA1_CHUNKSIZE_BYTE    64 
#define SHA1_LENGTHSIZE_BYTE    8   

static void sha1_expandword(const uint8_t* pdata, uint32_t* W)
{
	uint8_t i;

	for (i = 0; i < 16; i++)
	{
		W[i] = ((((uint32_t)(pdata[i * 4 + 0])) << 24) |
			    (((uint32_t)(pdata[i * 4 + 1])) << 16) |
			    (((uint32_t)(pdata[i * 4 + 2])) << 8)  |
			    (((uint32_t)(pdata[i * 4 + 3])) << 0));
	}

	for (i = 16; i < 80; i++)
	{
		/* Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array: */
		W[i] = Rotl32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
	}
}

static void sha1_round(uint32_t* a, uint32_t* b,uint32_t* c,uint32_t* d,uint32_t* e, uint8_t round, uint32_t* W)
{
	uint32_t ta,tb,tc,td,te;
	uint32_t f,k,temp;

	ta = *a;
	tb = *b;
	tc = *c;
	td = *d;
	te = *e;

	if (round < 20)
	{
		f = td ^ (tb  & (tc ^ td));
		k = 0x5A827999;
	}
	else if (round < 40)
	{
		f = tb ^ tc ^ td;
		k = 0x6ED9EBA1;		
	}
	else if (round < 60)
	{
		f = (tb & tc) | (td & (tb | tc));
		k = 0x8F1BBCDC;
	}
	else
	{
		f = tb ^ tc ^ td;
		k = 0xCA62C1D6;
	}

	temp = Rotl32(ta, 5) + f + te + k + W[round];
	*e = td;
	*d = tc;
	*c = Rotl32(tb, 30);
	*b = ta;
	*a = temp;

	return;
}

static void sha1_transform(uint32_t *state, const uint8_t *pdata)
{
	uint32_t W[80] = {0};

	sha1_expandword(pdata, W);

	uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    for (int i = 0; i < 80; ++i)
    {
    	sha1_round(&a, &b, &c, &d, &e, i, W); 
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    return;

}

static void sha1_initstate(uint32_t* state)
{  
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;
} 

/*
    @data: the data to be calulate
    @size: the size(bit) of @data 
    @digest: result
*/
static void sha1_calculatedigest(void* _self, const uint8_t *data, uint64_t size, uint8_t *digest)
{
	const uint8_t* pdata = data;
	uint32_t state[5];
	uint64_t unhashbyte;
	uint8_t last_chunk[SHA1_CHUNKSIZE_BYTE];
	uint8_t secondlast_chunk[SHA1_CHUNKSIZE_BYTE];
	uint8_t i;

	memset(last_chunk, 0, SHA1_CHUNKSIZE_BYTE);
	memset(secondlast_chunk, 0, SHA1_CHUNKSIZE_BYTE);

    unhashbyte = size >> 3;

    sha1_initstate(state);

	while (unhashbyte >= SHA1_CHUNKSIZE_BYTE)
	{
		sha1_transform(state, pdata);
		
		pdata += SHA1_CHUNKSIZE_BYTE;
		
		unhashbyte -= SHA1_CHUNKSIZE_BYTE;
	}

	if (unhashbyte < (SHA1_CHUNKSIZE_BYTE - SHA1_LENGTHSIZE_BYTE))
	{
		memcpy(last_chunk, pdata, unhashbyte);
		
		last_chunk[unhashbyte] = 0x80;		
	}
	else if (unhashbyte == (SHA1_CHUNKSIZE_BYTE - SHA1_LENGTHSIZE_BYTE))
	{
		memcpy(last_chunk, pdata, unhashbyte);
	}
	else
	{
		memcpy(secondlast_chunk, pdata, unhashbyte);
		
		secondlast_chunk[unhashbyte] = 0x80;

		sha1_transform(state, secondlast_chunk);
	}

	last_chunk[SHA1_CHUNKSIZE_BYTE - 8] = (uint8_t)(size >> 56);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 7] = (uint8_t)(size >> 48);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 6] = (uint8_t)(size >> 40);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 5] = (uint8_t)(size >> 32);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 4] = (uint8_t)(size >> 24);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 3] = (uint8_t)(size >> 16);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 2] = (uint8_t)(size >> 8);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 1] = (uint8_t)(size);

	sha1_transform(state, last_chunk);

	for (i = 0; i < 5; i++)
	{
		digest[i * 4 + 0] = (uint8_t)(state[i] >> 24);
		digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
		digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
		digest[i * 4 + 3] = (uint8_t)(state[i]);
	}

	return;
} 

static SHAvtbl const vtbl = {
	&sha1_calculatedigest,
};

static void* sha1_ctor(void *_self, va_list *app)
{
	SHA1 *self = _self;
	
	((const OBJECT*)Sha)->ctor(_self, app);

	return _self;
}

static void* sha1_dtor(void* _self)
{
	SHA1* self = _self;
	
	((const OBJECT*)Sha)->dtor(self);

	return _self;
}

static const OBJECT _Sha1 = {
    sizeof(SHA1),
    &vtbl,
    sha1_ctor, 
    sha1_dtor,	
};

const void* Sha1 = &_Sha1;