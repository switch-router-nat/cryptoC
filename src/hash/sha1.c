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

#include "../base/basetype.h"
#include "../base/object.h"
#include "../util/rolate_shift.h"
#include "sha.h"
#include "sha1.h"

#define SHA1_CHUNKSIZE       512 
#define SHA1_CHUNKSIZE_BYTE  64 

////////////////////////////////
// start of Steve Reid's code //
////////////////////////////////
#define blk0(i) (W[i] = x[i])
#define blk1(i) (W[i&15] = Rotl32(W[(i+13)&15]^W[(i+8)&15]^W[(i+2)&15]^W[i&15],1))

#define f1(x,y,z) (z^(x&(y^z)))
#define f2(x,y,z) (x^y^z)
#define f3(x,y,z) ((x&y)|(z&(x|y)))
#define f4(x,y,z) (x^y^z)

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=f1(w,x,y)+blk0(i)+0x5A827999+Rotl32(v,5);w=Rotl32(w,30);
#define R1(v,w,x,y,z,i) z+=f1(w,x,y)+blk1(i)+0x5A827999+Rotl32(v,5);w=Rotl32(w,30);
#define R2(v,w,x,y,z,i) z+=f2(w,x,y)+blk1(i)+0x6ED9EBA1+Rotl32(v,5);w=Rotl32(w,30);
#define R3(v,w,x,y,z,i) z+=f3(w,x,y)+blk1(i)+0x8F1BBCDC+Rotl32(v,5);w=Rotl32(w,30);
#define R4(v,w,x,y,z,i) z+=f4(w,x,y)+blk1(i)+0xCA62C1D6+Rotl32(v,5);w=Rotl32(w,30);
/*
	@state: 5 * 32bit
	@pdata: 64 bytes
*/
static void sha1_transform(cc_uint32_t *state, const cc_uint8_t *pdata)
{
	cc_uint32_t W[16];
	cc_uint32_t x[16];
	cc_uint8_t i;

	for (i = 0; i < 16; i++)
	{
		x[i] = (((cc_uint32_t)(*pdata) << 24)       | 
		        ((cc_uint32_t)(*(pdata + 1)) << 16) | 
		        ((cc_uint32_t)(*(pdata + 2)) << 8)  | 
		        ((cc_uint32_t)(*(pdata + 3))));
		pdata = pdata + 4;
	}

	cc_uint32_t a = state[0];
    cc_uint32_t b = state[1];
    cc_uint32_t c = state[2];
    cc_uint32_t d = state[3];
    cc_uint32_t e = state[4];

    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

}
//////////////////////////////
// end of Steve Reid's code //
//////////////////////////////

/*
    @data: the data to be calulate
    @size: the size(bit) of @data 
    @digest: result
*/
static void sha1_calculatedigest(void* _self, const cc_uint8_t *data, cc_uint32_t size[], cc_uint8_t *digest)
{
	const cc_uint8_t* pdata = data;
	cc_uint32_t state[5];
	cc_uint32_t size_h,size_l;
	cc_uint8_t last_chunk[SHA1_CHUNKSIZE_BYTE];
	cc_uint8_t secondlast_chunk[SHA1_CHUNKSIZE_BYTE];
	cc_uint8_t i;

	memset(last_chunk, 0, SHA1_CHUNKSIZE_BYTE);
	memset(secondlast_chunk, 0, SHA1_CHUNKSIZE_BYTE);

    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;

    size_h = size[0];
    size_l = size[1];

	while ((size_h > 0) || (size_l > SHA1_CHUNKSIZE))
	{
		sha1_transform(state, pdata);
		pdata = pdata + SHA1_CHUNKSIZE_BYTE;

		if (0 == size_l)
		{
			size_h = size_h - 1;
			size_l = -SHA1_CHUNKSIZE;
		}
		else
		{
			size_l = size_l - SHA1_CHUNKSIZE;
		}
	}

	if ((size_l>>3) <= (SHA1_CHUNKSIZE_BYTE - 9))
	{
		memcpy(last_chunk, pdata, size_l>>3);
		
		last_chunk[size_l>>3] = 0x80;		
	}
	else
	{
		memcpy(secondlast_chunk, pdata, size_l>>3);
		secondlast_chunk[size_l>>3] = 0x80;

		sha1_transform(state, secondlast_chunk);
	}

	last_chunk[SHA1_CHUNKSIZE_BYTE - 8] = (cc_uint8_t)(size[0]>>24);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 7] = (cc_uint8_t)(size[0]>>16);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 6] = (cc_uint8_t)(size[0]>>8);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 5] = (cc_uint8_t)(size[0]);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 4] = (cc_uint8_t)(size[1]>>24);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 3] = (cc_uint8_t)(size[1]>>16);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 2] = (cc_uint8_t)(size[1]>>8);
	last_chunk[SHA1_CHUNKSIZE_BYTE - 1] = (cc_uint8_t)(size[1]);

	sha1_transform(state, last_chunk);

	for (i = 0; i < 5; i++)
	{
		digest[i * 4 + 0] = (cc_uint8_t)(state[i] >> 24);
		digest[i * 4 + 1] = (cc_uint8_t)(state[i] >> 16);
		digest[i * 4 + 2] = (cc_uint8_t)(state[i] >> 8);
		digest[i * 4 + 3] = (cc_uint8_t)(state[i]);
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