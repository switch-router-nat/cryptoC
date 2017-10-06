/*
 * File       : aes.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-09-24     QshLyc       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "../base/basetype.h"
#include "../base/object.h"
#include "blockcipher.h"
#include "aes.h"
#include "aesconst.h"

static cc_uint32_t aes_rotsubword(cc_uint32_t word)
{
	cc_uint32_t b[4];

	/* RotWord */
	word = ((word & 0x00FFFFFF) << 8) | ((word & 0xFF000000) >> 24);


	b[0] = AES_SubByte[(word & 0xFF000000) >> 24];
	b[1] = AES_SubByte[(word & 0x00FF0000) >> 16];
	b[2] = AES_SubByte[(word & 0x0000FF00) >>  8];
	b[3] = AES_SubByte[(word & 0x000000FF)];

	word = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]; 

	return word;
}

static void* aes_ctor(void *_self, va_list *app)
{
    AES *self = _self;
   // enum aes_type_e type ;

    ((const OBJECT*)BlockCipher)->ctor(_self, app);

    self->super.blocksize = AES_BLOCKSIZE;

    self->type = va_arg(*app, enum aes_type_e);
	
	return self;
}

static void* aes_dtor(void* _self)
{
	((const OBJECT*)BlockCipher)->dtor(_self);
	
	return _self;
}

static int aes_calc_roundkey(AES* self, cc_uint8_t round)
{
	cc_uint32_t t;
	cc_uint32_t lastround;
	if (0 == round)
	{
		self->roundkey[0] = (self->key[0]  << 24)  | (self->key[1]  << 16)  | (self->key[2]  << 8) | (self->key[3]);
		self->roundkey[1] = (self->key[4]  << 24)  | (self->key[5]  << 16)  | (self->key[6]  << 8) | (self->key[7]);
		self->roundkey[2] = (self->key[8]  << 24)  | (self->key[9]  << 16)  | (self->key[10] << 8) | (self->key[11]);
		self->roundkey[3] = (self->key[12] << 24)  | (self->key[13] << 16)  | (self->key[14] << 8) | (self->key[15]);
	}
	else
	{
		lastround = round - 1;
		t = aes_rotsubword(self->roundkey[lastround * 4 + 3]) ^ AES128_RCon[round];
		self->roundkey[round * 4 + 0] = self->roundkey[lastround * 4 + 0] ^ t;
		self->roundkey[round * 4 + 1] = self->roundkey[lastround * 4 + 1] ^ self->roundkey[round * 4 + 0];
		self->roundkey[round * 4 + 2] = self->roundkey[lastround * 4 + 2] ^ self->roundkey[round * 4 + 1];
		self->roundkey[round * 4 + 3] = self->roundkey[lastround * 4 + 3] ^ self->roundkey[round * 4 + 2];
	}

	return 0;

}

static int aes_setkey(void* _self, const cc_uint8_t* userkey)
{
	AES* self = _self;
	cc_uint8_t round;
	cc_uint8_t keylen;
	cc_uint8_t maxround;
	int idx = 0;

	if (AES_TYPE_128 == self->type)
	{
		keylen   = AES128_KEYLEN;
		maxround = AES128_ROUND_NR;
	}
	else if(AES_TYPE_192 == self->type)
	{
		keylen   = AES192_KEYLEN;
		maxround = AES192_ROUND_NR;
	}
	else
	{
		keylen   = AES256_KEYLEN;
		maxround = AES256_ROUND_NR;
	}

	for (idx = 0; idx < keylen; idx++)
	{
		self->key[idx] = userkey[idx];
	}		

	for (round = 0;round < maxround; round++)
	{
		aes_calc_roundkey(self, round);
	}

	return 0;
}

static void aes_addroundkey(AES* self, cc_uint8_t round, cc_uint8_t* state)
{
	state[0] ^= (cc_uint8_t)(self->roundkey[round * 4] >> 24);
	state[1] ^= (cc_uint8_t)(self->roundkey[round * 4] >> 16);
	state[2] ^= (cc_uint8_t)(self->roundkey[round * 4] >> 8);
	state[3] ^= (cc_uint8_t)(self->roundkey[round * 4]);

	state[4] ^= (cc_uint8_t)(self->roundkey[round * 4 + 1] >> 24);
	state[5] ^= (cc_uint8_t)(self->roundkey[round * 4 + 1] >> 16);
	state[6] ^= (cc_uint8_t)(self->roundkey[round * 4 + 1] >> 8);
	state[7] ^= (cc_uint8_t)(self->roundkey[round * 4 + 1]);

	state[8]  ^= (cc_uint8_t)(self->roundkey[round * 4 + 2] >> 24);
	state[9]  ^= (cc_uint8_t)(self->roundkey[round * 4 + 2] >> 16);
	state[10] ^= (cc_uint8_t)(self->roundkey[round * 4 + 2] >> 8);
	state[11] ^= (cc_uint8_t)(self->roundkey[round * 4 + 2]);

	state[12] ^= (cc_uint8_t)(self->roundkey[round * 4 + 3] >> 24);
	state[13] ^= (cc_uint8_t)(self->roundkey[round * 4 + 3] >> 16);
	state[14] ^= (cc_uint8_t)(self->roundkey[round * 4 + 3] >> 8);
	state[15] ^= (cc_uint8_t)(self->roundkey[round * 4 + 3]);
}

static void aes_shiftrows(cc_uint8_t* state)
{
	cc_uint8_t temp;

	/* Row1: 1-byte shift */
	temp = state[1];
	state[1]  = state[5];
	state[5]  = state[9];
	state[9]  = state[13];
	state[13] = temp;

	/* Row2: 2-byte shift */
	state[2]  = state[2] ^ state[10];
	state[10] = state[2] ^ state[10];
	state[2]  = state[2] ^ state[10];

	state[6]  = state[6] ^ state[14];
	state[14] = state[6] ^ state[14];
	state[6]  = state[6] ^ state[14];

	/* Row3: 3-byte shift */
	temp = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7]  = state[3];
	state[3]  = temp;
}

static void aes_invshiftrows(cc_uint8_t* state)
{
	cc_uint8_t temp;
    
    /* Row1: 1-byte shift */
	temp = state[13];
	state[13] = state[9];
	state[9]  = state[5];
	state[5]  = state[1];
	state[1]  = temp;

	/* Row2: 2-byte shift */
	state[2]  = state[2] ^ state[10];
	state[10] = state[2] ^ state[10];
	state[2]  = state[2] ^ state[10];

	state[6]  = state[6] ^ state[14];
	state[14] = state[6] ^ state[14];
	state[6]  = state[6] ^ state[14];

	/* Row3: 3-byte shift */
	temp = state[3];
	state[3]  = state[7];
	state[7]  = state[11];
	state[11] = state[15];
	state[15] = temp;

}

/*
    GF(2^8) with irreducible polymimal x^8+x^4+x^3+x+1  
*/
static cc_uint8_t aes_GFmul(cc_uint8_t a, cc_uint8_t b)
{
	cc_uint8_t result = 0;
	cc_uint32_t sum;

	if (a && b)
	{
		sum = AES_MUL_LOG[a] + AES_MUL_LOG[b];
		if (sum > 255)
		{
			sum = sum - 255;
		}
		result = AES_MUL_EXP[sum];
	}

	return result;
} 

static void aes_mixcolumns(cc_uint8_t* state)
{
	cc_uint8_t t[16];
	cc_uint8_t col;
	memcpy(t, state, 16); 

	for (col = 0; col < 4; col++)
	{
		state[col * 4 + 0] = aes_GFmul(0x02, t[col * 4 + 0]) ^ aes_GFmul(0x03, t[col * 4 + 1]) ^ t[col * 4 + 2] ^ t[col * 4 + 3];
		state[col * 4 + 1] = t[col * 4 + 0] ^ aes_GFmul(0x02, t[col * 4 + 1]) ^ aes_GFmul(0x03, t[col * 4 + 2]) ^ t[col * 4 + 3];
		state[col * 4 + 2] = t[col * 4 + 0] ^ t[col * 4 + 1] ^ aes_GFmul(0x02, t[col * 4 + 2]) ^ aes_GFmul(0x03, t[col * 4 + 3]);
		state[col * 4 + 3] = aes_GFmul(0x03, t[col * 4 + 0]) ^ t[col * 4 + 1] ^ t[col * 4 + 2] ^ aes_GFmul(0x02, t[col * 4 + 3]);		
	}
}

static void aes_invmixcolumns(cc_uint8_t* state)
{
	cc_uint8_t t[16];
	cc_uint8_t col;

	memcpy(t, state, 16);

	for (col = 0; col < 4; col++)
	{
		state[col * 4 + 0] = aes_GFmul(0x0E, t[col * 4 + 0]) ^ aes_GFmul(0x0B, t[col * 4 + 1]) ^ aes_GFmul(0x0D, t[col * 4 + 2]) ^ aes_GFmul(0x09, t[col * 4 + 3]);
		state[col * 4 + 1] = aes_GFmul(0x09, t[col * 4 + 0]) ^ aes_GFmul(0x0E, t[col * 4 + 1]) ^ aes_GFmul(0x0B, t[col * 4 + 2]) ^ aes_GFmul(0x0D, t[col * 4 + 3]);
		state[col * 4 + 2] = aes_GFmul(0x0D, t[col * 4 + 0]) ^ aes_GFmul(0x09, t[col * 4 + 1]) ^ aes_GFmul(0x0E, t[col * 4 + 2]) ^ aes_GFmul(0x0B, t[col * 4 + 3]);
		state[col * 4 + 3] = aes_GFmul(0x0B, t[col * 4 + 0]) ^ aes_GFmul(0x0D, t[col * 4 + 1]) ^ aes_GFmul(0x09, t[col * 4 + 2]) ^ aes_GFmul(0x0E, t[col * 4 + 3]);	
	}	
}


static void aes_subbyte(cc_uint8_t* state)
{
	cc_uint8_t i;
	for (i = 0; i < 16; i++)
	{
		state[i] = AES_SubByte[state[i]];
	}
}

static void aes_invsubbyte(cc_uint8_t* state)
{
	cc_uint8_t i;
	for (i = 0; i < 16; i++)
	{
		state[i] = AES_InvSubByte[state[i]];
	}
}

static void aes_encryption(AES* self, cc_uint8_t maxround, const cc_uint8_t* inblock, cc_uint8_t* outblock)
{
	cc_uint8_t round = 0;
	cc_uint8_t state[16];

	memcpy(state, inblock, 16);

    /* round 0 */
	aes_addroundkey(self, 0, state);

	for(round = 1; round < maxround; round++)
	{
		aes_subbyte(state);
		
		aes_shiftrows(state);

		aes_mixcolumns(state);

		aes_addroundkey(self, round, state);
	}

	/* last round */
	aes_subbyte(state);

	aes_shiftrows(state);

	aes_addroundkey(self, maxround, state);

	memcpy(outblock, state, 16);
}

static void aes_decryption(AES* self, cc_uint8_t maxround, const cc_uint8_t* inblock, cc_uint8_t* outblock)
{
	cc_uint8_t round = 0;
	cc_uint8_t state[16];

	memcpy(state, inblock, 16);

	aes_addroundkey(self, maxround, state);

	for (round = maxround-1; round > 0; round--)
	{
		aes_invshiftrows(state);

		aes_invsubbyte(state);

		aes_addroundkey(self, round, state);

		aes_invmixcolumns(state);
	} 

	aes_invshiftrows(state);

	aes_invsubbyte(state);

	aes_addroundkey(self, 0, state);

	memcpy(outblock, state, 16);
}

/*

For AES128 , inblock and outblock is 128bit

*/
static int aes_processblock(void* _self, const cc_uint8_t* inblock, cc_uint8_t *outblock)
{
	AES* self = _self;
	enum blockcipher_dir_e dir;
	cc_uint8_t maxround = 0;

	dir = ((BLOCKCIPHER*)self)->dir;
	if (AES_TYPE_128 == self->type)
	{
		maxround = AES128_ROUND_NR - 1;
	}
	else if(AES_TYPE_192 == self->type)
	{
		maxround = AES192_ROUND_NR - 1;
	}
	else
	{
		maxround = AES256_ROUND_NR - 1;
	}

	if (BLOCKCIPHER_DIR_ENC == dir)
	{
		aes_encryption(self, maxround, inblock, outblock);
	}
	else
	{
		aes_decryption(self, maxround, inblock, outblock);
	}

	return 0;
}

static BLOCKCIPHERvtbl const aes_vtbl = {
	&aes_setkey,
	&aes_processblock,
};

static const OBJECT _Aes = {
    sizeof(AES),
    &aes_vtbl,
    aes_ctor, 
    aes_dtor,	
};

const void* Aes = &_Aes;
