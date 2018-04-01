/*
 * File       : des.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-08-15     QshLyc       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../cryptoc.h"
#include "../base/object.h"
#include "blockcipher.h"
#include "des.h"
#include "desconst.h"


static void* rawdes_ctor(void *_self, va_list *app)
{
	return _self;
}

static void* rawdes_dtor(void* _self)
{
	return _self;
}

static void rawdes_initial_permutation(uint32_t* text)
{
	uint32_t left;
	uint32_t right;
	uint32_t work;

	left  = text[1];
	right = text[0]; 

	work  = ((left >> 4) ^ right) & 0x0f0f0f0f;
	right ^= work;
	left  ^= (work << 4);

	work  = ((left >> 16) ^ right) & 0x0000ffff;
	right ^= work;
	left  ^= (work << 16);

	work  = ((right >> 2) ^ left) & 0x33333333;
	left  ^= work;
	right ^= (work << 2);

	work  = ((right >> 8) ^ left) & 0x00ff00ff;
	left  ^= work;
	right ^= (work << 8);

	work  = ((left >> 1) ^ right) & 0x55555555;
	right ^= work;
	left ^= (work << 1);

	text[1] = left;
	text[0] = right;
}

static void rawdes_final_permutation(uint32_t* text)
{
	uint32_t left;
	uint32_t right;
	uint32_t work;

	left  = text[1];
	right = text[0]; 

	work  = ((right >> 1) ^ left) & 0x55555555;
	left  ^= work;
	right ^= (work << 1);

	work  = ((left >> 8) ^ right) & 0x00ff00ff;
	right ^= work;
	left ^= (work << 8);

	work  = ((left >> 2) ^ right) & 0x33333333;
	right  ^= work;
	left ^= (work << 2);

	work  = ((right >> 16) ^ left) & 0x0000ffff;
	left ^= work;
	right  ^= (work << 16);

	work  = ((right >> 4) ^ left) & 0x0f0f0f0f;
	left ^= work;
	right  ^= (work << 4);

	work  = ((left >> 1) ^ right) & 0x55555555;
	right ^= work;
	left  ^= (work << 1);

	work  = ((right >> 1) ^ left) & 0x55555555;
	left ^= work;
	right  ^= (work << 1);

	text[1] = left;
	text[0] = right;
}

static void rawdes_docryption(void* _self, enum blockcipher_dir_e dir, uint32_t *text)
{	
	int round = 0;
	int round_start = 0;
	int round_count = 0; 
	uint8_t temp[8];
	uint32_t l,_l,r,_r;
	RAW_DES* self = (RAW_DES*)_self;
	uint8_t *kptr = self->roundkey;

	l = text[1];
	r = text[0];
	
	if (BLOCKCIPHER_DIR_ENC == dir)
	{
		round_start = 0;
	}
	else
	{
		round_start = 15;
	}

	for (round = round_start; round_count < 16 ;round_count++)
	{
		_r = r;
		_l = l;

		uint32_t r_ex[2] = {0, 0};
 
		r_ex[0] = ((r & 0x0000000F) << 1)  | ((r & 0x80000000) >> 31) | ((r & 0x00000010) << 1) |
		          ((r & 0x000000F0) << 5)  | ((r & 0x00000008) << 5)  | ((r & 0x00000100) << 5) |
		          ((r & 0x00000F00) << 9)  | ((r & 0x00000080) << 9)  | ((r & 0x00001000) << 9) |
		          ((r & 0x0000F000) << 13) | ((r & 0x00000800) << 13) | ((r & 0x00010000) << 13);

		r_ex[1] = ((r & 0x000F0000) >> 15) | ((r & 0x00008000) >> 15) | ((r & 0x00100000) >> 15) |
		          ((r & 0x00F00000) >> 11) | ((r & 0x00080000) >> 11) | ((r & 0x01000000) >> 11) |
		          ((r & 0x0F000000) >>  7) | ((r & 0x00800000) >>  7) | ((r & 0x10000000) >>  7) |
		          ((r & 0xF0000000) >>  3) | ((r & 0x08000000) >>  3) | ((r & 0x00000001) << 29);

		temp[0] = kptr[round*8 + 0] ^ (r_ex[0] & 0x0000003F);
		temp[1] = kptr[round*8 + 1] ^ ((r_ex[0] & 0x00003F00) >> 8);
		temp[2] = kptr[round*8 + 2] ^ ((r_ex[0] & 0x003F0000) >> 16);
		temp[3] = kptr[round*8 + 3] ^ ((r_ex[0] & 0x3F000000) >> 24);
		temp[4] = kptr[round*8 + 4] ^ (r_ex[1] & 0x0000003F);
		temp[5] = kptr[round*8 + 5] ^ ((r_ex[1] & 0x00003F00) >> 8);
		temp[6] = kptr[round*8 + 6] ^ ((r_ex[1] & 0x003F0000) >> 16);
		temp[7] = kptr[round*8 + 7] ^ ((r_ex[1] & 0x3F000000) >> 24);


		temp[7] = (((temp[7]&0x20)>>4) | ((temp[7]&0x01)))*16 + ((temp[7]&0x1E)>>1);
		temp[6] = (((temp[6]&0x20)>>4) | ((temp[6]&0x01)))*16 + ((temp[6]&0x1E)>>1);
		temp[5] = (((temp[5]&0x20)>>4) | ((temp[5]&0x01)))*16 + ((temp[5]&0x1E)>>1);
		temp[4] = (((temp[4]&0x20)>>4) | ((temp[4]&0x01)))*16 + ((temp[4]&0x1E)>>1);
		temp[3] = (((temp[3]&0x20)>>4) | ((temp[3]&0x01)))*16 + ((temp[3]&0x1E)>>1);
		temp[2] = (((temp[2]&0x20)>>4) | ((temp[2]&0x01)))*16 + ((temp[2]&0x1E)>>1);
		temp[1] = (((temp[1]&0x20)>>4) | ((temp[1]&0x01)))*16 + ((temp[1]&0x1E)>>1);
		temp[0] = (((temp[0]&0x20)>>4) | ((temp[0]&0x01)))*16 + ((temp[0]&0x1E)>>1);

    	r = _l ^  (DES_Spbox[0][temp[7]] | 
     		       DES_Spbox[1][temp[6]] |
     		       DES_Spbox[2][temp[5]] | 
    		       DES_Spbox[3][temp[4]] |
    		       DES_Spbox[4][temp[3]] | 
    		       DES_Spbox[5][temp[2]] |
    		       DES_Spbox[6][temp[1]] | 
    		       DES_Spbox[7][temp[0]] );
    	
    	l = _r;

    	/* printf("left%d: %x  right%d %x\n", round ,l, round, r); */

		if (BLOCKCIPHER_DIR_ENC == dir)
		{
			round++;
		}
		else
		{
			round--;
		}
	}

	text[1] = r;
	text[0] = l;
}

static int rawdes_calc_roundkey(RAW_DES* self, uint32_t left, uint32_t right, uint8_t round)
{
	uint32_t l = 0;
	uint32_t r = 0;
	int idx;

	/* shift left example
    /*  MSB     right(28bit valid)     LSB    MSB     left(28bit valid)       LSB
	     00001234XXXXXXXXXXXXXXXXXXXXABCD     0000ABABXXXXXXXXXXXXXXXXXXXXCDCD 
	=>  cyclic left shit  (2) bit
         000034XXXXXXXXXXXXXXXXXXXXABCD12     0000ABXXXXXXXXXXXXXXXXXXXXCDCDAB
	*/
	left = ((left << DES_KeyLeftShift[round]) | (left >> (28 - DES_KeyLeftShift[round]))) & 0x0FFFFFFF;
	right = ((right << DES_KeyLeftShift[round]) | (right >> (28 - DES_KeyLeftShift[round]))) & 0x0FFFFFFF;
	
	/* Compression box */    
	for (idx = 0; idx < 48; idx++)
	{
		uint32_t *src;
		uint32_t *dest;
		uint8_t srcbit;
		uint8_t destbit;

		srcbit = DES_KeyCompression[idx] - 1; 
		if (idx < 24)
		{
			dest = &l;
			destbit = idx;
		}
		else
		{
			dest = &r;
			destbit = idx - 24;
		}

		if (srcbit < 28)
		{
			src = &left;
		}
		else
		{
			src = &right;
			srcbit -= 28;
		}

		*dest |= ((*src & (0x08000000 >> srcbit)) ? (0x00800000 >> destbit) : 0); 
	}   

	self->roundkey[round * 8 + 7] = (uint8_t)((l & 0x00FC0000) >> 18);
	self->roundkey[round * 8 + 6] = (uint8_t)((l & 0x0003F000) >> 12);
	self->roundkey[round * 8 + 5] = (uint8_t)((l & 0x00000FC0) >>  6);
	self->roundkey[round * 8 + 4] = (uint8_t)((l & 0x0000003F));

	self->roundkey[round * 8 + 3] = (uint8_t)((r & 0x00FC0000) >> 18);
	self->roundkey[round * 8 + 2] = (uint8_t)((r & 0x0003F000) >> 12);
	self->roundkey[round * 8 + 1] = (uint8_t)((r & 0x00000FC0) >>  6);
	self->roundkey[round * 8 + 0] = (uint8_t)((r & 0x0000003F));

}	


static int rawdes_setkey(RAW_DES* self, const char* userkey)
{
	uint32_t left  = 0;    
	uint32_t right = 0;
	uint8_t bitshift  = 0;
	uint8_t byteshift = 0;
	uint8_t bytepos   = 0;
	uint8_t round = 0;
	int idx = 0;

	if (strlen(userkey) < DES_KEYLENGTH_BYTE)
	{
		userkey = "defaultkey";
	}

	for (idx = 0; idx < DES_KEYLENGTH_BYTE; idx++)
	{
		self->key[idx] = userkey[DES_KEYLENGTH_BYTE - 1 - idx];
	}	

	/* Partity drop */
	for (idx = 0; idx < 56; idx++)
	{
		byteshift = (DES_ParityDrop[idx] - 1) / 8;
		bytepos   = (DES_ParityDrop[idx] - 1) % 8;
	 	
	 	if (idx < 28)
	 	{
	 		left |=  (self->key[7 - byteshift] & (0x80 >> bytepos)) ? (0x08000000 >> idx) : 0; 
	 	}
	 	else
	 	{
	 		right |= (self->key[7- byteshift] & (0x80 >> bytepos)) ? (0x08000000 >> (idx - 28)) : 0; 
	 	}
	}

	for (round = 0;round < 16; round++)
	{
		rawdes_calc_roundkey(self, left, right, round);
	}

	return 0;
}


/* inBlock = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}*/
/* text[1] = 0x31323334  */
/* text[0] = 0x35363738  */
static void rawdes_getblock(uint32_t *text, const uint8_t* inblock)
{
	text[1] = (inblock[0] << 24) | (inblock[1] << 16) | (inblock[2] << 8) | (inblock[3]);   
	text[0] = (inblock[4] << 24) | (inblock[5] << 16) | (inblock[6] << 8) | (inblock[7]);   
}

static void rawdes_putblock(uint32_t *text, uint8_t* outblock)
{
	outblock[0] = (text[1] & 0xFF000000) >> 24;
	outblock[1] = (text[1] & 0x00FF0000) >> 16;
	outblock[2] = (text[1] & 0x0000FF00) >> 8;
	outblock[3] = text[1] & 0x000000FF;

	outblock[4] = (text[0] & 0xFF000000) >> 24;
	outblock[5] = (text[0] & 0x00FF0000) >> 16;
	outblock[6] = (text[0] & 0x0000FF00) >> 8;
	outblock[7] = text[0] & 0x000000FF;

	return;
}

static const OBJECT _RawDes = {
    sizeof(RAW_DES),
    NULL,
    rawdes_ctor, 
    rawdes_dtor,	
};

const void* RawDes = &_RawDes;

static void* des_ctor(void *_self, va_list *app)
{
	void *m_des;

    DES *self = ((const OBJECT*)BlockCipher)->ctor(_self, app);

	m_des = new(RawDes);
	self->m_des = (RAW_DES*)m_des;
	self->super.blocksize = DES_BLOCKSIZE;

	return self;
}

static void* des_dtor(void* _self)
{
	DES* self = _self;
	
	delete(self->m_des);

	((const OBJECT*)BlockCipher)->dtor(self);
	
	return self;
}


static int des_setkey(void* _self, const uint8_t* userkey)
{
	DES* self = (DES*)_self;

	rawdes_setkey(self->m_des, userkey);

	return 0;
}

/* inblock  8 byte */
/* outblock 8 byte */
static int des_processblock(void* _self, const uint8_t* inblock, uint8_t *outblock)
{
	DES* self = (DES*)_self;

	enum blockcipher_dir_e dir;
	uint32_t text[2];

	dir = ((BLOCKCIPHER*)self)->dir;

	rawdes_getblock(text, inblock);

	rawdes_initial_permutation(text);

	rawdes_docryption(self->m_des, dir, text);

	rawdes_final_permutation(text);

	rawdes_putblock(text, outblock);

	return 0;
}

static BLOCKCIPHERvtbl const des_vtbl = {
	&des_setkey,
	&des_processblock,
};

static const OBJECT _Des = {
    sizeof(DES),
    &des_vtbl,
    des_ctor, 
    des_dtor,	
};

const void* Des = &_Des;



/*************************************************************************/
static void* des_3des_ctor(void *_self, va_list *app)
{
	void *m_des1;
	void *m_des2;
	void *m_des3;
	
    DES_3DES *self = ((const OBJECT*)BlockCipher)->ctor(_self, app);

	m_des1 = new(RawDes);
	m_des2 = new(RawDes);
	m_des3 = new(RawDes);

	self->m_des1 = (RAW_DES*)m_des1;
	self->m_des2 = (RAW_DES*)m_des2;
	self->m_des3 = (RAW_DES*)m_des3;

	self->super.blocksize = DES_BLOCKSIZE;

	return self;
}

static void* des_3des_dtor(void* _self)
{
	DES_3DES* self = (DES_3DES*)_self;
	
	delete(self->m_des1);
	delete(self->m_des2);
	delete(self->m_des3);

	((const OBJECT*)BlockCipher)->dtor(self);
	
	return self;
}

static int des_3des_setkey(void* _self, const uint8_t* userkey)
{
	DES_3DES* self = (DES_3DES*)_self;

	rawdes_setkey(self->m_des1, userkey);
	rawdes_setkey(self->m_des2, userkey);
	rawdes_setkey(self->m_des3, userkey);

	return 0;
}

static int des_3des_processblock(void* _self, const uint8_t* inblock, uint8_t *outblock)
{
	enum blockcipher_dir_e dir;
	uint32_t text[2];
	DES_3DES* self = (DES_3DES*)_self;

	dir = ((BLOCKCIPHER*)self)->dir;

	rawdes_getblock(text, inblock);

	rawdes_initial_permutation(text);

	if (BLOCKCIPHER_DIR_ENC == dir)
	{
		rawdes_docryption(self->m_des1, BLOCKCIPHER_DIR_ENC, text);
		rawdes_docryption(self->m_des2, BLOCKCIPHER_DIR_DEC, text);
		rawdes_docryption(self->m_des3, BLOCKCIPHER_DIR_ENC, text);
	}
	else
	{
		rawdes_docryption(self->m_des1, BLOCKCIPHER_DIR_DEC, text);
		rawdes_docryption(self->m_des2, BLOCKCIPHER_DIR_ENC, text);
		rawdes_docryption(self->m_des3, BLOCKCIPHER_DIR_DEC, text);
	}

	rawdes_final_permutation(text);

	rawdes_putblock(text, outblock);

	return 0;
}

static BLOCKCIPHERvtbl const des_3des_vtbl = {
	&des_3des_setkey,
	&des_3des_processblock,
};


static const OBJECT _Des_3Des = {
    sizeof(DES_3DES),
    &des_3des_vtbl,
    des_3des_ctor, 
    des_3des_dtor,	
};

const void* Des_3Des = &_Des_3Des;
