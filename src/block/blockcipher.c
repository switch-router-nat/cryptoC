/*
 * File       : blockcipher.c
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


/* 
    virtual function  implement by BLOCKCIPHER
*/
static int blockcipher_setkey(void* _self, const uint8_t* userkey)
{
	return 0;
}

static int blockcipher_processblock(void *_self, const uint8_t* inBlock, uint8_t *outBlock)
{
	return 0;
}

/* Virtual Table of BLOCKCIPHER */
static BLOCKCIPHERvtbl const vtbl = {
	&blockcipher_setkey,
	&blockcipher_processblock,
};

/* 
      pad mode  
*/
static int blockcipher_pad_zero
(
	void *_self, 
	const uint8_t* plaintext, 
	uint32_t plainlen, 
	uint32_t* nr_unpadblock, 
	uint8_t* lastblock
)
{
	BLOCKCIPHER* self  = _self;
	uint8_t  blocksize = self->blocksize;
	uint32_t nr_block  = 0;
	uint32_t unpadbyte = 0;

	memset(lastblock, 0, blocksize);

	nr_block = (plainlen + blocksize -1) / blocksize;

	*nr_unpadblock = nr_block - 1;

	unpadbyte = plainlen - (nr_block - 1) * blocksize;

	memcpy(lastblock, plaintext + (nr_block - 1) * blocksize, unpadbyte);

	return 0;
}


static int blockcipher_unpad_zero
(
	void *_self, 
	const uint8_t* plaintext, 
	uint32_t plainlen, 
	uint32_t* nr_unpadblock, 
	uint8_t* nr_unpadbyte
)
{
	BLOCKCIPHER* self  = _self;
	uint8_t  blocksize = self->blocksize;
	uint32_t nr_block  = 0;

	nr_block = plainlen / blocksize;

	*nr_unpadblock = nr_block - 1;

	*nr_unpadbyte  = blocksize;

	return 0;
}

static int blockcipher_pad_pkcs7
(
	void *_self, 
	const uint8_t* plaintext, 
	uint32_t plainlen,
	uint32_t* nr_unpadblock, 
	uint8_t*  lastblock
)
{
	BLOCKCIPHER* self  = _self;
	uint8_t  blocksize = self->blocksize;
	uint32_t nr_block  = 0;
	uint8_t  nr_unpadbyte = 0;
	uint8_t  padcontent;

	memset(lastblock, 0, blocksize);

	nr_block = (plainlen + blocksize -1) / blocksize;

	nr_unpadbyte = plainlen - (nr_block - 1) * blocksize;
	if (nr_unpadbyte == blocksize)
	{
		nr_block++;
		nr_unpadbyte = 0;
	}

	*nr_unpadblock = nr_block - 1;

	memcpy(lastblock, plaintext + (nr_block - 1) * blocksize, nr_unpadbyte);

	padcontent = blocksize - nr_unpadbyte;

	memset(lastblock + nr_unpadbyte, blocksize - nr_unpadbyte, padcontent);

	return 0;
}

static int blockcipher_unpad_pkcs7
(
	void *_self, 
	const uint8_t* plaintext, 
	uint32_t plainlen, 
	uint32_t* nr_unpadblock, 
	uint8_t* nr_unpadbyte
)
{
	BLOCKCIPHER* self  = _self;
	uint8_t  blocksize  = self->blocksize;
	uint8_t  padcontent = 0;
	uint32_t nr_block   = 0;

	nr_block = plainlen / blocksize;

	padcontent = plaintext[plainlen - 1];	

	*nr_unpadblock = nr_block - 1;

	*nr_unpadbyte  = blocksize - padcontent;

	return 0;
}

static struct blockcipher_pad_operations blockcipher_pad_zero_ops = 
{
	.pad   = &blockcipher_pad_zero,
	.unpad = &blockcipher_unpad_zero,
};

static struct blockcipher_pad_operations blockcipher_pad_pkcs7_ops = 
{
	.pad   = &blockcipher_pad_pkcs7,
	.unpad = &blockcipher_unpad_pkcs7,
};

static struct blockcipher_pad_operations* blockcipher_pad_operations_table[] = 
{
	[BLOCKCIPHER_PAD_ZERO]  = &blockcipher_pad_zero_ops,
	[BLOCKCIPHER_PAD_PKCS7] = &blockcipher_pad_pkcs7_ops,
};


/*
	blockcipher mode
*/

static int blockcipher_xor(uint8_t* dest, uint8_t* xor, const uint8_t* src, uint8_t size)
{
	uint8_t i;

	if (NULL == xor)
	{
		memcpy(dest, src, size);
		return 0;
	}
	else
	{
		for (i = 0; i < size; i++)
		{
			dest[i] = xor[i] ^ src[i];
		}
	}

	return 0;
}

static int blockcipher_proc_block(void* _self, const uint8_t* inblock, uint8_t* outblock)
{
	BLOCKCIPHER* self = _self;
	(((BLOCKCIPHERvtbl*)(((OBJECT*)(self->object))->vptr))->ProcessBlock)((void*)self, inblock, outblock);

	return 0;
}

static int blockcipher_enc_ECB(void *_self, const uint8_t* plaintext, uint32_t plainlen, uint8_t* ciphertext, uint32_t* cipherlen)
{
	BLOCKCIPHER* self = _self;
	uint8_t  blocksize = self->blocksize;
	uint32_t unpad_nr  = 0;
	uint8_t* block_last;	
	uint8_t  i;

 	block_last = (uint8_t*)malloc(blocksize);

 	memset(block_last, 0, blocksize);
	
	self->pad_ops->pad(_self, plaintext, plainlen, &unpad_nr, block_last);
	for (i = 0; i < unpad_nr; i++)
	{	
		blockcipher_proc_block(self, plaintext + blocksize * i, ciphertext + blocksize * i);
	}

	blockcipher_proc_block(self, block_last, ciphertext + blocksize * i);
	
	*cipherlen = (unpad_nr + 1) * blocksize;

	free(block_last);

	return 0;
}

static int blockcipher_dec_ECB(void *_self, const uint8_t* ciphertext, uint32_t cipherlen, uint8_t* plaintext, uint32_t* plainlen)
{
	BLOCKCIPHER* self = _self;
	uint8_t  blocksize = self->blocksize;
	uint32_t nr_block  = cipherlen / blocksize;
	uint32_t nr_unpadblock;
	uint8_t  nr_unpadbyte;
	uint8_t  i;

	for (i = 0; i < nr_block; i++)
	{	
		blockcipher_proc_block(self, ciphertext + blocksize * i, plaintext + blocksize * i);
	}

	self->pad_ops->unpad(_self, plaintext, cipherlen, &nr_unpadblock, &nr_unpadbyte);

	*plainlen = nr_unpadblock * blocksize + nr_unpadbyte;		

	return 0;
}

static int blockcipher_enc_CBC(void *_self, const uint8_t* plaintext, uint32_t plainlen, uint8_t* ciphertext, uint32_t* cipherlen)
{
	BLOCKCIPHER* self = _self;
	uint8_t  blocksize = self->blocksize;
	uint32_t unpad_nr  = 0;
	uint8_t* block_in;
	uint8_t* block_out;
	uint8_t* block_last;
	
	uint8_t  i;

	block_in  = (uint8_t*)malloc(blocksize);
 	block_out = (uint8_t*)malloc(blocksize);
 	block_last = (uint8_t*)malloc(blocksize);

 	memset(block_in, 0, blocksize);
 	memset(block_out, 0, blocksize);
 	memset(block_last, 0, blocksize);

 	if (self->iv)
 	{
 		memcpy(block_out, self->iv, blocksize);
 	}

	self->pad_ops->pad(_self, plaintext, plainlen, &unpad_nr, block_last);
	for (i = 0; i < unpad_nr; i++)
	{	
		blockcipher_xor(block_in, block_out, plaintext + blocksize * i, blocksize);

		blockcipher_proc_block(self, block_in, block_out);

		blockcipher_xor(ciphertext + blocksize * i, NULL, block_out, blocksize);
	}

	blockcipher_xor(block_in, block_out, block_last, blocksize);

	blockcipher_proc_block(self, block_in, block_out);

	blockcipher_xor(ciphertext + blocksize * i, NULL, block_out, blocksize);
	
	*cipherlen = (unpad_nr + 1) * blocksize;

	free(block_in);
	free(block_last);
	free(block_out);

	return 0;
}

static int blockcipher_dec_CBC(void *_self, const uint8_t* ciphertext, uint32_t cipherlen, uint8_t* plaintext, uint32_t* plainlen)
{
	BLOCKCIPHER* self = _self;
	uint8_t  blocksize = self->blocksize;
	uint32_t nr_block  = cipherlen / blocksize;
	uint32_t nr_unpadblock;
	uint8_t  nr_unpadbyte;
	uint8_t* block_in;
	uint8_t* block_out;
	uint8_t* block_xor;
	uint8_t  i;

	block_in  = (uint8_t*)malloc(blocksize);
 	block_out = (uint8_t*)malloc(blocksize);
 	block_xor = (uint8_t*)malloc(blocksize);

 	memset(block_in, 0, blocksize);
 	memset(block_out, 0, blocksize);
 	memset(block_xor, 0, blocksize);

 	if (self->iv)
 	{
 		memcpy(block_xor, self->iv, blocksize);
 	}

	for (i = 0; i < nr_block; i++)
	{
		/*  inbuf = D(cipher) */	
		blockcipher_proc_block(self, ciphertext + blocksize * i, block_out);

		blockcipher_xor(plaintext + blocksize * i, block_xor, block_out, blocksize);

		memcpy(block_xor, ciphertext + blocksize * i, blocksize);
	}

	self->pad_ops->unpad(_self, plaintext, cipherlen, &nr_unpadblock, &nr_unpadbyte);

	*plainlen = nr_unpadblock * blocksize + nr_unpadbyte;		
	
	free(block_in);
	free(block_out);
	free(block_xor);

	return 0;
}


static struct blockcipher_mode_operations blockcipher_mode_ECB_ops = 
{
	.enc = &blockcipher_enc_ECB,
	.dec = &blockcipher_dec_ECB,
};

static struct blockcipher_mode_operations blockcipher_mode_CBC_ops = 
{
	.enc = &blockcipher_enc_CBC, 
	.dec = &blockcipher_dec_CBC,
};

static struct blockcipher_mode_operations* blockcipher_mode_operations_table[] = 
{
	[BLOCKCIPHER_MODE_ECB] = &blockcipher_mode_ECB_ops,
	[BLOCKCIPHER_MODE_CBC] = &blockcipher_mode_CBC_ops,
};


static void* blockcipher_ctor(void *_self, va_list *app)
{
	BLOCKCIPHER *self = _self;
	
	/*  use ECB mode default  */
	self->mode     = BLOCKCIPHER_MODE_ECB;
	self->mode_ops = blockcipher_mode_operations_table[BLOCKCIPHER_MODE_ECB]; 

	/*  use zeropading default */
	self->pad       = BLOCKCIPHER_PAD_ZERO;
	self->pad_ops   = blockcipher_pad_operations_table[BLOCKCIPHER_PAD_ZERO];

	self->iv = NULL;

	return _self;
}


static void* blockcipher_dtor(void* _self)
{
	BLOCKCIPHER* self = _self;
	
	if (self->iv)
	{
		free(self->iv);
	}
	
	return _self;
}

static const OBJECT _BLockCipher = {
    sizeof(BLOCKCIPHER),
    &vtbl,
    blockcipher_ctor, 
    blockcipher_dtor,	
};

const void* BlockCipher = &_BLockCipher;


int BlockCipher_SetKey(void* _self, const char* userkey)
{
	BLOCKCIPHER* self = _self;
	return (((BLOCKCIPHERvtbl*)(((OBJECT*)(self->object))->vptr))->SetKey)((void*)self, userkey);
}

int BlockCipher_SetMode(void* _self, enum blockcipher_mode_e mode)
{
	BLOCKCIPHER* self = _self;
	self->mode     = mode;
	self->mode_ops = blockcipher_mode_operations_table[mode]; 
}

int BlockCipher_SetIV(void* _self, uint8_t* iv, uint8_t iv_len)
{
	BLOCKCIPHER* self = _self;

	if (0 == iv_len)
	{
		iv_len = self->blocksize;
	}

	uint8_t* mp = (uint8_t*)malloc(iv_len);

	memcpy(mp, iv, iv_len);

	self->iv = mp;
	
	return 0;
}

int BlockCipher_SetPad(void* _self, enum blockcipher_pad_e pad)
{
	BLOCKCIPHER* self = _self;
	self->pad         = pad;
	self->pad_ops     = blockcipher_pad_operations_table[pad];

	return 0;
}

int BlockCipher_Encryption
(
	void* _self, 
	const uint8_t* plaintext, 
	uint32_t plainlen, 
	uint8_t*  ciphertext,
	uint32_t* cipherlen
)
{
	BLOCKCIPHER* self = _self;	

	self->dir = BLOCKCIPHER_DIR_ENC;

	self->mode_ops->enc(self, plaintext, plainlen, ciphertext, cipherlen);

	return 0;

}

int BlockCipher_Decryption
(
	void* _self, 
	const uint8_t* ciphertext, 
	uint32_t cipherlen, 
	uint8_t* plaintext, 
	uint32_t* plainlen
)
{
	BLOCKCIPHER* self = _self;	

	self->dir = BLOCKCIPHER_DIR_DEC;

	self->mode_ops->dec(self, ciphertext, cipherlen, plaintext, plainlen);

	return 0;

}
