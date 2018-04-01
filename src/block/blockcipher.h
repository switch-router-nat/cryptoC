/*
 * File       : descipher.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-08-15     QshLyc       first version
 */

#ifndef _BLOCKCIPHER_H_
#define _BLOCKCIPHER_H_

extern const void* BlockCipher;

#define BLOCKCIPHER_BLOCKSIZE_DEFAULT   8

enum blockcipher_dir_e{
	BLOCKCIPHER_DIR_ENC = 0,
	BLOCKCIPHER_DIR_DEC,
};

struct blockcipher_mode_operations{
	int (*enc)(void *_self, const uint8_t* plaintext, uint32_t plainlen, uint8_t* ciphertext, uint32_t* cipherlen);
	int (*dec)(void *_self, const uint8_t* ciphertext, uint32_t cipherlen, uint8_t* plaintext, uint32_t* plainlen);
};

struct blockcipher_pad_operations{
	int (*pad)(void *_self, const uint8_t* plaintext, uint32_t plainlen, uint32_t* nr_unpadblock, uint8_t* lastblock);
	int (*unpad)(void *_self, const uint8_t* plaintext, uint32_t plainlen, uint32_t* nr_unpadblock, uint8_t* nr_unpadbyte);
};

typedef struct{
    const void* object;
    uint8_t   blocksize;
    enum blockcipher_dir_e  dir;
    enum blockcipher_mode_e mode;
    struct blockcipher_mode_operations* mode_ops;
	enum blockcipher_pad_e pad;
	struct blockcipher_pad_operations* pad_ops; 
	uint8_t* iv;
	void* data;
}BLOCKCIPHER;

typedef struct {
	int (*SetKey)(void* _self, const uint8_t* userkey);
	int (*ProcessBlock)(void *_self, const uint8_t* inBlock, uint8_t *outBlock);
}BLOCKCIPHERvtbl;

#endif 