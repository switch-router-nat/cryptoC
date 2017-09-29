/*
 * File       : aes.h *
 * Change Logs:
 * Date           Author       Notes
 * 2017-09-25     QshLyc       first version
 */
#ifndef _AES_H_
#define _AES_H_


enum aes_type_e{
	AES_TYPE_128 = 0,
	AES_TYPE_192,
	AES_TYPE_256
};

#define AES128_KEYLEN      16
#define AES192_KEYLEN      24
#define AES256_KEYLEN      32

#define AES_BLOCKSIZE   16

#define AES128_ROUND_NR    11
#define AES192_ROUND_NR    13
#define AES256_ROUND_NR    15

/*
typedef struct{

}
*/

extern const void* Aes;

typedef struct{
	BLOCKCIPHER super;
	enum aes_type_e type;
	cc_uint8_t  key[AES256_KEYLEN];              /* User Key */
	cc_uint32_t roundkey[AES256_ROUND_NR * 4];   /* Round Key*/
}AES;


#endif