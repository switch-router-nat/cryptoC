/*
 * File       : des.h *
 * Change Logs:
 * Date           Author       Notes
 * 2017-08-15     QshLyc       first version
 */
#ifndef _DES_H_
#define _DES_H_


#define DES_KEYLENGTH_BYTE  8
#define DES_BLOCKSIZE       8   

extern const void* Des;
extern const void* Des_3Des;

typedef struct{
	const void* object;
	cc_uint8_t key[DES_KEYLENGTH_BYTE];    /* User Key */
	cc_uint8_t roundkey[16 * 8];           /* Round Key*/
}RAW_DES;


typedef struct{
	BLOCKCIPHER super;
	RAW_DES *m_des;
}DES;

typedef struct{
	BLOCKCIPHER super;
	RAW_DES *m_des1;
	RAW_DES *m_des2;
	RAW_DES *m_des3;
}DES_3DES;


#endif