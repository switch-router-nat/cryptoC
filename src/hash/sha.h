/*
 * File       : sha.h *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-05     QshLyc       first version
 */
#ifndef _SHA_H_
#define _SHA_H_

extern const void* Sha;

typedef struct {
	void (*CalculateDigest)(void* _self, const cc_uint8_t *data, cc_uint32_t size[], cc_uint8_t *digest);
}SHAvtbl;

typedef struct{
    const void* object;
}SHA;


void SHA_CalculateDigest(void* _self, const cc_uint8_t *data, cc_uint32_t size[], cc_uint8_t *digest);

#endif