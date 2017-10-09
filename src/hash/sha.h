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
	void (*CalculateDigest)(void* _self, const uint8_t *data, uint64_t size, uint8_t *digest);
}SHAvtbl;

typedef struct{
    const void* object;
}SHA;


void SHA_CalculateDigest(void* _self, const uint8_t *data, uint64_t size, uint8_t *digest);

#endif