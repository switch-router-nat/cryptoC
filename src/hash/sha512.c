/*
 * File       : sha512.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-06     QshLyc       first version
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
#include "sha512.h"

#define SHA512_CHUNKSIZE       1024 
#define SHA512_CHUNKSIZE_BYTE   128 
#define SHA512_LENGTHSIZE_BYTE   16   



/*
	@state: 5 * 32bit
	@pdata: 64 bytes
*/
static void sha512_transform(uint32_t *state, const uint8_t *pdata)
{


}

/*
    @data: the data to be calulate
    @size: the size(bit) of @data 
    @digest: result
*/
static void sha512_calculatedigest(void* _self, const uint8_t *data, uint64_t size[], uint8_t *digest)
{

/*
    state[0][0] = 0x6a09e667;
    state[0][1] = 0xf3bcc908;
    state[1][0] = 0xbb67ae85;
    state[1][1] = 0x84caa73b;

    state[2][0] = 0x3c6ef372;
    state[2][1] = 0xfe94f82b;
    state[3][0] = 0xa54ff53a;
    state[3][1] = 0x5f1d36f1;

    state[4][0] = 0x510e527f;
    state[4][1] = 0xade682d1;
    state[5][0] = 0x9b05688c;
    state[5][1] = 0x2b3e6c1f;

    state[6][0] = 0x1f83d9ab;
    state[6][1] = 0xfb41bd6b;
    state[7][0] = 0x5be0cd19;
    state[7][1] = 0x137e2179;

    size_h = size[0];
    size_l = size[1];
*/
	return;
} 

static SHAvtbl const vtbl = {
	&sha512_calculatedigest,
};

static void* sha512_ctor(void *_self, va_list *app)
{
	SHA512 *self = _self;
	
	((const OBJECT*)Sha)->ctor(_self, app);

	return _self;
}

static void* sha512_dtor(void* _self)
{
	SHA512* self = _self;
	
	((const OBJECT*)Sha)->dtor(self);

	return _self;
}

static const OBJECT _Sha512 = {
    sizeof(SHA512),
    &vtbl,
    sha512_ctor, 
    sha512_dtor,	
};

const void* Sha512 = &_Sha512;