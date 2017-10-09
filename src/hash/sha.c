/*
 * File       : sha.c
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
#include <stdint.h>

#include "../base/object.h"
#include "sha.h"


static void sha_calculatedigest(void* _self, const uint8_t *data, uint64_t size, uint8_t *digest)
{
	return;
} 

/* Virtual Table of BLOCKCIPHER */
static SHAvtbl const vtbl = {
	&sha_calculatedigest,
};

static void* sha_ctor(void *_self, va_list *app)
{
	SHA *self = _self;
	
	return _self;
}

static void* sha_dtor(void* _self)
{
	SHA* self = _self;
	
	return _self;
}

static const OBJECT _Sha = {
    sizeof(SHA),
    &vtbl,
    sha_ctor, 
    sha_dtor,	
};

const void* Sha = &_Sha;


void SHA_CalculateDigest(void* _self, const uint8_t *data, uint64_t size, uint8_t *digest)
{
	SHA* self = _self;
	(((SHAvtbl*)(((OBJECT*)(self->object))->vptr))->CalculateDigest)((void*)self, data, size, digest);

	return;
}