/*
 * File       : ds.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-15     QshLyc       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../base/object.h"
#include "ds.h"

/* 
    virtual function implement by DS Base
*/
static int ds_keygenerate(void* _self)
{
	return 0;
}

static int ds_signature(void* _self, const uint8_t* text, uint32_t textlen, uint8_t* sig, uint32_t* siglen)
{
	return 0;
}

static int ds_verify(void *_self, const uint8_t* text, uint32_t textlen, uint8_t* sig, uint32_t siglen)
{
	return 0;
}

/* Virtual Table of DS Base */
static DSBASEvtbl const vtbl = {
	&ds_keygenerate,
	&ds_signature,
	&ds_verify,
};

static void* ds_ctor(void *_self, va_list *app)
{
	DSBASE *self = _self;
	
	self->state = DS_INIT;

	return _self;
}

static void* ds_dtor(void* _self)
{
	DSBASE* self = _self;
	return _self;
}

static const OBJECT _DSbase = {
    sizeof(DSBASE),
    &vtbl,
    ds_ctor, 
    ds_dtor,	
};

const void* DSbase = &_DSbase;


int DS_KeyGenerate(void* _self)
{
	DSBASE* self = _self;
	return (((DSBASEvtbl*)(((OBJECT*)(self->object))->vptr))->keygenerate)((void*)self);
}

int DS_Signature(void* _self, const uint8_t* msg, uint32_t msglen, uint8_t* sig, uint32_t* siglen)
{
	DSBASE* self = _self;

	if (self->state != DS_PUBPRIKEY)
	{
		return 0;
	}

	return (((DSBASEvtbl*)(((OBJECT*)(self->object))->vptr))->signature)((void*)self, msg, msglen, sig, siglen);
}

int DS_Verify(void* _self, const uint8_t* msg, uint32_t msglen, uint8_t* sig, uint32_t siglen)
{
	DSBASE* self = _self;

	if (self->state != DS_PUBKEYONLY)
	{
		return 0;
	}

	return (((DSBASEvtbl*)(((OBJECT*)(self->object))->vptr))->verify)((void*)self, msg, msglen, sig, siglen);
}