/*
 * File       : ans1.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-12-15     Qshlyc      first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../cryptoc.h"
#include "../base/object.h"
#include "../bn/bn.h"
#include "list.h"
#include "cont.h"
#include "asn1.h"


struct asn1_buff* asn1buf_alloc(uint8_t page)
{
	struct asn1_buff* asb = (struct asn1_buff *)malloc(sizeof(struct asn1_buff));
	if (asb)
	{
		asb->head = (uint8_t*) malloc(page * ASN1_BUFF_PAGE_SIZE);
		if (asb->head)
		{
			asb->data = asb->head + page * ASN1_BUFF_PAGE_SIZE;
			asb->tail = asb->head + page * ASN1_BUFF_PAGE_SIZE;
			asb->page = page;
		}
	}

	return asb;
}

void asn1_buf_destroy(struct asn1_buff* asb)
{
	if (asb)
	{
		if (asb->head)
			free(asb->head);
		free(asb);
	}

	return;
}

void asn1_buf_reset(struct asn1_buff* asb)
{
	if (asb)
	{
		asb->data = asb->tail;
	}

	return;
}

static void asn1buf_enlarge(struct asn1_buff *asb)
{
	int i = 0;
	asb->page++;
	asb->head = realloc(asb->head, asb->page);

	for (i = asb->page-2; i >= 0; i--)
	{
		memcpy(asb->head + ASN1_BUFF_PAGE_SIZE*(i+1),  
			   asb->head + ASN1_BUFF_PAGE_SIZE*i, 
			   ASN1_BUFF_PAGE_SIZE);
	}

	asb->data += ASN1_BUFF_PAGE_SIZE;
	asb->tail += ASN1_BUFF_PAGE_SIZE;

	return;
}

/*       
                +------+                          +------+
                |      |       		asb->data --->|------|
                |      |                      len |      |
  asb->data --->|------|                      ----|      | 
                |      |                          |      |
                |      |   =>                     |      |
  asb->tail --->|------|            asb->tail --->|------| 
                |      |                          |      |
                +------+                          +------|

*/
static uint8_t *asn1buf_push(struct asn1_buff *asb, uint32_t len)
{
	if(asb->head + len > asb->data)
	{
		asn1buf_enlarge(asb);
	}

	asb->data -= len;

	return asb->data;
}

static uint8_t asn1_lsize(uint32_t size)
{
	if (size < 0x80)
	{
		return 1;
	}
	else if(size < 0xFF)
	{
		return 2;
	}
	else
	{
		return 3;
	}
}

static void asn1_write_tl(struct asn1_buff *asb, uint8_t tag, uint32_t vsize)
{
	asb->data[0] = tag;

	if (vsize < 0x80)
	{
		asb->data[1] = (uint8_t)vsize;
	}
	else if(vsize < 0xFF)
	{
		asb->data[1] = 0x81;
		asb->data[2] = (uint8_t)vsize;
	}
	else
	{
		asb->data[1] = 0x82;
		asb->data[2] = (vsize & 0x0000ff00)>>8;
		asb->data[3] = (uint8_t)vsize;
	}

	return;
}

static void* asn1_element_ctor(void *_self, va_list *app)
{
	ASN1_ELEMENT* self = (ASN1_ELEMENT *)_self;

	cc_list_item_init(&self->item);

	self->size = 0;

	return _self;
}

static void* asn1_element_dtor(void* _self)
{
	return _self;
}


static ASN1_ELEMENTvtbl const asn1_element_vtbl = {
	NULL,
	NULL,
	NULL,
};

static const OBJECT _Asn1_Element = {
    sizeof(ASN1_ELEMENT),
    &asn1_element_vtbl,
    asn1_element_ctor, 
    asn1_element_dtor,	
};

const void* Asn1_Element = &_Asn1_Element;

/**********************************************************/
static void* asn1_interger_ctor(void *_self, va_list *app)
{
	ASN1_INTERGER* self = ((const OBJECT*)Asn1_Element)->ctor(_self, app);
	b_uint32_t* bn;
	uint32_t flag;

	bn = va_arg(*app, b_uint32_t*);
	flag = va_arg(*app, uint32_t);

	self->super.type = ASN1_TYPE_INTERGER;
	self->bn = bn;
	self->flag = flag;
	
	return _self;
}

static void* asn1_interger_dtor(void* _self)
{
	return _self;
}


static uint32_t asn1_interger_write(void* _self, struct asn1_buff* asb)
{
	ASN1_INTERGER* self = _self;
	b_uint32_t* bn = self->bn;
	uint32_t i = 0;
	uint32_t vsize;
	uint8_t lsize;
	uint8_t remainder;
	int topbit;

	b_valid_top(bn);
	b_valid_bit(bn->data[bn->top], &topbit);

	vsize = (bn->len - bn->top)*4;
	if (0 != vsize)
	{
		if (topbit >= 24)
		{
			vsize -= 3;
		}
		else if (topbit >= 16)
		{
			vsize -= 2;
		}
		else if (topbit >= 8)
		{
			vsize -= 1;
		}

	    /* reserve space fot V */
		asn1buf_push(asb, vsize);

		remainder = vsize & 0x03;
		if (remainder)
		{
			for (; i < remainder; ++i)
			{
				int j = 8 * (remainder - 1 - i);
				asb->data[i] = (bn->data[bn->top] >> j) & 0x000000ff;
			}
		}

		while (i < vsize)
		{
			int j = bn->top + (i+3)>>2;
			asb->data[i++] = bn->data[j] >> 24;
			asb->data[i++] = bn->data[j] >> 16;
			asb->data[i++] = bn->data[j] >> 8;
			asb->data[i++] = bn->data[j];
		}
	}
	else /* bn->data = 0 */
	{
		vsize = 1;
		/* reserve space fot V */
		asn1buf_push(asb, vsize);
		asb->data[0] = 0;
	}

    if (self->flag & ASN1_INTERGER_FLAG_MINUSPLUS)
    {
    	vsize += 1;
    	asn1buf_push(asb, 1);
    	asb->data[0] = bn->neg ? 0x01:0x00;
    }

	lsize = asn1_lsize(vsize);

 	/* reserve space fot T + L */
	asn1buf_push(asb, 1 + lsize);

	asn1_write_tl(asb, ASN1_TAG_INTEGER, vsize);

	self->super.size = 1 + lsize + vsize; /* T + L + V */

	return self->super.size;
}

static int asn1_interger_parse(void *_self, struct asn1_buff* asb)
{
	/* TODO */
	return 0;
}

static ASN1_ELEMENTvtbl const asn1_interger_vtbl = {
	&asn1_interger_write,
	&asn1_interger_parse,
	NULL,
};

static const OBJECT _Asn1_Interger = {
    sizeof(ASN1_INTERGER),
    &asn1_interger_vtbl,
    asn1_interger_ctor, 
    asn1_interger_dtor,	
};

const void* Asn1_Interger = &_Asn1_Interger;


/**********************************************************/
static void* asn1_objectid_ctor(void *_self, va_list *app)
{
	ASN1_OBJECTID* self = ((const OBJECT*)Asn1_Element)->ctor(_self, app);
		
	self->oid = va_arg(*app, uint8_t*);
	self->super.type = ASN1_TYPE_OID;
	
	return _self;
}

static void* asn1_objectid_dtor(void* _self)
{
	return _self;
}


static uint32_t asn1_objectid_write(void* _self, struct asn1_buff* asb)
{
	ASN1_OBJECTID* self = (ASN1_OBJECTID *)_self;
	int info[10];
	int i = 0;
	int j = 0;
	uint8_t lsize = 0;
	uint32_t vsize = 0;

	char* oid = strdup(self->oid); 

	char* temp = strtok(oid,".");
    while(temp)
    {
    	info[i++] = atoi(temp);
        temp = strtok(NULL,".");
    }

    for (j = i-1;  j >= 2; --j)
    {
    	if (info[j] < 0x80)
    	{
    		vsize += 1;
    		asn1buf_push(asb, 1);
    		asb->data[0] = info[j];
    	}
    	else if (info[j] < 0x4000)
    	{
    		vsize += 2;
    		asn1buf_push(asb, 2);
    		asb->data[0] = 0x80 | (info[j] >> 7);
    		asb->data[1] = info[j] & 0x7f;
    	}
    	else 
    	{
    		vsize += 3;
    		asn1buf_push(asb, 3);
    		asb->data[0] = 0x80 | (info[j] >> 14);
    		asb->data[1] = 0x80 | (info[j] >> 7);
    		asb->data[2] = info[j] & 0x7f;
    	}
    }

    vsize += 1;
    asn1buf_push(asb, 1);
    asb->data[0] = info[0]*40 + info[1];

	free(oid);

	lsize = asn1_lsize(vsize);

 	/* reserve space fot T + L */
	asn1buf_push(asb, 1 + lsize);

	asn1_write_tl(asb, ASN1_TAG_OID, vsize);

	/* T + L + V */
	self->super.size = 1 + lsize + vsize; 

	return self->super.size;
}

static int asn1_objectid_parse(void *_self, struct asn1_buff* asb)
{
	/* TODO */
	return 0;
}

static ASN1_ELEMENTvtbl const asn1_objectid_vtbl = {
	&asn1_objectid_write,
	&asn1_objectid_parse,
	NULL,
};

static const OBJECT _Asn1_Objectid = {
    sizeof(ASN1_OBJECTID),
    &asn1_objectid_vtbl,
    asn1_objectid_ctor, 
    asn1_objectid_dtor,	
};

const void* Asn1_Objectid = &_Asn1_Objectid;

/**********************************************************/
static void* asn1_null_ctor(void *_self, va_list *app)
{
	ASN1_NULL* self = ((const OBJECT*)Asn1_Element)->ctor(_self, app);
		
	self->super.type = ASN1_TYPE_NULL;
	
	return _self;
}

static void* asn1_null_dtor(void* _self)
{
	return _self;
}


static uint32_t asn1_null_write(void* _self, struct asn1_buff* asb)
{
	ASN1_NULL* self = (ASN1_NULL *)_self;
	uint8_t lsize;

	/* calculate size of L */
    lsize = asn1_lsize(0);

    /* reserve space fot T + L */
	asn1buf_push(asb, lsize + 1);

	/* write T\L */
	asn1_write_tl(asb, ASN1_TAG_NULL, 0);

	self->super.size = 1 + lsize; /* T + L + V */

	return self->super.size;
}

static int asn1_null_parse(void *_self, struct asn1_buff* asb)
{
	/* TODO */
	return 0;
}

static ASN1_ELEMENTvtbl const asn1_null_vtbl = {
	&asn1_null_write,
	&asn1_null_parse,
	NULL,
};

static const OBJECT _Asn1_Null = {
    sizeof(ASN1_NULL),
    &asn1_null_vtbl,
    asn1_null_ctor, 
    asn1_null_dtor,	
};

const void* Asn1_Null = &_Asn1_Null;

/**********************************************************/
static void* asn1_bitstring_ctor(void *_self, va_list *app)
{
	ASN1_BITSTRING *self = ((const OBJECT*)Asn1_Element)->ctor(_self, app);

	self->super.type = ASN1_TYPE_BITSTRING;

	self->pad = 0;

	cc_list_init(&self->head);

	return _self;
}

static void* asn1_bitstring_dtor(void* _self)
{
	return _self;
}


static uint32_t asn1_bitstring_write(void* _self, struct asn1_buff* asb)
{
	ASN1_BITSTRING* self = _self;
	ASN1_ELEMENT* element;
	struct cc_list_item *it;
	uint32_t vsize = 0;
	uint8_t  lsize= 0;

	/* Firstly, Write the sequence's children */
	for (it  = cc_list_begin (&self->head);
         it != cc_list_end (&self->head);
         it  = cc_list_next (&self->head, it)) {

		element = cc_cont(it, ASN1_ELEMENT, item);
		vsize += Asn1_Write(element, asb);
    }

    vsize++;

    /* reserve space fot pad */
	asn1buf_push(asb, 1);

	/* fill pad byte */
	asb->data[0] = self->pad;

	/* calculate size of L */
    lsize = asn1_lsize(vsize);

    /* reserve space fot T + L */
	asn1buf_push(asb, lsize + 1);

	/* write T\L */
	asn1_write_tl(asb, ASN1_TAG_BITSTRING, vsize);

	self->super.size = 1 + lsize + vsize; /* T + L + V */

	return self->super.size;
}

static int asn1_bitstring_parse(void *_self, struct asn1_buff* asb)
{
	/* TODO */
	return 0;
}

static int asn1_bitstring_addchild(void *_self, void* _child)
{
	ASN1_BITSTRING* self = (ASN1_BITSTRING* )_self;
	ASN1_ELEMENT* child = (ASN1_ELEMENT* )_child;

	cc_list_insert (&self->head, &child->item, cc_list_begin(&self->head));

	return 0;
}

static ASN1_ELEMENTvtbl const asn1_bitstring_vtbl = {
	&asn1_bitstring_write,
	&asn1_bitstring_parse,
	&asn1_bitstring_addchild,
};

static const OBJECT _Asn1_Bitstring = {
    sizeof(ASN1_BITSTRING),
    &asn1_bitstring_vtbl,
    asn1_bitstring_ctor, 
    asn1_bitstring_dtor,	
};

const void* Asn1_Bitstring = &_Asn1_Bitstring;

/**********************************************************/
static void* asn1_octetstring_ctor(void *_self, va_list *app)
{
	ASN1_OCTETSTRING *self = ((const OBJECT*)Asn1_Element)->ctor(_self, app);

	self->super.type = ASN1_TYPE_OCTETSTRING;

	cc_list_init(&self->head);

	return _self;
}

static void* asn1_octetstring_dtor(void* _self)
{
	return _self;
}


static uint32_t asn1_octetstring_write(void* _self, struct asn1_buff* asb)
{
	ASN1_SEQUENCE* self = _self;
	ASN1_ELEMENT* element;
	struct cc_list_item *it;
	uint32_t vsize = 0;
	uint8_t  lsize= 0;

	/* Firstly, Write the sequence's children */
	for (it  = cc_list_begin (&self->head);
         it != cc_list_end (&self->head);
         it  = cc_list_next (&self->head, it)) {

		element = cc_cont(it, ASN1_ELEMENT, item);
		vsize += Asn1_Write(element, asb);
    }

    lsize = asn1_lsize(vsize);

    /* reserve space fot T + L */
	asn1buf_push(asb, lsize + 1);

	/* write T\L */
	asn1_write_tl(asb, ASN1_TAG_OCTETSTRING, vsize);

	self->super.size = 1 + lsize + vsize; /* T + L + V */

	return self->super.size;
}

static int asn1_octetstring_parse(void *_self, struct asn1_buff* asb)
{
	/* TODO */
	return 0;
}

static int asn1_octetstring_addchild(void *_self, void* _child)
{
	ASN1_OCTETSTRING* self = (ASN1_OCTETSTRING* )_self;
	ASN1_ELEMENT* child = (ASN1_ELEMENT* )_child;

	cc_list_insert (&self->head, &child->item, cc_list_begin(&self->head));

	return 0;
}

static ASN1_ELEMENTvtbl const asn1_octetstring_vtbl = {
	&asn1_octetstring_write,
	&asn1_octetstring_parse,
	&asn1_octetstring_addchild,
};

static const OBJECT _Asn1_Octetstring = {
    sizeof(ASN1_OCTETSTRING),
    &asn1_octetstring_vtbl,
    asn1_octetstring_ctor, 
    asn1_octetstring_dtor,	
};

const void* Asn1_Octetstring = &_Asn1_Octetstring;

/**********************************************************/
static void* asn1_sequence_ctor(void *_self, va_list *app)
{
	ASN1_SEQUENCE *self = ((const OBJECT*)Asn1_Element)->ctor(_self, app);

	self->super.type = ASN1_TYPE_SEQUENCE;

	cc_list_init(&self->head);

	return _self;
}

static void* asn1_sequence_dtor(void* _self)
{
	return _self;
}


static uint32_t asn1_sequence_write(void* _self, struct asn1_buff* asb)
{
	ASN1_SEQUENCE* self = _self;
	ASN1_ELEMENT* element;
	struct cc_list_item *it;
	uint32_t vsize = 0;
	uint8_t  lsize= 0;

	/* Firstly, Write the sequence's children */
	for (it  = cc_list_begin (&self->head);
         it != cc_list_end (&self->head);
         it  = cc_list_next (&self->head, it)) {

		element = cc_cont(it, ASN1_ELEMENT, item);
		vsize += Asn1_Write(element, asb);
    }

    lsize = asn1_lsize(vsize);

    /* reserve space fot T + L */
	asn1buf_push(asb, lsize + 1);

	/* write T\L */
	asn1_write_tl(asb, ASN1_TAG_SEQUENCE, vsize);

	self->super.size = 1 + lsize + vsize; /* T + L + V */

	return self->super.size;
}

static int asn1_sequence_parse(void *_self, struct asn1_buff* asb)
{
	/* TODO */
	return 0;
}

static int asn1_sequence_addchild(void *_self, void* _child)
{
	ASN1_SEQUENCE* self = (ASN1_SEQUENCE* )_self;
	ASN1_ELEMENT* child = (ASN1_ELEMENT* )_child;

	cc_list_insert (&self->head, &child->item, cc_list_begin(&self->head));

	return 0;
}

static ASN1_ELEMENTvtbl const asn1_sequence_vtbl = {
	&asn1_sequence_write,
	&asn1_sequence_parse,
	&asn1_sequence_addchild,
};

static const OBJECT _Asn1_Sequence = {
    sizeof(ASN1_SEQUENCE),
    &asn1_sequence_vtbl,
    asn1_sequence_ctor, 
    asn1_sequence_dtor,	
};

const void* Asn1_Sequence = &_Asn1_Sequence;

/************************************************************************/
uint32_t Asn1_Write(void* _self, struct asn1_buff* asb)
{
	ASN1_ELEMENT* self = _self;
	return (((ASN1_ELEMENTvtbl*)(((OBJECT*)(self->object))->vptr))->write)((void*)self, asb);
}


int Asn1_AddChild(void* _self, void* child)
{
	ASN1_ELEMENT* self = _self;
	(((ASN1_ELEMENTvtbl*)(((OBJECT*)(self->object))->vptr))->addchild)((void*)self, child);

	return 0;
}