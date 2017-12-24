/*
 * File       :  asn.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-12-08     QshLyc       first version
 */

#ifndef _CRYPTOC_ASN1_H_
#define _CRYPTOC_ASN1_H_

#ifdef __cplusplus
extern "C" {
#endif


#define ASN1_TAG_INTEGER     0x02
#define ASN1_TAG_NULL        0x05
#define ASN1_TAG_OID         0x06
#define ASN1_TAG_SEQUENCE    0x30	
#define ASN1_TAG_BITSTRING   0x03	
#define ASN1_TAG_OCTETSTRING 0x04	

#define ASN1_BUFF_PAGE_SIZE 1024
struct asn1_buff{
	uint8_t* head;
	uint8_t* data;
	uint8_t* tail;
	uint8_t  page;
};

enum asn1_type{
	ASN1_TYPE_INTERGER,
	ASN1_TYPE_SEQUENCE,
	ASN1_TYPE_OID,
	ASN1_TYPE_BITSTRING,
	ASN1_TYPE_OCTETSTRING,
	ASN1_TYPE_NULL,
};

typedef struct{
	const void* object;
	struct cc_list_item item;
	enum asn1_type type;
	uint32_t size;
}ASN1_ELEMENT;

typedef struct {
	uint32_t (*write)(void* _self, struct asn1_buff* asb);
	int (*parse)(void *_self, struct asn1_buff* asb);
	int (*addchild)(void* _self, void* child);
}ASN1_ELEMENTvtbl;


typedef struct{
	ASN1_ELEMENT super;
}ASN1_NULL;

typedef struct{
	ASN1_ELEMENT super;
	uint8_t* oid;
}ASN1_OBJECTID;

#define ASN1_INTERGER_FLAG_DEFAULT   0x00000000
#define ASN1_INTERGER_FLAG_MINUSPLUS 0x00000001
typedef struct{
	ASN1_ELEMENT super;
	b_uint32_t* bn;
	uint32_t flag;
}ASN1_INTERGER;

typedef struct{
	ASN1_ELEMENT super;
	struct cc_list head;	
}ASN1_SEQUENCE;

typedef struct{
	ASN1_ELEMENT super;
	uint8_t pad;
	struct cc_list head;	
}ASN1_BITSTRING;

typedef struct{
	ASN1_ELEMENT super;
	struct cc_list head;	
}ASN1_OCTETSTRING;

extern const void* Asn1_Element;
extern const void* Asn1_Null;
extern const void* Asn1_Objectid;
extern const void* Asn1_Interger;
extern const void* Asn1_Sequence;
extern const void* Asn1_Bitstring;
extern const void* Asn1_Octetstring;


struct asn1_buff* asn1buf_alloc(uint8_t page);
void asn1_buf_destroy(struct asn1_buff* asb);
void asn1_buf_reset(struct asn1_buff* asb);

uint32_t Asn1_Write(void* _self, struct asn1_buff* asb);
int Asn1_AddChild(void* _self, void* child);

#ifdef __cplusplus
}
#endif

#endif
