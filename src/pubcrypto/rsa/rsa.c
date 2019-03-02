/*
 * File       : rsa.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     187J3X1       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../cryptoc.h"
#include "../../base/object.h"
#include "../../bn/bn.h"
#include "../../util/base64.h"
#include "../../util/list.h"
#include "../../util/asn1.h"
#include "rsa.h"

static  uint32_t _rsa_e_2pow16_1[32] = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00010001};

static b_uint32_t rsa_e_2pow16_1 = {_rsa_e_2pow16_1, 32, 31, 15, 0};

static void* rsa_ctor(void *_self, va_list *app)
{
    RSA* self = (RSA*)_self;

    self->e = &rsa_e_2pow16_1;
    self->d = b_create(32);
    self->n = b_create(32);

    self->p   = b_create(16);
    self->q   = b_create(16);
    self->dp  = b_create(16);
    self->dq  = b_create(16);
    self->cp  = b_create(16);
    self->cq  = b_create(16);
    self->qcp = b_create(32);
    self->pcq = b_create(32);
    self->ready = 0;

    self->version = b_create(1);
    b_assign(self->version , 0);

    return _self;
}

static void* rsa_dtor(void* _self)
{
    RSA* self = (RSA*)_self;

    b_destroy(self->d);
    b_destroy(self->n);
    b_destroy(self->p);
    b_destroy(self->q);
    b_destroy(self->dp);
    b_destroy(self->dq);
    b_destroy(self->cp);
    b_destroy(self->cq);
    b_destroy(self->qcp);
    b_destroy(self->pcq);
    b_destroy(self->version);

    return _self;
}

static void rsa_gen_d(RSA* self, b_uint32_t* fn, b_ctx_t* ctx)
{
    b_uint32_t* e = self->e;
    b_uint32_t* d = self->d;
    b_uint32_t* gcd;
    b_ctx_bkp_t bkp;

    b_ctx_save(ctx, &bkp);
    gcd = b_ctx_alloc(ctx, fn->len);
    b_zero(gcd);

    b_zero(d);

    //ex_euclidean_algorithm(fn, e, gcd, d, ctx);
    b_inverse(e, fn, d, ctx);

    b_uint32_t* c;
    c = b_ctx_alloc(ctx, fn->len<<1);
    b_zero(c);
    b_mulmod(e, d, fn, c, ctx); 

    if (d->neg)
    {
        b_sub(fn, d, d);
        d->neg = 0;
        b_zero(c);
        b_mulmod(e, d, fn, c, ctx);
    }

    b_ctx_restore(ctx, &bkp);

    return;
}

void rsa_key_generate(void* _self)
{
    RSA* self = (RSA*)_self;

    b_uint32_t* fn;
    b_uint32_t* gcd;
    b_uint32_t* tmp;

    int len = 16;
    b_ctx_t ctx;
    b_ctx_init(&ctx, len);

    fn  = b_ctx_alloc(&ctx, len<<1);
    gcd = b_ctx_alloc(&ctx, len);
    tmp = b_ctx_alloc(&ctx, len);

    prime_random(self->p, &ctx);
    dump("prime p", self->p);

    prime_random(self->q, &ctx);
    dump("prime q", self->q);

    b_mul(self->p, self->q, self->n);

    dump("n", self->n);

    b_sub2(self->p, 0x00000001, 0);
    b_sub2(self->q, 0x00000001, 0);

    /* fn = (p-1)*(q-1) */
    b_mul(self->p, self->q, fn);

    rsa_gen_d(self, fn, &ctx);

    dump("generate e", self->e);

    dump("generate d", self->d);

    /* dp = d mod (p-1) */
    b_mod(self->d, self->p, self->dp, &ctx);

    /* dq = d mod (q-1) */
    b_mod(self->d, self->q, self->dq, &ctx);

    b_add2(self->p, 0x00000001, 0);
    b_add2(self->q, 0x00000001, 0);

    if (b_cmp(self->p, self->q) > 0)
    {
        /* cp = q^(-1) mod p */
        b_inverse(self->q, self->p, self->cp, &ctx);

        b_mod(self->p, self->q, tmp, &ctx);

        /* cq = p^(-1) mod q = (p mod q)^(-1) mod q*/	
        b_inverse(tmp, self->q, self->cq, &ctx);	
    }
    else
    {
        /* cq = p^(-1) mod q */
        b_inverse(self->p, self->q, self->cq, &ctx);

        b_mod(self->q, self->p, tmp, &ctx);

        /* cp = q^(-1) mod p = (q mod p)^(-1) mod p */
        b_inverse(tmp, self->p, self->cp, &ctx);	
    }

    /* qcp = q*cp */
    b_mul(self->q, self->cp, self->qcp);

    /* pcq = p*cq */
    b_mul(self->p, self->cq, self->pcq);

    self->ready = 1;

    b_ctx_fini(&ctx);

    return;
}

/*
 *  calculate element size 
 *  @plusminusbit indicates if there is 1 byte for bn->neg
 */
static void rsa_calc_elementsize(b_uint32_t* bn, int plusminusbit, uint8_t* tlsize, uint8_t* vsize)
{
    int topbit;
    b_valid_top(bn);
    b_valid_bit(bn->data[bn->top], &topbit);

    uint8_t len = (bn->len - bn->top)*4;
    if (topbit >= 24)
    {
        len -= 3;
    }
    else if (topbit >= 16)
    {
        len -= 2;
    }
    else if (topbit >= 8)
    {
        len -= 1;
    }

    if (plusminusbit)
    {
        /* if plusminusbit is set, we need byte for plusminus   */
        len ++;
    }

    *vsize = len;

    if (len >= 128)
    {
        *tlsize = 3; /* t:1 byte   l:2 bytes */
    }
    else
    {
        *tlsize = 2; /* t:1 byte   l:1 bytes */
    }

    return;
}

int rsa_gen_pubkeypem(void* _self, char* filename, enum rsa_format format)
{
    RSA* self = (RSA*)_self;
    FILE* fp = NULL;
    int rc = 0;
    uint32_t asn1_size  = 0;
    uint32_t coded_size = 0;
    uint8_t base64str[128];
    uint32_t base64str_size = 0;

    /* write to file */	
    fp = fopen(filename, "w");
    if (fp == NULL)
    {
        rc = -2;
        goto err_done;
    }

	if (RSA_FORMAT_PKCS8 == format)
	{	
        void* asn1_sequence  = new(Asn1_Sequence);
        void* oid_sequence   = new(Asn1_Sequence);
        void* bitstring      = new(Asn1_Bitstring);

        Asn1_AddChild(asn1_sequence, oid_sequence);
        Asn1_AddChild(asn1_sequence, bitstring);

        void* oid  = new(Asn1_Objectid, "1.2.840.113549.1.1.1");
        void* null = new(Asn1_Null);

        Asn1_AddChild(oid_sequence, oid);
        Asn1_AddChild(oid_sequence, null);

        void* pkcs1 = new(Asn1_Sequence);
        Asn1_AddChild(bitstring, pkcs1);

        void* n = new(Asn1_Interger, self->n, ASN1_INTERGER_FLAG_MINUSPLUS);
        void* e = new(Asn1_Interger, self->e, ASN1_INTERGER_FLAG_DEFAULT);

        Asn1_AddChild(pkcs1, n);
        Asn1_AddChild(pkcs1, e);

        struct asn1_buff* asb =  asn1buf_alloc(1);

        /* write asn1_sequence to asb */
        asn1_size = Asn1_Write(asn1_sequence, asb);

        fputs("-----BEGIN PUBLIC KEY-----\n", fp);

        while ((asn1_size - coded_size) >= 48)
        {
            base64str_size = cc_base64_encode(asb->data + coded_size, 48, base64str);
            base64str[base64str_size] = '\n';
            base64str[base64str_size + 1] = '\0';
            coded_size += 48;
            fputs(base64str, fp);
        }

        if ((asn1_size - coded_size) > 0)
        {
            base64str_size = cc_base64_encode(asb->data + coded_size, asn1_size - coded_size, base64str);
            base64str[base64str_size] = '\n';
            base64str[base64str_size + 1] = '\0';
            fputs(base64str, fp);		
        }

        fputs("-----END PUBLIC KEY-----\n", fp);

        asn1_buf_destroy(asb);

        delete(asn1_sequence);
        delete(oid_sequence);
        delete(bitstring);
        delete(oid);
        delete(null);
        delete(pkcs1);
        delete(n);
        delete(e);
    }
    else
    {
        /*
         * An RSA public key should be represented with theASN.1 type RSAPublickey:

         * RSAPublickey ::= SEQUENCE {
        	 * modulus INTEGER, -- n
        	 * publicExponent INTEGER   -- e
         * }
         *
         * 
        */
        void* asn1_sequence  =  new(Asn1_Sequence);
        void* n = new(Asn1_Interger, self->n, ASN1_INTERGER_FLAG_MINUSPLUS);
        void* e = new(Asn1_Interger, self->e, ASN1_INTERGER_FLAG_DEFAULT);

        Asn1_AddChild(asn1_sequence, n);
        Asn1_AddChild(asn1_sequence, e);

        struct asn1_buff* asb =  asn1buf_alloc(1);

        /* write asn1_sequence to asb */
        asn1_size = Asn1_Write(asn1_sequence, asb);

        fputs("-----BEGIN RSA PUBLIC KEY-----\n", fp);

        while ((asn1_size - coded_size) >= 48)
        {
            base64str_size = cc_base64_encode(asb->data + coded_size, 48, base64str);
            base64str[base64str_size] = '\n';
            base64str[base64str_size + 1] = '\0';
            coded_size += 48;
            fputs(base64str, fp);
        }

        if ((asn1_size - coded_size) > 0)
        {
            base64str_size = cc_base64_encode(asb->data + coded_size, asn1_size - coded_size, base64str);
            base64str[base64str_size] = '\n';
            base64str[base64str_size + 1] = '\0';
            fputs(base64str, fp);		
        }

        fputs("-----END RSA PUBLIC KEY-----\n", fp);

        asn1_buf_destroy(asb);
        delete(n);
        delete(e);
        delete(asn1_sequence);
	}

err_done:
    if (fp)
        fclose(fp);

    return rc;
}

int rsa_gen_prikeypem(void* _self, char* filename, enum rsa_format format)
{
    RSA* self = (RSA*)_self;
    FILE* fp = NULL;
    int rc = 0;
    uint32_t asn1_size  = 0;
    uint32_t coded_size = 0;
    uint8_t base64str[1024];
    uint32_t base64str_size = 0;

    /* write to file */	
    fp = fopen(filename, "w");
    if (fp == NULL)
    {
        rc = -2;
        goto err_done;
    }

    if (RSA_FORMAT_PKCS8 == format)
    {
        /*
        * An RSA public key should be represented with theASN.1 type RSAPublickey:
        *
        * RSAPublickey_PKCS8 ::= SEQUENCE {
        *      version      Version,
        *      oid_sequence OID_SEQUENCE,  
        *		octetstring  OCTET_STRING_PKCS1,	 	
        * }
        * Version :: = INTEGER{ two-prime(0), multi(1)}
        *
        * OID_SEQUENCE ::= SEQUENCE {
        *      oid OBJECT-IDENTIFIER,  
        *	 	null NULL  
        * }
        *
        * BIT_STRING_PKCS1 ::= OCTET_STRING{
        *      pkcs1 RSAPrivatekey_PKCS1  
        * }
        *      
        * RSAPrivatekey_PKCS1 ::= SEQUENCE {
        * 	  version            Version,
        * 	  modulus            INTEGER,   ------ n
        *    publicExponent     INTEGER,   ------ e
        *    privateExponent    INTEGER,   ------ d
        *    prime1             INTEGER,   ------ p
        *    prime2             INTEGER,   ------ q
        *    exponent1          INTEGER,   ------ d mod (p-1)
        *    exponent2          INTEGER,   ------ d mod (q-1)
        *    coefficient        INTEGER,   ------- (inverse of q) mod p
        *    otherPrimeInfos    OtherPrimeInfos   ------ OPTIONAL exist when Version=1 
        *   
        * }
        *
        */

        void* asn1_sequence = new(Asn1_Sequence);
        void* version       = new(Asn1_Interger, self->version, ASN1_INTERGER_FLAG_DEFAULT); 
        void* oid_sequence  = new(Asn1_Sequence);
        void* octetstring   = new(Asn1_Octetstring);

        Asn1_AddChild(asn1_sequence, version);
        Asn1_AddChild(asn1_sequence, oid_sequence);
        Asn1_AddChild(asn1_sequence, octetstring);

        void* oid  = new(Asn1_Objectid, "1.2.840.113549.1.1.1");
        void* null = new(Asn1_Null);
        Asn1_AddChild(oid_sequence, oid);
        Asn1_AddChild(oid_sequence, null);

        void* pkcs1 = new(Asn1_Sequence);
        Asn1_AddChild(octetstring, pkcs1);

        void* version2 = new(Asn1_Interger, self->version, ASN1_INTERGER_FLAG_DEFAULT); 
        void* n = new(Asn1_Interger, self->n, ASN1_INTERGER_FLAG_MINUSPLUS);
        void* e = new(Asn1_Interger, self->e, ASN1_INTERGER_FLAG_DEFAULT);
        void* d = new(Asn1_Interger, self->d, ASN1_INTERGER_FLAG_DEFAULT);
        void* p = new(Asn1_Interger, self->p, ASN1_INTERGER_FLAG_MINUSPLUS);
        void* q = new(Asn1_Interger, self->q, ASN1_INTERGER_FLAG_MINUSPLUS);
        void* dp = new(Asn1_Interger, self->dp, ASN1_INTERGER_FLAG_DEFAULT);
        void* dq = new(Asn1_Interger, self->dq, ASN1_INTERGER_FLAG_DEFAULT);
        void* cp = new(Asn1_Interger, self->cp, ASN1_INTERGER_FLAG_DEFAULT);

        Asn1_AddChild(pkcs1, version2);
        Asn1_AddChild(pkcs1, n);
        Asn1_AddChild(pkcs1, e);
        Asn1_AddChild(pkcs1, d);
        Asn1_AddChild(pkcs1, p);
        Asn1_AddChild(pkcs1, q);
        Asn1_AddChild(pkcs1, dp);
        Asn1_AddChild(pkcs1, dq);
        Asn1_AddChild(pkcs1, cp);

        struct asn1_buff* asb =  asn1buf_alloc(1);

        /* write asn1_sequence to asb */
        asn1_size = Asn1_Write(asn1_sequence, asb);

        fputs("-----BEGIN PRIVATE KEY-----\n", fp);
        while ((asn1_size - coded_size) >= 48)
        {
            base64str_size = cc_base64_encode(asb->data + coded_size, 48, base64str);
            base64str[base64str_size] = '\n';
            base64str[base64str_size + 1] = '\0';
            coded_size += 48;
            fputs(base64str, fp);
        }

        if ((asn1_size - coded_size) > 0)
        {
            base64str_size = cc_base64_encode(asb->data + coded_size, asn1_size - coded_size, base64str);
            base64str[base64str_size] = '\n';
            base64str[base64str_size + 1] = '\0';
            fputs(base64str, fp);		
        }

        fputs("-----END PRIVATE KEY-----\n", fp);

        asn1_buf_destroy(asb);

        delete(asn1_sequence);
        delete(version);
        delete(oid_sequence);
        delete(octetstring);
        delete(oid);
        delete(null);
        delete(pkcs1);
        delete(version2);
        delete(n);
        delete(e);
        delete(d);
        delete(p);
        delete(q);
        delete(dp);
        delete(dq);
        delete(cp);
    }
    else
    {
        /********************** PKCS 1 ******************************/
        /*
         * An RSA private key should be represented with theASN.1 type RSAPrivateKey:
         * RSAPrivateKey :: = SEQUENCE{
         * version            Version,
         * modulus            INTEGER,   ------ n
         * publicExponent     INTEGER,   ------ e
         * privateExponent    INTEGER,   ------ d
         * prime1             INTEGER,   ------ p
         * prime2             INTEGER,   ------ q
         * exponent1          INTEGER,   ------ d mod (p-1)
         * exponent2          INTEGER,   ------ d mod (q-1)
         * coefficient        INTEGER,   ------- (inverse of q) mod p
         * otherPrimeInfos    OtherPrimeInfos   ------ OPTIONAL exist when Version=1 
         }

        	 Version :: = INTEGER{ two-prime(0), multi(1)}
        	 *
         */

        void* asn1_sequence = new(Asn1_Sequence);
        void* version = new(Asn1_Interger, self->version, ASN1_INTERGER_FLAG_DEFAULT); 
        void* n = new(Asn1_Interger, self->n, ASN1_INTERGER_FLAG_MINUSPLUS);
        void* e = new(Asn1_Interger, self->e, ASN1_INTERGER_FLAG_DEFAULT);
        void* d = new(Asn1_Interger, self->d, ASN1_INTERGER_FLAG_DEFAULT);
        void* p = new(Asn1_Interger, self->p, ASN1_INTERGER_FLAG_MINUSPLUS);
        void* q = new(Asn1_Interger, self->q, ASN1_INTERGER_FLAG_MINUSPLUS);
        void* dp = new(Asn1_Interger, self->dp, ASN1_INTERGER_FLAG_DEFAULT);
        void* dq = new(Asn1_Interger, self->dq, ASN1_INTERGER_FLAG_DEFAULT);
        void* cp = new(Asn1_Interger, self->cp, ASN1_INTERGER_FLAG_DEFAULT);

        Asn1_AddChild(asn1_sequence, version);
        Asn1_AddChild(asn1_sequence, n);
        Asn1_AddChild(asn1_sequence, e);
        Asn1_AddChild(asn1_sequence, d);
        Asn1_AddChild(asn1_sequence, p);
        Asn1_AddChild(asn1_sequence, q);
        Asn1_AddChild(asn1_sequence, dp);
        Asn1_AddChild(asn1_sequence, dq);
        Asn1_AddChild(asn1_sequence, cp);

        struct asn1_buff* asb =  asn1buf_alloc(1);

        /* write asn1_sequence to asb */
        asn1_size = Asn1_Write(asn1_sequence, asb);

        fputs("-----BEGIN RSA PRIVATE KEY-----\n", fp);
        while ((asn1_size - coded_size) >= 48)
        {
            base64str_size = cc_base64_encode(asb->data + coded_size, 48, base64str);
            base64str[base64str_size] = '\n';
            base64str[base64str_size + 1] = '\0';
            coded_size += 48;
            fputs(base64str, fp);
        }

        if ((asn1_size - coded_size) > 0)
        {
            base64str_size = cc_base64_encode(asb->data + coded_size, asn1_size - coded_size, base64str);
            base64str[base64str_size] = '\n';
            base64str[base64str_size + 1] = '\0';
            fputs(base64str, fp);		
        }

        fputs("-----END RSA PRIVATE KEY-----\n", fp);

        asn1_buf_destroy(asb);

        delete(version);
        delete(n);
        delete(e);
        delete(d);
        delete(p);
        delete(q);
        delete(dp);
        delete(dq);
        delete(cp);

        delete(asn1_sequence);
    }

err_done:
    if (fp)
        fclose(fp);

    return rc;
}

int rsa_encryption(void* _self, b_uint32_t* x, b_uint32_t* y)
{
    RSA* self = (RSA*)_self;
    b_ctx_t ctx;
    b_ctx_init(&ctx, 16);

    if (!self->e)
    {
        return -1;
    }

    b_expmod(x, self->e, self->n, y, &ctx);

    b_ctx_fini(&ctx);

    return 0;
}

int rsa_decryption(void* _self, b_uint32_t* y, b_uint32_t* x)
{
    RSA* self = (RSA*)_self;
    b_uint32_t* xp;
    b_uint32_t* xq;
    b_uint32_t* yp;
    b_uint32_t* yq;
    b_uint32_t* x1;
    b_uint32_t* x2;

    b_ctx_t ctx;
    b_ctx_init(&ctx, 16);

    if (0 == self->ready)
    {
        return -1;
    }

    xp = b_ctx_alloc(&ctx, 16);
    xq = b_ctx_alloc(&ctx, 16);
    yp = b_ctx_alloc(&ctx, 16);
    yq = b_ctx_alloc(&ctx, 16);
    x1 = b_ctx_alloc(&ctx, 32);
    x2 = b_ctx_alloc(&ctx, 32);

    /* yp = y mod p */
    b_mod(y, self->p, yp, &ctx);

    /* yq = y mod q */
    b_mod(y, self->q, yq, &ctx);

    /* xp = yp^dp mod p */
    b_expmod(y, self->dp, self->p, xp, &ctx);

    /* xq = yq^dq mod q */
    b_expmod(y, self->dq, self->q, xq, &ctx);

    /* x1 = [qcp] * xp mod n */
    b_mulmod(self->qcp, xp, self->n, x1, &ctx);

    /* x2 = [pcq] * xq mod n  */
    b_mulmod(self->pcq, xq, self->n, x2, &ctx);

    /* x = (x1 + x2) mod n */
    b_addmod(x1, x2, self->n, x, &ctx);

    b_ctx_fini(&ctx);

    return 0;
}

static const OBJECT _Rsa = {
    sizeof(RSA),
    NULL,
    rsa_ctor, 
    rsa_dtor,	
};

const void* Rsa = &_Rsa;
