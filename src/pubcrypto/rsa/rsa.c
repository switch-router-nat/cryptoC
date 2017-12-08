/*
 * File       : rsa.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     QshLyc       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../base/object.h"
#include "../../bn/bn.h"
#include "../../util/base64.h"
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

	// rsa_gen_prikey(self);

	self->ready = 1;

	b_ctx_fini(&ctx);

	return;
}

/*
 * @buffer: destination buffer
 * @i: start position to fill
 * @tlsize: element tl size
 * @vsize:  element v size
*/
static void rsa_fill_elementdata(uint8_t* buffer, uint32_t i, b_uint32_t* bn, uint8_t tlsize, uint8_t vsize, int plusminusbit)
{
	buffer[i++] = 0x02;
	
	if (tlsize == 3)
	{
		buffer[i++] = 0x81;
	}
	
	buffer[i++] = vsize;
	
	if (plusminusbit)
	{
		buffer[i++] = bn->neg ? 0x01:0x00;
		vsize--;
	}

	switch (vsize % 4)
	{
		case 0:
		{
			buffer[i++] = (bn->data[bn->top] >> 24) & 0xff;
		}
		/* fall through */
		case 3:
		{
			buffer[i++] = (bn->data[bn->top] >> 16) & 0xff; 
		}
		/* fall through */
		case 2:
		{
			buffer[i++] = (bn->data[bn->top] >> 8) & 0xff; 
		}
		/* fall through */
		case 1:
		{
			buffer[i++] = (bn->data[bn->top]) & 0xff; 
		}
	}
	
	int j;
	
	for (j = bn->top + 1;j < bn->len ;j++)
	{
		buffer[i++] = (bn->data[j] >> 24) & 0xff;
		buffer[i++] = (bn->data[j] >> 16) & 0xff;
		buffer[i++] = (bn->data[j] >> 8) & 0xff;
		buffer[i++] = (bn->data[j]) & 0xff;
	}

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

static void rsa_gen_prikeybase(RSA* self, uint8_t* buffer, uint32_t* size)
{
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
     }b
	 *
	*/

	uint32_t elements_size = 0;
	uint8_t n_tlsize, e_tlsize, d_tlsize, p_tlsize, q_tlsize, dp_tlsize, dq_tlsize, cp_tlsize;
	uint8_t  n_vsize,  e_vsize,  d_vsize,  p_vsize,  q_vsize,  dp_vsize,  dq_vsize,  cp_vsize;
	uint32_t total_size = 0;
	uint32_t i = 0;
	
	rsa_calc_elementsize(self->n, 1, &n_tlsize, &n_vsize);
	rsa_calc_elementsize(self->e, 0, &e_tlsize, &e_vsize);
	rsa_calc_elementsize(self->d, 0, &d_tlsize, &d_vsize);
	rsa_calc_elementsize(self->p, 1, &p_tlsize, &p_vsize);
	rsa_calc_elementsize(self->q, 1, &q_tlsize, &q_vsize);
	rsa_calc_elementsize(self->dp, 0, &dp_tlsize, &dp_vsize);
	rsa_calc_elementsize(self->dq, 0, &dq_tlsize, &dq_vsize);
	rsa_calc_elementsize(self->cp, 0, &cp_tlsize, &cp_vsize);

	elements_size = n_tlsize + n_vsize + 
					e_tlsize + e_vsize +
					d_tlsize + d_vsize +
					p_tlsize + p_vsize +
					q_tlsize + q_vsize +
					dp_tlsize + dp_vsize +
					dq_tlsize + dq_vsize +
					cp_tlsize + cp_vsize;

	/* 3 bytes version */
	elements_size += 3;

	total_size = elements_size;			
	if (elements_size >= 256)
	{
		/* we need another 2 bytes for identity header */
		total_size += 2;
	}
	else if (elements_size >= 128)
	{
		/* we need another 1 byte for identity header */
		total_size ++;
	}

	/* 2 byte identity header */
	total_size += 2;  

	/********************* fill header **************************/
	buffer[i++] = 0x30;
	if (elements_size >= 256)
	{
		buffer[i++] = 0x82;
		buffer[i++] = elements_size >> 8;
		buffer[i++] = elements_size & 0xff;
	}
	else if (elements_size >= 128)
	{
		buffer[i++] = 0x81;
		buffer[i++] = elements_size;
	}
	else
	{
		buffer[i++] = elements_size;
	}

	/********************* fill elements **************************/
	/* version = 0 */
	buffer[i++] = 0x02;
	buffer[i++] = 0x01;
	buffer[i++] = 0x00;

	/* fill the pubkey buffer: n */
	rsa_fill_elementdata(buffer, i, self->n, n_tlsize, n_vsize, 1);
	i = i + n_tlsize + n_vsize;

	/* fill the pubkey buffer: e */
	rsa_fill_elementdata(buffer, i, self->e, e_tlsize, e_vsize, 0);
	i = i + e_tlsize + e_vsize;

	/* fill the pubkey buffer: d */
	rsa_fill_elementdata(buffer, i, self->d, d_tlsize, d_vsize, 0);
	i = i + d_tlsize + d_vsize;

	/* fill the pubkey buffer: p */
	rsa_fill_elementdata(buffer, i, self->p, p_tlsize, p_vsize, 1);
	i = i + p_tlsize + p_vsize;

	/* fill the pubkey buffer: q */
	rsa_fill_elementdata(buffer, i, self->q, q_tlsize, q_vsize, 1);
	i = i + q_tlsize + q_vsize;

	/* fill the pubkey buffer: dp */
	rsa_fill_elementdata(buffer, i, self->dp, dp_tlsize, dp_vsize, 0);
	i = i + dp_tlsize + dp_vsize;

	/* fill the pubkey buffer: dp */
	rsa_fill_elementdata(buffer, i, self->dq, dq_tlsize, dq_vsize, 0);
	i = i + dq_tlsize + dq_vsize;

	/* fill the pubkey buffer: cp */
	rsa_fill_elementdata(buffer, i, self->cp, cp_tlsize, cp_vsize, 0);
	i = i + cp_tlsize + cp_vsize;

	*size = total_size;

	return;
}

static void rsa_gen_pubkeybase(RSA* self, uint8_t* buffer, uint32_t* size)
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
	uint32_t elements_size = 0;
	uint8_t n_vsize, e_vsize;
	uint8_t n_tlsize, e_tlsize;
	uint32_t total_size = 0;
	uint32_t i = 0;
	
	rsa_calc_elementsize(self->n, 1, &n_tlsize, &n_vsize);
	rsa_calc_elementsize(self->e, 0, &e_tlsize, &e_vsize);

	elements_size = n_tlsize + n_vsize + 
					e_tlsize + e_vsize;

	total_size = elements_size;			
	if (elements_size >= 256)
	{
		/* we need another 2 bytes for identity header */
		total_size += 2;
	}
	else if (elements_size >= 128)
	{
		/* we need another 1 byte for identity header */
		total_size ++;
	}

	/* 2 byte identity header */
	total_size += 2;  

	/********************* fill header **************************/
	buffer[i++] = 0x30;
	if (elements_size >= 256)
	{
		buffer[i++] = 0x82;
		buffer[i++] = elements_size >> 8;
		buffer[i++] = elements_size & 0xff;
	}
	else if (elements_size >= 128)
	{
		buffer[i++] = 0x81;
		buffer[i++] = elements_size;
	}
	else
	{
		buffer[i++] = elements_size;
	}

	/********************* fill elements **************************/

	/* fill the pubkey buffer: n */
	rsa_fill_elementdata(buffer, i, self->n, n_tlsize, n_vsize, 1);
	i = i + n_tlsize + n_vsize;

	/* fill the pubkey buffer: e */
	rsa_fill_elementdata(buffer, i, self->e, e_tlsize, e_vsize, 0);
	i = i + e_tlsize + e_vsize;

	*size = total_size;

	return;
}


#define RSA_PUBKEY_PKCS8_PREFIXSIZE 22
static const uint8_t rsa_pubkey_pkcs8_prefix[RSA_PUBKEY_PKCS8_PREFIXSIZE] = 
												   {0x30, 0x81, 0xFF,  
													      0x30, 0x0d,
															    0x06, 0x09,
															          0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
															    0x05, 0x00,
														  0x03, 0x81, 0xFF, 0x00};

int rsa_gen_pubkeypem(void* _self, char* filename, enum rsa_format format)
{
	RSA* self = (RSA*)_self;
	FILE* fp = NULL;
	int rc = 0;
	uint8_t* pkcs1_buffer = NULL;
	uint8_t* pkcs8_buffer = NULL;
	uint32_t pkcs1_size = 0;
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

	pkcs1_buffer = (uint8_t*)malloc(256);
	if (NULL == pkcs1_buffer)
	{
		rc = -1;
		goto err_done;
	}

	/* generate base part */
	rsa_gen_pubkeybase(self, pkcs1_buffer, &pkcs1_size);

	if (RSA_FORMAT_PKCS8 == format)
	{
		pkcs8_buffer = (uint8_t*)malloc(256);
		if (NULL == pkcs8_buffer)
		{
			rc = -1;
			goto err_done;
		}

		memcpy(pkcs8_buffer, rsa_pubkey_pkcs8_prefix, RSA_PUBKEY_PKCS8_PREFIXSIZE);

		pkcs8_buffer[2]  = RSA_PUBKEY_PKCS8_PREFIXSIZE- 3 + pkcs1_size;
		pkcs8_buffer[20] = pkcs1_size - 3 + 4;

		/* cat prefix with pkcs1_buffer */
		memcpy(&pkcs8_buffer[RSA_PUBKEY_PKCS8_PREFIXSIZE], pkcs1_buffer, pkcs1_size);

		fputs("-----BEGIN PUBLIC KEY-----\n", fp);

		uint32_t tot_size = pkcs1_size + RSA_PUBKEY_PKCS8_PREFIXSIZE;

		while ((tot_size - coded_size) >= 48)
		{
			base64str_size = cc_base64_encode(pkcs8_buffer + coded_size, 48, base64str);
			base64str[base64str_size] = '\n';
			base64str[base64str_size + 1] = '\0';
			coded_size += 48;
			fputs(base64str, fp);
		}
		
		if ((tot_size - coded_size) > 0)
		{
			base64str_size = cc_base64_encode(pkcs8_buffer + coded_size, tot_size - coded_size, base64str);
			base64str[base64str_size] = '\n';
			base64str[base64str_size + 1] = '\0';
			fputs(base64str, fp);		
		}

		fputs("-----END PUBLIC KEY-----\n", fp);
	}
	else{

		fputs("-----BEGIN RSA PUBLIC KEY-----\n", fp);

		while ((pkcs1_size - coded_size) >= 48)
		{
			base64str_size = cc_base64_encode(pkcs1_buffer + coded_size, 48, base64str);
			base64str[base64str_size] = '\n';
			base64str[base64str_size + 1] = '\0';
			coded_size += 48;
			fputs(base64str, fp);
		}
		
		if ((pkcs1_size - coded_size) > 0)
		{
			base64str_size = cc_base64_encode(pkcs1_buffer + coded_size, pkcs1_size - coded_size, base64str);
			base64str[base64str_size] = '\n';
			base64str[base64str_size + 1] = '\0';
			fputs(base64str, fp);		
		}

		fputs("-----END RSA PUBLIC KEY-----\n", fp);
	}

err_done:
	if (fp)
		fclose(fp);
	free(pkcs1_buffer);
	free(pkcs8_buffer);

	return rc;
}

#define RSA_PRIKEY_PKCS8_PREFIXSIZE 26
static const uint8_t rsa_prikey_pkcs8_prefix[RSA_PRIKEY_PKCS8_PREFIXSIZE] = 
												   {0x30, 0x82, 0x02, 0x75, 
 														  0x02, 0x01, 0x00, 
													      0x30, 0x0d, 
													            0x06, 0x09, 
													          	      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 
													            0x05, 0x00, 
													      0x04, 0x82, 0x02, 0x5f};

int rsa_gen_prikeypem(void* _self, char* filename, enum rsa_format format)
{
	RSA* self = (RSA*)_self;
	FILE* fp = NULL;
	int rc = 0;
	uint8_t* pkcs1_buffer = NULL;
	uint8_t* pkcs8_buffer = NULL;
	uint32_t pkcs1_size = 0;
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

	pkcs1_buffer = (uint8_t*)malloc(1024);
	if (NULL == pkcs1_buffer)
	{
		rc = -1;
		goto err_done;
	}

	/* generate base part */
	rsa_gen_prikeybase(self, pkcs1_buffer, &pkcs1_size);

	if (RSA_FORMAT_PKCS8 == format)
	{
		pkcs8_buffer = (uint8_t*)malloc(1024);
		if (NULL == pkcs8_buffer)
		{
			rc = -1;
			goto err_done;
		}

		memcpy(pkcs8_buffer, rsa_prikey_pkcs8_prefix, RSA_PRIKEY_PKCS8_PREFIXSIZE);

		pkcs8_buffer[25] = pkcs1_buffer[3] + 4;
		pkcs8_buffer[3]  = pkcs1_buffer[3] + RSA_PRIKEY_PKCS8_PREFIXSIZE;

		/* cat prefix with pkcs1_buffer */
		memcpy(&pkcs8_buffer[RSA_PRIKEY_PKCS8_PREFIXSIZE], pkcs1_buffer, pkcs1_size);

		fputs("-----BEGIN PRIVATE KEY-----\n", fp);

		uint32_t tot_size = pkcs1_size + RSA_PRIKEY_PKCS8_PREFIXSIZE;

		while ((tot_size - coded_size) >= 48)
		{
			base64str_size = cc_base64_encode(pkcs8_buffer + coded_size, 48, base64str);
			base64str[base64str_size] = '\n';
			base64str[base64str_size + 1] = '\0';
			coded_size += 48;
			fputs(base64str, fp);
		}
		
		if ((tot_size - coded_size) > 0)
		{
			base64str_size = cc_base64_encode(pkcs8_buffer + coded_size, tot_size - coded_size, base64str);
			base64str[base64str_size] = '\n';
			base64str[base64str_size + 1] = '\0';
			fputs(base64str, fp);		
		}

		fputs("-----END PRIVATE KEY-----\n", fp);
	}
	else{
		/********************** PKCS 1 *****************************8*/

		fputs("-----BEGIN RSA PRIVATE KEY-----\n", fp);
		while ((pkcs1_size - coded_size) >= 48)
		{
			base64str_size = cc_base64_encode(pkcs1_buffer + coded_size, 48, base64str);
			base64str[base64str_size] = '\n';
			base64str[base64str_size + 1] = '\0';
			coded_size += 48;
			fputs(base64str, fp);
		}
		
		if ((pkcs1_size - coded_size) > 0)
		{
			base64str_size = cc_base64_encode(pkcs1_buffer + coded_size, pkcs1_size - coded_size, base64str);
			base64str[base64str_size] = '\n';
			base64str[base64str_size + 1] = '\0';
			fputs(base64str, fp);		
		}

		fputs("-----END RSA PRIVATE KEY-----\n", fp);
	}

err_done:
	if (fp)
		fclose(fp);
	free(pkcs1_buffer);
	free(pkcs8_buffer);

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
