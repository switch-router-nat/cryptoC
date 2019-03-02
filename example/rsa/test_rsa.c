/*
 * File       :  test_rsa.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19    187J3X1       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <cryptoc.h>

int main()
{
    b_uint32_t b_x,b_y;
    FILE* fp_prikey = NULL;
    FILE* fp_pubkey = NULL;
    uint32_t filesize;
    uint8_t* filebuf;
    uint8_t base64buf[1024];
    uint32_t base64size;
    uint32_t size;

    uint32_t x[32] = {0x00000001, 0x12345678, 0xABABABAB, 0xFFFFFFFF,0x11223344, 0x12345678, 0xABABABAB, 0xFFFFFFFF,
                    0x11223344, 0x12345678, 0xABABABAB, 0xFFFFFFFF,0x11223344, 0x12345678, 0xABABABAB, 0xFFFFFFFF,
                    0x11223344, 0x12345678, 0xABABABAB, 0xFFFFFFFF,0x11223344, 0x12345678, 0xABABABAB, 0xFFFFFFFF,
                    0x11223344, 0x12345678, 0xABABABAB, 0xFFFFFFFF,0x11223344, 0x12345678, 0xABABABAB, 0xFFFFFFFF};
    uint32_t y[32] = {0};

    b_x.data = x;
    b_x.len  = sizeof(x)/sizeof(uint32_t);
    b_x.neg  = 0;

    b_y.data = y;
    b_y.len  = sizeof(y)/sizeof(uint32_t);
    b_y.neg  = 0;

    void* rsa = new(Rsa);

    rsa_key_generate(rsa);

    if (0 == rsa_encryption(rsa, &b_x, &b_y))
    {
        dump("ut y ", &b_y);
    }

    if (0 == rsa_decryption(rsa, &b_y, &b_x))
    {
        dump("ut x ", &b_x);
    }

    rsa_gen_pubkeypem(rsa, "pubkey.pem", RSA_FORMAT_PKCS8);
    rsa_gen_prikeypem(rsa, "prikey.pem", RSA_FORMAT_PKCS8);

    delete(rsa);

    return 0;	
}

