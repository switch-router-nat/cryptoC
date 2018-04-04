#ifndef MD5_H
#define MD5_H


typedef struct
{
    unsigned int count[2];
    unsigned int state[4];
    unsigned char buffer[64];   // 512 bit
}md5_ctx;


typedef struct{
    const void* object;
    md5_ctx ctx;
}MD5;


#endif