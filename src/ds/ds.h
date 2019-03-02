/*
 * File       : ds.h
 * Description: Digital Signature base
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-15     187J3X1       first version
 */

#ifndef _DS_H_
#define _DS_H_

extern const void* DSbase;


enum ds_state_e{
    DS_INIT = 0,
    DS_PUBKEYONLY,    /* only have public key     */
    DS_PUBPRIKEY,     /* public/private key valid */
};

typedef struct{
    const void* object;
    enum ds_state_e state;
}DSBASE;

typedef struct {
    int (*keygenerate)(void* _self);
    int (*signature)(void* _self, const uint8_t* msg, uint32_t msglen, uint8_t* sig, uint32_t* siglen);
    int (*verify)(void* _self, const uint8_t* msg, uint32_t msglen, uint8_t* sig, uint32_t siglen);
}DSBASEvtbl;


// int DS_GenerateKey(void* _self);

#endif 