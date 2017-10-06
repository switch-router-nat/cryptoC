/*
 * File       : rolate_shift.c *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-05     QshLyc       first version
 */
#include "../base/basetype.h"
#include "rolate_shift.h"


/*
    rolate shift @word @l bit 
*/
cc_uint32_t Rotl32(cc_uint32_t word, cc_uint8_t l)
{
	cc_uint32_t w;
	
	w = (word << l) | (word >> (32 - l));

	return w;
}




