#ifndef _CRYPTOC_CONT_
#define _CRYPTOC_CONT_

#include <stddef.h>

/*  Takes a pointer to a member variable and computes pointer to the structure
    that contains it. 'type' is type of the structure, not the member. */
#define cc_cont(ptr, type, member) \
    (ptr ? ((type*) (((char*) ptr) - offsetof(type, member))) : NULL)

#endif
