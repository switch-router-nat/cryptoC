/*
 * File       : object.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-08-09     187J3X1       first version
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>

#include "object.h"

void *new (const void* _object,...)
{
    const OBJECT *object = _object;	
    void *p = calloc(1, object->size);

    *(const OBJECT **)p = object;

    if (object->ctor)
    {
        va_list ap;
        va_start(ap, _object);
        p = object->ctor(p,&ap);
        va_end(ap);
    }
    return p;
}

void delete (void* self)
{
    const OBJECT **cp = self;
    if(self && *cp && (*cp)->dtor)
        self = (*cp)->dtor(self);
    free(self);
}
