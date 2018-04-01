/*
 * File       : object.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-08-09     QshLyc       first version
 */

#ifndef _OBJECT_H_
#define _OBJECT_H_

typedef struct{
    size_t  size;
    void const *vptr;
    void* (* ctor)(void* self, va_list *app);
    void* (* dtor)(void* self);
}OBJECT;


#endif

