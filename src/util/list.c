/*
 * File       :  list.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-12-09     187J3X1       first version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "list.h"

void cc_list_init (struct cc_list *self)
{
    self->first = NULL;
    self->last = NULL;
}

void cc_list_item_init (struct cc_list_item *self)
{
    self->prev = NULL;
    self->next = NULL;
}

struct cc_list_item *cc_list_begin (struct cc_list *self)
{
    return self->first;
}

struct cc_list_item *cc_list_end (struct cc_list *self)
{
    return NULL;
}

struct cc_list_item *cc_list_next (struct cc_list *self, struct cc_list_item *it)
{
    return it->next;
}

void cc_list_insert (struct cc_list *self, struct cc_list_item *item, struct cc_list_item *it)
{
    item->prev = it ? it->prev : self->last;
    item->next = it;
    if (item->prev)
        item->prev->next = item;
    if (item->next)
        item->next->prev = item;
    if (!self->first || self->first == it)
        self->first = item;
    if (!it)
        self->last = item;
}