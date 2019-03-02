/*
 * File       :  list.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-12-08     187J3X1       first version
 */

#ifndef _CRYPTOC_LIST_H_
#define _CRYPTOC_LIST_H_

#ifdef __cplusplus
extern "C" {
#endif

struct cc_list_item {
    struct cc_list_item *next;
    struct cc_list_item *prev;
};

struct cc_list {
    struct cc_list_item *first;
    struct cc_list_item *last;
};

/*  Initialise the list. */
void cc_list_init (struct cc_list *self);

/*  Initialize a list item. At this point it is not part of any list. */
void cc_list_item_init (struct cc_list_item *self);

/*  Returns iterator to the first item in the list. */
struct cc_list_item *cc_list_begin (struct cc_list *self);

/*  Returns iterator to one past the last item in the list. */
struct cc_list_item *cc_list_end (struct cc_list *self);

/*  Returns iterator to an item prior to the one pointed to by 'it'. */
struct cc_list_item *cc_list_prev (struct cc_list *self, struct cc_list_item *it);

/*  Returns iterator to one past the item pointed to by 'it'. */
struct cc_list_item *cc_list_next (struct cc_list *self, struct cc_list_item *it);

/*  Adds the item to the list before the item pointed to by 'it'. Priot to
    insertion item should not be part of any list. */
void cc_list_insert (struct cc_list *self, struct cc_list_item *item, struct cc_list_item *it);

#ifdef __cplusplus
}
#endif

#endif
