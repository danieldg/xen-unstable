/******************************************************************************
 * list.h
 * 
 * Useful linked-list definitions taken from the Linux kernel.
 */

#ifndef __XEN_LIST_H__
#define __XEN_LIST_H__

#include <xen/lib.h>

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*
 * Insert a new entry between two known consecutive entries. 
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head * new,
    struct list_head * prev,
    struct list_head * next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *new, struct list_head *head)
{
    __list_add(new, head, head->next);
}

/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev,
                              struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
    ASSERT(entry->next->prev == entry);
    ASSERT(entry->prev->next == entry);
    __list_del(entry->prev, entry->next);
}

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void list_del_init(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    INIT_LIST_HEAD(entry);
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(struct list_head *head)
{
    return head->next == head;
}

/**
 * list_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice(struct list_head *list, struct list_head *head)
{
    struct list_head *first = list->next;

    if ( first != list )
    {
        struct list_head *last = list->prev;
        struct list_head *at = head->next;

        first->prev = head;
        head->next = first;

        last->next = at;
        at->prev = last;
    }
}

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:    the type of the struct this is embedded in.
 * @member:    the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * list_for_each    -    iterate over a list
 * @pos:    the &struct list_head to use as a loop counter.
 * @head:    the head for your list.
 */
#define list_for_each(pos, head)                                \
    for ( pos = (head)->next; pos != (head); pos = pos->next )

/**
 * list_for_each_safe    -    iterate over a list safe against removal
 *                            of list entry
 * @pos:    the &struct list_head to use as a loop counter.
 * @n:        another &struct list_head to use as temporary storage
 * @head:    the head for your list.
 */
#define list_for_each_safe(pos, n, head)                        \
    for ( pos = (head)->next, n = pos->next; pos != (head);     \
          pos = n, n = pos->next )

/**
 * list_for_each_backwards_safe    -    iterate backwards over a list safe
 *                                      against removal of list entry
 * @pos:    the &struct list_head to use as a loop counter.
 * @n:        another &struct list_head to use as temporary storage
 * @head:    the head for your list.
 */
#define list_for_each_backwards_safe(pos, n, head)              \
    for ( pos = (head)->prev, n = pos->prev; pos != (head);     \
          pos = n, n = pos->prev )

/**
 * list_for_each_entry    -    iterate over list of given type
 * @pos:    the type * to use as a loop counter.
 * @head:    the head for your list.
 * @member:    the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)                          \
    for ( pos = list_entry((head)->next, typeof(*pos), member),         \
          prefetch(pos->member.next);                                   \
          &pos->member != (head);                                       \
          pos = list_entry(pos->member.next, typeof(*pos), member),     \
          prefetch(pos->member.next) )

/**
 * list_for_each_entry_safe - iterate over list of given type safe
 *                            against removal of list entry
 * @pos:    the type * to use as a loop counter.
 * @n:        another type * to use as temporary storage
 * @head:    the head for your list.
 * @member:    the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)                  \
    for ( pos = list_entry((head)->next, typeof(*pos), member),         \
          n = list_entry(pos->member.next, typeof(*pos), member);       \
          &pos->member != (head);                                       \
          pos = n, n = list_entry(n->member.next, typeof(*n), member) )

/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
    h->next = NULL;
    h->pprev = NULL;
}

static inline int hlist_unhashed(const struct hlist_node *h)
{
    return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *h)
{
    return !h->first;
}

static inline void __hlist_del(struct hlist_node *n)
{
    struct hlist_node *next = n->next;
    struct hlist_node **pprev = n->pprev;
    *pprev = next;
    if ( next )
        next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
    __hlist_del(n);
}

static inline void hlist_del_init(struct hlist_node *n)
{
    if ( !hlist_unhashed(n) )
    {
        __hlist_del(n);
        INIT_HLIST_NODE(n);
    }
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
    struct hlist_node *first = h->first;
    n->next = first;
    if ( first )
        first->pprev = &n->next;
    h->first = n;
    n->pprev = &h->first;
}

/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,
                    struct hlist_node *next)
{
    n->pprev = next->pprev;
    n->next = next;
    next->pprev = &n->next;
    *(n->pprev) = n;
}

static inline void hlist_add_after(struct hlist_node *n,
                    struct hlist_node *next)
{
    next->next = n->next;
    n->next = next;
    next->pprev = &n->next;

    if ( next->next )
        next->next->pprev  = &next->next;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head)                                       \
    for (pos = (head)->first; pos && ({ prefetch(pos->next); 1; });     \
         pos = pos->next)

#define hlist_for_each_safe(pos, n, head)                       \
    for ( pos = (head)->first; pos && ({ n = pos->next; 1; });  \
          pos = n )

/**
 * hlist_for_each_entry    - iterate over list of given type
 * @tpos:    the type * to use as a loop cursor.
 * @pos:    the &struct hlist_node to use as a loop cursor.
 * @head:    the head for your list.
 * @member:    the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member)                   \
    for ( pos = (head)->first;                                          \
          pos && ({ prefetch(pos->next); 1;}) &&                        \
          ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;});      \
          pos = pos->next )

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing
 *                                 after current point
 * @tpos:    the type * to use as a loop cursor.
 * @pos:    the &struct hlist_node to use as a loop cursor.
 * @member:    the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(tpos, pos, member)                \
    for ( pos = (pos)->next;                                            \
          pos && ({ prefetch(pos->next); 1;}) &&                        \
          ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;});      \
          pos = pos->next )

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from
 *                             current point
 * @tpos:    the type * to use as a loop cursor.
 * @pos:    the &struct hlist_node to use as a loop cursor.
 * @member:    the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(tpos, pos, member)                    \
    for ( ; pos && ({ prefetch(pos->next); 1;}) &&                      \
          ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;});      \
          pos = pos->next )

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe
 *                             against removal of list entry
 * @tpos:    the type * to use as a loop cursor.
 * @pos:    the &struct hlist_node to use as a loop cursor.
 * @n:        another &struct hlist_node to use as temporary storage
 * @head:    the head for your list.
 * @member:    the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_safe(tpos, pos, n, head, member)           \
    for ( pos = (head)->first;                                          \
          pos && ({ n = pos->next; 1; }) &&                             \
          ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;});      \
          pos = n )

#endif /* __XEN_LIST_H__ */

