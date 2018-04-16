/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2017 University of North Carolina at Chapel Hill and
   Fortanix, Inc.
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * list.h
 *
 * This file defines the list API for the PAL and Library OS.
 */

#ifndef LIST_H
#define LIST_H

// Use a new list implementation

/* This list implementation stores a pointer to the next object and casts to
 * the object, rather than using offsetof().  We try to encapsulate this
 * change in a macro for declarations, which generates a type declaration for
 * each list object (giving marginally more help from the compiler
 * in detecting bugs.
 * 
 * In particular, there is a small trade-off in that the association between
 * list heads and nodes is more explicit and a few more casting errors can be
 * caught by the compiler, but we add a parameter to some functions (well,
 * macros) to pass the field of the struct.
 */

/* How-to:
 * 
 * Each list has a pointer (listp) type, and a node (list)type.  We assume
 * list nodes are embedded in a larger structure; the name of this structure
 * is used as part of the list type.
 * 
 * To define a listp/list pair for a struct foo:
 * 
 * DEFINE_LIST(foo);
 * struct foo {
 *   int x;
 *   LIST_TYPE(foo) list; // The list node 
 * };
 * 
 * DEFINE_LISTP(foo);
 * static LISTP_TYPE(foo) the_list = LISTP_INIT;
 * 
 * -----
 * 
 * From here, you can use listp_add variants to add an object from the list:
 * 
 * struct foo *f = malloc(sizeof(struct foo));
 * f->x = 1;
 * INIT_LIST_HEAD(f, list); // The second parameter is the structure member
 * listp_add(f, &the_list, list);
 * 
 * -----
 * 
 * There are a number of add variants, some that add in a given position,
 * others that add to the head or the tail.
 * 
 * You can search for an object using a variant of listp_for_each_entry. The
 * safe variants are safe against deletion.
 * 
 * You can remove an object from a list using listp_del.  
 * 
 * In this example, we delete everything with a key bigger than 5.
 * 
 * LIST_TYPE(foo) *f, *n; // n is not used, just for scratch space
 * listp_for_each_entry_safe(f, n, &the_list, list) {
 *    if (f->x > 4) {
 *         listp_del(f, &the_list, list);
 *         free(f);
 *    }
 * }
 * 
 * 
 * listp_splice moves an entire listp onto another, and list_move_tail takes 
 * an element off of one list and places it on another.
 * 
 * static LISTP_TYPE(foo) other_list; // Assume it is full of goodies
 *  // Move everything on other_list to the_list
 * listp_splice_tail(&other_list, &the_list, list, foo); // the third argument
 *                                                       // is the field; the
 *                                                       // fourth is the type
 *                                                       // of the nodes (not 
 *                                                       // the head pointer).
 * 
 * // Use listp_empty to test for emptiness of the list 
 * assert(listp_empty(&other_ist));
 * 
 *  // Now move back anythign less than 6 back to other_list
 * listp_for_each_entry_safe(f, n, &the_list, list) {
 *    if (f->x < 6) 
 *         listp_move_tail(f, &other_list, &the_list, list);
 * }
 * 
 */

// Maybe TODO?
//
// Change the order of (node, head, field) -> (head, node, field)
// drop the listp type to reduce code changes?
// Cleaner way to express types
// Add assertion to delete (in debugging mode) that item is on list
// There are a few places where knowing the listp for deletion is cumbersome;
//    maybe drop this requirement?

#include <stdbool.h>

#ifdef DEBUG
#include <assert.h>
#define LIST_ASSERT(cond) assert(cond)
#else
#define LIST_ASSERT(cond)
#endif

/* For these macros, do not include the string 'struct' */
#define LIST_TYPE(STRUCT) struct list_head ##_## STRUCT
#define LISTP_TYPE(STRUCT) struct listp ##_## STRUCT

/* Declare the enclosing struct for convenience, on 
 * the assumption that this is primarily used in structure 
 * definitions, and harmless if duplicated. */
#define DEFINE_LIST(STRUCT)                     \
    struct STRUCT;                              \
    LIST_TYPE(STRUCT) {                         \
        struct STRUCT *next, *prev;             \
    }

/* We use LISTP for pointers to a list.  This project only really needs
 * doubly-linked lists.  We used hlists to get a single pointer for more
 * efficient hash tables, but they were still effectively doubly-linked
 * lists. */
#define DEFINE_LISTP(STRUCT)                    \
    LISTP_TYPE(STRUCT) {                        \
        struct STRUCT * first;                  \
    }

#define LISTP_INIT {NULL}

/* A node not on a list uses NULL; on a list, you 
 * store self pointers */
#define INIT_LIST_HEAD(OBJECT, FIELD) do {      \
        (OBJECT)->FIELD.next = NULL;            \
        (OBJECT)->FIELD.prev = NULL;            \
    } while (0)


#define INIT_LISTP(OBJECT) do {                 \
        (OBJECT)->first = NULL;                 \
    } while (0)

#define listp_empty(HEAD) ((HEAD)->first == NULL)

#define list_empty(NODE, FIELD)                 \
    ((NODE)->FIELD.next == NULL)

/* This helper takes 3 arguments - all should be containing structures,
 * and the field to use for the offset to the list node */
#define __list_add(NEW, NEXT, PREV, FIELD) do {       \
        typeof(NEW) __tmp_next = (NEXT);              \
        typeof(NEW) __tmp_prev = (PREV);              \
        __tmp_prev->FIELD.next = (NEW);               \
        __tmp_next->FIELD.prev = (NEW);               \
        (NEW)->FIELD.next = __tmp_next;               \
        (NEW)->FIELD.prev = __tmp_prev;               \
    } while (0)

#define list_add(NEW, HEAD, FIELD)                 \
    __list_add(NEW, (HEAD)->FIELD.next, HEAD, FIELD)

#define listp_add(NEW, HEAD, FIELD) do {                    \
        if ((HEAD)->first == NULL) {                        \
            (HEAD)->first = (NEW);                          \
            (NEW)->FIELD.next = (NEW);                      \
            (NEW)->FIELD.prev = (NEW);                      \
        } else {                                            \
            __list_add(NEW, (HEAD)->first, (HEAD)->first->FIELD.prev, FIELD); \
            (HEAD)->first = (NEW);                          \
        }                                                   \
    } while (0)

/* If NODE is defined, add NEW after NODE; if not, 
 * put NEW at the front of the list */
#define listp_add_after(NEW, NODE, HEAD, FIELD) do { \
        if (NODE)                                \
            list_add(NEW, NODE, FIELD);          \
        else                                     \
            listp_add(NEW, HEAD, FIELD);         \
    } while(0)

#define list_add_tail(NEW, HEAD, FIELD)                 \
    __list_add(NEW, HEAD, (HEAD)->FIELD.prev, FIELD)

#define listp_add_tail(NEW, HEAD, FIELD) do {               \
        if ((HEAD)->first == NULL) {                        \
            (HEAD)->first = (NEW);                          \
            (NEW)->FIELD.next = (NEW);                      \
            (NEW)->FIELD.prev = (NEW);                      \
        } else                                              \
            list_add_tail(NEW, (HEAD)->first, FIELD);       \
    } while (0)

/* Or deletion needs to know the list root */
#define listp_del(NODE, HEAD, FIELD) do {                               \
        if ((HEAD)->first == (NODE)) {                                  \
            if ((NODE)->FIELD.next == NODE) {                           \
                (HEAD)->first = NULL;                                   \
            } else {                                                    \
                (HEAD)->first = (NODE)->FIELD.next;                     \
            }                                                           \
        }                                                               \
        LIST_ASSERT((NODE)->FIELD.prev->FIELD.next == (NODE));          \
        LIST_ASSERT((NODE)->FIELD.next->FIELD.prev == (NODE));          \
        (NODE)->FIELD.prev->FIELD.next = (NODE)->FIELD.next;            \
        (NODE)->FIELD.next->FIELD.prev = (NODE)->FIELD.prev;            \
    } while(0)

#define listp_del_init(NODE, HEAD, FIELD) do {  \
        listp_del(NODE, HEAD, FIELD);           \
        INIT_LIST_HEAD(NODE, FIELD);            \
    } while(0)

/* Keep vestigial TYPE and FIELD parameters to minimize disruption
 * when switching from Linux list implementation */
#define listp_first_entry(LISTP, TYPE, FIELD) ((LISTP)->first)

/* New API: return last entry in list */
#define listp_last_entry(LISTP, TYPE, FIELD) ((LISTP)->first->FIELD.prev)

/* New API: return next entry in list */
#define listp_next_entry(NODE, LISTP, FIELD)                            \
        ((NODE) == (LISTP)->first->FIELD.prev ? NULL : (NODE)->FIELD.next)

/* New API: return previous entry in list */
#define listp_prev_entry(NODE, LISTP, FIELD)                            \
        ((NODE) == (LISTP)->first ? NULL : (NODE)->FIELD.prev)

/* Vestigial - for compat with Linux list code; rename to listp?
 */
#define list_entry(LISTP, TYPE, FIELD) (LISTP)

#define listp_for_each_entry(CURSOR, HEAD, FIELD)                       \
    for (bool first_iter = ((CURSOR) = (HEAD)->first,                   \
                            !!(HEAD)->first);                           \
         first_iter || (CURSOR) != (HEAD)->first;                       \
         (CURSOR) = (CURSOR)->FIELD.next, first_iter = false)

#define listp_for_each_entry_reverse(CURSOR, HEAD, FIELD)                   \
    for (bool first_iter = ((CURSOR) = ((HEAD)->first                       \
                                       ? (HEAD)->first->FIELD.prev          \
                                       : (HEAD)->first),                    \
                           !!(HEAD)->first);                                \
         first_iter || ((CURSOR) && (CURSOR)->FIELD.next != (HEAD)->first); \
         (CURSOR) = (CURSOR)->FIELD.prev, first_iter = false)

#define listp_for_each_entry_safe(CURSOR, TMP, HEAD, FIELD)                 \
    for (bool first_iter = ((CURSOR) = (HEAD)->first,                       \
                            (TMP) = ((CURSOR)                               \
                                     ? (CURSOR)->FIELD.next                 \
                                     : (CURSOR)),                           \
                            !!(HEAD)->first);                               \
         (HEAD)->first && (first_iter || (CURSOR) != (HEAD)->first);        \
         /* Handle the case where the first element was removed. */         \
         first_iter = first_iter && (TMP) != (CURSOR) && (HEAD)->first == (TMP), \
         (CURSOR) = (TMP),                                                  \
         (TMP) = (TMP)->FIELD.next)

/* Continue safe iteration with CURSOR->next */
#define listp_for_each_entry_safe_continue(CURSOR, TMP, HEAD, FIELD)     \
    for ((CURSOR) = (CURSOR)->FIELD.next,                                \
         (TMP) = (CURSOR)->FIELD.next;                                   \
         (CURSOR) != (HEAD)->first && (HEAD)->first;                     \
         (CURSOR) = (TMP),                                               \
         (TMP) = (TMP)->FIELD.next)

/* Assertion code written in Graphene project */
#define check_list_head(TYPE, head, FIELD)                              \
        do {                                                            \
            TYPE pos;                                                   \
            listp_for_each_entry(pos, head, FIELD) {                    \
                assert((pos->FIELD.prev != pos && pos->FIELD.next != pos) \
                       || (pos->FIELD.prev == pos && pos->FIELD.next == pos)); \
                assert(pos->FIELD.prev->FIELD.next == pos);             \
                assert(pos->FIELD.next->FIELD.prev == pos);             \
            }                                                           \
        } while (0)

// Add NEW to OLD at position first (assuming first is all we need for now)
// Can probably drop TYPE with some preprocessor smarts
#define listp_splice(NEW, OLD, FIELD, TYPE) do {                     \
        if(!listp_empty(NEW)) {                                      \
            if(listp_empty(OLD)) {                                   \
                (OLD)->first = (NEW)->first;                         \
            } else {                                                 \
                struct TYPE *last_old = (OLD)->first->FIELD.prev;    \
                (OLD)->first->FIELD.prev->FIELD.next = (NEW)->first;    \
                (OLD)->first->FIELD.prev = (NEW)->first->FIELD.prev;    \
                (NEW)->first->FIELD.prev->FIELD.next = (OLD)->first;   \
                (NEW)->first->FIELD.prev = last_old;                  \
                (OLD)->first = (NEW)->first;                         \
            }                                                        \
        }                                                            \
    } while (0)

// Add NEW to OLD at last position
// Can probably drop TYPE with some preprocessor smarts
#define listp_splice_tail(NEW, OLD, FIELD, TYPE) do {                \
        if(!listp_empty(NEW)) {                                      \
            if(listp_empty(OLD)) {                                   \
                (OLD)->first = (NEW)->first;                         \
            } else {                                                 \
                struct TYPE *last_old = (OLD)->first->FIELD.prev;       \
                last_old->FIELD.next = (NEW)->first;                    \
                (OLD)->first->FIELD.prev = (NEW)->first->FIELD.prev;    \
                (NEW)->first->FIELD.prev->FIELD.next = (OLD)->first;    \
                (NEW)->first->FIELD.prev = last_old;                    \
            }                                                        \
        }                                                            \
    } while (0)

#define listp_splice_init(NEW, OLD, FIELD, TYPE) do {       \
        listp_splice(NEW, OLD, FIELD, TYPE);                \
        INIT_LISTP(NEW);                                    \
    } while(0);


#define listp_splice_tail_init(NEW, OLD, FIELD, TYPE) do {  \
        listp_splice_tail(NEW, OLD, FIELD, TYPE);           \
        INIT_LISTP(NEW);                                    \
    } while(0);
    
// list_move_tail - delete from OLD, make tail of NEW
#define listp_move_tail(NODE, NEW, OLD, FIELD) do {   \
        listp_del_init(NODE, OLD, FIELD);             \
        listp_add_tail(NODE, NEW, FIELD);             \
    } while (0)


#endif // LIST_H
