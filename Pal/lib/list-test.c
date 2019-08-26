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

/* Unit test for the new list implementation */

#include "list.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

DEFINE_LIST(simple);
struct simple {
    int idx;
    LIST_TYPE(simple) list;
};

DEFINE_LISTP(simple);
static LISTP_TYPE(simple) list_in_the_sky      = LISTP_INIT;
static LISTP_TYPE(simple) list_in_the_basement = LISTP_INIT;

/* Use some static arrays to assert expected list contents */
int sol1[7]  = {1, 2, 3, 4, 5, 6, 7};
int sol2[10] = {1, 2, 25, 3, 4, 45, 5, 6, 65, 7};
int sol3[17] = {1, 2, 25, 3, 4, 45, 5, 6, 65, 7, 8, 9, 10, 11, 12, 13, 14};
int sol4[20] = {1, 2, 25, 3, 4, 45, 5, 6, 65, 7, 8, 85, 9, 10, 105, 11, 12, 125, 13, 14};
int sol5[7]  = {7, 6, 5, 4, 3, 2, 1};
int sol6[4]  = {7, 5, 3, 1};
int sol7[10] = {7, 5, 3, 1, 13, 12, 11, 10, 9, 8};
int sol8[17] = {7, 5, 3, 1, 13, 12, 11, 10, 9, 8, 20, 19, 18, 17, 16, 15, 14};

void print_list(LISTP_TYPE(simple)* listp) {
    struct simple* tmp;
    printf("Beginning of list\n");
    LISTP_FOR_EACH_ENTRY(tmp, listp, list) {
        printf("List element %d\n", tmp->idx);
    }
    printf("End of list\n\n");
}

void assert_list(LISTP_TYPE(simple)* listp, int len, int* array, int stop_early_ok) {
    int j = 0;
    struct simple* tmp;
    int stop_early = 0;
    CHECK_LIST_HEAD(struct simple*, listp, list);
    LISTP_FOR_EACH_ENTRY(tmp, listp, list) {
        if (j >= len) {
            stop_early = 1;
            break;
        }
        assert(tmp->idx == array[j]);
        j++;
    }
    assert(j >= len);
    if (!stop_early)
        assert(tmp == listp->first);
    else
        assert(stop_early_ok);
}

void print_list_reverse(LISTP_TYPE(simple)* listp) {
    struct simple* tmp;
    printf("Beginning of list\n");
    LISTP_FOR_EACH_ENTRY_REVERSE(tmp, listp, list) {
        printf("List element %d\n", tmp->idx);
    }
    printf("End of list\n\n");
}

int main() {
    int i;
    struct simple* tmp;
    struct simple* tmp2;
    struct simple* n;

    assert(LISTP_EMPTY(&list_in_the_sky));

    /* Try printing an empty list */
    print_list(&list_in_the_sky);

    /* Test adding things to the listp */
    for (i = 0; i < 7; i++) {
        tmp      = malloc(sizeof(struct simple));
        tmp->idx = 7 - i;
        INIT_LIST_HEAD(tmp, list);
        assert(LIST_EMPTY(tmp, list));
        LISTP_ADD(tmp, &list_in_the_sky, list);
        assert(!LIST_EMPTY(tmp, list));
        assert_list(&list_in_the_sky, i, &sol1[6 - i], 1);
    }
    assert(!LISTP_EMPTY(&list_in_the_sky));

    assert_list(&list_in_the_sky, 7, sol1, 0);

    /* Test LIST_ADD  - i.e., adding things in the middle of the list*/
    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &list_in_the_sky, list) {
        if ((tmp->idx % 2) == 0) {
            tmp2      = malloc(sizeof(struct simple));
            tmp2->idx = (tmp->idx * 10) + 5;
            INIT_LIST_HEAD(tmp2, list);
            assert(LIST_EMPTY(tmp2, list));
            LIST_ADD(tmp2, tmp, list);
            assert(!LIST_EMPTY(tmp2, list));
        }
    }

    // print_list(&list_in_the_sky);
    // print_list_reverse(&list_in_the_sky);
    assert_list(&list_in_the_sky, 10, sol2, 0);

    /* Try adding some integers to the tail of the list */
    for (i = 0; i < 7; i++) {
        tmp      = malloc(sizeof(struct simple));
        tmp->idx = 8 + i;
        INIT_LIST_HEAD(tmp, list);
        assert(LIST_EMPTY(tmp, list));
        LISTP_ADD_TAIL(tmp, &list_in_the_sky, list);
        assert(!LIST_EMPTY(tmp, list));
    }
    assert(!LISTP_EMPTY(&list_in_the_sky));

    assert_list(&list_in_the_sky, 17, sol3, 0);

    /* Test LIST_ADD_TAIL by adding ints from end */
    LISTP_FOR_EACH_ENTRY(tmp, &list_in_the_sky, list) {
        if (tmp->idx <= 7 || tmp->idx > 20)
            continue;

        if ((tmp->idx % 2) == 1) {
            tmp2      = malloc(sizeof(struct simple));
            tmp2->idx = ((tmp->idx - 1) * 10) + 5;
            INIT_LIST_HEAD(tmp2, list);
            assert(LIST_EMPTY(tmp2, list));
            LIST_ADD_TAIL(tmp2, tmp, list);
            assert(!LIST_EMPTY(tmp2, list));
        }
    }

    // print_list(&list_in_the_sky);
    // print_list_reverse(&list_in_the_sky);
    assert_list(&list_in_the_sky, 20, sol4, 0);

    printf("Deletion test starting\n\n");

    /* Test list deletion and safe iteration by destroying the list*/
    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &list_in_the_sky, list) {
        LISTP_DEL(tmp, &list_in_the_sky, list);
        free(tmp);
        // print_list(&list_in_the_sky);
    }
    assert(LISTP_EMPTY(&list_in_the_sky));

    printf("Deletion test Ending\n\n");

    /* Rebuild the list */
    for (i = 0; i < 7; i++) {
        tmp      = malloc(sizeof(struct simple));
        tmp->idx = 7 - i;
        INIT_LIST_HEAD(tmp, list);
        assert(LIST_EMPTY(tmp, list));
        LISTP_ADD(tmp, &list_in_the_sky, list);
        assert(!LIST_EMPTY(tmp, list));
    }
    assert(!LISTP_EMPTY(&list_in_the_sky));

    printf("Deletion test 2 starting\n\n");

    /* Test LISTP_DEL_INIT by migrating to another list */
    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &list_in_the_sky, list) {
        LISTP_DEL(tmp, &list_in_the_sky, list);
        LISTP_ADD(tmp, &list_in_the_basement, list);
        // print_list(&list_in_the_sky);
        // print_list(&list_in_the_basement);
    }

    // print_list(&list_in_the_sky);
    // print_list(&list_in_the_basement);
    assert(LISTP_EMPTY(&list_in_the_sky));
    assert_list(&list_in_the_basement, 7, sol5, 0);

    /* Test LISTP_FIRST_ENTRY, for funzies */
    assert(LISTP_FIRST_ENTRY(&list_in_the_basement, simple, list)->idx == 7);

    /*
    printf("List in the sky:\n");
    print_list(&list_in_the_sky);
    printf("\nList in the basement:\n");
    print_list(&list_in_the_basement);
    printf("\nfin\n");
    printf("\nList in the basement, but backward:\n");
    print_list_reverse(&list_in_the_basement);
    printf("\nfin\n");
    printf("\nList in the sky, but backward:\n");
    print_list_reverse(&list_in_the_sky);
    printf("\nfin\n");
    */

    printf("Deletion test 2 Ending\n\n");

    /* Test LISTP_FOR_EACH_ENTRY_SAFE_CONTINUE; stop on 4
     * after deleting 6 and 4, break, and continue.
     * */
    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &list_in_the_basement, list) {
        if (0 == (tmp->idx % 2)) {
            int idx = tmp->idx;
            LISTP_DEL(tmp, &list_in_the_basement, list);
            // NB: The continue pointer needs to be valid (will probably work
            // by accident even if 4 isn't freed, so better to leak one node
            if (idx == 4)
                break;
            else
                free(tmp);
        }
    }

    // printf("Continuing\n");

    LISTP_FOR_EACH_ENTRY_SAFE_CONTINUE(tmp, n, &list_in_the_basement, list) {
        if (0 == (tmp->idx % 2)) {
            LISTP_DEL(tmp, &list_in_the_basement, list);
            free(tmp);
        }
    }

    // print_list(&list_in_the_sky);
    // print_list(&list_in_the_basement);
    assert(LISTP_EMPTY(&list_in_the_sky));
    assert_list(&list_in_the_basement, 4, sol6, 0);

    /* Test list_splice variants.  Rebuild sky list again */
    /* Rebuild the list */
    for (i = 8; i < 14; i++) {
        tmp      = malloc(sizeof(struct simple));
        tmp->idx = i;
        INIT_LIST_HEAD(tmp, list);
        assert(LIST_EMPTY(tmp, list));
        LISTP_ADD(tmp, &list_in_the_sky, list);
        assert(!LIST_EMPTY(tmp, list));
    }
    assert(!LISTP_EMPTY(&list_in_the_sky));

    printf("Begin splice tests \n\n");

    /* Test listp splice */
    LISTP_SPLICE_INIT(&list_in_the_basement, &list_in_the_sky, list, simple);

    assert(LISTP_EMPTY(&list_in_the_basement));
    assert_list(&list_in_the_sky, 10, sol7, 0);

    LISTP_SPLICE(&list_in_the_sky, &list_in_the_basement, list, simple);
    INIT_LISTP(&list_in_the_sky);

    assert(LISTP_EMPTY(&list_in_the_sky));
    assert_list(&list_in_the_basement, 10, sol7, 0);

    /* Test splicing onto the tail */
    /* Rebuild the list */
    for (i = 14; i < 21; i++) {
        tmp      = malloc(sizeof(struct simple));
        tmp->idx = i;
        INIT_LIST_HEAD(tmp, list);
        assert(LIST_EMPTY(tmp, list));
        LISTP_ADD(tmp, &list_in_the_sky, list);
        assert(!LIST_EMPTY(tmp, list));
    }
    assert(!LISTP_EMPTY(&list_in_the_sky));

    LISTP_SPLICE_TAIL(&list_in_the_sky, &list_in_the_basement, list, simple);
    INIT_LISTP(&list_in_the_sky);

    /*
    printf("\nList in the basement:\n");
    print_list(&list_in_the_basement);
    printf("\nfin\n");

    printf("\nList in the sky:\n");
    print_list(&list_in_the_sky);
    printf("\nfin\n");
    */

    printf("Before list move test \n\n");

    /* Test LISTP_MOVE_TAIL */
    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &list_in_the_basement, list) {
        LISTP_MOVE_TAIL(tmp, &list_in_the_sky, &list_in_the_basement, list);
    }

    assert(LISTP_EMPTY(&list_in_the_basement));
    assert_list(&list_in_the_sky, 17, sol8, 0);

    printf("After list move test \n\n");

    /*
    printf("\nList in the basement:\n");
    print_list(&list_in_the_basement);
    printf("\nfin\n");

    printf("\nList in the sky:\n");
    print_list(&list_in_the_sky);
    printf("\nfin\n");
    */

    printf("All tests passed!\n");
    return 0;
}
