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

static bool compare_node(const void* first, const void* second);
static void add_node(int idx, LISTP_TYPE(simple)* the_list);
static void destroy_list(LISTP_TYPE(simple)*  the_list);
static int test_list_sort();

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

void print_list(LISTP_TYPE(simple)* the_list) {
  struct simple *f, *n;
  if (!the_list)
    return;
    printf("Beginning of list\n");
    LISTP_FOR_EACH_ENTRY_SAFE(f, n, the_list, list) {
        printf("List element %d\n", f->idx);
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
    int sort_ret = 0;

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

    sort_ret = test_list_sort();
    assert(sort_ret == 0);
    printf("Verified list sorting.\n\n");

    printf("All tests passed!\n");
    return 0;
}

/* compare_node function, used to sort the list. */
static bool compare_node(const void* first, const void* second) {
    if (!first || !second)
        return false;

    return (((struct simple* )first)->idx <
                ((struct simple* )second)->idx);
}

static void add_node(int idx, LISTP_TYPE(simple)* the_list) {
    struct simple* list_node = NULL;
    size_t len = 0;
    if (!the_list)
        return;
    list_node = (struct simple*)malloc(sizeof(struct simple));
    if (!list_node)
        return;
    list_node->idx = idx;
    LISTP_ADD_TAIL(list_node, the_list, list);
    /*printf("%s: added list_node_ptr=%p, idx->%d\n", __func__, list_node, list_node->idx);*/
}

static void destroy_list(LISTP_TYPE(simple)*  the_list) {
    LISTP_CLEAR_AND_FREE_EACH_LIST_ITEM(the_list, simple);
}

static int verify_sort(LISTP_TYPE(simple)*  the_list, int *sorted_arr, int len) {
  struct simple *f, *n;
  int i = 0;

  if (!the_list)
    return -1;

  LISTP_FOR_EACH_ENTRY_SAFE(f, n, the_list, list) {
    if (f->idx != sorted_arr[i]) {
        printf("list val=%d, does not match sorted arr val=%d\n", f->idx, sorted_arr[i]);
        return -1;
    }
    else {
        i = (i < len - 1) ? (i + 1):i;
    }
  }
  if (len != (i + 1)) {
    printf("list len=%d, expected len=%d\n", i + 1, len);
    return -1;
  }
    return 0;
}

static int test_list_sort() {
    #define NUM_OF_INPUTS 11

    typedef struct _arr_in {
        int *arr;
        size_t arr_len;
    }arr_in_t;

    int sort_ret = 0;

    int arr1[] = {20};
    int arr2[] = {20, 10};
    int arr3[] = {20, 10, 30};
    int arr4[] = {20, 10, 30, 5};
    int arr5[] = {5, 20, 10, 30};
    int arr6[] = {10, 20, 30, 40, 15, 50, 60, 70};
    int arr7[] = {10, 40, 30, 20, 5, 70, 60, 50};
    int arr8[] = {10, 20, 40, 50, 70, 90, 101, 201, 301};
    int arr9[] = {100, 20, 40, 30, 50, 70, 60, 90, 80, 10};
    int arr10[] = {100, 20, 40, 30, 80, 50, 70, 60, 90, 80, 10, 101, 201, 301};
    int arr11[] = {11, 50, 30, 11, 20, 2, 12, 2, 5, 70, 7, 8, 7, 8, 12, 50, 1};

    int sorted_arr1[] = {20};
    int sorted_arr2[] = {10, 20};
    int sorted_arr3[] = {10, 20, 30};
    int sorted_arr4[] = {5, 10, 20, 30};
    int sorted_arr5[] = {5, 10, 20, 30};
    int sorted_arr6[] = {10, 15, 20, 30, 40, 50, 60, 70};
    int sorted_arr7[] = {5, 10, 20, 30, 40, 50, 60, 70};
    int sorted_arr8[] = {10, 20, 40, 50, 70, 90, 101, 201, 301};
    int sorted_arr9[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    int sorted_arr10[] = {10, 20, 30, 40, 50, 60, 70, 80, 80, 90, 100, 101, 201, 301};
    int sorted_arr11[] = {1, 2, 2, 5, 7, 7, 8, 8, 11, 11, 12, 12, 20, 30, 50, 50, 70};

    arr_in_t arr_in[NUM_OF_INPUTS] = {{arr1, sizeof(arr1)/sizeof(int)},
            {arr2, sizeof(arr2)/sizeof(int)}, {arr3, sizeof(arr3)/sizeof(int)},
            {arr4, sizeof(arr4)/sizeof(int)}, {arr5, sizeof(arr5)/sizeof(int)},
            {arr6, sizeof(arr6)/sizeof(int)}, {arr7, sizeof(arr7)/sizeof(int)},
            {arr8, sizeof(arr8)/sizeof(int)}, {arr9, sizeof(arr9)/sizeof(int)},
            {arr10, sizeof(arr10)/sizeof(int)}, {arr11, sizeof(arr11)/sizeof(int)}};

    arr_in_t sorted_arr_in[NUM_OF_INPUTS] = {{sorted_arr1, sizeof(sorted_arr1)/sizeof(int)},
    {sorted_arr2, sizeof(sorted_arr2)/sizeof(int)}, {sorted_arr3, sizeof(sorted_arr3)/sizeof(int)},
    {sorted_arr4, sizeof(sorted_arr4)/sizeof(int)}, {sorted_arr5, sizeof(sorted_arr5)/sizeof(int)},
    {sorted_arr6, sizeof(sorted_arr6)/sizeof(int)}, {sorted_arr7, sizeof(sorted_arr7)/sizeof(int)},
    {sorted_arr8, sizeof(sorted_arr8)/sizeof(int)}, {sorted_arr9, sizeof(sorted_arr9)/sizeof(int)},
    {sorted_arr10, sizeof(sorted_arr10)/sizeof(int)}, {sorted_arr11, sizeof(sorted_arr11)/sizeof(int)}};

    for (int cnt = 0; cnt < NUM_OF_INPUTS; cnt++) {
        size_t size = arr_in[cnt].arr_len;
        size_t list_len = 0;
        if (size != sorted_arr_in[cnt].arr_len) {
            printf("size mismatch, arr_in size=%lu, sorted arr size=%lu\n",
            size, sorted_arr_in[cnt].arr_len);
            return -1;
        }

        LISTP_TYPE(simple) the_list;
        INIT_LISTP(&the_list);
        LISTP_SET_COMPARE_FUNCTION(&the_list, compare_node);

        for (int i = 0; i < size; i++) {
            add_node(arr_in[cnt].arr[i], &the_list);
        }
        LISTP_GET_SIZE(&the_list, simple, list_len);
        if (list_len != size) {
            printf("length mismatch. ERROR, list_len=%lu, size=%lu\n",
            list_len, size);
            destroy_list(&the_list);
            return -1;
        }
        LISTP_SORT(&the_list, simple);
        /*print_list(&the_list);*/
        sort_ret += verify_sort(&the_list, sorted_arr_in[cnt].arr, size);
        destroy_list(&the_list);
    }
    return sort_ret;
}