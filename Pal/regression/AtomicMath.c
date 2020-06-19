#include <atomic.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    int64_t my_int = 0;
    struct atomic_int a_int;
    __atomic_store_n(&a_int.counter, 0, __ATOMIC_SEQ_CST);

    /* Check that INT_MIN and INT_MAX wrap around consistently
     * with atomic values.
     *
     * Check atomic_sub specifically.
     */
    my_int -= INT_MIN;
    __atomic_sub_fetch(&a_int.counter, INT_MIN, __ATOMIC_SEQ_CST);

    if (my_int == __atomic_load_n(&a_int.counter, __ATOMIC_SEQ_CST))
        pal_printf("Subtract INT_MIN: Both values match %ld\n", my_int);
    else
        pal_printf("Subtract INT_MIN: Values do not match %ld, %ld\n",
                   my_int, __atomic_load_n(&a_int.counter, __ATOMIC_SEQ_CST));

    __atomic_store_n(&a_int.counter, 0, __ATOMIC_SEQ_CST);
    my_int = 0;

    my_int -= INT_MAX;
    __atomic_sub_fetch(&a_int.counter, INT_MAX, __ATOMIC_SEQ_CST);

    if (my_int == __atomic_load_n(&a_int.counter, __ATOMIC_SEQ_CST))
        pal_printf("Subtract INT_MAX: Both values match %ld\n", my_int);
    else
        pal_printf("Subtract INT_MAX: Values do not match %ld, %ld\n",
                   my_int, __atomic_load_n(&a_int.counter, __ATOMIC_SEQ_CST));

    /* Check that 64-bit signed values also wrap properly. */
    __atomic_store_n(&a_int.counter, 0, __ATOMIC_SEQ_CST);
    my_int = 0;

    my_int -= LLONG_MIN;
    __atomic_sub_fetch(&a_int.counter, LLONG_MIN, __ATOMIC_SEQ_CST);

    if (my_int == __atomic_load_n(&a_int.counter, __ATOMIC_SEQ_CST))
        pal_printf("Subtract LLONG_MIN: Both values match %ld\n", my_int);
    else
        pal_printf("Subtract LLONG_MIN: Values do not match %ld, %ld\n", my_int,
                   __atomic_load_n(&a_int.counter, __ATOMIC_SEQ_CST));

    __atomic_store_n(&a_int.counter, 0, __ATOMIC_SEQ_CST);
    my_int = 0;

    my_int -= LLONG_MAX;
    __atomic_sub_fetch(&a_int.counter, LLONG_MAX, __ATOMIC_SEQ_CST);

    if (my_int == __atomic_load_n(&a_int.counter, __ATOMIC_SEQ_CST))
        pal_printf("Subtract LLONG_MAX: Both values match %ld\n", my_int);
    else
        pal_printf("Subtract LLONG_MAX: Values do not match %ld, %ld\n", my_int,
                   __atomic_load_n(&a_int.counter, __ATOMIC_SEQ_CST));

    return 0;
}
