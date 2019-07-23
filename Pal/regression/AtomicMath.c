#include <atomic.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    int64_t my_int = 0;
    struct atomic_int a_int;
    atomic_set(&a_int, 0);

    /* Check that INT_MIN and INT_MAX wrap around consistently
     * with atomic values.
     *
     * Check atomic_sub specifically.
     */
    my_int -= INT_MIN;
    atomic_sub(INT_MIN, &a_int);

    if (my_int == atomic_read(&a_int))
        pal_printf("Subtract INT_MIN: Both values match %ld\n", my_int);
    else
        pal_printf("Subtract INT_MIN: Values do not match %ld, %ld\n", my_int, atomic_read(&a_int));

    atomic_set(&a_int, 0);
    my_int = 0;

    my_int -= INT_MAX;
    atomic_sub(INT_MAX, &a_int);

    if (my_int == atomic_read(&a_int))
        pal_printf("Subtract INT_MAX: Both values match %ld\n", my_int);
    else
        pal_printf("Subtract INT_MAX: Values do not match %ld, %ld\n", my_int, atomic_read(&a_int));

    /* Check that 64-bit signed values also wrap properly. */
    atomic_set(&a_int, 0);
    my_int = 0;

    my_int -= LLONG_MIN;
    atomic_sub(LLONG_MIN, &a_int);

    if (my_int == atomic_read(&a_int))
        pal_printf("Subtract LLONG_MIN: Both values match %ld\n", my_int);
    else
        pal_printf("Subtract LLONG_MIN: Values do not match %ld, %ld\n", my_int,
                   atomic_read(&a_int));

    atomic_set(&a_int, 0);
    my_int = 0;

    my_int -= LLONG_MAX;
    atomic_sub(LLONG_MAX, &a_int);

    if (my_int == atomic_read(&a_int))
        pal_printf("Subtract LLONG_MAX: Both values match %ld\n", my_int);
    else
        pal_printf("Subtract LLONG_MAX: Values do not match %ld, %ld\n", my_int,
                   atomic_read(&a_int));

    return 0;
}
