/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include <atomic.h>

#include <string.h>
#include <limits.h>

int main (int argc, char ** argv, char ** envp)
{
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
    pal_printf("Subtract INT_MIN: Both values match %lld\n", my_int);
  else
    pal_printf("Subtract INT_MIN: Values do not match %lld, %lld\n", my_int, atomic_read(&a_int));

  atomic_set(&a_int, 0);
  my_int = 0;

  my_int -= INT_MAX;
  atomic_sub(INT_MAX, &a_int);

  if (my_int == atomic_read(&a_int))
    pal_printf("Subtract INT_MAX: Both values match %lld\n", my_int);
  else
    pal_printf("Subtract INT_MAX: Values do not match %lld, %lld\n", my_int, atomic_read(&a_int));
  
  /* Check that 64-bit signed values also wrap properly. */
  atomic_set(&a_int, 0);
  my_int = 0;
  
  my_int -= LLONG_MIN;
  atomic_sub(LLONG_MIN, &a_int);

  if (my_int == atomic_read(&a_int))
    pal_printf("Subtract LLONG_MIN: Both values match %lld\n", my_int);
  else
    pal_printf("Subtract LLONG_MIN: Values do not match %lld, %lld\n", my_int, atomic_read(&a_int));

  atomic_set(&a_int, 0);
  my_int = 0;

  my_int -= LLONG_MAX;
  atomic_sub(LLONG_MAX, &a_int);

  if (my_int == atomic_read(&a_int))
    pal_printf("Subtract LLONG_MAX: Both values match %lld\n", my_int);
  else
    pal_printf("Subtract LLONG_MAX: Values do not match %lld, %lld\n", my_int, atomic_read(&a_int));

  
  return 0;
}
