#ifndef _UDIVMODTI4_H
#define _UDIVMODTI4_H

typedef          long long di_int;
typedef unsigned long long du_int;

typedef          int si_int;
typedef unsigned int su_int;

typedef          int ti_int __attribute__((mode (TI)));
typedef unsigned int tu_int __attribute__((mode (TI)));

tu_int __udivti3(tu_int a, tu_int b);

#endif /* _UDIVMODTI4 */
