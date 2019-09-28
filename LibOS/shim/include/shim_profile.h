/* Copyright (C) 2014 Stony Brook University
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
 * shim_profile.h
 *
 * This file includes macros and types for profiling the library OS
 * performance.
 */

#ifndef _SHIM_PROFILE_H_
#define _SHIM_PROFILE_H_

#ifdef PROFILE

#include <atomic.h>

struct shim_profile {
    const char* name;
    enum { CATEGORY, OCCURENCE, INTERVAL } type;
    bool disabled;
    struct shim_profile* root;
    union {
        struct {
            struct atomic_int count;
        } occurence;
        struct {
            struct atomic_int count;
            struct atomic_int time;
        } interval;
    } val;
} __attribute__((aligned(64)));

struct profile_val {
    int idx;
    union {
        struct {
            unsigned int count;
        } occurence;
        struct {
            unsigned int count;
            unsigned long time;
        } interval;
    } val;
};

extern struct shim_profile __profile;
extern struct shim_profile __profile_end;

#define N_PROFILE (((void*)&__profile_end - (void*)&__profile) / sizeof(struct shim_profile))

#define PROFILES (&__profile)

#define DEFINE_PROFILE_CATEGORY(prof, rprof) _DEFINE_PROFILE_CATEGORY(prof, rprof)
#define _DEFINE_PROFILE_CATEGORY(prof, rprof)                                   \
    extern struct shim_profile profile_##rprof;                                 \
    struct shim_profile profile_##prof __attribute__((section(".profile"))) = { \
        .name = #prof,                                                          \
        .root = &profile_##rprof,                                               \
        .type = CATEGORY,                                                       \
    };

#define DEFINE_PROFILE_CATEGORY_DISABLED(prof, rprof) _DEFINE_PROFILE_CATEGORY(prof, rprof)
#define _DEFINE_PROFILE_CATEGORY_DISABLED(prof, rprof)                          \
    extern struct shim_profile profile_##rprof;                                 \
    struct shim_profile profile_##prof __attribute__((section(".profile"))) = { \
        .name     = #prof,                                                      \
        .disabled = true,                                                       \
        .root     = &profile_##rprof,                                           \
        .type     = CATEGORY,                                                   \
    };

#define DEFINE_PROFILE_OCCURENCE(prof, rprof) _DEFINE_PROFILE_OCCURENCE(prof, rprof)
#define _DEFINE_PROFILE_OCCURENCE(prof, rprof)                                  \
    extern struct shim_profile profile_##rprof;                                 \
    struct shim_profile profile_##prof __attribute__((section(".profile"))) = { \
        .name = #prof,                                                          \
        .root = &profile_##rprof,                                               \
        .type = OCCURENCE,                                                      \
    };

#define DEFINE_PROFILE_INTERVAL(prof, rprof) _DEFINE_PROFILE_INTERVAL(prof, rprof)
#define _DEFINE_PROFILE_INTERVAL(prof, rprof)                                   \
    extern struct shim_profile profile_##rprof;                                 \
    struct shim_profile profile_##prof __attribute__((section(".profile"))) = { \
        .name = #prof,                                                          \
        .root = &profile_##rprof,                                               \
        .type = INTERVAL,                                                       \
    };

#define profile_ profile_root

#define INC_PROFILE_OCCURENCE(prof) _INC_PROFILE_OCCURENCE(prof)
#define _INC_PROFILE_OCCURENCE(prof)                                                          \
    ({                                                                                        \
        extern struct shim_profile profile_##prof;                                            \
        profile_##prof.disabled ? 0 : atomic_inc_return(&profile_##prof.val.occurence.count); \
    })

#define ADD_PROFILE_OCCURENCE(prof, num) _ADD_PROFILE_OCCURENCE(prof, num)
#define _ADD_PROFILE_OCCURENCE(prof, num)                                                          \
    ({                                                                                             \
        extern struct shim_profile profile_##prof;                                                 \
        profile_##prof.disabled ? 0 : atomic_add_return(num, &profile_##prof.val.occurence.count); \
    })

#define BEGIN_PROFILE_INTERVAL()         \
    unsigned long _interval;             \
    do {                                 \
        _interval = DkSystemTimeQuery(); \
    } while (0)

#define BEGIN_PROFILE_INTERVAL_SET(val) \
    unsigned long _interval;            \
    do {                                \
        _interval = (val);              \
    } while (0)

#define SET_PROFILE_INTERVAL(val) \
    do {                          \
        _interval = (val);        \
    } while (0)

#define GET_PROFILE_INTERVAL() DkSystemTimeQuery()

#define UPDATE_PROFILE_INTERVAL()               \
    ({                                          \
        unsigned long _c = DkSystemTimeQuery(); \
        unsigned long _t = _c - _interval;      \
        _interval        = _c;                  \
        _t;                                     \
    })

#define ASSIGN_PROFILE_INTERVAL(prof) _ASSIGN_PROFILE_INTERVAL(prof)
#define _ASSIGN_PROFILE_INTERVAL(prof)         \
    extern struct shim_profile profile_##prof; \
    struct shim_profile* _profile = &profile_##prof;

#define SAVE_PROFILE_INTERVAL_ASSIGNED()                  \
    ({                                                    \
        _profile->disabled ? 0 : ({                       \
            unsigned long _t = UPDATE_PROFILE_INTERVAL(); \
            atomic_inc(&_profile->val.interval.count);    \
            atomic_add(_t, &_profile->val.interval.time); \
            _t;                                           \
        });                                               \
    })

#define SAVE_PROFILE_INTERVAL(prof) _SAVE_PROFILE_INTERVAL(prof)
#define _SAVE_PROFILE_INTERVAL(prof)                           \
    ({                                                         \
        extern struct shim_profile profile_##prof;             \
        profile_##prof.disabled ? 0 : ({                       \
            unsigned long _t = UPDATE_PROFILE_INTERVAL();      \
            atomic_inc(&profile_##prof.val.interval.count);    \
            atomic_add(_t, &profile_##prof.val.interval.time); \
            _t;                                                \
        });                                                    \
    })

#define SAVE_PROFILE_INTERVAL_SINCE(prof, since) _SAVE_PROFILE_INTERVAL_SINCE(prof, since)
#define _SAVE_PROFILE_INTERVAL_SINCE(prof, since)              \
    ({                                                         \
        extern struct shim_profile profile_##prof;             \
        profile_##prof.disabled ? 0 : ({                       \
            unsigned long _c = DkSystemTimeQuery();            \
            unsigned long _t = _c - (since);                   \
            atomic_inc(&profile_##prof.val.interval.count);    \
            atomic_add(_t, &profile_##prof.val.interval.time); \
            _t;                                                \
        });                                                    \
    })

#define SAVE_PROFILE_INTERVAL_SET(prof, begin, end) _SAVE_PROFILE_INTERVAL_SET(prof, begin, end)
#define _SAVE_PROFILE_INTERVAL_SET(prof, begin, end)           \
    ({                                                         \
        extern struct shim_profile profile_##prof;             \
        profile_##prof.disabled ? 0 : ({                       \
            unsigned long _t = (end) - (begin);                \
            atomic_inc(&profile_##prof.val.interval.count);    \
            atomic_add(_t, &profile_##prof.val.interval.time); \
            _t;                                                \
        });                                                    \
    })

#else

#define DEFINE_PROFILE_CATEGORY(prof, rprof)
#define DEFINE_PROFILE_OCCURENCE(prof, rprof)
#define DEFINE_PROFILE_INTERVAL(prof, rprof)
#define INC_PROFILE_OCCURENCE(prof) do {} while (0)
#define ADD_PROFILE_OCCURENCE(prof, val) do {} while (0)
#define BEGIN_PROFILE_INTERVAL() do {} while (0)
#define BEGIN_PROFILE_INTERVAL_SET(val) do {} while (0)
#define SET_PROFILE_INTERVAL(val) do {} while (0)
#define GET_PROFILE_INTERVAL() 0
#define UPDATE_PROFILE_INTERVAL() do {} while (0)
#define ASSIGN_PROFILE_INTERVAL(prof) do {} while (0)
#define SAVE_PROFILE_INTERVAL_ASSIGNED() do {} while (0)
#define SAVE_PROFILE_INTERVAL(prof) do {} while (0)
#define SAVE_PROFILE_INTERVAL_SINCE(prof, time) do {} while (0)
#define SAVE_PROFILE_INTERVAL_SET(prof, begin, end) do {} while (0)

#endif

#endif /* _SHIM_PROFILE_H_ */
