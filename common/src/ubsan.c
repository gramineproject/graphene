/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file defines handlers for undefined behavior sanitization (UBSan).
 *
 * Normally, code compiled with UBSan is linked against a special library (libubsan). Unfortunately,
 * that library depends on libc, and it's not easy to adapt to a no-stdlib setting. Instead, we
 * create our own minimal handlers for UBSan errors.
 *
 * For more information, see:
 *
 * - UBSan documentation: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
 *
 * - libubsan source code in LLVM repository: https://github.com/llvm/llvm-project/
 *   (compiler-rt/lib/ubsan/ubsan_handlers.cpp)
 */

#ifdef UBSAN

#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "log.h"

/* Type definitions (adapted from libubsan) */

struct TypeDescriptor;

struct SourceLocation {
    const char* Filename;
    uint32_t Line;
    uint32_t Column;
};

struct TypeMismatchData {
    struct SourceLocation Loc;
    const struct TypeDescriptor* Type;
    unsigned char LogAlignment;
    unsigned char TypeCheckKind;
};

typedef uintptr_t ValueHandle;

static void ubsan_log_location(struct SourceLocation* Loc) {
    log_error("ubsan: %s:%d:%d", Loc->Filename, Loc->Line, Loc->Column);
}

/*
 * Simple handlers: print source location and a format string based on parameters.
 *
 * Note that in UBSan API, the first parameter for some of these handlers is not a SourceLocation,
 * but a bigger struct that begins with SourceLocation (and contains additional details, which we
 * ignore).
 */

#define HANDLER(name)       __ubsan_handle_##name
#define HANDLER_ABORT(name) __ubsan_handle_##name##_abort

#define __UBSAN_SIMPLE_HANDLER(name, fmt, params, ...) \
    void HANDLER(name) params;                         \
    void HANDLER(name) params {                        \
        log_error("ubsan: " fmt, ##__VA_ARGS__); \
        ubsan_log_location(Loc);                       \
    }                                                  \
    void HANDLER_ABORT(name) params;                   \
    void HANDLER_ABORT(name) params {                  \
        HANDLER(name)(Loc, ##__VA_ARGS__);             \
        abort();                                       \
    }

#define UBSAN_SIMPLE_HANDLER_0(name, fmt) \
    __UBSAN_SIMPLE_HANDLER(name, fmt, (struct SourceLocation* Loc))

#define UBSAN_SIMPLE_HANDLER_1(name, fmt) \
    __UBSAN_SIMPLE_HANDLER(name, fmt, (struct SourceLocation* Loc, ValueHandle A), A)

#define UBSAN_SIMPLE_HANDLER_2(name, fmt)                                                         \
    __UBSAN_SIMPLE_HANDLER(name, fmt, (struct SourceLocation* Loc, ValueHandle A, ValueHandle B), \
                           A, B)

#define UBSAN_SIMPLE_HANDLER_3(name, fmt)                                                         \
    __UBSAN_SIMPLE_HANDLER(name, fmt, (struct SourceLocation* Loc, ValueHandle A, ValueHandle B,  \
                                       ValueHandle C),                                            \
                           A, B, C)

UBSAN_SIMPLE_HANDLER_2(add_overflow,
                       "overflow: %ld + %ld")
UBSAN_SIMPLE_HANDLER_2(sub_overflow,
                       "overflow: %ld - %ld")
UBSAN_SIMPLE_HANDLER_2(mul_overflow,
                       "overflow: %ld * %ld")
UBSAN_SIMPLE_HANDLER_2(divrem_overflow,
                       "overflow: %ld / %ld")
UBSAN_SIMPLE_HANDLER_1(negate_overflow,
                       "overflow: - %ld")
UBSAN_SIMPLE_HANDLER_2(pointer_overflow,
                       "pointer overflow: applying offset to 0x%lx produced 0x%lx")
UBSAN_SIMPLE_HANDLER_1(load_invalid_value,
                       "load of invalid value: %ld")
UBSAN_SIMPLE_HANDLER_0(builtin_unreachable,
                       "__builtin_unreachable")
UBSAN_SIMPLE_HANDLER_2(shift_out_of_bounds,
                       "shift out of bounds: %ld, %ld")
UBSAN_SIMPLE_HANDLER_1(out_of_bounds,
                       "array index out of bounds: %ld")
UBSAN_SIMPLE_HANDLER_1(vla_bound_not_positive,
                       "variable-length array bound bound is not positive: %ld")
UBSAN_SIMPLE_HANDLER_1(float_cast_overflow,
                       "float cast overflow from 0x%lx")
UBSAN_SIMPLE_HANDLER_0(missing_return,
                       "execution reached end of value-returning function without returning a "
                       "value")
UBSAN_SIMPLE_HANDLER_2(implicit_conversion,
                       "implicit conversion changed the value %ld to %ld")
UBSAN_SIMPLE_HANDLER_1(type_mismatch,
                       "type mismatch for pointer 0x%lx")
UBSAN_SIMPLE_HANDLER_3(alignment_assumption,
                       "alignment assumption failed for pointer 0x%lx (%ld byte alignment, offset "
                       "%ld)")
UBSAN_SIMPLE_HANDLER_0(nonnull_arg,
                       "null pointer passed as an argument declared to never be null")
UBSAN_SIMPLE_HANDLER_0(nonnull_return_v1,
                       "null pointer returned from function declared to never return null")
UBSAN_SIMPLE_HANDLER_0(nullability_return_v1,
                       "null pointer returned from function declared to never return null")

/* More complex handlers, displaying additional information. */

void __ubsan_handle_type_mismatch_v1(struct TypeMismatchData* Data, ValueHandle Pointer);
void __ubsan_handle_type_mismatch_v1_abort(struct TypeMismatchData* Data, ValueHandle Pointer);

void __ubsan_handle_type_mismatch_v1(struct TypeMismatchData* Data, ValueHandle Pointer) {
    if (!Pointer) {
        log_error("ubsan: null pointer dereference");
    } else if (Pointer & ((1 << Data->LogAlignment) - 1)) {
        log_error("ubsan: misaligned address %p for type with alignment %u", (void*)Pointer,
                  1 << Data->LogAlignment);
    } else {
        log_error("ubsan: address %p with insufficient space for object", (void*)Pointer);
    }

    ubsan_log_location(&Data->Loc);
}

void __ubsan_handle_type_mismatch_v1_abort(struct TypeMismatchData* Data, ValueHandle Pointer) {
    __ubsan_handle_type_mismatch_v1(Data, Pointer);
    abort();
}

#endif /* UBSAN */
