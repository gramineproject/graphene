/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2017 - 2019 CK Tan
 * Copyright (C) 2020 Intel Corporation
 */

#ifndef TOML_H
#define TOML_H

#include <stdint.h>

typedef struct toml_table_t toml_table_t;
typedef struct toml_array_t toml_array_t;

/* A raw value, must be processed by toml_rto* before using */
typedef const char* toml_raw_t;

/* Timestamp types. The year, month, day, hour, minute, second, z fields may be NULL if they are
 * not relevant. E.g., in a DATE type, the hour, minute, second and z fields will be NULLs. */
typedef struct toml_timestamp_t toml_timestamp_t;
struct toml_timestamp_t {
    struct {
        int year, month, day;
        int hour, minute, second, millisec;
        char z[10];
    } __buffer; /* internal. do not use. */
    int *year, *month, *day;
    int *hour, *minute, *second, *millisec;
    char* z;
};

/* Parse a NULL-terminated string containing the full config. Return a table on success,
 * or 0 otherwise. Caller must toml_free(the-return-value) after use. */
toml_table_t* toml_parse(char* conf, char* errbuf, int errbufsz);

/* Free the table returned by toml_parse() */
void toml_free(toml_table_t* tab);

/* Retrieve the key in table at keyidx. Return 0 if out of range. */
const char* toml_key_in(const toml_table_t* tab, int keyidx);

/* Lookup table by key. Return the element or 0 if not found. */
toml_raw_t toml_raw_in(const toml_table_t* tab, const char* key);
toml_array_t* toml_array_in(const toml_table_t* tab, const char* key);
toml_table_t* toml_table_in(const toml_table_t* tab, const char* key);

/* Return the array kind: 't'able, 'a'rray, 'v'alue */
char toml_array_kind(const toml_array_t* arr);

/* For array kind 'v'alue, return the type of values:  i:int, d:double, b:bool, s:string, t:time,
 * D:date, T:timestamp, 0 if unknown */
char toml_array_type(const toml_array_t* arr);

/* Return the number of elements in the array */
int toml_array_nelem(const toml_array_t* arr);

/* Return the key of an array */
const char* toml_array_key(const toml_array_t* arr);

/* Return the number of key-values in a table */
int toml_table_nkval(const toml_table_t* tab);

/* Return the number of arrays in a table */
int toml_table_narr(const toml_table_t* tab);

/* Return the number of sub-tables in a table */
int toml_table_ntab(const toml_table_t* tab);

/* Return the key of a table */
const char* toml_table_key(const toml_table_t* tab);

/* Deref array by index. Return the element at idx or 0 if out of range. */
toml_raw_t toml_raw_at(const toml_array_t* arr, int idx);
toml_array_t* toml_array_at(const toml_array_t* arr, int idx);
toml_table_t* toml_table_at(const toml_array_t* arr, int idx);

/* Raw to string/boolean/int/double/timestamp. Return 0 on success, -1 otherwise. */
int toml_rtos(toml_raw_t s, char** ret);  /* caller must free(ret) after use */
int toml_rtob(toml_raw_t s, int* ret);
int toml_rtoi(toml_raw_t s, int64_t* ret);
int toml_rtod(toml_raw_t s, double* ret);
int toml_rtod_ex(toml_raw_t s, double* ret, char* buf, int buflen);
int toml_rtots(toml_raw_t s, toml_timestamp_t* ret);

/* misc */
int toml_utf8_to_ucs(const char* orig, int len, int64_t* ret);
int toml_ucs_to_utf8(int64_t code, char buf[6]);

#endif /* TOML_H */
