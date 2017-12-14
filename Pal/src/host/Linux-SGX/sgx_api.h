/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

#ifndef SGX_API_H
#define SGX_API_H

#include "pal_error.h"

int sgx_ocall (unsigned long code, void * ms);

void * sgx_ocalloc (uint64_t size);
void sgx_ocfree (void);

bool sgx_is_within_enclave (const void * addr, uint64_t size);

int sgx_report (sgx_arch_targetinfo_t * targetinfo,
                void * reportdata, sgx_arch_report_t * report);

int sgx_getkey (sgx_arch_keyrequest_t * keyrequest, sgx_arch_key128_t * key);

int sgx_get_report (sgx_arch_hash_t * mrenclave,
                    sgx_arch_attributes_t * attributes,
                    void * enclave_data,
                    sgx_arch_report_t * report);

int sgx_verify_report (sgx_arch_report_t * report);

uint32_t rdrand (void);
uint64_t rdfsbase (void);
void wrfsbase (uint64_t addr);

#endif /* SGX_API_H */
