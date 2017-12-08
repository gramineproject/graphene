/* Copyright (C) 2017 Fortanix, Inc.

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

#ifndef MBEDTLS_PLATFORM_H
#define MBEDTLS_PLATFORM_H

/* For standard library apis. */
#include "api.h"

void * malloc(size_t size);
void * calloc (size_t nmem, size_t size);
void free(void *);

#define mbedtls_calloc calloc
#define mbedtls_free free

#endif
