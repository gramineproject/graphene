/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */
/*
 * Copyright 2018 Intel Corporation.
 * Copyright 2018 Isaku Yamahata <isaku.yamahata at intel.com>
 *                               <isaku.yamahata at gmail.com>
 * All Rights Reserved.
 *
 * This file is part of Graphene Library OS.
 *
 * Graphene Library OS is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Graphene Library OS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SHIM_VDSO_H_
#define _SHIM_VDSO_H_

/* 4094 for mage size */
extern unsigned char vdso_so[4096] __attribute((aligned(4096)));

#endif /* _SHIM_VDSO_H_ */
