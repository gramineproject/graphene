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

extern const uint8_t vdso_so[];
extern const size_t vdso_so_size;

int vdso_map_migrate(void);

#endif /* _SHIM_VDSO_H_ */
