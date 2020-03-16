/*
 * Copyright (C) 2018 Intel Corporation
 *                    Isaku Yamahata <isaku.yamahata at gmail.com>
 *                                   <isaku.yamahata at intel.com>
 * All Rights Reserved.
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
 *
 * Linker script for Graphene vDSO emulation
 */

PHDRS
{
        text            PT_LOAD         FLAGS(5) FILEHDR PHDRS;
        dynamic         PT_DYNAMIC      FLAGS(4);
        note            PT_NOTE         FLAGS(4);
        eh_frame_hdr    PT_GNU_EH_FRAME;
}

SECTIONS
{
        . = SIZEOF_HEADERS;
        .hash : { *(.hash) } :text
        .gnu.hash : { *(.gnu.hash) }
        .dynsym : { *(.dynsym) }
        .dynstr : { *(.dynstr) }
        .gnu.version : { *(.gnu.version) }
        .gnu.version_d : { *(.gnu.version_d) }
        .gnu.version_r : { *(.gnu.version_r) }
        .dynamic : { *(.dynamic) } :text :dynamic
        .rodata : {
                *(.rodata*)
                *(.data*)
                *(.sdata*)
                *(.got.plt) *(.got)
                *(.gnu.linkonce.d.*)
                *(.bss*)
                *(.dynbss*)
                *(.gnu.linkonce.b.*)
        } : text
        .note : { *(.note.*) } :text :note
        .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
        .eh_frame : { KEEP (*(.eh_frame)) } :text
        .text   : { *(.text*) } : text = 0x90909090,

        /DISCARD/ : {
                *(.discard)
                *(.discard.*)
        }
}

VERSION {
        LINUX_2.6 {
        global:
                clock_gettime;
                __vdso_clock_gettime;
                gettimeofday;
                __vdso_gettimeofday;
                getcpu;
                __vdso_getcpu;
                time;
                __vdso_time;

                __vdso_shim_clock_gettime;
                __vdso_shim_gettimeofday;
                __vdso_shim_getcpu;
                __vdso_shim_time;
        local: *;
        };
}
